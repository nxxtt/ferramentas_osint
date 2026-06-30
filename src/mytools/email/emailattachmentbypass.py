#!/usr/bin/env python3
"""Modulo de testes de Email Attachment Bypass.

Testa se o servidor de email/filtro de anexos pode ser contornado usando
tecnicas de bypass em anexos:
  - Double extensions: shell.php.jpg
  - MIME type spoofing: .php com Content-Type: image/jpeg
  - Polyglot files: JPEG+PHP, PNG+PHP (magic bytes + codigo)
  - Null byte injection: shell.php%00.jpg
  - Case sensitivity: shell.PhP
  - Trailing dots/spaces: shell.php.
  - Semicolon trick: shell.php;.jpg (old IIS/ASP)
  - Magic byte bypass: GIF89a header + PHP code

Fluxo:
  1. Conecta ao SMTP (porta 25/587/465)
  2. Gera payloads de teste (extensao dupla, MIME spoof, polyglots, etc.)
  3. Envia emails com cada payload como anexo via email.mime
  4. Classifica se cada tecnica foi aceita, rejeitada ou bloqueada
  5. Retorna resultado consolidado com severidade
"""
import argparse
import contextlib
import logging
import smtplib
from dataclasses import asdict, dataclass
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from mytools.core.utils import (
    Cyber,
    add_base_args,
    color,
    create_banner,
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.emailattachmentbypass")

DEFAULT_PORTS = [25, 587, 465]

_ATTACH_BYPASS_PAYLOADS: dict[str, tuple[str, str, bytes]] = {
    "double_ext_php_jpg": ("shell.php.jpg", "application/octet-stream", b"<?php echo 'test'; ?>"),
    "double_ext_php_png": ("shell.php.png", "image/png", b"<?php echo 'test'; ?>"),
    "double_ext_phtml_jpg": ("shell.phtml.jpg", "image/jpeg", b"<?php echo 'test'; ?>"),
    "double_ext_php5_jpg": ("shell.php5.jpg", "image/jpeg", b"<?php echo 'test'; ?>"),
    "mime_spoof_php_as_jpg": ("test.php", "image/jpeg", b"<?php echo 'test'; ?>"),
    "mime_spoof_php_as_png": ("test.php", "image/png", b"<?php echo 'test'; ?>"),
    "polyglot_jpg_php": ("polyglot.jpg", "image/jpeg", b"\xff\xd8\xff\xe0<?php echo 'test'; ?>"),
    "polyglot_png_php": ("polyglot.png", "image/png", b"\x89PNG\r\n\x1a\n<?php echo 'test'; ?>"),
    "null_byte": ("shell.php%00.jpg", "image/jpeg", b"<?php echo 'test'; ?>"),
    "case_upper": ("shell.PHP", "application/x-php", b"<?php echo 'test'; ?>"),
    "case_mixed": ("shell.PhP", "application/x-php", b"<?php echo 'test'; ?>"),
    "trailing_dot": ("shell.php.", "application/x-php", b"<?php echo 'test'; ?>"),
    "semicolon": ("shell.php;.jpg", "image/jpeg", b"<?php echo 'test'; ?>"),
    "magic_bytes_gif": ("shell.gif", "image/gif", b"GIF89a;<?php echo 'test'; ?>"),
}

_CATEGORY_MAP: dict[str, list[str]] = {
    "double_ext": [
        "double_ext_php_jpg", "double_ext_php_png",
        "double_ext_phtml_jpg", "double_ext_php5_jpg",
    ],
    "mime_spoof": ["mime_spoof_php_as_jpg", "mime_spoof_php_as_png"],
    "polyglot": ["polyglot_jpg_php", "polyglot_png_php"],
    "null_byte": ["null_byte"],
    "case": ["case_upper", "case_mixed"],
    "trailing": ["trailing_dot"],
    "semicolon": ["semicolon"],
    "magic_bytes": ["magic_bytes_gif"],
}


@dataclass(frozen=True, slots=True)
class BypassAttempt:
    """Resultado de uma tentativa individual de bypass."""
    technique: str
    filename: str
    content_type: str
    status: str  # accepted, rejected, blocked, error
    server_response: str
    error: str


@dataclass(frozen=True, slots=True)
class BypassResult:
    """Resultado completo da verificacao de attachment bypass."""
    target: str
    port: int
    tls: bool
    banner: str
    attempts: list[BypassAttempt]
    accepted_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str  # vulnerable, secure, warning


def _connect_smtp(target: str, port: int, timeout: float) -> tuple[smtplib.SMTP, bool]:
    """Conecta ao servidor SMTP e retorna (conexao, tls_ativo)."""
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(target, port, timeout=timeout)
            return server, True
        server = smtplib.SMTP(target, port, timeout=timeout)
    except smtplib.SMTPConnectError as exc:
        raise ConnectionError(f"Falha ao conectar: {exc}") from exc
    except OSError as exc:
        raise ConnectionError(f"Erro de conexao: {exc}") from exc
    tls_active = False
    try:
        banner_text = server.ehlo()
        if b"STARTTLS" in (banner_text[1] if isinstance(banner_text, tuple) else b""):
            server.starttls()
            server.ehlo()
            tls_active = True
    except (smtplib.SMTPException, OSError):
        pass
    return server, tls_active


def _get_banner(server: smtplib.SMTP) -> str:
    """Retorna o banner EHLO do servidor."""
    try:
        _code, banner = server.ehlo()
        return banner.decode("utf-8", errors="replace") if isinstance(banner, bytes) else str(banner)
    except smtplib.SMTPException:
        return ""


def _build_attachment_email(
    from_addr: str,
    to_addr: str,
    filename: str,
    content_type: str,
    payload: bytes,
) -> MIMEMultipart:
    """Construi email com anexo de teste."""
    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = f"Attachment Bypass Test — {filename}"

    body = MIMEText(f"Attachment bypass test for: {filename}", "plain", "utf-8")
    msg.attach(body)

    part = MIMEBase("application", "octet-stream")
    part.set_payload(payload)
    part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
    part.replace_header("Content-Type", content_type)
    msg.attach(part)

    return msg


def _send_bypass_email(
    server: smtplib.SMTP,
    from_addr: str,
    to_addr: str,
    filename: str,
    content_type: str,
    payload: bytes,
) -> tuple[bool, str]:
    """Envia email com anexo de bypass e retorna (aceito, detalhes)."""
    msg = _build_attachment_email(from_addr, to_addr, filename, content_type, payload)

    try:
        server.ehlo()
        server.mail(from_addr)
        server.rcpt(to_addr)
        server.data(msg.as_string())
        server.rset()
        return True, "accepted"
    except smtplib.SMTPResponseException as exc:
        return False, f"{exc.smtp_code} {exc.smtp_error}"
    except smtplib.SMTPException as exc:
        return False, str(exc)


def scan_attachment_bypass(
    target: str,
    port: int = 587,
    from_addr: str = "test@example.com",
    to_addr: str = "test@example.com",
    timeout: float = 10.0,
    category: str | None = None,
) -> BypassResult:
    """Executa a verificacao de Email Attachment Bypass."""
    attempts: list[BypassAttempt] = []
    issues: list[str] = []
    banner = ""
    tls_active = False

    try:
        server, tls_active = _connect_smtp(target, port, timeout)
    except ConnectionError as exc:
        issues.append(f"Falha de conexao: {exc}")
        return BypassResult(
            target=target, port=port, tls=False, banner="",
            attempts=[], accepted_techniques=[], blocked_techniques=[],
            issues=issues, overall_status="error",
        )

    try:
        banner = _get_banner(server)

        if category:
            selected_names = _CATEGORY_MAP.get(category, [])
            if not selected_names:
                issues.append(f"Categoria desconhecida: {category}")
                selected_names = list(_ATTACH_BYPASS_PAYLOADS.keys())
        else:
            selected_names = list(_ATTACH_BYPASS_PAYLOADS.keys())

        for name in selected_names:
            filename, content_type, payload = _ATTACH_BYPASS_PAYLOADS[name]

            try:
                accepted, details = _send_bypass_email(
                    server, from_addr, to_addr, filename, content_type, payload,
                )
                status = "accepted" if accepted else "rejected"

                if accepted:
                    issues.append(f"Tecnica aceita: {name} ({filename})")

                attempts.append(BypassAttempt(
                    technique=name,
                    filename=filename,
                    content_type=content_type,
                    status=status,
                    server_response=details[:200],
                    error="",
                ))
            except (smtplib.SMTPException, OSError) as exc:
                attempts.append(BypassAttempt(
                    technique=name,
                    filename=filename,
                    content_type=content_type,
                    status="error",
                    server_response="",
                    error=str(exc)[:200],
                ))

    finally:
        with contextlib.suppress(smtplib.SMTPException):
            server.quit()

    accepted = [a.technique for a in attempts if a.status == "accepted"]
    blocked = [a.technique for a in attempts if a.status in ("rejected", "blocked", "error")]

    if accepted:
        overall = "vulnerable"
    elif blocked and not accepted:
        overall = "secure"
    else:
        overall = "warning"

    if overall == "vulnerable":
        issues.append(f"{len(accepted)}/{len(attempts)} tecnicas de bypass aceitas")
    elif overall == "secure":
        issues.append("Todas as tecnicas bloqueadas ou rejeitadas")
    else:
        issues.append("Resultado inconclusivo")

    return BypassResult(
        target=target,
        port=port,
        tls=tls_active,
        banner=banner[:200],
        attempts=attempts,
        accepted_techniques=accepted,
        blocked_techniques=blocked,
        issues=issues,
        overall_status=overall,
    )


def print_results(result: BypassResult) -> None:
    """Exibe o relatorio de Email Attachment Bypass."""
    print(color("\n[+] Email Attachment Bypass — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Target: {color(result.target, Cyber.WHITE, Cyber.BOLD)}:{result.port}")
    print(f"  TLS: {color('Sim' if result.tls else 'Nao', Cyber.CYAN)}")
    print()

    status_colors = {
        "vulnerable": (Cyber.RED, Cyber.BOLD),
        "secure": (Cyber.GREEN, Cyber.BOLD),
        "warning": (Cyber.YELLOW, ""),
        "error": (Cyber.YELLOW, ""),
    }
    sc = status_colors.get(result.overall_status, (Cyber.WHITE, ""))
    print(f"  Status: {color(result.overall_status.upper(), *sc)}")
    print()

    accepted = [a for a in result.attempts if a.status == "accepted"]

    status_icons = {
        "accepted": color("[!]", Cyber.RED, Cyber.BOLD),
        "rejected": color("[+]", Cyber.GREEN),
        "blocked": color("[+]", Cyber.GREEN),
        "error": color("[-]", Cyber.YELLOW),
    }

    print(color("  Tecnicas testadas:", Cyber.CYAN, Cyber.BOLD))
    for a in result.attempts:
        icon = status_icons.get(a.status, color("[?]", Cyber.WHITE))
        print(f"    {icon} {a.technique}")
        print(f"      Arquivo: {a.filename}  |  MIME: {a.content_type}")
        if a.status == "accepted":
            print(f"      Resposta: {a.server_response[:80]}")
        elif a.status == "error":
            print(f"      Erro: {a.error[:80]}")
        print()

    if result.issues:
        print(color("  Observacoes:", Cyber.YELLOW, Cyber.BOLD))
        for issue in result.issues:
            print(f"    {color('[!]', Cyber.YELLOW)} {issue}")
        print()

    if result.overall_status == "vulnerable":
        print(color(f"  [-] Servidor VULNERAVEL — {len(accepted)}/{len(result.attempts)} bypasses aceitos", Cyber.RED, Cyber.BOLD))
        print(color("  [-] Remedio: whitelist de extensoes, validacao de magic bytes, scan de conteudo", Cyber.CYAN))
    elif result.overall_status == "secure":
        print(color("  [+] Servidor seguro — todas as tecnicas bloqueadas", Cyber.GREEN, Cyber.BOLD))
    else:
        print(color("  [!] Resultado inconclusivo — revisar manualmente", Cyber.YELLOW))


def banner_art() -> None:
    """Exibe o banner do Email Attachment Bypass."""
    art = r"""
    __  __    _    ___ _   _ _____     _    ____
   |  \/  |  / \  |_ _| \ | | ____|   / \  |  _ \
   | |\/| | / _ \  | ||  \| |  _|    / _ \ | |_) |
   | |  | |/ ___ \ | || |\  | |___  / ___ \|  _ <
   |_|  |_/_/   \_\___|_| \_|_____\/_/   \_\_| \_\
"""
    create_banner(art, "   attachment bypass: testa bypass de filtros de anexos (double ext, MIME spoof, polyglots)")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Email Attachment Bypass — testa bypass de filtros de anexos de email.",
        epilog="Verifica se o servidor aceita anexos maliciosos com tecnicas de bypass.",
    )
    add_base_args(parser)
    parser.add_argument("target", nargs="?", help="Host SMTP alvo (ex: mail.example.com).")
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=587,
        help="Porta SMTP. Padrao: 587",
    )
    parser.add_argument(
        "--from-addr",
        default="test@example.com",
        help="Endereco FROM para os testes. Padrao: test@example.com",
    )
    parser.add_argument(
        "--to-addr",
        default="test@example.com",
        help="Endereco TO para os testes. Padrao: test@example.com",
    )
    parser.add_argument(
        "--category", "-c",
        choices=list(_CATEGORY_MAP.keys()),
        help="Testa apenas uma categoria de bypass.",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    target = getattr(args, "target", None)
    if not target:
        print(color("[!] Informe um host SMTP.", Cyber.RED))
        return 1

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma conexao SMTP sera feita.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Target: {color(target, Cyber.WHITE, Cyber.BOLD)}:{args.port}")
        return 0

    result = scan_attachment_bypass(
        target=target,
        port=args.port,
        from_addr=args.from_addr,
        to_addr=args.to_addr,
        timeout=args.timeout,
        category=getattr(args, "category", None),
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["target", "port", "overall_status", "accepted_techniques", "issues"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Email Attachment Bypass."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(a.target),
        prompt="attachbypass> ",
        description="Email Attachment Bypass — testa bypass de filtros de anexos de email.",
        example="mail.example.com --port 587",
        contextual_help=(
            "Uso: <host> [opcoes]\n"
            "Exemplos:\n"
            "  mail.example.com\n"
            "  mail.example.com --port 25\n"
            "  mail.example.com --from-addr admin@test.com\n"
            "  mail.example.com --category polyglot\n"
            "  mail.example.com --category double_ext"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
