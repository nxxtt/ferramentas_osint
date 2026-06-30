#!/usr/bin/env python3
"""Modulo de testes de Email Address Quoting Bypass.

Testa se o servidor SMTP aceita enderecos de email com local-parts
citados (quoted) que podem contornar filtros, blocklists e sistemas
anti-spam. Baseado em RFC 5321/5322.

Tecnicas testadas:
  - quoted_basic: "user"@domain.com (bypass de blocklists)
  - quoted_space: "user name"@domain.com (bypass de allowlists)
  - quoted_dot: "user.name"@domain.com (bypass de filtros)
  - quoted_special: "user!name"@domain.com (bypass de regex)
  - quoted_at: "user@other.com"@domain.com (misrouting - CVE-2025-13033)
  - quoted_backslash: "user\\name"@domain.com (bypass de parsing)
  - quoted_double_dot: "user..name"@domain.com (bypass de normalizacao)
  - quoted_leading_space: " user"@domain.com (bypass de dedup)
  - comment_syntax: user(comment)@domain.com (bypass de filtros)
  - backslash_escape: user\\.name@domain.com (bypass de escaping)
  - angle_bracket: <user>@domain.com (bypass de parsing)
  - unicode_local: 用户@domain.com (bypass de ASCII filters)
  - null_byte: user\\x00name@domain.com (misrouting old PHP)
  - ip_literal: user@[127.0.0.1] (bypass de DNS checks)

Fluxo:
  1. Conecta ao SMTP (porta 25/587/465) com STARTTLS
  2. Para cada endereco citado: MAIL FROM + RCPT TO
  3. Classifica resposta: accepted (250) / rejected (550) / error
  4. Retorna resultado consolidado com severidade
"""
import argparse
import contextlib
import logging
import smtplib
from dataclasses import asdict, dataclass

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

logger = logging.getLogger("mytools.emailaddressbypass")

DEFAULT_PORTS = [25, 587, 465]

_CATEGORY_MAP: dict[str, list[str]] = {
    "quoted": [
        "quoted_basic", "quoted_space", "quoted_dot",
        "quoted_special", "quoted_leading_space",
    ],
    "special": [
        "quoted_at", "quoted_backslash", "quoted_double_dot",
        "comment_syntax", "backslash_escape",
    ],
    "encoding": [
        "angle_bracket", "unicode_local", "null_byte",
    ],
    "literal": ["ip_literal"],
}


def _build_payloads(domain: str) -> dict[str, str]:
    """Constrói enderecos de teste para o dominio informado."""
    return {
        "quoted_basic": f'"user"@{domain}',
        "quoted_space": f'"user name"@{domain}',
        "quoted_dot": f'"user.name"@{domain}',
        "quoted_special": f'"user!name"@{domain}',
        "quoted_at": f'"user@other.com"@{domain}',
        "quoted_backslash": f'"user\\name"@{domain}',
        "quoted_double_dot": f'"user..name"@{domain}',
        "quoted_leading_space": f'" user"@{domain}',
        "comment_syntax": f'user(comment)@{domain}',
        "backslash_escape": f'user\\.name@{domain}',
        "angle_bracket": f'<user>@{domain}',
        "unicode_local": f'用户@{domain}',
        "null_byte": f'user\x00name@{domain}',
        "ip_literal": 'user@[127.0.0.1]',
    }


@dataclass(frozen=True, slots=True)
class AddressAttempt:
    """Resultado de uma tentativa individual de bypass."""
    technique: str
    email_address: str
    status: str  # accepted, rejected, error
    server_response: str
    error: str


@dataclass(frozen=True, slots=True)
class AddressResult:
    """Resultado completo da verificacao de address quoting bypass."""
    target: str
    port: int
    tls: bool
    banner: str
    attempts: list[AddressAttempt]
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


def _test_address(
    server: smtplib.SMTP,
    from_addr: str,
    to_addr: str,
) -> tuple[bool, str]:
    """Testa se servidor aceita RCPT TO com endereco citado."""
    try:
        server.ehlo()
        server.mail(from_addr)
        code, msg = server.rcpt(to_addr)
        server.rset()
        accepted = code in (250, 251)
        detail = f"{code} {msg.decode('utf-8', errors='replace') if isinstance(msg, bytes) else msg}"
        return accepted, detail
    except smtplib.SMTPResponseException as exc:
        return False, f"{exc.smtp_code} {exc.smtp_error}"
    except smtplib.SMTPException as exc:
        return False, str(exc)


def scan_address_bypass(
    target: str,
    port: int = 587,
    from_addr: str = "test@example.com",
    domain: str | None = None,
    timeout: float = 10.0,
    category: str | None = None,
) -> AddressResult:
    """Executa a verificacao de Email Address Quoting Bypass."""
    attempts: list[AddressAttempt] = []
    issues: list[str] = []
    banner = ""
    tls_active = False
    test_domain = domain or target

    try:
        server, tls_active = _connect_smtp(target, port, timeout)
    except ConnectionError as exc:
        issues.append(f"Falha de conexao: {exc}")
        return AddressResult(
            target=target, port=port, tls=False, banner="",
            attempts=[], accepted_techniques=[], blocked_techniques=[],
            issues=issues, overall_status="error",
        )

    try:
        banner = _get_banner(server)
        payloads = _build_payloads(test_domain)

        if category:
            selected_names = _CATEGORY_MAP.get(category, [])
            if not selected_names:
                issues.append(f"Categoria desconhecida: {category}")
                selected_names = list(payloads.keys())
        else:
            selected_names = list(payloads.keys())

        for name in selected_names:
            email_addr = payloads[name]

            try:
                accepted, details = _test_address(server, from_addr, email_addr)
                status = "accepted" if accepted else "rejected"

                if accepted:
                    issues.append(f"Endereco aceito: {name} ({email_addr})")

                attempts.append(AddressAttempt(
                    technique=name,
                    email_address=email_addr,
                    status=status,
                    server_response=details[:200],
                    error="",
                ))
            except (smtplib.SMTPException, OSError) as exc:
                attempts.append(AddressAttempt(
                    technique=name,
                    email_address=email_addr,
                    status="error",
                    server_response="",
                    error=str(exc)[:200],
                ))

    finally:
        with contextlib.suppress(smtplib.SMTPException):
            server.quit()

    accepted = [a.technique for a in attempts if a.status == "accepted"]
    blocked = [a.technique for a in attempts if a.status in ("rejected", "error")]

    if accepted:
        overall = "vulnerable"
    elif blocked:
        overall = "secure"
    else:
        overall = "warning"

    if overall == "vulnerable":
        issues.append(f"{len(accepted)}/{len(attempts)} enderecos citados aceitos")
    elif overall == "secure":
        issues.append("Todos os enderecos citados bloqueados ou rejeitados")
    else:
        issues.append("Resultado inconclusivo")

    return AddressResult(
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


def print_results(result: AddressResult) -> None:
    """Exibe o relatorio de Email Address Quoting Bypass."""
    print(color("\n[+] Email Address Quoting Bypass — Relatorio:", Cyber.GREEN, Cyber.BOLD))
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

    status_icons = {
        "accepted": color("[!]", Cyber.RED, Cyber.BOLD),
        "rejected": color("[+]", Cyber.GREEN),
        "error": color("[-]", Cyber.YELLOW),
    }

    print(color("  Enderecos testados:", Cyber.CYAN, Cyber.BOLD))
    for a in result.attempts:
        icon = status_icons.get(a.status, color("[?]", Cyber.WHITE))
        print(f"    {icon} {a.technique}")
        print(f"      Email: {a.email_address}")
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
        print(color(f"  [-] Servidor VULNERAVEL — {len(result.accepted_techniques)}/{len(result.attempts)} enderecos citados aceitos", Cyber.RED, Cyber.BOLD))
        print(color("  [-] Risco: bypass de blocklists, misrouting (CVE-2025-13033), filter evasion", Cyber.CYAN))
        print(color("  [-] Remedio: rejeitar enderecos com local-parts citados no RCPT TO", Cyber.CYAN))
    elif result.overall_status == "secure":
        print(color("  [+] Servidor seguro — todos os enderecos citados bloqueados", Cyber.GREEN, Cyber.BOLD))
    else:
        print(color("  [!] Resultado inconclusivo — revisar manualmente", Cyber.YELLOW))


def banner_art() -> None:
    """Exibe o banner do Email Address Quoting Bypass."""
    art = r"""
    __  __    _    __  __  ___        _____                    _
   |  \/  |  / \  |  \/  |/ _ \      |_   _|__ _ __ _ __ ___ | |
   | |\/| | / _ \ | |\/| | | | |_____  | |/ _ \ '__| '_ ` _ \| |
   | |  | |/ ___ \| |  | | |_| |_____| | |  __/ |  | | | | | | |
   |_|  |_/_/   \_\_|  |_|\___/       |_| \___|_|  |_| |_| |_|_|
"""
    create_banner(art, "   address bypass: testa bypass de blocklists via local-parts citados (RFC 5321/5322)")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Email Address Quoting Bypass — testa bypass de blocklists via local-parts citados.",
        epilog="Verifica se o servidor aceita enderecos RFC 5321/5322 citados que bypassam filtros.",
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
        "--domain",
        help="Dominio alvo para construir enderecos de teste. Padrao: target",
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

    result = scan_address_bypass(
        target=target,
        port=args.port,
        from_addr=args.from_addr,
        domain=getattr(args, "domain", None),
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
    """Ponto de entrada principal do Email Address Quoting Bypass."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(a.target),
        prompt="addrbypass> ",
        description="Email Address Quoting Bypass — testa bypass de blocklists via local-parts citados.",
        example="mail.example.com --port 587",
        contextual_help=(
            "Uso: <host> [opcoes]\n"
            "Exemplos:\n"
            "  mail.example.com\n"
            "  mail.example.com --port 25\n"
            "  mail.example.com --domain example.com\n"
            "  mail.example.com --category quoted\n"
            "  mail.example.com --category special"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
