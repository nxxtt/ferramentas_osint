#!/usr/bin/env python3
"""Modulo de testes de SMTP Downgrade Attack.

Testa se um servidor SMTP pode ser forcado a operar em plaintext mesmo
anunciando STARTTLS:
  - STARTTLS Strip: verifica se TLS e obrigatorio ou opcional
  - Plaintext Fallback: testa se servidor aceita email sem TLS
  - HELO Downgrade: envia HELO em vez de EHLO
  - Auth without TLS: testa se autenticacao e aceita em plaintext
  - MITM resilience: verifica se servidor força TLS

Fluxo:
  1. Conecta ao SMTP (porta 25/587)
  2. Verifica EHLO e suporte a STARTTLS
  3. Tenta operacoes em plaintext
  4. Classifica seguranca
"""
import argparse
import contextlib
import logging
import smtplib
from dataclasses import asdict, dataclass

from utils import (
    Cyber,
    add_base_args,
    color,
    create_banner,
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.smtpdowngrade")

DEFAULT_PORTS = [25, 587]


@dataclass(frozen=True, slots=True)
class DowngradeTest:
    """Resultado de um teste individual de downgrade."""
    name: str
    status: str  # pass, fail, vulnerable, error
    description: str
    details: str


@dataclass(frozen=True, slots=True)
class DowngradeResult:
    """Resultado completo da verificacao de downgrade."""
    target: str
    port: int
    banner: str
    ehlo_advertises_starttls: bool
    supports_starttls: bool
    requires_starttls: bool
    plaintext_accepted: bool
    helo_downgrade_accepted: bool
    auth_without_tls: bool
    tests: list[DowngradeTest]
    issues: list[str]
    overall_status: str  # secure, vulnerable, warning


def _connect_smtp(target: str, port: int, timeout: float) -> smtplib.SMTP:
    """Conecta ao servidor SMTP em plaintext."""
    try:
        server = smtplib.SMTP(target, port, timeout=timeout)
    except smtplib.SMTPConnectError as exc:
        raise ConnectionError(f"Falha ao conectar: {exc}") from exc
    except OSError as exc:
        raise ConnectionError(f"Erro de conexao: {exc}") from exc
    return server


def _get_banner(server: smtplib.SMTP) -> str:
    """Retorna o banner EHLO do servidor."""
    try:
        _code, banner = server.ehlo()
        return banner.decode("utf-8", errors="replace") if isinstance(banner, bytes) else str(banner)
    except smtplib.SMTPException:
        return ""


def _check_starttls(server: smtplib.SMTP) -> bool:
    """Verifica se o servidor suporta STARTTLS."""
    try:
        _code, _msg = server.starttls()
        server.ehlo()
        return True
    except smtplib.SMTPNotSupportedError:
        return False
    except smtplib.SMTPException:
        return False


def _test_plaintext_mail(
    server: smtplib.SMTP,
    from_addr: str,
    to_addr: str,
) -> tuple[bool, str]:
    """Testa se servidor aceita MAIL FROM/RCPT TO em plaintext."""
    try:
        server.ehlo()
        code1, _msg1 = server.mail(from_addr)
        code2, _msg2 = server.rcpt(to_addr)
        server.rset()
        return True, f"MAIL FROM={code1} RCPT TO={code2}"
    except smtplib.SMTPResponseException as exc:
        return False, f"{exc.smtp_code} {exc.smtp_error}"
    except smtplib.SMTPException as exc:
        return False, str(exc)


def _test_helo_downgrade(target: str, port: int, timeout: float) -> tuple[bool, str]:
    """Testa se servidor aceita HELO em vez de EHLO."""
    try:
        server = smtplib.SMTP(target, port, timeout=timeout)
        code, _msg = server.helo()
        accepted = code == 250
        server.quit()
        return accepted, f"HELO response: {code}"
    except (smtplib.SMTPException, OSError) as exc:
        return False, str(exc)


def scan_smtp_downgrade(
    target: str,
    port: int = 587,
    from_addr: str = "test@example.com",
    to_addr: str = "test@example.com",
    timeout: float = 10.0,
) -> DowngradeResult:
    """Executa a verificacao de SMTP Downgrade Attack."""
    tests: list[DowngradeTest] = []
    issues: list[str] = []
    banner = ""
    advertises_starttls = False
    supports_starttls = False
    requires_starttls = True
    plaintext_accepted = False
    helo_downgrade_accepted = False
    auth_without_tls = False

    # Test 1: Connect and check banner
    try:
        server = _connect_smtp(target, port, timeout)
    except ConnectionError as exc:
        issues.append(f"Falha de conexao: {exc}")
        return DowngradeResult(
            target=target, port=port, banner="", ehlo_advertises_starttls=False,
            supports_starttls=False, requires_starttls=True, plaintext_accepted=False,
            helo_downgrade_accepted=False, auth_without_tls=False,
            tests=[], issues=issues, overall_status="error",
        )

    try:
        banner = _get_banner(server)
        advertises_starttls = "STARTTLS" in banner

        tests.append(DowngradeTest(
            name="EHLO STARTTLS Advertisement",
            status="pass" if advertises_starttls else "fail",
            description="Servidor anuncia STARTTLS no EHLO",
            details=banner[:200],
        ))

        # Test 2: Try STARTTLS
        if advertises_starttls:
            supports_starttls = _check_starttls(server)
            tests.append(DowngradeTest(
                name="STARTTLS Negotiation",
                status="pass" if supports_starttls else "vulnerable",
                description="Servidor aceita STARTTLS",
                details="STARTTLS OK" if supports_starttls else "STARTTLS falhou",
            ))

        # Test 3: Plaintext fallback — test if server accepts mail without TLS
        server2 = _connect_smtp(target, port, timeout)
        try:
            accepted, details = _test_plaintext_mail(server2, from_addr, to_addr)
            plaintext_accepted = accepted

            if accepted and advertises_starttls:
                requires_starttls = False
                tests.append(DowngradeTest(
                    name="Plaintext Mail Fallback",
                    status="vulnerable",
                    description="Servidor aceita email em plaintext mesmo anunciando STARTTLS",
                    details=details,
                ))
                issues.append("Servidor aceita plaintext — downgrade possivel")
            elif accepted:
                tests.append(DowngradeTest(
                    name="Plaintext Mail Accepted",
                    status="pass",
                    description="Servidor aceita email em plaintext (sem STARTTLS anunciado)",
                    details=details,
                ))
            else:
                tests.append(DowngradeTest(
                    name="Plaintext Mail Rejected",
                    status="pass",
                    description="Servidor rejeita email em plaintext",
                    details=details,
                ))
        finally:
            with contextlib.suppress(smtplib.SMTPException):
                server2.quit()

        # Test 4: HELO downgrade
        helo_ok, helo_details = _test_helo_downgrade(target, port, timeout)
        helo_downgrade_accepted = helo_ok
        tests.append(DowngradeTest(
            name="HELO Downgrade",
            status="fail" if helo_ok else "pass",
            description="Servidor aceita HELO (downgrade de EHLO)" if helo_ok else "Servidor nao aceita HELO",
            details=helo_details,
        ))

        # Test 5: Auth without TLS
        server3 = _connect_smtp(target, port, timeout)
        try:
            server3.ehlo()
            code, _msg = server3.docmd("AUTH LOGIN")
            auth_without_tls = code in (234, 334)
            tests.append(DowngradeTest(
                name="AUTH without TLS",
                status="vulnerable" if auth_without_tls else "pass",
                description="Servidor aceita AUTH em plaintext" if auth_without_tls else "Servidor exige TLS para AUTH",
                details=f"AUTH response: {code}",
            ))
            if auth_without_tls:
                issues.append("Servidor aceita autenticacao em plaintext — MITM possivel")
        except (smtplib.SMTPException, OSError) as exc:
            tests.append(DowngradeTest(
                name="AUTH without TLS",
                status="pass",
                description="Servidor rejeita AUTH em plaintext",
                details=str(exc),
            ))
        finally:
            with contextlib.suppress(smtplib.SMTPException):
                server3.quit()

    finally:
        with contextlib.suppress(smtplib.SMTPException):
            server.quit()

    # Overall status
    vulnerable_tests = [t for t in tests if t.status == "vulnerable"]
    if vulnerable_tests:
        overall = "vulnerable"
    elif any(t.status == "fail" for t in tests):
        overall = "warning"
    else:
        overall = "secure"

    if overall == "vulnerable":
        issues.append("Servidor vulneravel a SMTP Downgrade Attack")
    elif overall == "secure":
        issues.append("Servidor force TLS corretamente")

    return DowngradeResult(
        target=target,
        port=port,
        banner=banner[:200],
        ehlo_advertises_starttls=advertises_starttls,
        supports_starttls=supports_starttls,
        requires_starttls=requires_starttls,
        plaintext_accepted=plaintext_accepted,
        helo_downgrade_accepted=helo_downgrade_accepted,
        auth_without_tls=auth_without_tls,
        tests=tests,
        issues=issues,
        overall_status=overall,
    )


def print_results(result: DowngradeResult) -> None:
    """Exibe o relatorio de SMTP Downgrade Attack."""
    print(color("\n[+] SMTP Downgrade Attack — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Target: {color(result.target, Cyber.WHITE, Cyber.BOLD)}:{result.port}")
    print()

    status_colors = {
        "secure": (Cyber.GREEN, Cyber.BOLD),
        "vulnerable": (Cyber.RED, Cyber.BOLD),
        "warning": (Cyber.YELLOW, ""),
        "error": (Cyber.RED, ""),
    }
    sc = status_colors.get(result.overall_status, (Cyber.WHITE, ""))
    print(f"  Status: {color(result.overall_status.upper(), *sc)}")
    print()

    print(f"  STARTTLS anunciado: {color('Sim' if result.ehlo_advertises_starttls else 'Nao', Cyber.CYAN)}")
    print(f"  STARTTLS suportado: {color('Sim' if result.supports_starttls else 'Nao', Cyber.CYAN)}")
    print(f"  TLS obrigatório: {color('Sim' if result.requires_starttls else 'Nao', Cyber.GREEN if result.requires_starttls else Cyber.RED)}")
    print(f"  Plaintext aceito: {color('Sim' if result.plaintext_accepted else 'Nao', Cyber.RED if result.plaintext_accepted else Cyber.GREEN)}")
    print(f"  HELO downgrade: {color('Sim' if result.helo_downgrade_accepted else 'Nao', Cyber.YELLOW if result.helo_downgrade_accepted else Cyber.GREEN)}")
    print(f"  AUTH sem TLS: {color('Sim' if result.auth_without_tls else 'Nao', Cyber.RED if result.auth_without_tls else Cyber.GREEN)}")
    print()

    if result.tests:
        print(color("  Testes:", Cyber.CYAN, Cyber.BOLD))
        for t in result.tests:
            status_icons = {
                "pass": color("[+]", Cyber.GREEN),
                "fail": color("[!]", Cyber.YELLOW),
                "vulnerable": color("[!]", Cyber.RED, Cyber.BOLD),
                "error": color("[-]", Cyber.RED),
            }
            icon = status_icons.get(t.status, color("[?]", Cyber.WHITE))
            print(f"    {icon} {t.name}")
            print(f"      {t.description}")
            print()
        print()

    if result.issues:
        print(color("  Observacoes:", Cyber.YELLOW, Cyber.BOLD))
        for issue in result.issues:
            print(f"    {color('[!]', Cyber.YELLOW)} {issue}")
        print()

    if result.overall_status == "secure":
        print(color("  [+] Servidor protegido contra downgrade — força TLS", Cyber.GREEN, Cyber.BOLD))
    elif result.overall_status == "vulnerable":
        print(color("  [-] Servidor VULNERAVEL a SMTP Downgrade Attack", Cyber.RED, Cyber.BOLD))
        print(color("  [-] Remedio: Forcar STARTTLS obrigatorio e rejeitar plaintext", Cyber.CYAN))
    else:
        print(color("  [!] Servidor com configuracao parcial — revisar", Cyber.YELLOW))


def banner_art() -> None:
    """Exibe o banner do SMTP Downgrade."""
    art = r"""
   _____ __  __ ____   _    _  ______   ____  _   _ ______    ____
  / ____|  \/  |  _ \ | |  | |/ / ___| / ___|| | | |  _ \  / ___|
 | (___ | |\/| | |_) || |  | ' /\___ \ \___ \| |_| | |_) || |
  \___ \| |  | |  __/ | |  | . < ___) | ___) |  _  |  __/ | |___
  |____/|_|  |_|_|    |_|  |_|\_\____/ |____/|_| |_|_|     \____|
"""
    create_banner(art, "   smtp downgrade: testa forcar downgrade de STARTTLS para plaintext")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="SMTP Downgrade Attack — testa forcar downgrade de STARTTLS.",
        epilog="Verifica se o servidor SMTP pode ser forcado a operar em plaintext.",
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

    result = scan_smtp_downgrade(
        target=target,
        port=args.port,
        from_addr=args.from_addr,
        to_addr=args.to_addr,
        timeout=args.timeout,
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["target", "port", "overall_status", "issues"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do SMTP Downgrade."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(a.target),
        prompt="smtpdown> ",
        description="SMTP Downgrade — testa forcar downgrade de STARTTLS.",
        example="mail.example.com --port 587",
        contextual_help=(
            "Uso: <host> [opcoes]\n"
            "Exemplos:\n"
            "  mail.example.com\n"
            "  mail.example.com --port 25\n"
            "  mail.example.com --from-addr admin@test.com"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
