#!/usr/bin/env python3
"""Modulo de deteccao de Log Injection.

Testa se o servidor e vulneravel a injecao de conteudo em logs via:
  - user_agent — Injecao via User-Agent header
  - referer — Injecao via Referer header
  - custom_header — Headers customizados (X-Forwarded-For, X-Real-IP)
  - url_path — Path traversal e injecao em logs de acesso
  - bypass — Encoding, unicode, double encoding

Fluxo:
  1. Envia request baseline para obter resposta de referencia
  2. Envia requests com payloads de log injection
  3. Verifica se o servidor reflete ou processa o payload indevidamente
  4. Classifica: vulnerable, blocked, error
  5. Retorna resultado consolidado com severidade
"""

import argparse
import logging
from dataclasses import asdict, dataclass

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    init_scanner,
    print_exploit_info,
    print_json,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.loginjection")

_CATEGORY_MAP: dict[str, list[str]] = {
    "user_agent": ["ua_crlf", "ua_xss", "ua_sqli", "ua_pathtraversal", "ua_logforging"],
    "referer": ["ref_crlf", "ref_fakeurl", "ref_xss", "ref_sqli", "ref_logforging"],
    "custom_header": [
        "xff_inject",
        "xrealip_inject",
        "xcustom_inject",
        "xorigin_inject",
        "xforwarded_inject",
    ],
    "url_path": [
        "path_newline",
        "path_tab",
        "path_nullbyte",
        "path_crlf",
        "path_logforge",
    ],
    "bypass": [
        "bypass_encoding",
        "bypass_unicode",
        "bypass_doubleencode",
        "bypass_chunked",
        "bypass_case",
    ],
}

_MARKER = "LOGINJECT_TEST"


async def _test_baseline(
    client: httpx.AsyncClient, url: str
) -> tuple[int, int, dict[str, str], bytes]:
    """Envia request baseline para obter status, tamanho, headers e corpo."""
    try:
        resp = await client.get(url, follow_redirects=True)
        return resp.status_code, len(resp.content), dict(resp.headers), resp.content
    except httpx.RequestError:
        return 0, 0, {}, b""


async def _test_user_agent(
    client: httpx.AsyncClient,
    url: str,
) -> list[LogInjectAttempt]:
    """Testa injecao via User-Agent header."""
    results: list[LogInjectAttempt] = []
    _b_status, _b_size, _b_headers, _b_body = await _test_baseline(client, url)

    test_cases: list[tuple[str, str, str]] = [
        ("ua_crlf", "User-Agent", f"{_MARKER}%0d%0aX-Injected: test"),
        ("ua_xss", "User-Agent", f"<script>alert('{_MARKER}')</script>"),
        ("ua_sqli", "User-Agent", f"' OR 1=1 -- {_MARKER}"),
        ("ua_pathtraversal", "User-Agent", f"../../../etc/passwd {_MARKER}"),
        ("ua_logforging", "User-Agent", f"INFO [{_MARKER}] Fake log entry"),
    ]

    for technique, header_name, header_value in test_cases:
        try:
            resp = await client.get(
                url, headers={header_name: header_value}, follow_redirects=True
            )
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if _MARKER.lower() in resp_body.lower():
                vulnerable = True
                details = f"User-Agent refletido no body: {header_value[:80]}"

            results.append(
                LogInjectAttempt(
                    exploit="%0a[IMPORTANT] fake log entry",
                    tool="curl",
                    technique=technique,
                    category="user_agent",
                    header_name=header_name,
                    payload=header_value,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                LogInjectAttempt(
                    technique=technique,
                    category="user_agent",
                    header_name=header_name,
                    payload=header_value,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )
    return results


async def _test_referer(
    client: httpx.AsyncClient,
    url: str,
) -> list[LogInjectAttempt]:
    """Testa injecao via Referer header."""
    results: list[LogInjectAttempt] = []

    test_cases: list[tuple[str, str, str]] = [
        ("ref_crlf", "Referer", f"https://evil.com/{_MARKER}%0d%0aX-Injected: test"),
        ("ref_fakeurl", "Referer", f"https://{_MARKER}.evil.com/"),
        ("ref_xss", "Referer", f"<script>alert('{_MARKER}')</script>"),
        ("ref_sqli", "Referer", f"' OR 1=1 -- {_MARKER}"),
        ("ref_logforging", "Referer", f"INFO [{_MARKER}] Fake log entry"),
    ]

    for technique, header_name, header_value in test_cases:
        try:
            resp = await client.get(
                url, headers={header_name: header_value}, follow_redirects=True
            )
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if _MARKER.lower() in resp_body.lower():
                vulnerable = True
                details = f"Referer refletido no body: {header_value[:80]}"

            results.append(
                LogInjectAttempt(
                    exploit="%0a[IMPORTANT] fake log entry",
                    tool="curl",
                    technique=technique,
                    category="referer",
                    header_name=header_name,
                    payload=header_value,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                LogInjectAttempt(
                    technique=technique,
                    category="referer",
                    header_name=header_name,
                    payload=header_value,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )
    return results


async def _test_custom_header(
    client: httpx.AsyncClient,
    url: str,
) -> list[LogInjectAttempt]:
    """Testa injecao via headers customizados."""
    results: list[LogInjectAttempt] = []

    test_cases: list[tuple[str, str, str]] = [
        ("xff_inject", "X-Forwarded-For", f"127.0.0.1, {_MARKER}"),
        ("xrealip_inject", "X-Real-IP", f"127.0.0.1, {_MARKER}"),
        ("xcustom_inject", "X-Custom-Header", _MARKER),
        ("xorigin_inject", "X-Origin", f"https://{_MARKER}.evil.com"),
        ("xforwarded_inject", "X-Forwarded-Host", f"{_MARKER}.evil.com"),
    ]

    for technique, header_name, header_value in test_cases:
        try:
            resp = await client.get(
                url, headers={header_name: header_value}, follow_redirects=True
            )
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if _MARKER.lower() in resp_body.lower():
                vulnerable = True
                details = (
                    f"Custom header refletido no body: {header_name}: {header_value}"
                )

            results.append(
                LogInjectAttempt(
                    exploit="%0a[IMPORTANT] fake log entry",
                    tool="curl",
                    technique=technique,
                    category="custom_header",
                    header_name=header_name,
                    payload=header_value,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                LogInjectAttempt(
                    technique=technique,
                    category="custom_header",
                    header_name=header_name,
                    payload=header_value,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )
    return results


async def _test_url_path(
    client: httpx.AsyncClient,
    url: str,
) -> list[LogInjectAttempt]:
    """Testa path traversal e injecao em logs de acesso."""
    results: list[LogInjectAttempt] = []

    test_cases: list[tuple[str, str]] = [
        ("path_newline", f"/{_MARKER}%0d%0a"),
        ("path_tab", f"/{_MARKER}%09"),
        ("path_nullbyte", f"/{_MARKER}%00"),
        ("path_crlf", f"/{_MARKER}%0d%0aFake-Header: test"),
        ("path_logforge", f"/{_MARKER}?action=INFO+Fake+log+entry"),
    ]

    for technique, path in test_cases:
        try:
            target_url = url.rstrip("/") + path
            resp = await client.get(target_url, follow_redirects=True)
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if _MARKER.lower() in resp_body.lower():
                vulnerable = True
                details = f"Path payload refletido no body: {path}"

            results.append(
                LogInjectAttempt(
                    exploit="%0a[IMPORTANT] fake log entry",
                    tool="curl",
                    technique=technique,
                    category="url_path",
                    header_name="URL",
                    payload=path,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                LogInjectAttempt(
                    technique=technique,
                    category="url_path",
                    header_name="URL",
                    payload=path,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )
    return results


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
) -> list[LogInjectAttempt]:
    """Testa bypass de validacao via encoding e tricks."""
    results: list[LogInjectAttempt] = []

    test_cases: list[tuple[str, str, str]] = [
        ("bypass_encoding", "User-Agent", f"{_MARKER}%250d%250a"),
        ("bypass_unicode", "User-Agent", f"{_MARKER}%e2%80%a8%e2%80%a9"),
        (
            "bypass_doubleencode",
            "User-Agent",
            f"%253Cscript%253E{_MARKER}%253C/script%253E",
        ),
        ("bypass_chunked", "User-Agent", f"{_MARKER}"),
        ("bypass_case", "User-Agent", f"<ScRiPt>{_MARKER}</ScRiPt>"),
    ]

    for technique, header_name, header_value in test_cases:
        try:
            resp = await client.get(
                url, headers={header_name: header_value}, follow_redirects=True
            )
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if _MARKER.lower() in resp_body.lower():
                vulnerable = True
                details = f"Bypass via {header_name}: payload refletido"

            results.append(
                LogInjectAttempt(
                    exploit="%0a[IMPORTANT] fake log entry",
                    tool="curl",
                    technique=technique,
                    category="bypass",
                    header_name=header_name,
                    payload=header_value,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                LogInjectAttempt(
                    technique=technique,
                    category="bypass",
                    header_name=header_name,
                    payload=header_value,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )
    return results


@dataclass(frozen=True, slots=True)
class LogInjectAttempt:
    """Tentativa individual de Log Injection."""

    technique: str
    category: str
    header_name: str
    payload: str
    status: int
    size: int
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class LogInjectResult:
    """Resultado consolidado do scan de Log Injection."""

    target: str
    tls: bool
    attempts: list[LogInjectAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def print_results(result: LogInjectResult) -> None:
    """Exibe os resultados do scan de Log Injection."""
    vuln = [a for a in result.attempts if a.vulnerable]
    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]
    errors = [a for a in result.attempts if a.error]

    print(color("\n--- Log Injection ---", Cyber.CYAN, Cyber.BOLD))
    print(color(f"  Alvo:         {result.target}", Cyber.WHITE))
    print(color(f"  TLS:          {'sim' if result.tls else 'nao'}", Cyber.WHITE))
    print(color(f"  Testes:       {len(result.attempts)}", Cyber.WHITE))
    print(color(f"  Vulneraveis:  {len(vuln)}", Cyber.GREEN if vuln else Cyber.GRAY))
    print(color(f"  Bloqueados:   {len(blocked)}", Cyber.GRAY))
    print(color(f"  Erros:        {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if vuln:
        print(color("\n  [+] Vulnerabilidades detectadas:", Cyber.GREEN, Cyber.BOLD))
        seen: set[str] = set()
        for a in vuln:
            key = f"{a.technique}:{a.header_name}"
            if key in seen:
                continue
            seen.add(key)
            print(color(f"    [{a.category}] {a.technique}", Cyber.GREEN))
            print(color(f"      Header: {a.header_name}", Cyber.WHITE))
            print(color(f"      Status: {a.status}", Cyber.WHITE))
            if a.details:
                print(color(f"      Detalhes: {a.details}", Cyber.GRAY))
            print_exploit_info(a.exploit, a.tool)
        print(
            color(
                f"\n  Total: {len(result.attempts)} testes, {len(vuln)} vulneraveis",
                Cyber.WHITE,
            )
        )
    else:
        print(color("\n  [-] Nenhum Log Injection detectado", Cyber.YELLOW))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
    proxy: str | None = None,
    json_output: bool = False,
) -> int:
    """Executa o scan de Log Injection."""
    logger.info("Log Injection scan para %s", target)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout, proxy=proxy) as client:
        all_attempts: list[LogInjectAttempt] = []
        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            if cat == "user_agent":
                all_attempts.extend(await _test_user_agent(client, target))
            elif cat == "referer":
                all_attempts.extend(await _test_referer(client, target))
            elif cat == "custom_header":
                all_attempts.extend(await _test_custom_header(client, target))
            elif cat == "url_path":
                all_attempts.extend(await _test_url_path(client, target))
            elif cat == "bypass":
                all_attempts.extend(await _test_bypass(client, target))

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})
        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )
        issues: list[str] = []

        if not vuln_techs and not blocked_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = LogInjectResult(
            target=target,
            tls=tls,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked_techs,
            issues=issues,
            overall_status="vulnerable"
            if vuln_techs
            else ("safe" if blocked_techs else "unknown"),
        )

        if json_output:
            print_json(asdict(result))
        else:
            print_results(result)
        logger.info(
            "Log Injection scan concluido: %d testes, %d vulneraveis",
            len(all_attempts),
            len(vuln_techs),
        )

        if output_file:
            write_output(output_file, asdict(result))
            logger.info("Resultados salvos em %s", output_file)

        return 1 if vuln_techs else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""
    art = r"""
    _    __  _____    _    _     _
   | |  / _|/ _ \ \  / \  | |   | |
   | |_| |_| | | \ \/  \ | |   | |
   |  _|  _| |_| | \  /  \| |___| |___
   |_| |_|  \___/  \/    \_\_____|_____|
"""
    create_banner(
        art, "   log injection: user_agent, referer, custom_header, url_path, bypass"
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""
    parser = argparse.ArgumentParser(
        prog="mytools-loginjection",
        description="Log Injection — testa injecao de conteudo em logs via headers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-loginjection https://target.com\n"
            "  mytools-loginjection https://target.com -c user_agent\n"
            "  mytools-loginjection https://target.com -c referer\n"
            "  mytools-loginjection https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
    parser.add_argument("url", help="URL alvo para o scan")
    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=["all", "user_agent", "referer", "custom_header", "url_path", "bypass"],
        help="Categoria de testes (default: todas)",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Log Injection a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("Log Injection scan iniciado para %s", args.url)
    categories: list[str] = []
    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]
    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
            proxy=getattr(args, "proxy", None),
            json_output=getattr(args, "json_output", False),
        ),
    )


def main() -> int:
    """Entry point do modulo Log Injection."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="loginjection> ",
        description="Log Injection interativo.",
        example="https://target.com -c user_agent",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c user_agent\n"
            "  https://target.com -c referer\n"
            "  https://target.com -c bypass\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
