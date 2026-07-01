#!/usr/bin/env python3
"""Modulo de testes de Open Redirect.

Testa se o servidor e vulneravel a redirecionamentos abusivos:
  - Redirect via query params (url, next, redirect, etc.)
  - Redirect via paths (/redirect, /login, /go, etc.)
  - Redirect via headers (Referer, Location)
  - Redirect via fragment (#)
  - Bypass de filtros (encoding, protocol-relative, null byte, etc.)

Open Redirect permite que um atacante redirecione usuarios para sites
maliciosos, facilitando phishing e roubo de credenciais.

Fluxo:
  1. Envia requisicao baseline sem redirect
  2. Envia requisicoes com payloads de redirect
  3. Verifica se Location header aponta para dominio externo
  4. Classifica cada tecnica: vulnerable, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparse
import asyncio
import logging
from collections.abc import Awaitable
from dataclasses import asdict, dataclass
from urllib.parse import quote, urlparse, urlunparse

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.openredirect")

_CATEGORY_MAP: dict[str, list[str]] = {
    "param": ["param_url", "param_next", "param_redirect", "param_return", "param_dest"],
    "path": ["path_redirect", "path_login", "path_go", "path_link"],
    "header": ["header_referer", "header_callback"],
    "fragment": ["fragment_redirect"],
    "bypass": ["bypass_protocol", "bypass_nullbyte", "bypass userinfo", "bypass_fragment", "bypass_backslash", "bypass_percent", "bypass_double_slash", "bypass_subdomain"],
}

_REDIRECT_PARAMS: list[str] = [
    "url", "next", "redirect", "redirect_to", "return",
    "return_to", "go", "goto", "out", "continue",
    "dest", "destination",
]

_REDIRECT_PATHS: list[str] = [
    "/redirect", "/login", "/signin", "/auth", "/link", "/go",
]

_EVIL_DOMAIN: str = "evil.com"

_BYPASS_TECHNIQUES: list[tuple[str, str, str]] = [
    ("bypass_protocol", "url", "//evil.com"),
    ("bypass_nullbyte", "url", "http://evil.com%00.example.com"),
    ("bypass userinfo", "url", "http://evil.com@example.com"),
    ("bypass_fragment", "url", "http://evil.com#.example.com"),
    ("bypass_backslash", "url", "http://evil.com\\@.example.com"),
    ("bypass_percent", "url", "http://evil%2ecom"),
    ("bypass_double_slash", "url", "///evil.com"),
    ("bypass_subdomain", "url", "http://evil.com%E3%80%82example.com"),
]


@dataclass(frozen=True, slots=True)
class OpenRedirectAttempt:
    """Tentativa individual de open redirect."""

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
    redirect_location: str
    vulnerable: bool
    details: str
    error: str


@dataclass(frozen=True, slots=True)
class OpenRedirectResult:
    """Resultado consolidado do scan de open redirect."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[OpenRedirectAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _is_external_redirect(location: str, target_domain: str) -> bool:
    """Verifica se o Location aponta para dominio externo."""
    if not location:
        return False
    parsed = urlparse(location)
    return (
        (bool(parsed.hostname) and parsed.hostname != target_domain)
        or (
            location.startswith("//")
            and not location.startswith(f"//{target_domain}")
        )
    )


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_param_redirect(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[OpenRedirectAttempt]:
    """Testa open redirect via query parameters."""
    attempts: list[OpenRedirectAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    target_domain = parsed.hostname or ""
    base_url = urlunparse(parsed._replace(query=""))

    for param in _REDIRECT_PARAMS:
        test_url = f"{base_url}?{param}={_EVIL_DOMAIN}"
        technique = f"param_{param}"

        try:
            resp = await client.get(test_url, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            location = resp.headers.get("location", "")
            status_changed = t_status != b_status
            vuln = _is_external_redirect(location, target_domain)

            attempts.append(OpenRedirectAttempt(
                technique=technique,
                category="param",
                url=test_url,
                payload=f"{param}={_EVIL_DOMAIN}",
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                redirect_location=location,
                vulnerable=vuln,
                details=f"Redirect -> {location}" if vuln else f"Status {b_status}->{t_status}" if status_changed else "Sem redirect",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(OpenRedirectAttempt(
                technique=technique,
                category="param",
                url=test_url,
                payload=f"{param}={_EVIL_DOMAIN}",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                redirect_location="",
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


async def _test_path_redirect(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[OpenRedirectAttempt]:
    """Testa open redirect via paths."""
    attempts: list[OpenRedirectAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    target_domain = parsed.hostname or ""
    base_url = urlunparse(parsed._replace(path="", query=""))

    for path in _REDIRECT_PATHS:
        test_url = f"{base_url}{path}?url={_EVIL_DOMAIN}"
        technique = f"path_{path.lstrip('/')}"

        try:
            resp = await client.get(test_url, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            location = resp.headers.get("location", "")
            status_changed = t_status != b_status
            vuln = _is_external_redirect(location, target_domain)

            attempts.append(OpenRedirectAttempt(
                technique=technique,
                category="path",
                url=test_url,
                payload=f"{path}?url={_EVIL_DOMAIN}",
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                redirect_location=location,
                vulnerable=vuln,
                details=f"Redirect -> {location}" if vuln else f"Status {b_status}->{t_status}" if status_changed else "Sem redirect",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(OpenRedirectAttempt(
                technique=technique,
                category="path",
                url=test_url,
                payload=f"{path}?url={_EVIL_DOMAIN}",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                redirect_location="",
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


async def _test_header_redirect(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[OpenRedirectAttempt]:
    """Testa open redirect via headers."""
    attempts: list[OpenRedirectAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    target_domain = parsed.hostname or ""

    header_payloads = [
        ("header_referer", "Referer", f"http://{_EVIL_DOMAIN}"),
        ("header_callback", "Referer", f"http://{_EVIL_DOMAIN}/callback"),
    ]

    for technique, header_name, header_value in header_payloads:
        try:
            resp = await client.get(url, headers={header_name: header_value}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            location = resp.headers.get("location", "")
            status_changed = t_status != b_status
            vuln = _is_external_redirect(location, target_domain)

            attempts.append(OpenRedirectAttempt(
                technique=technique,
                category="header",
                url=url,
                payload=f"{header_name}: {header_value}",
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                redirect_location=location,
                vulnerable=vuln,
                details=f"Redirect -> {location}" if vuln else f"Status {b_status}->{t_status}" if status_changed else "Sem redirect",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(OpenRedirectAttempt(
                technique=technique,
                category="header",
                url=url,
                payload=f"{header_name}: {header_value}",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                redirect_location="",
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


async def _test_fragment_redirect(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[OpenRedirectAttempt]:
    """Testa open redirect via fragment."""
    attempts: list[OpenRedirectAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    target_domain = parsed.hostname or ""

    test_url = f"{url}#{_EVIL_DOMAIN}"
    try:
        resp = await client.get(test_url, follow_redirects=False)
        t_status = resp.status_code
        t_size = len(resp.content)
        location = resp.headers.get("location", "")
        status_changed = t_status != b_status
        vuln = _is_external_redirect(location, target_domain)

        attempts.append(OpenRedirectAttempt(
            technique="fragment_redirect",
            category="fragment",
            url=test_url,
            payload=f"#{_EVIL_DOMAIN}",
            status_baseline=b_status,
            status_test=t_status,
            size_baseline=b_size,
            size_test=t_size,
            status_changed=status_changed,
            size_changed=abs(t_size - b_size) > 50,
            redirect_location=location,
            vulnerable=vuln,
            details=f"Redirect -> {location}" if vuln else f"Status {b_status}->{t_status}" if status_changed else "Sem redirect",
            error="",
        ))
    except httpx.RequestError as exc:
        attempts.append(OpenRedirectAttempt(
            technique="fragment_redirect",
            category="fragment",
            url=test_url,
            payload=f"#{_EVIL_DOMAIN}",
            status_baseline=b_status,
            status_test=0,
            size_baseline=b_size,
            size_test=0,
            status_changed=False,
            size_changed=False,
            redirect_location="",
            vulnerable=False,
            details="",
            error=str(exc),
        ))

    return attempts


async def _test_bypass_redirect(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[OpenRedirectAttempt]:
    """Testa open redirect via bypass de filtros."""
    attempts: list[OpenRedirectAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    target_domain = parsed.hostname or ""
    base_url = urlunparse(parsed._replace(query=""))

    for technique, param, payload in _BYPASS_TECHNIQUES:
        test_url = f"{base_url}?{param}={quote(payload, safe='')}"

        try:
            resp = await client.get(test_url, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            location = resp.headers.get("location", "")
            status_changed = t_status != b_status
            vuln = _is_external_redirect(location, target_domain)

            attempts.append(OpenRedirectAttempt(
                technique=technique,
                category="bypass",
                url=test_url,
                payload=f"{param}={payload}",
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                redirect_location=location,
                vulnerable=vuln,
                details=f"Redirect -> {location}" if vuln else f"Status {b_status}->{t_status}" if status_changed else "Sem redirect",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(OpenRedirectAttempt(
                technique=technique,
                category="bypass",
                url=test_url,
                payload=f"{param}={payload}",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                redirect_location="",
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


async def scan_open_redirect(
    url: str,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
    category: str | None = None,
    concurrency: int = 5,
) -> OpenRedirectResult:
    """Executa scan de open redirect contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent=user_agent or "MyTools/openredirect",
        proxy=proxy,
        timeout=timeout,
        verify=verify,
    ) as client:
        b_status, b_size, _ = await _test_baseline(client, url)
        baseline = (b_status, b_size, b"")

        sem = asyncio.Semaphore(concurrency)

        async def _limited(coro: Awaitable[object]) -> object:
            async with sem:
                return await coro

        tasks: list[Awaitable[object]] = []
        selected = _CATEGORY_MAP.get(category, []) if category else []

        if not category or category == "param":
            tasks.append(_limited(_test_param_redirect(client, url, baseline)))
        if not category or category == "path":
            tasks.append(_limited(_test_path_redirect(client, url, baseline)))
        if not category or category == "header":
            tasks.append(_limited(_test_header_redirect(client, url, baseline)))
        if not category or category == "fragment":
            tasks.append(_limited(_test_fragment_redirect(client, url, baseline)))
        if not category or category == "bypass":
            tasks.append(_limited(_test_bypass_redirect(client, url, baseline)))

        if category and not selected:
            return OpenRedirectResult(
                target=url,
                baseline_status=b_status,
                baseline_size=b_size,
                tls=tls,
                attempts=[],
                vulnerable_techniques=[],
                blocked_techniques=[],
                issues=[f"Categoria desconhecida: {category}"],
                overall_status="error",
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_attempts: list[OpenRedirectAttempt] = []
        for r in results:
            if isinstance(r, list):
                all_attempts.extend(r)

    vulnerable: list[str] = []
    blocked: list[str] = []
    issues: list[str] = []

    seen: set[str] = set()
    for att in all_attempts:
        if att.technique not in seen:
            seen.add(att.technique)
            if att.vulnerable:
                vulnerable.append(att.technique)
            elif att.status_changed:
                blocked.append(att.technique)

    if vulnerable:
        issues.append(f"{len(vulnerable)} tecnicas de open redirect vulneraveis")
    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return OpenRedirectResult(
        target=url,
        baseline_status=b_status,
        baseline_size=b_size,
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=vulnerable,
        blocked_techniques=blocked,
        issues=issues,
        overall_status=overall,
    )


def print_results(result: OpenRedirectResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  OPEN REDIRECT SCAN", Cyber.CYAN))
    print(color("=" * 60, Cyber.CYAN))
    print(color(f"  Target: {result.target}", Cyber.WHITE))
    print(color(f"  Baseline: {result.baseline_status} ({result.baseline_size} bytes)", Cyber.GRAY))
    print(color(f"  TLS: {'Sim' if result.tls else 'Nao'}", Cyber.GRAY))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN
    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    if result.vulnerable_techniques:
        print(color("\n  [VULNERAVEL]", Cyber.RED))
        for tech in result.vulnerable_techniques:
            print(color(f"    - {tech}", Cyber.RED))

    if result.blocked_techniques:
        print(color("\n  [BLOQUEADO]", Cyber.GREEN))
        for tech in result.blocked_techniques:
            print(color(f"    - {tech}", Cyber.GREEN))

    if result.issues:
        print(color("\n  Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))

    print(color("=" * 60, Cyber.CYAN))


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-openredirect",
        description="Open Redirect — detecta redirecionamentos abusivos em web apps.",
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de teste (param, path, header, fragment, bypass)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Numero de requisicoes simultaneas (default: 5)",
    )
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan unico e retorna codigo de saida."""
    init_scanner(args)
    url = getattr(args, "url", None) or getattr(args, "target", None)
    if not url:
        print(color("Especifique uma URL alvo.", Cyber.RED))
        return 1

    result = safe_asyncio_run(
        scan_open_redirect(
            url=url,
            timeout=getattr(args, "timeout", 10.0),
            user_agent=getattr(args, "user_agent", None),
            proxy=getattr(args, "proxy", None),
            verify=getattr(args, "verify", False),
            category=getattr(args, "category", None),
            concurrency=getattr(args, "concurrency", 5),
        )
    )
    print_results(result)

    output_path = getattr(args, "output", None)
    if output_path:
        write_output(output_path, asdict(result))
        print(color(f"\nResultados salvos em: {output_path}", Cyber.GREEN))

    return 0 if result.overall_status != "error" else 1


banner_art = create_banner(
    r"""
     _   _                      ___                         _
    | \ | |                    / _ \                       | |
    |  \| | _____  ___   _   / /_\ \ ___ ___ _ __  ___  __| | ___  _ __
    | . ` |/ _ \ \/ / | | | |  _  |/ __/ __| '_ \/ _ \/ _` |/ _ \| '_ \
    | |\  |  __/>  <| |_| | | | | | (_| (__| | | |  __/ (_| | (_) | | | |
    |_| \_|\___/_/\_\\__, |  \_| |_/\___\___|_| |_|\___|\__,_|\___/|_| |_|
                      __/ |
                     |___/
    """,
    "Open Redirect — detecta redirecionamentos abusivos em web apps",
)


def main() -> int:
    """Ponto de entrada principal do CLI."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="redirect> ",
        description="Open Redirect interativo.",
        example="https://target.com -c param",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c param\n"
            "  https://target.com -c bypass\n"
            "  https://target.com -c path --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
