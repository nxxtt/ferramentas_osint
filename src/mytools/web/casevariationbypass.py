#!/usr/bin/env python3
"""Modulo de testes de Case Variation Bypass.

Testa se o servidor e vulneravel a bypass via variacao de case:
  - Paths: /Admin, /ADMIN, /aDmIn
  - Parametros: ?ADMIN=test, ?aDmIn=test
  - Headers: AUTHORIZATION, aUthOrIzAtIoN
  - Extensions: .PHP, .PhP, .pHp
  - Cookies: SESSIONID, PhPsEsSiD

Fluxo:
  1. Envia requisicao baseline com URL original
  2. Envia requisicoes com variacoes de case
  3. Compara respostas (status, tamanho, corpo)
  4. Classifica cada tecnica: vulnerable, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparse
import asyncio
import logging
from collections.abc import Awaitable
from dataclasses import asdict, dataclass
from urllib.parse import urlparse, urlunparse

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

logger = logging.getLogger("mytools.casevariationbypass")

_CATEGORY_MAP: dict[str, list[str]] = {
    "path": ["path_upper", "path_mixed", "path_title"],
    "param": ["param_upper", "param_mixed", "param_value"],
    "header": ["header_auth_upper", "header_auth_mixed", "header_cookie"],
    "extension": ["ext_upper", "ext_mixed", "ext_double"],
    "cookie": ["cookie_upper", "cookie_mixed", "cookie_value"],
}

_PATH_CASES: list[tuple[str, str]] = [
    ("path_upper", "/ADMIN"),
    ("path_upper", "/LOGIN"),
    ("path_upper", "/DASHBOARD"),
    ("path_mixed", "/aDmIn"),
    ("path_mixed", "/AdMiN"),
    ("path_mixed", "/AdMiNiStRaToR"),
    ("path_title", "/Admin"),
    ("path_title", "/Login"),
    ("path_title", "/Dashboard"),
]

_PARAM_CASES: list[tuple[str, str, str]] = [
    ("param_upper", "ADMIN", "test"),
    ("param_upper", "USER", "test"),
    ("param_mixed", "aDmIn", "test"),
    ("param_mixed", "UsEr", "test"),
    ("param_value", "role", "Admin"),
    ("param_value", "role", "ADMIN"),
]

_HEADER_CASES: list[tuple[str, str, str]] = [
    ("header_auth_upper", "AUTHORIZATION", "Bearer test123"),
    ("header_auth_mixed", "aUthOrIzAtIoN", "Bearer test123"),
    ("header_cookie", "SESSIONID", "abc123"),
    ("header_cookie", "PhpSeSsId", "abc123"),
]

_EXT_CASES: list[tuple[str, str]] = [
    ("ext_upper", "/page.PHP"),
    ("ext_upper", "/page.ASPX"),
    ("ext_upper", "/page.JSP"),
    ("ext_mixed", "/page.PhP"),
    ("ext_mixed", "/page.AspX"),
    ("ext_mixed", "/page.jSp"),
    ("ext_double", "/image.jpg.PHP"),
    ("ext_double", "/file.txt.AsPx"),
]

_COOKIE_CASES: list[tuple[str, str, str]] = [
    ("cookie_upper", "SESSIONID", "abc123"),
    ("cookie_upper", "PHPSESSID", "abc123"),
    ("cookie_mixed", "PhPsEsSiD", "abc123"),
    ("cookie_mixed", "SeSsIoN", "abc123"),
    ("cookie_value", "session", "Admin"),
    ("cookie_value", "session", "ADMIN"),
]


@dataclass(frozen=True, slots=True)
class CaseVariationAttempt:
    """Tentativa individual de case variation bypass."""

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
    vulnerable: bool
    details: str
    error: str


@dataclass(frozen=True, slots=True)
class CaseVariationResult:
    """Resultado consolidado do scan de case variation bypass."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[CaseVariationAttempt]
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


async def _test_path_case(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[CaseVariationAttempt]:
    """Testa case variation em paths."""
    attempts: list[CaseVariationAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_path = parsed.path.rstrip("/")

    for technique, case_path in _PATH_CASES:
        test_url = urlunparse(parsed._replace(path=base_path + case_path))
        try:
            resp = await client.get(test_url, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(CaseVariationAttempt(
                technique=technique,
                category="path",
                url=test_url,
                payload=case_path,
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
            attempts.append(CaseVariationAttempt(
                technique=technique,
                category="path",
                url=test_url,
                payload=case_path,
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


async def _test_param_case(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[CaseVariationAttempt]:
    """Testa case variation em parametros."""
    attempts: list[CaseVariationAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    for technique, param_name, param_value in _PARAM_CASES:
        try:
            resp = await client.get(base_url, params={param_name: param_value}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(CaseVariationAttempt(
                technique=technique,
                category="param",
                url=base_url,
                payload=f"{param_name}={param_value}",
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
            attempts.append(CaseVariationAttempt(
                technique=technique,
                category="param",
                url=base_url,
                payload=f"{param_name}={param_value}",
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


async def _test_header_case(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[CaseVariationAttempt]:
    """Testa case variation em headers."""
    attempts: list[CaseVariationAttempt] = []
    b_status, b_size, _ = baseline

    for technique, header_name, header_value in _HEADER_CASES:
        try:
            resp = await client.get(url, headers={header_name: header_value}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(CaseVariationAttempt(
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
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(CaseVariationAttempt(
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
                vulnerable=False,
                details="",
                error=str(exc),
            ))

    return attempts


async def _test_extension_case(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[CaseVariationAttempt]:
    """Testa case variation em extensoes de arquivo."""
    attempts: list[CaseVariationAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_path = parsed.path.rstrip("/")

    for technique, ext_path in _EXT_CASES:
        test_url = urlunparse(parsed._replace(path=base_path + ext_path))
        try:
            resp = await client.get(test_url, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(CaseVariationAttempt(
                technique=technique,
                category="extension",
                url=test_url,
                payload=ext_path,
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
            attempts.append(CaseVariationAttempt(
                technique=technique,
                category="extension",
                url=test_url,
                payload=ext_path,
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


async def _test_cookie_case(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[CaseVariationAttempt]:
    """Testa case variation em cookies."""
    attempts: list[CaseVariationAttempt] = []
    b_status, b_size, _ = baseline

    for technique, cookie_name, cookie_value in _COOKIE_CASES:
        try:
            resp = await client.get(url, headers={"Cookie": f"{cookie_name}={cookie_value}"}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(CaseVariationAttempt(
                technique=technique,
                category="cookie",
                url=url,
                payload=f"{cookie_name}={cookie_value}",
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
            attempts.append(CaseVariationAttempt(
                technique=technique,
                category="cookie",
                url=url,
                payload=f"{cookie_name}={cookie_value}",
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


async def scan_case_variation(
    url: str,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
    category: str | None = None,
    concurrency: int = 5,
) -> CaseVariationResult:
    """Executa scan de case variation bypass contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent=user_agent or "MyTools/casevariationbypass",
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

        if not category or category == "path":
            tasks.append(_limited(_test_path_case(client, url, baseline)))
        if not category or category == "param":
            tasks.append(_limited(_test_param_case(client, url, baseline)))
        if not category or category == "header":
            tasks.append(_limited(_test_header_case(client, url, baseline)))
        if not category or category == "extension":
            tasks.append(_limited(_test_extension_case(client, url, baseline)))
        if not category or category == "cookie":
            tasks.append(_limited(_test_cookie_case(client, url, baseline)))

        if category and not selected:
            return CaseVariationResult(
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
        all_attempts: list[CaseVariationAttempt] = []
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
        issues.append(f"{len(vulnerable)} tecnicas de case variation vulneraveis")
    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return CaseVariationResult(
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


def print_results(result: CaseVariationResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  CASE VARIATION BYPASS SCAN", Cyber.CYAN))
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
        prog="mytools-casevar",
        description="Case Variation Bypass — testa bypass de filtros via variacao de case.",
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de teste (path, param, header, extension, cookie)",
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
        scan_case_variation(
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
     _   _                      _____                   _             _
    | \ | |                    |  __ \                 (_)           | |
    |  \| | _____  ___   _  __| |  | | ___  _ __ _ __  _ _ __   __ _| |
    | . ` |/ _ \ \/ / | | |/ _` |  | |/ _ \| '__| '_ \| | '_ \ / _` | |
    | |\  |  __/>  <| |_| | (_| |  | | (_) | |  | | | | | | | | | (_| | |_
    |_| \_|\___/_/\_\\__,_|\__,_|_|  \___/|_|  |_| |_|_|_| |_|\__,_|\__|

    """,
    "Case Variation Bypass — detecta bypass de filtros via variacao de case",
)


def main() -> int:
    """Ponto de entrada principal do CLI."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="casevar> ",
        description="Case Variation Bypass interativo.",
        example="https://target.com -c path",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c path\n"
            "  https://target.com -c header\n"
            "  https://target.com -c extension --proxy http://127.0.0.1:8080"
        ),
    )
