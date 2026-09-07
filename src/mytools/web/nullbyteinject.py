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
import logging
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    Cyber,
    color,
    create_async_client,
    print_exploit_info,
    run_concurrent,
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

    exploit: str = ""

    tool: str = ""


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

                attempts.append(
                    NullByteAttempt(
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
                        details=f"Status {b_status}->{t_status}"
                        if status_changed
                        else "Sem mudanca",
                        error="",
                        exploit="file.php%00.jpg" if vulnerable else "",
                        tool="wfuzz",
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    NullByteAttempt(
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
                    )
                )

    return attempts


async def _test_null_in_headers(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[NullByteAttempt]:
    """Testa null bytes em headers HTTP."""

    attempts: list[NullByteAttempt] = []

    b_status, b_size, _ = baseline

    header_payloads = {
        "ua_null": ("User-Agent", "Mozilla/5.0%00Bot"),
        "cookie_null": ("Cookie", "session=abc%00def"),
        "auth_null": ("Authorization", "Bearer token%00"),
        "referer_null": ("Referer", "https://example.com%00/admin"),
    }

    for technique, (header_name, header_value) in header_payloads.items():
        try:
            resp = await client.get(
                url, headers={header_name: header_value}, follow_redirects=False
            )

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            size_changed = abs(t_size - b_size) > 50

            vulnerable = status_changed and t_status == 200

            attempts.append(
                NullByteAttempt(
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
                    details=f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca",
                    error="",
                    exploit="file.php%00.jpg" if vulnerable else "",
                    tool="wfuzz",
                )
            )

        except (httpx.RequestError, ValueError) as exc:
            attempts.append(
                NullByteAttempt(
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
                )
            )

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
            resp = await client.get(
                base_url, params={"q": f"test{null_byte}"}, follow_redirects=False
            )

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                NullByteAttempt(
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
                    details=f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca",
                    error="",
                    exploit="file.php%00.jpg" if vulnerable else "",
                    tool="wfuzz",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                NullByteAttempt(
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
                )
            )

        # POST param

        try:
            resp = await client.post(
                base_url, data={"field": f"value{null_byte}"}, follow_redirects=False
            )

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                NullByteAttempt(
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
                    details=f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca",
                    error="",
                    exploit="file.php%00.jpg" if vulnerable else "",
                    tool="wfuzz",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                NullByteAttempt(
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
                )
            )

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

            attempts.append(
                NullByteAttempt(
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
                    details=f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca",
                    error="",
                    exploit="file.php%00.jpg" if vulnerable else "",
                    tool="wfuzz",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                NullByteAttempt(
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
                )
            )

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

            attempts.append(
                NullByteAttempt(
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
                    details=f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca",
                    error="",
                    exploit="file.php%00.jpg" if vulnerable else "",
                    tool="wfuzz",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                NullByteAttempt(
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
                )
            )

    return attempts


async def _test_auth_bypass(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[NullByteAttempt]:
    """Testa auth bypass via null bytes."""

    attempts: list[NullByteAttempt] = []

    b_status, b_size, _ = baseline

    auth_payloads = [
        ("basic_null", "Authorization", "Basic YWRtaW46cGFzc3dvcmQ%00"),
        ("token_null", "X-Auth-Token", "abc123%00"),
        ("session_null", "Cookie", "PHPSESSID=abc%00def"),
    ]

    for technique, header_name, header_value in auth_payloads:
        try:
            resp = await client.get(
                url, headers={header_name: header_value}, follow_redirects=False
            )

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                NullByteAttempt(
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
                    details=f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca",
                    error="",
                    exploit="file.php%00.jpg" if vulnerable else "",
                    tool="wfuzz",
                )
            )

        except (httpx.RequestError, ValueError) as exc:
            attempts.append(
                NullByteAttempt(
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
                )
            )

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
        b_status, b_size, b_body = await _test_baseline(client, url)

        baseline = (b_status, b_size, b_body)

        coros = []

        selected = _CATEGORY_MAP.get(category, []) if category else []

        if not category or category == "url":
            coros.append(_test_null_in_url(client, url, baseline))

        if not category or category == "header":
            coros.append(_test_null_in_headers(client, url, baseline))

        if not category or category == "param":
            coros.append(_test_null_in_params(client, url, baseline))

        if not category or category == "traversal":
            coros.append(_test_path_traversal(client, url, baseline))

        if not category or category == "auth":
            coros.append(_test_auth_bypass(client, url, baseline))

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

        results = await run_concurrent(coros, concurrency)

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


def print_results_fn(result: NullByteResult) -> None:
    """Exibe os resultados do scan formatados."""

    print()

    print(color("=" * 60, Cyber.CYAN))

    print(color("  NULL BYTE INJECTION SCAN", Cyber.CYAN))

    print(color("=" * 60, Cyber.CYAN))

    print(color(f"  Target: {result.target}", Cyber.WHITE))

    print(
        color(
            f"  Baseline: {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.GRAY,
        )
    )

    print(color(f"  TLS: {'Sim' if result.tls else 'Nao'}", Cyber.GRAY))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN

    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    if result.vulnerable_techniques:
        print(color("\n  [VULNERAVEL]", Cyber.RED))

        for tech in result.vulnerable_techniques:
            print(color(f"    - {tech}", Cyber.RED))

            a = next((a for a in result.attempts if a.technique == tech), None)

            if a:
                print_exploit_info(a.exploit, a.tool)

    if result.blocked_techniques:
        print(color("\n  [BLOQUEADO]", Cyber.GREEN))

        for tech in result.blocked_techniques:
            print(color(f"    - {tech}", Cyber.GREEN))

    if result.issues:
        print(color("\n  Observacoes:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))

    print(color("=" * 60, Cyber.CYAN))


class NullByteScanner(BaseScanner):
    """Scanner de Null Byte Injection."""

    prog = "mytools-nullbyte"
    description = "Null Byte Injection \u2014 testa injecao de null bytes em URLs, headers e parametros."
    prompt = "nullbyte> "
    module_name = "mytools.nullbyteinject"
    banner_text = r"""
     _   _                      _____             _
    | \ | |                    |_   _|           | |
    |  \| | _____  ___   _  _    | | ___  _ __ | |_
    | . ` |/ _ \ \/ / | | || |   | |/ _ \ '_ \| __|
    | |\  |  __/>  <| |_| || |   | | (_)| | | | |_
    |_| \_|\___/_/\_\\\__,_||_|   \_/\___|_| |_|\__|

    """
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("url", nargs="?", help="URL alvo para teste")
        parser.add_argument(
            "-c",
            "--category",
            choices=list(_CATEGORY_MAP.keys()),
            help="Categoria de teste (url, header, param, traversal, auth)",
        )
        parser.add_argument(
            "--concurrency",
            type=int,
            default=5,
            help="Numero de requisicoes simultaneas (default: 5)",
        )

    async def run_scan(self, **kwargs):  # type: ignore[override]
        return await scan_null_byte(**kwargs)

    def print_results(self, result: object) -> None:
        print_results_fn(result)  # type: ignore[arg-type]

    def _example(self) -> str:
        return "https://target.com -c url"

    def _help(self) -> str:
        return (
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c url\n"
            "  https://target.com -c header --proxy http://127.0.0.1:8080\n"
            "  https://target.com -c traversal --timeout 15"
        )


scanner = NullByteScanner()
main = scanner.main
run_once = scanner.run_once
banner_art = scanner._make_banner()

# Backward-compatible re-exports for tests
build_parser = scanner.build_parser
print_results = print_results_fn

if __name__ == "__main__":
    raise SystemExit(main())
