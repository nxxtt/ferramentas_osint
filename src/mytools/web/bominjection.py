#!/usr/bin/env python3

"""Modulo de testes de BOM Injection.



Testa se o servidor e vulneravel a injecao de Byte Order Mark (BOM):

  - BOM em URLs (paths, query params)

  - BOM em headers HTTP (Referer, Cookie, User-Agent)

  - BOM em corpo de requisicoes POST (form, JSON)

  - BOM em nomes de arquivos upload

  - Bypass de filtros via BOM invisivel



BOMs sao caracteres Unicode especiais no inicio de um stream de dados que

indicam a codificaÃ§Ã£o. Podem ser usados para bypass de filtros que nao

reconhecem BOM, confundir parsers de charset, ou causar erros de decodificacao.



Fluxo:

  1. Envia requisicao baseline sem BOM

  2. Envia requisicoes com BOM injetados em diferentes posicoes

  3. Compara respostas (status, tamanho, headers, corpo)

  4. Classifica cada tecnica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import logging
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

import httpx

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    Cyber,
    color,
    create_async_client,
    print_exploit_info,
    run_concurrent,
)

logger = logging.getLogger("mytools.bominjection")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "url": ["bom_path", "bom_query"],
    "header": ["bom_referer", "bom_cookie", "bom_ua"],
    "body": ["bom_form", "bom_json", "bom_raw"],
    "upload": ["bom_filename", "bom_field"],
}


def _load_category_map() -> dict[str, list[str]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "bominjection", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )
    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()


_BOM_VARIANTS_DEFAULT: dict[str, str] = {
    "utf8_bom": "\ufeff",
    "utf16_le": "\ufffe",
    "utf16_be": "\ufeff",
    "utf32_le": "\ufffe",
    "utf32_be": "\ufeff",
    "utf7_bom": "+/v8",
}


def _load_bom_variants() -> dict[str, str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "bominjection", default={"bom_variants": _BOM_VARIANTS_DEFAULT}
    )
    return data.get("bom_variants", _BOM_VARIANTS_DEFAULT)


_BOM_VARIANTS = _load_bom_variants()


_BOM_BYTES: dict[str, bytes] = {
    "utf8_bom": b"\xef\xbb\xbf",
    "utf16_le": b"\xff\xfe",
    "utf16_be": b"\xfe\xff",
    "utf32_le": b"\xff\xfe\x00\x00",
    "utf32_be": b"\x00\x00\xfe\xff",
    "utf7_bom": b"+/v8",
}


_SENSITIVE_STRINGS_DEFAULT: list[str] = [
    "<script>alert(1)</script>",
    "' OR 1=1 --",
    "../../etc/passwd",
    "admin",
    "SELECT * FROM users",
    "test%00value",
]


def _load_sensitive_strings() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "bominjection", default={"sensitive_strings": _SENSITIVE_STRINGS_DEFAULT}
    )
    return data.get("sensitive_strings", _SENSITIVE_STRINGS_DEFAULT)


_SENSITIVE_STRINGS = _load_sensitive_strings()


@dataclass(frozen=True, slots=True)
class BomAttempt:
    """Tentativa individual de BOM injection."""

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
class BomResult:
    """Resultado consolidado do scan de BOM injection."""

    target: str

    baseline_status: int

    baseline_size: int

    tls: bool

    attempts: list[BomAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def _bom_url(url: str, bom_name: str, bom_char: str, position: str) -> str:
    """ConstrÃ³i URL com BOM injetado."""

    parsed = urlparse(url)

    if not parsed.scheme:
        parsed = urlparse(f"http://{url}")

    if position == "path":
        path = parsed.path.rstrip("/") + "/" + bom_char + "admin"

        return urlunparse(parsed._replace(path=path))

    elif position == "query":
        existing = parsed.query

        sep = "&" if existing else ""

        new_query = f"{existing}{sep}test={bom_char}value"

        return urlunparse(parsed._replace(query=new_query))

    return url


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""

    try:
        resp = await client.get(url, follow_redirects=False)

        return resp.status_code, len(resp.content), resp.content

    except httpx.RequestError:
        return 0, 0, b""


async def _test_bom_url(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[BomAttempt]:
    """Testa BOM injection em URLs."""

    attempts: list[BomAttempt] = []

    b_status, b_size, _ = baseline

    for bom_name, bom_char in _BOM_VARIANTS.items():
        bom_url_char = "".join(f"%{b:02x}" for b in _BOM_BYTES[bom_name])
        for position in ["path", "query"]:
            test_url = _bom_url(url, bom_name, bom_url_char, position)

            technique = f"bom_{bom_name}_{position}"

            try:
                resp = await client.get(test_url, follow_redirects=False)

                t_status = resp.status_code

                t_size = len(resp.content)

                status_changed = t_status != b_status

                size_changed = abs(t_size - b_size) > 50

                vulnerable = status_changed and t_status == 200

                attempts.append(
                    BomAttempt(
                        technique=technique,
                        category="url",
                        url=test_url,
                        payload=f"{bom_name}={bom_char}",
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
                        exploit="\\xef\\xbb\\xbf" if vulnerable else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    BomAttempt(
                        technique=technique,
                        category="url",
                        url=test_url,
                        payload=f"{bom_name}={bom_char}",
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


async def _test_bom_headers(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[BomAttempt]:
    """Testa BOM injection em headers."""

    attempts: list[BomAttempt] = []

    b_status, b_size, _ = baseline

    header_payloads = [
        (
            "bom_referer",
            "Referer",
            f"https://example.com{_BOM_VARIANTS['utf8_bom']}admin",
        ),
        ("bom_cookie", "Cookie", f"session={_BOM_VARIANTS['utf8_bom']}abc123"),
        ("bom_ua", "User-Agent", f"Mozilla/5.0{_BOM_VARIANTS['utf8_bom']}compatible"),
    ]

    for technique, header_name, header_value in header_payloads:
        try:
            resp = await client.get(
                url, headers={header_name: header_value}, follow_redirects=False
            )

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                BomAttempt(
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
                    details=f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca",
                    error="",
                    exploit="\\xef\\xbb\\xbf" if vulnerable else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                BomAttempt(
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


async def _test_bom_body(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[BomAttempt]:
    """Testa BOM injection em corpo de requisicoes POST."""

    attempts: list[BomAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    base_url = urlunparse(parsed._replace(query=""))

    test_payloads = [
        ("bom_form", "form", {"field": f"{_BOM_VARIANTS['utf8_bom']}test"}),
        ("bom_json", "json", {"data": f"{_BOM_VARIANTS['utf8_bom']}payload"}),
        ("bom_raw", "raw", f"{_BOM_VARIANTS['utf8_bom']}raw body content"),
    ]

    for technique, method, data in test_payloads:
        try:
            if method == "form":
                resp = await client.post(base_url, data=data, follow_redirects=False)

            elif method == "json":
                resp = await client.post(
                    base_url,
                    json=data,
                    headers={"Content-Type": "application/json"},
                    follow_redirects=False,
                )

            else:
                resp = await client.post(
                    base_url,
                    content=data.encode(),
                    headers={"Content-Type": "text/plain"},
                    follow_redirects=False,
                )

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                BomAttempt(
                    technique=technique,
                    category="body",
                    url=base_url,
                    payload=str(data),
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
                    exploit="\\xef\\xbb\\xbf" if vulnerable else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                BomAttempt(
                    technique=technique,
                    category="body",
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
                )
            )

    return attempts


async def _test_bom_upload(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[BomAttempt]:
    """Testa BOM injection em uploads de arquivo."""

    attempts: list[BomAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    base_url = urlunparse(parsed._replace(query=""))

    upload_payloads = [
        ("bom_filename", f"{_BOM_VARIANTS['utf8_bom']}test.txt", "file_content"),
        ("bom_field", "test.txt", f"{_BOM_VARIANTS['utf8_bom']}file_content"),
    ]

    for technique, filename, content in upload_payloads:
        try:
            resp = await client.post(
                base_url,
                files={"file": (filename, content.encode(), "text/plain")},
                follow_redirects=False,
            )

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                BomAttempt(
                    technique=technique,
                    category="upload",
                    url=base_url,
                    payload=f"filename={filename}, content={content[:20]}",
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
                    exploit="\\xef\\xbb\\xbf" if vulnerable else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                BomAttempt(
                    technique=technique,
                    category="upload",
                    url=base_url,
                    payload=f"filename={filename}, content={content[:20]}",
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


async def scan_bom_injection(
    url: str,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
    category: str | None = None,
    concurrency: int = 5,
) -> BomResult:
    """Executa scan de BOM injection contra a URL alvo."""

    parsed = urlparse(url)

    if not parsed.scheme:
        url = f"http://{url}"

        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent=user_agent or "MyTools/bominjection",
        proxy=proxy,
        timeout=timeout,
        verify=verify,
    ) as client:
        b_status, b_size, b_body = await _test_baseline(client, url)

        baseline = (b_status, b_size, b_body)

        coros = []

        selected = _CATEGORY_MAP.get(category, []) if category else []

        if not category or category == "url":
            coros.append(_test_bom_url(client, url, baseline))

        if not category or category == "header":
            coros.append(_test_bom_headers(client, url, baseline))

        if not category or category == "body":
            coros.append(_test_bom_body(client, url, baseline))

        if not category or category == "upload":
            coros.append(_test_bom_upload(client, url, baseline))

        if category and not selected:
            return BomResult(
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

        all_attempts: list[BomAttempt] = []

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
        issues.append(f"{len(vulnerable)} tecnicas de BOM injection vulneraveis")

    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return BomResult(
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


def print_results_fn(result: BomResult) -> None:
    """Exibe os resultados do scan formatados."""

    print()

    print(color("=" * 60, Cyber.CYAN))

    print(color("  BOM INJECTION SCAN", Cyber.CYAN))

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

        for a in result.attempts:
            if a.vulnerable:
                print(color(f"    - {a.technique}", Cyber.RED))

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


class BominjectionScanner(BaseScanner):
    """Scanner de BOM Injection â€” testa injecao de Byte Order Mark em web apps.."""

    prog = "mytools-bominject"
    description = "BOM Injection â€” testa injecao de Byte Order Mark em web apps."
    prompt = "bom> "
    module_name = "mytools.bominjection"
    banner_text = r"""


     _   _                      ____             _

    | \ | |                    |  _ \           | |

    |  \| | _____  ___   _  __| |_) |_ __ ___ | | _____ _ __

    | . ` |/ _ \ \/ / | | |/ _`  _ <| '_ ` _ \| |/ / _ \ '__|

    | |\  |  __/>  <| |_| | (_| |_) | | | | | |   <  __/ |

    |_| \_|\___/_/\_\\__,_|\__,_.__/|_| |_| |_|_|\_\___|_|
    """
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("url", nargs="?", help="URL alvo para teste")
        parser.add_argument(
            "-c",
            "--category",
            choices=list(_CATEGORY_MAP.keys()),
            help="Categoria de teste (url, header, body, upload)",
        )
        parser.add_argument(
            "--concurrency",
            type=int,
            default=5,
            help="Numero de requisicoes simultaneas (default: 5)",
        )

    async def run_scan(self, **kwargs):  # type: ignore[override]
        return await scan_bom_injection(**kwargs)

    def print_results(self, result: object) -> None:
        print_results_fn(result)  # type: ignore[arg-type]

    def _example(self) -> str:
        return "https://target.com -c url"

    def _help(self) -> str:
        return (
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            " https://target.com\n"
            " https://target.com -c url\n"
            " https://target.com -c body\n"
            " https://target.com -c upload --proxy http://127.0.0.1:8080"
        )


scanner = BominjectionScanner()
main = scanner.main
run_once = scanner.run_once
banner_art = scanner._make_banner()

# Backward-compatible re-exports for tests
build_parser = scanner.build_parser
print_results = print_results_fn

if __name__ == "__main__":
    raise SystemExit(main())
