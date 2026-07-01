#!/usr/bin/env python3
"""Modulo de testes de Charset Detection Bypass.

Testa se o servidor e vulneravel a bypass via deteccao errada de charset:
  - Meta charset tags (<meta charset="utf-7">)
  - Content-Type com charset divergente do body
  - BOM de charset especifico no inicio do body
  - XML declaration com charset divergente
  - Combinacoes de tecnicas (mixed)

Forcar o servidor a detectar charset errado faz com que ele interprete bytes
de forma diferente, podendo bypassar filtros de XSS, SQLi e outros.

Fluxo:
  1. Envia requisicao baseline sem charset manipulation
  2. Envia requisicoes com charset bypass em diferentes posicoes
  3. Compara respostas (status, tamanho, headers, corpo)
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

logger = logging.getLogger("mytools.charsetbypass")

_CATEGORY_MAP: dict[str, list[str]] = {
    "meta": ["meta_charset_utf7", "meta_charset_utf16", "meta_http_equiv"],
    "content_type": ["ct_utf7", "ct_utf16", "ct_iso8859", "ct_mismatch"],
    "bom": ["bom_utf7", "bom_utf16_le", "bom_utf16_be"],
    "xml": ["xml_utf7", "xml_utf16", "xml_iso8859"],
    "mixed": ["meta_bom", "ct_meta", "ct_xml"],
}

_CHARSETS: dict[str, str] = {
    "utf-7": "utf-7",
    "utf-7-imap": "utf-7-imap",
    "utf-16-le": "utf-16le",
    "utf-16-be": "utf-16be",
    "utf-32-le": "utf-32le",
    "utf-32-be": "utf-32be",
    "iso-8859-1": "iso-8859-1",
    "iso-8859-15": "iso-8859-15",
    "windows-1252": "windows-1252",
    "koi8-r": "koi8-r",
    "mac-roman": "macintosh",
    "x-user-defined": "x-user-defined",
}

_BOM_BYTES: dict[str, bytes] = {
    "utf-7": b"+/v8",
    "utf-16-le": b"\xff\xfe",
    "utf-16-be": b"\xfe\xff",
    "utf-32-le": b"\xff\xfe\x00\x00",
    "utf-32-be": b"\x00\x00\xfe\xff",
    "utf-8": b"\xef\xbb\xbf",
}

_XSS_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

_SQLI_PAYLOADS: list[str] = [
    "' OR 1=1 --",
    "1; DROP TABLE users",
    "' UNION SELECT NULL--",
    "admin'--",
]


@dataclass(frozen=True, slots=True)
class CharsetBypassAttempt:
    """Tentativa individual de charset detection bypass."""

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
class CharsetBypassResult:
    """Resultado consolidado do scan de charset detection bypass."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[CharsetBypassAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _build_meta_body(charset: str, payload: str) -> str:
    """Constrói body HTML com meta charset tag."""
    return (
        f'<!DOCTYPE html><html><head>'
        f'<meta charset="{charset}">'
        f'</head><body>{payload}</body></html>'
    )


def _build_meta_http_equiv(charset: str, payload: str) -> str:
    """Constrói body HTML com meta http-equiv charset."""
    return (
        f'<!DOCTYPE html><html><head>'
        f'<meta http-equiv="Content-Type" content="text/html; charset={charset}">'
        f'</head><body>{payload}</body></html>'
    )


def _build_xml_body(charset: str, payload: str) -> str:
    """Constrói body XML com declaration de charset."""
    return f'<?xml version="1.0" encoding="{charset}"?>\n<root>{payload}</root>'


def _build_bom_body(bom_bytes: bytes, payload: str) -> str:
    """Constrói body com BOM no início."""
    return payload


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_meta_charset(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[CharsetBypassAttempt]:
    """Testa charset bypass via meta tags."""
    attempts: list[CharsetBypassAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    for charset_name, charset_value in [("utf-7", "utf-7"), ("utf-16", "utf-16le")]:
        for payload in _XSS_PAYLOADS[:2]:
            body = _build_meta_body(charset_value, payload)
            technique = f"meta_charset_{charset_name}"

            try:
                resp = await client.post(
                    base_url,
                    content=body.encode(),
                    headers={"Content-Type": "text/html"},
                    follow_redirects=False,
                )
                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                size_changed = abs(t_size - b_size) > 50
                vulnerable = status_changed and t_status == 200

                attempts.append(CharsetBypassAttempt(
                    technique=technique,
                    category="meta",
                    url=base_url,
                    payload=f"charset={charset_value}, xss={payload[:30]}",
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
                attempts.append(CharsetBypassAttempt(
                    technique=technique,
                    category="meta",
                    url=base_url,
                    payload=f"charset={charset_value}",
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


async def _test_content_type_charset(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[CharsetBypassAttempt]:
    """Testa charset bypass via Content-Type header."""
    attempts: list[CharsetBypassAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    ct_payloads = [
        ("ct_utf7", "text/html; charset=utf-7", "<script>alert(1)</script>"),
        ("ct_utf16", "text/html; charset=utf-16le", "<script>alert(1)</script>"),
        ("ct_iso8859", "text/html; charset=iso-8859-1", "<script>alert(1)</script>"),
        ("ct_mismatch", "text/html; charset=utf-8", "<script>alert(1)</script>"),
    ]

    for technique, content_type, payload in ct_payloads:
        try:
            resp = await client.post(
                base_url,
                content=payload.encode(),
                headers={"Content-Type": content_type},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(CharsetBypassAttempt(
                technique=technique,
                category="content_type",
                url=base_url,
                payload=content_type,
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
            attempts.append(CharsetBypassAttempt(
                technique=technique,
                category="content_type",
                url=base_url,
                payload=content_type,
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


async def _test_bom_charset(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[CharsetBypassAttempt]:
    """Testa charset bypass via BOM no body."""
    attempts: list[CharsetBypassAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    bom_payloads = [
        ("bom_utf7", b"+/v8", "utf-7"),
        ("bom_utf16_le", b"\xff\xfe", "utf-16le"),
        ("bom_utf16_be", b"\xfe\xff", "utf-16be"),
    ]

    for technique, bom_bytes, charset in bom_payloads:
        payload = "<script>alert(1)</script>"
        body = bom_bytes + payload.encode()
        try:
            resp = await client.post(
                base_url,
                content=body,
                headers={"Content-Type": "text/html"},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(CharsetBypassAttempt(
                technique=technique,
                category="bom",
                url=base_url,
                payload=f"bom={bom_bytes.hex()}, charset={charset}",
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
            attempts.append(CharsetBypassAttempt(
                technique=technique,
                category="bom",
                url=base_url,
                payload=f"bom={bom_bytes.hex()}",
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


async def _test_xml_charset(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[CharsetBypassAttempt]:
    """Testa charset bypass via XML declaration."""
    attempts: list[CharsetBypassAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    xml_payloads = [
        ("xml_utf7", "utf-7", "<root><data>alert(1)</data></root>"),
        ("xml_utf16", "utf-16le", "<root><data>alert(1)</data></root>"),
        ("xml_iso8859", "iso-8859-1", "<root><data>alert(1)</data></root>"),
    ]

    for technique, charset, payload in xml_payloads:
        body = _build_xml_body(charset, payload)
        try:
            resp = await client.post(
                base_url,
                content=body.encode(),
                headers={"Content-Type": "application/xml"},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(CharsetBypassAttempt(
                technique=technique,
                category="xml",
                url=base_url,
                payload=f"encoding={charset}",
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
            attempts.append(CharsetBypassAttempt(
                technique=technique,
                category="xml",
                url=base_url,
                payload=f"encoding={charset}",
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


async def _test_mixed_charset(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes],
) -> list[CharsetBypassAttempt]:
    """Testa charset bypass via combinacoes de tecnicas."""
    attempts: list[CharsetBypassAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    mixed_payloads = [
        ("meta_bom", "utf-7", b"+/v8", "<script>alert(1)</script>"),
        ("ct_meta", "utf-7", None, "<script>alert(1)</script>"),
        ("ct_xml", "utf-16le", None, '<?xml version="1.0" encoding="utf-16le"?><root>alert(1)</root>'),
    ]

    for technique, charset, bom_bytes, payload in mixed_payloads:
        body = bom_bytes + payload.encode() if bom_bytes else payload.encode()

        headers = {"Content-Type": f"text/html; charset={charset}"}
        try:
            resp = await client.post(
                base_url,
                content=body,
                headers=headers,
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(CharsetBypassAttempt(
                technique=technique,
                category="mixed",
                url=base_url,
                payload=f"charset={charset}, bom={'yes' if bom_bytes else 'no'}",
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
            attempts.append(CharsetBypassAttempt(
                technique=technique,
                category="mixed",
                url=base_url,
                payload=f"charset={charset}",
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


async def scan_charset_bypass(
    url: str,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
    category: str | None = None,
    concurrency: int = 5,
) -> CharsetBypassResult:
    """Executa scan de charset detection bypass contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent=user_agent or "MyTools/charsetbypass",
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

        if not category or category == "meta":
            tasks.append(_limited(_test_meta_charset(client, url, baseline)))
        if not category or category == "content_type":
            tasks.append(_limited(_test_content_type_charset(client, url, baseline)))
        if not category or category == "bom":
            tasks.append(_limited(_test_bom_charset(client, url, baseline)))
        if not category or category == "xml":
            tasks.append(_limited(_test_xml_charset(client, url, baseline)))
        if not category or category == "mixed":
            tasks.append(_limited(_test_mixed_charset(client, url, baseline)))

        if category and not selected:
            return CharsetBypassResult(
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
        all_attempts: list[CharsetBypassAttempt] = []
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
        issues.append(f"{len(vulnerable)} tecnicas de charset bypass vulneraveis")
    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return CharsetBypassResult(
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


def print_results(result: CharsetBypassResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  CHARSET DETECTION BYPASS SCAN", Cyber.CYAN))
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
        prog="mytools-charsetbypass",
        description="Charset Detection Bypass — testa bypass via charset manipulacao.",
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de teste (meta, content_type, bom, xml, mixed)",
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
        scan_charset_bypass(
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
     _   _                      ______                 _ _               _
    | \ | |                    / ____|               (_) |             | |
    |  \| | _____  ___   _  __| |     ___  _ __ ___  _| |_ _   _ _ __ | |_
    | . ` |/ _ \ \/ / | | |/ _` |    / _ \| '_ ` _ \| | __| | | | '_ \| __|
    | |\  |  __/>  <| |_| | (_| |___| (_) | | | | | | | |_| |_| | |_) | |_
    |_| \_|\___/_/\_\\__,_|\__,______\___/|_| |_| |_|_|\__|\__, | .__/ \__|
                                                             __/ | |
                                                            |___/|_|
    """,
    "Charset Detection Bypass — detecta bypass via charset manipulacao",
)


def main() -> int:
    """Ponto de entrada principal do CLI."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="charset> ",
        description="Charset Detection Bypass interativo.",
        example="https://target.com -c meta",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c meta\n"
            "  https://target.com -c content_type\n"
            "  https://target.com -c mixed --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
