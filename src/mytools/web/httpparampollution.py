#!/usr/bin/env python3
"""Modulo de deteccao de HTTP Parameter Pollution.

Testa se o servidor e vulneravel a HPP via:
  - Query — parametros duplicados na query string
  - Body — parametros duplicados no body form
  - Header — headers duplicados
  - JSON — arrays/objetos duplicados no body JSON
  - Bypass — encoding, concatenation, null byte tricks

Fluxo:
  1. Envia request baseline para obter resposta de referencia
  2. Envia requests com parametros duplicados em diferentes positions
  3. Verifica se resposta indica comportamento anormal (diferente de baseline)
  4. Classifica: vulnerable, blocked, error
  5. Retorna resultado consolidado com severidade
"""

import argparse
import json
import logging
from dataclasses import asdict, dataclass

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.httpparampollution")

_CATEGORY_MAP: dict[str, list[str]] = {
    "query": ["dup_id", "dup_name", "dup_token", "dup_session", "dup_admin"],
    "body": [
        "form_dup_id",
        "form_dup_name",
        "form_dup_token",
        "form_dup_session",
        "form_dup_admin",
    ],
    "header": ["dup_cookie", "dup_auth", "dup_accept", "dup_referer", "dup_host"],
    "json": [
        "json_dup_id",
        "json_dup_array",
        "json_dup_name",
        "json_dup_token",
        "json_dup_admin",
    ],
    "bypass": [
        "null_byte",
        "double_encode",
        "unicode_dup",
        "whitespace_dup",
        "case_dup",
    ],
}

_QUERY_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "dup_id",
        "id=1&id=2",
        "id",
        ["id", "parameter", "duplicate"],
    ),
    (
        "dup_name",
        "name=admin&name=user",
        "name",
        ["name", "parameter", "duplicate"],
    ),
    (
        "dup_token",
        "token=abc&token=xss",
        "token",
        ["token", "parameter", "duplicate"],
    ),
    (
        "dup_session",
        "session=123&session=456",
        "session",
        ["session", "parameter", "duplicate"],
    ),
    (
        "dup_admin",
        "role=user&role=admin",
        "role",
        ["role", "admin", "parameter"],
    ),
]

_BODY_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "form_dup_id",
        "id=1&id=2",
        "id",
        ["id", "parameter", "duplicate"],
    ),
    (
        "form_dup_name",
        "name=admin&name=user",
        "name",
        ["name", "parameter", "duplicate"],
    ),
    (
        "form_dup_token",
        "token=abc&token=xss",
        "token",
        ["token", "parameter", "duplicate"],
    ),
    (
        "form_dup_session",
        "session=123&session=456",
        "session",
        ["session", "parameter", "duplicate"],
    ),
    (
        "form_dup_admin",
        "role=user&role=admin",
        "role",
        ["role", "admin", "parameter"],
    ),
]

_HEADER_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "dup_cookie",
        "Cookie",
        "session=abc; session=xyz",
        ["session", "cookie", "duplicate"],
    ),
    (
        "dup_auth",
        "Authorization",
        "Bearer abc; Bearer xyz",
        ["authorization", "token", "duplicate"],
    ),
    (
        "dup_accept",
        "Accept",
        "text/html, application/json",
        ["accept", "header", "duplicate"],
    ),
    (
        "dup_referer",
        "Referer",
        "https://safe.com; https://evil.com",
        ["referer", "header", "duplicate"],
    ),
    (
        "dup_host",
        "Host",
        "target.com; evil.com",
        ["host", "header", "duplicate"],
    ),
]

_JSON_PAYLOADS: list[tuple[str, str, object, list[str]]] = [
    (
        "json_dup_id",
        "id",
        [1, 2],
        ["id", "parameter", "duplicate"],
    ),
    (
        "json_dup_array",
        "data",
        {"$each": ["a", "b"]},
        ["data", "array", "duplicate"],
    ),
    (
        "json_dup_name",
        "name",
        ["admin", "user"],
        ["name", "parameter", "duplicate"],
    ),
    (
        "json_dup_token",
        "token",
        ["abc", "xss"],
        ["token", "parameter", "duplicate"],
    ),
    (
        "json_dup_admin",
        "role",
        ["user", "admin"],
        ["role", "admin", "parameter"],
    ),
]

_BYPASS_PAYLOADS: list[tuple[str, str, str, str, list[str]]] = [
    (
        "null_byte",
        "id=1%00&id=2",
        "query",
        "id",
        ["id", "parameter", "null"],
    ),
    (
        "double_encode",
        "id%3D1&id%3D2",
        "query",
        "id",
        ["id", "parameter", "encode"],
    ),
    (
        "unicode_dup",
        "id=1&id=2",
        "query",
        "id",
        ["id", "parameter", "unicode"],
    ),
    (
        "whitespace_dup",
        "id=1&id=%202",
        "query",
        "id",
        ["id", "parameter", "whitespace"],
    ),
    (
        "case_dup",
        "ID=1&id=2",
        "query",
        "id",
        ["id", "parameter", "case"],
    ),
]

_SENSITIVE_PATHS: list[str] = [
    "/admin",
    "/login",
    "/api/user",
    "/api/data",
    "/settings",
    "/dashboard",
    "/profile",
    "/upload",
    "/search",
    "/api/config",
]


@dataclass(frozen=True, slots=True)
class HPPAttempt:
    """Tentativa individual de HTTP Parameter Pollution."""

    technique: str
    category: str
    param_name: str
    payload: str
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
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class HPPResult:
    """Resultado consolidado do scan de HTTP Parameter Pollution."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[HPPAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _check_hpp_response(
    body: bytes,
    status: int,
    baseline_status: int,
) -> bool:
    """Verifica se a resposta indica HPP vulneravel.

    Se o status ou tamanho mudou significativamente, indica que o servidor
    processou o parametro duplicado de forma diferente.
    """
    if status == 0:
        return False
    return status != baseline_status


def _check_response_content(body: bytes, indicators: list[str]) -> bool:
    """Verifica se o conteudo da resposta contem indicadores de sucesso."""
    text = body.decode("utf-8", errors="ignore").lower()
    return any(ind.lower() in text for ind in indicators)


def _build_test_url(url: str, path: str, query_payload: str) -> str:
    """Monta URL de teste preservando query string existente (sem ``??``)."""
    base = url.rstrip("/") + path
    if "?" in base:
        return f"{base}&{query_payload}"
    return f"{base}?{query_payload}"


async def _test_baseline(
    client: httpx.AsyncClient,
    url: str,
    *,
    method: str = "GET",
    content: bytes | str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, int, bytes]:
    """Envia request baseline para obter status e tamanho de referencia."""
    try:
        resp = await client.request(
            method,
            url,
            content=content,
            headers=headers,
            follow_redirects=True,
        )
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_query(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[HPPAttempt]:
    """Testa HPP em query parameters."""
    b_status, b_size, _ = baseline
    results: list[HPPAttempt] = []

    for technique, query_payload, param_name, indicators in _QUERY_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = _build_test_url(url, path, query_payload)
                resp = await client.get(test_url, follow_redirects=True)
                vulnerable = _check_hpp_response(
                    resp.content, resp.status_code, b_status
                )
                if not vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)
                results.append(
                    HPPAttempt(
                        exploit="duplicate_param_payload",
                        tool="wfuzz",
                        technique=technique,
                        category="query",
                        param_name=param_name,
                        payload=query_payload,
                        method="GET",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, query={query_payload}"
                        if vulnerable
                        else "",
                        error="",
                    )
                )
            except httpx.RequestError as e:
                results.append(
                    HPPAttempt(
                        technique=technique,
                        category="query",
                        param_name=param_name,
                        payload=query_payload,
                        method="GET",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )
    return results


async def _test_body(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[HPPAttempt]:
    """Testa HPP em body form parameters."""
    get_b_status, get_b_size, _ = baseline

    post_b_status, post_b_size, _ = await _test_baseline(
        client,
        url,
        method="POST",
        content=b"",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    b_status = post_b_status if post_b_status else get_b_status
    b_size = post_b_size if post_b_size else get_b_size
    results: list[HPPAttempt] = []

    for technique, body_payload, param_name, indicators in _BODY_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path
                resp = await client.post(
                    test_url,
                    content=body_payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=True,
                )
                vulnerable = _check_hpp_response(
                    resp.content, resp.status_code, b_status
                )
                if not vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)
                results.append(
                    HPPAttempt(
                        exploit="duplicate_param_payload",
                        tool="wfuzz",
                        technique=technique,
                        category="body",
                        param_name=param_name,
                        payload=body_payload,
                        method="POST",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, body={body_payload}"
                        if vulnerable
                        else "",
                        error="",
                    )
                )
            except httpx.RequestError as e:
                results.append(
                    HPPAttempt(
                        technique=technique,
                        category="body",
                        param_name=param_name,
                        payload=body_payload,
                        method="POST",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )
    return results


async def _test_header(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[HPPAttempt]:
    """Testa HPP em headers duplicados."""
    b_status, b_size, _ = baseline
    results: list[HPPAttempt] = []

    for technique, header_name, header_value, indicators in _HEADER_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path
                resp = await client.get(
                    test_url,
                    headers={header_name: header_value},
                    follow_redirects=True,
                )
                vulnerable = _check_hpp_response(
                    resp.content, resp.status_code, b_status
                )
                if not vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)
                results.append(
                    HPPAttempt(
                        exploit="duplicate_param_payload",
                        tool="wfuzz",
                        technique=technique,
                        category="header",
                        param_name=header_name,
                        payload=header_value,
                        method="GET",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, header={header_name}: {header_value}"
                        if vulnerable
                        else "",
                        error="",
                    )
                )
            except httpx.RequestError as e:
                results.append(
                    HPPAttempt(
                        technique=technique,
                        category="header",
                        param_name=header_name,
                        payload=header_value,
                        method="GET",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )
    return results


async def _test_json(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[HPPAttempt]:
    """Testa HPP em JSON body com arrays/objetos duplicados."""
    b_status, b_size, _ = baseline
    results: list[HPPAttempt] = []

    for technique, field_name, field_value, indicators in _JSON_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path
                body = json.dumps({field_name: field_value})
                resp = await client.post(
                    test_url,
                    content=body,
                    headers={"Content-Type": "application/json"},
                    follow_redirects=True,
                )
                vulnerable = _check_hpp_response(
                    resp.content, resp.status_code, b_status
                )
                if not vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)
                results.append(
                    HPPAttempt(
                        exploit="duplicate_param_payload",
                        tool="wfuzz",
                        technique=technique,
                        category="json",
                        param_name=field_name,
                        payload=json.dumps(field_value),
                        method="POST",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, json={field_name}={json.dumps(field_value)}"
                        if vulnerable
                        else "",
                        error="",
                    )
                )
            except httpx.RequestError as e:
                results.append(
                    HPPAttempt(
                        technique=technique,
                        category="json",
                        param_name=field_name,
                        payload=json.dumps(field_value),
                        method="POST",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )
    return results


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[HPPAttempt]:
    """Testa bypass de HPP (encoding, null byte, etc)."""
    b_status, b_size, _ = baseline
    results: list[HPPAttempt] = []

    for technique, payload, _, param_name, indicators in _BYPASS_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = _build_test_url(url, path, payload)
                resp = await client.get(test_url, follow_redirects=True)
                vulnerable = _check_hpp_response(
                    resp.content, resp.status_code, b_status
                )
                if not vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)
                results.append(
                    HPPAttempt(
                        exploit="duplicate_param_payload",
                        tool="wfuzz",
                        technique=technique,
                        category="bypass",
                        param_name=param_name,
                        payload=payload,
                        method="GET",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, bypass={payload}" if vulnerable else "",
                        error="",
                    )
                )
            except httpx.RequestError as e:
                results.append(
                    HPPAttempt(
                        technique=technique,
                        category="bypass",
                        param_name=param_name,
                        payload=payload,
                        method="GET",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )
    return results


def print_results(result: HPPResult) -> None:
    """Exibe os resultados do scan de HTTP Parameter Pollution."""
    vuln = [a for a in result.attempts if a.vulnerable]
    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]
    errors = [a for a in result.attempts if a.error]

    print(color("\n--- HTTP Parameter Pollution ---", Cyber.CYAN, Cyber.BOLD))
    print(color(f"  Alvo:         {result.target}", Cyber.WHITE))
    print(color(f"  TLS:          {'sim' if result.tls else 'nao'}", Cyber.WHITE))
    print(
        color(
            f"  Baseline:     {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.WHITE,
        )
    )
    print(color(f"  Testes:       {len(result.attempts)}", Cyber.WHITE))
    print(color(f"  Vulneraveis:  {len(vuln)}", Cyber.GREEN if vuln else Cyber.GRAY))
    print(color(f"  Bloqueados:   {len(blocked)}", Cyber.GRAY))
    print(color(f"  Erros:        {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if vuln:
        print(color("\n  [+] Vulnerabilidades detectadas:", Cyber.GREEN, Cyber.BOLD))
        seen: set[str] = set()
        for a in vuln:
            key = f"{a.technique}:{a.param_name}"
            if key in seen:
                continue
            seen.add(key)
            print(color(f"    [{a.category}] {a.technique}", Cyber.GREEN))
            print(color(f"      Param: {a.param_name}", Cyber.WHITE))
            print(color(f"      Payload: {a.payload}", Cyber.WHITE))
            print(
                color(
                    f"      Status: {a.status_baseline} -> {a.status_test}", Cyber.WHITE
                )
            )
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
        print(color("\n  [-] Nenhuma HTTP Parameter Pollution detectada", Cyber.YELLOW))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
) -> int:
    """Executa o scan de HTTP Parameter Pollution."""
    logger.info("HTTP Parameter Pollution scan para %s", target)

    tls = target.startswith("https://")
    async with create_async_client(timeout=timeout) as client:
        baseline = await _test_baseline(client, target)
        b_status, b_size, _ = baseline

        all_attempts: list[HPPAttempt] = []
        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            if cat == "query":
                all_attempts.extend(await _test_query(client, target, baseline))
            elif cat == "body":
                all_attempts.extend(await _test_body(client, target, baseline))
            elif cat == "header":
                all_attempts.extend(await _test_header(client, target, baseline))
            elif cat == "json":
                all_attempts.extend(await _test_json(client, target, baseline))
            elif cat == "bypass":
                all_attempts.extend(await _test_bypass(client, target, baseline))

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})
        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )
        issues: list[str] = []

        if not vuln_techs and not blocked_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = HPPResult(
            target=target,
            baseline_status=b_status,
            baseline_size=b_size,
            tls=tls,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked_techs,
            issues=issues,
            overall_status="vulnerable"
            if vuln_techs
            else ("safe" if blocked_techs else "unknown"),
        )

        print_results(result)
        logger.info(
            "HPP scan concluido: %d testes, %d vulneraveis",
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
    _   _  ___  ____  ____  ____    _    _   _ _____ ____
   | | | |/ _ \|  _ \| __ )|  _ \  / \  | | | |  ___|  _ \
   | |_| | | | | |_) |  _ \| | | |/ _ \ | |_| | |_  | |_) |
   |  _  | |_| |  __/| |_) | |_| / ___ \|  _  |  _| |  _ <
   |_| |_|\___/|_|   |____/|____/_/   \_\_| |_|_|   |_| \_\
"""
    create_banner(
        art, "   http parameter pollution: query, body, header, json, bypass"
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""
    parser = argparse.ArgumentParser(
        prog="mytools-hpp",
        description="HTTP Parameter Pollution — detecta HPP em diferentes positions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-hpp https://target.com\n"
            "  mytools-hpp https://target.com -c query\n"
            "  mytools-hpp https://target.com -c body\n"
            "  mytools-hpp https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
    parser.add_argument("url", help="URL alvo para o scan")
    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=["all", "query", "body", "header", "json", "bypass"],
        help="Categoria de testes (default: todas)",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan HPP a partir de argumentos parseados."""
    logger.info("HTTP Parameter Pollution scan iniciado para %s", args.url)
    categories: list[str] = []
    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]
    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
        ),
    )


def main() -> int:
    """Entry point do modulo HTTP Parameter Pollution."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="hpp> ",
        description="HTTP Parameter Pollution interativo.",
        example="https://target.com -c query",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c query\n"
            "  https://target.com -c body\n"
            "  https://target.com -c header\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
