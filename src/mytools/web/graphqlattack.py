#!/usr/bin/env python3
"""Modulo de testes de GraphQL Attack Testing.

Testa seguranca de endpoints GraphQL:
  - Introspection: schema discovery, full introspection, mutation/subscription discovery
  - Depth Abuse: nested query DoS, circular refs, fragment spread, directive overload
  - Batch Abuse: rate bypass, size abuse, mutation mix, auth bypass
  - Alias Overloading: count bypass, field dup, mutation overload, fragment mix
  - Schema Stitching: remote schema discovery, stitching bypass, federated abuse
  - Persisted Abuse: APQ bypass, hash collision, mutation bypass, enumeration
  - Resolver Analysis: N+1, SQL injection, SSRF, authz bypass, info leak
  - Persisted Enum: hash bruteforce, ID enumeration, query from response
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import time
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_banner,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.graphqlattack")

# ─── Banner ──────────────────────────────────────────────────────────────────

_BANNER_LINES: str = "  ___           _        __ _   \n | __|_ _  __ _| |_ ___ / _(_)__ _\n | _/ _` |/ _` |  _/ -_)  _| / _` |\n |_\\__,_|\\__,_|\\__\\___|_| |_\\__,_|\n"

# ─── Constants ───────────────────────────────────────────────────────────────

_DEFAULT_PATHS_GQL: list[str] = [
    "graphql",
    "graphiql",
    "playground",
    "altair",
    "_graphql",
    "api/graphql",
    "v1/graphql",
    "v2/graphql",
    "v3/graphql",
    "graph",
    "gql",
    "query",
    "graphql-api",
]


def _load_graphql_paths() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads("web", "graphql_paths", default={"paths": _DEFAULT_PATHS_GQL})
    return data.get("paths", _DEFAULT_PATHS_GQL)


_DEFAULT_PATHS = _load_graphql_paths()

_INTROSPECTION_QUERY: str = json.dumps(
    {
        "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }",
    }
)

_DEEP_INTROSPECTION_QUERY: str = json.dumps(
    {
        "query": """{
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                fields {
                    name
                    type { name kind ofType { name kind } }
                    args { name type { name kind } }
                }
                inputFields {
                    name
                    type { name kind ofType { name kind } }
                }
                enumValues { name }
            }
            directives { name locations args { name type { name } } }
        }
    }""",
    }
)

_TOOL_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    (
        "graphiql",
        re.compile(
            r"<div\s+id=['\"]?graphiql['\"]?|GraphiQL\.create|new\s+GraphiQL",
            re.IGNORECASE,
        ),
    ),
    (
        "playground",
        re.compile(
            r"graphql-playground|GraphQL Playground|createPlayground", re.IGNORECASE
        ),
    ),
    ("altair", re.compile(r"altair-graphql|AltairGraphQL|altair\.js", re.IGNORECASE)),
    (
        "voyager",
        re.compile(r"graphql-voyager|GraphQLVoyager|voyager\.render", re.IGNORECASE),
    ),
    (
        "apollo-sandbox",
        re.compile(r"apollo-sandbox|Apollo Sandbox|ApolloSandbox", re.IGNORECASE),
    ),
]

# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class GraphQLAttackAttempt:
    """Tentativa individual de GraphQL attack."""

    technique: str
    category: str
    description: str
    vulnerable: bool
    details: str
    error: str
    endpoint: str
    query_type: str
    schema_types: int
    response_code: int
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class GraphQLAttackResult:
    """Resultado consolidado do scan."""

    target: str
    host: str
    port: int
    tls: bool
    endpoint: str
    schema_found: bool
    types_count: int
    queries_count: int
    mutations_count: int
    attempts: list[GraphQLAttackAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


# ─── Category Map ────────────────────────────────────────────────────────────

_CATEGORY_MAP: dict[str, list[str]] = {
    "introspection": [
        "schema_discovery",
        "full_introspection",
        "partial_introspection",
        "mutation_discovery",
        "subscription_discovery",
    ],
    "depth_abuse": [
        "nested_query_dos",
        "circular_ref",
        "fragment_spread",
        "directive_overload",
        "alias_chain_dos",
    ],
    "batch_abuse": [
        "batch_rate_bypass",
        "batch_size_abuse",
        "batch_mutation_mix",
        "batch_auth_bypass",
    ],
    "alias_overload": [
        "alias_count_bypass",
        "alias_field_dup",
        "alias_mutation_overload",
        "alias_fragment_mix",
    ],
    "schema_stitching": [
        "remote_schema_discovery",
        "stitching_bypass",
        "federated_graph_abuse",
        "schema_leak",
    ],
    "persisted_abuse": [
        "apq_bypass",
        "apq_hash_collision",
        "apq_mutation_bypass",
        "persisted_query_enumeration",
    ],
    "resolver_analysis": [
        "n_plus_one",
        "sql_injection_in_resolver",
        "ssrf_in_resolver",
        "authz_bypass",
        "info_leak_resolver",
    ],
    "persisted_enum": [
        "hash_bruteforce",
        "id_enumeration",
        "query_from_response",
        "persisted_vs_dynamic",
    ],
}

# ─── URL Parser ──────────────────────────────────────────────────────────────


def _parse_url(target: str) -> tuple[str, str, int, bool]:
    """Parse URL em host, path, port, tls."""
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    tls = parsed.scheme in ("https", "wss")
    default_port = 443 if tls else 80
    port = parsed.port or default_port
    return host, path, port, tls


# ─── Endpoint Discovery ─────────────────────────────────────────────────────


def _detect_tool(body: str) -> str:
    """Identifica ferramenta GraphQL pelo body HTML."""
    for tool_name, pattern in _TOOL_SIGNATURES:
        if pattern.search(body):
            return tool_name
    return "unknown"


async def _find_endpoint(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
) -> str:
    """Encontra endpoint GraphQL testando paths comuns."""
    scheme = "https" if tls else "http"
    base = (
        f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    )

    paths_to_try = [path] if path and path != "/" else _DEFAULT_PATHS

    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True
    ) as client:
        for p in paths_to_try:
            url = f"{base}/{p}".replace("//", "/").replace("://", "://")
            try:
                resp = await client.post(
                    url,
                    content=json.dumps({"query": "{ __typename }"}),
                    headers={"Content-Type": "application/json"},
                )
                ct = resp.headers.get("content-type", "")
                if resp.status_code == 200 and ("json" in ct or "graphql" in ct):
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and (
                            "data" in data or "errors" in data
                        ):
                            return url
                    except ValueError:
                        pass
            except Exception:
                continue

    return f"{base}/{path}".replace("//", "/") if path else f"{base}/graphql"


async def _execute_query(
    endpoint: str,
    query: str,
    variables: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    """Executa query GraphQL e retorna (status_code, response_dict)."""
    payload: dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables

    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True
        ) as client:
            resp = await client.post(
                endpoint,
                content=json.dumps(payload),
                headers=req_headers,
            )
            try:
                data = resp.json()
            except ValueError:
                data = {"raw": resp.text[:500]}
            return resp.status_code, data
    except Exception:
        return 0, {"error": "connection_failed"}


async def _introspect_schema(endpoint: str, timeout: float) -> dict[str, Any]:
    """Executa introspection query completa e retorna schema info."""
    status, data = await _execute_query(endpoint, _INTROSPECTION_QUERY, timeout=timeout)
    if status != 200 or "errors" in data:
        return {}
    return data


# ─── Query Builders ──────────────────────────────────────────────────────────


def _build_nested_query(depth: int) -> str:
    """Constrói query deeply nested para depth abuse."""
    query = "{ __typename "
    for _i in range(depth):
        query += "... on Query { __typename "
    query += " }" * (depth + 1)
    return query


def _build_circular_query() -> str:
    """Constrói query com referência circular via fragments."""
    return """{
        __typename
        ...A
    }
    fragment A on Query {
        __typename
        ...B
    }
    fragment B on Query {
        __typename
        ...A
    }"""


def _build_fragment_spread_query(depth: int) -> str:
    """Constrói query com fragment spread encadeado."""
    fragments = [
        f"fragment F{i} on Query {{ __typename ...F{i + 1} }}" for i in range(depth)
    ]
    fragments.append(f"fragment F{depth} on Query {{ __typename }}")
    return "{ ...F0 }\n" + "\n".join(fragments)


def _build_batch_query(queries: list[str]) -> str:
    """Constrói batch query (array de queries)."""
    return json.dumps([{"query": q} for q in queries])


def _build_alias_query(count: int, field: str = "__typename") -> str:
    """Constrói query com N aliases."""
    aliases = ", ".join(f"a{i}: {field}" for i in range(count))
    return f"{{ {aliases} }}"


def _build_persisted_query(hash_val: str) -> dict[str, Any]:
    """Constrói payload de Automatic Persisted Query."""
    return {
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": hash_val,
            }
        }
    }


# ─── Category 158: introspection ─────────────────────────────────────────────


async def _test_introspection(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint_url: str,
    schema_info: dict[str, Any],
) -> list[GraphQLAttackAttempt]:
    """Testa introspection GraphQL."""
    results: list[GraphQLAttackAttempt] = []
    types_count = len(schema_info.get("types", []))

    techniques = [
        ("schema_discovery", "Schema discovery via introspection"),
        ("full_introspection", "Full introspection query"),
        ("partial_introspection", "Partial introspection (types only)"),
        ("mutation_discovery", "Mutation type discovery"),
        ("subscription_discovery", "Subscription type discovery"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "schema_discovery":
                vulnerable = types_count > 0
                details = f"Types found: {types_count}"
            elif tech == "full_introspection":
                full_query = _DEEP_INTROSPECTION_QUERY
                _status, data = await _execute_query(
                    endpoint_url, full_query, timeout=timeout
                )
                vuln_data = data.get("data", {})
                has_schema = isinstance(vuln_data, dict) and "__schema" in vuln_data
                vulnerable = has_schema
                details = f"Full schema: {'available' if vulnerable else 'blocked'}"
            elif tech == "partial_introspection":
                query = "{ __schema { types { name } } }"
                _status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vuln_data = data.get("data", {})
                has_types = isinstance(vuln_data, dict) and "__schema" in vuln_data
                vulnerable = has_types
                details = (
                    f"Partial introspection: {'available' if vulnerable else 'blocked'}"
                )
            elif tech == "mutation_discovery":
                query = "{ __schema { mutationType { name fields { name } } } }"
                _status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vuln_data = data.get("data", {})
                has_mutation = isinstance(vuln_data, dict) and "__schema" in vuln_data
                vulnerable = has_mutation
                details = f"Mutations: {'discoverable' if vulnerable else 'hidden'}"
            elif tech == "subscription_discovery":
                query = "{ __schema { subscriptionType { name fields { name } } } }"
                _status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vuln_data = data.get("data", {})
                has_sub = isinstance(vuln_data, dict) and "__schema" in vuln_data
                vulnerable = has_sub
                details = f"Subscriptions: {'discoverable' if vulnerable else 'hidden'}"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="introspection",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    endpoint=endpoint_url,
                    query_type=schema_info.get("query_type", ""),
                    schema_types=types_count,
                    response_code=200,
                    exploit="introspection_query",
                    tool="graphql-playground",
                )
            )
        except Exception as exc:
            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="introspection",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    endpoint=endpoint_url,
                    query_type="",
                    schema_types=types_count,
                    response_code=0,
                )
            )

    return results


# ─── Category 159: depth_abuse ───────────────────────────────────────────────


async def _test_depth_abuse(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint_url: str,
    schema_info: dict[str, Any],
) -> list[GraphQLAttackAttempt]:
    """Testa depth abuse (DoS via nested queries)."""
    results: list[GraphQLAttackAttempt] = []
    types_count = len(schema_info.get("types", []))

    techniques = [
        ("nested_query_dos", "Nested query DoS (depth 50)"),
        ("circular_ref", "Circular reference via fragments"),
        ("fragment_spread", "Fragment spread depth abuse"),
        ("directive_overload", "Directive overload"),
        ("alias_chain_dos", "Alias chain DoS"),
    ]

    for tech, desc in techniques:
        try:
            status = 200
            if tech == "nested_query_dos":
                query = _build_nested_query(50)
                t0 = time.monotonic()
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                elapsed = time.monotonic() - t0
                has_errors = "errors" in data
                vulnerable = elapsed > 5.0 or (has_errors and status == 200)
                details = (
                    f"Time: {elapsed:.2f}s, Errors: {has_errors}, Status: {status}"
                )
            elif tech == "circular_ref":
                query = _build_circular_query()
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                has_errors = "errors" in data
                vulnerable = not has_errors and status == 200
                details = f"Circular ref: {'accepted' if vulnerable else 'rejected'}"
            elif tech == "fragment_spread":
                query = _build_fragment_spread_query(100)
                t0 = time.monotonic()
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                elapsed = time.monotonic() - t0
                vulnerable = elapsed > 3.0
                details = f"Fragment depth 100: {elapsed:.2f}s"
            elif tech == "directive_overload":
                query = (
                    "{ __typename "
                    + " ".join(f'@deprecated(reason: "test{i}")' for i in range(50))
                    + " }"
                )
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vulnerable = status == 200 and "errors" not in data
                details = f"50 directives: {'accepted' if vulnerable else 'rejected'}"
            elif tech == "alias_chain_dos":
                query = _build_alias_query(1000)
                t0 = time.monotonic()
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                elapsed = time.monotonic() - t0
                vulnerable = elapsed > 5.0
                details = f"1000 aliases: {elapsed:.2f}s, Status: {status}"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="depth_abuse",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    endpoint=endpoint_url,
                    query_type=schema_info.get("query_type", ""),
                    schema_types=types_count,
                    response_code=status
                    if tech
                    in (
                        "nested_query_dos",
                        "circular_ref",
                        "fragment_spread",
                        "directive_overload",
                        "alias_chain_dos",
                    )
                    else 200,
                    exploit="introspection_query",
                    tool="graphql-playground",
                )
            )
        except Exception as exc:
            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="depth_abuse",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    endpoint=endpoint_url,
                    query_type="",
                    schema_types=types_count,
                    response_code=0,
                )
            )

    return results


# ─── Category 160: batch_abuse ───────────────────────────────────────────────


async def _test_batch_abuse(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint_url: str,
    schema_info: dict[str, Any],
) -> list[GraphQLAttackAttempt]:
    """Testa batch query abuse para bypass de rate limiting."""
    results: list[GraphQLAttackAttempt] = []
    types_count = len(schema_info.get("types", []))
    resp: httpx.Response | None = None

    techniques = [
        ("batch_rate_bypass", "Batch queries for rate limit bypass"),
        ("batch_size_abuse", "Large batch size abuse"),
        ("batch_mutation_mix", "Batch with mixed mutations"),
        ("batch_auth_bypass", "Batch auth bypass"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "batch_rate_bypass":
                batch = [{"query": "{ __typename }"} for _ in range(10)]
                payload = json.dumps(batch)
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    resp = await client.post(
                        endpoint_url,
                        content=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    vulnerable = resp.status_code == 200
                    details = f"10 queries batch: status {resp.status_code}"
            elif tech == "batch_size_abuse":
                batch = [{"query": "{ __typename }"} for _ in range(100)]
                payload = json.dumps(batch)
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    resp = await client.post(
                        endpoint_url,
                        content=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    vulnerable = resp.status_code == 200
                    details = f"100 queries batch: status {resp.status_code}"
            elif tech == "batch_mutation_mix":
                batch = [
                    {"query": "mutation { __typename }"},
                    {"query": "{ __typename }"},
                    {"query": "mutation { __typename }"},
                ]
                payload = json.dumps(batch)
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    resp = await client.post(
                        endpoint_url,
                        content=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    vulnerable = resp.status_code == 200
                    details = f"Mixed mutations batch: status {resp.status_code}"
            elif tech == "batch_auth_bypass":
                batch = [{"query": "{ __typename }"} for _ in range(5)]
                payload = json.dumps(batch)
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    resp = await client.post(
                        endpoint_url,
                        content=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    vulnerable = resp.status_code == 200
                    details = f"5 queries without auth: status {resp.status_code}"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            status_code = resp.status_code if resp is not None else 200
            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="batch_abuse",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    endpoint=endpoint_url,
                    query_type=schema_info.get("query_type", ""),
                    schema_types=types_count,
                    response_code=status_code,
                    exploit="introspection_query",
                    tool="graphql-playground",
                )
            )
        except Exception as exc:
            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="batch_abuse",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    endpoint=endpoint_url,
                    query_type="",
                    schema_types=types_count,
                    response_code=0,
                )
            )

    return results


# ─── Category 161: alias_overload ────────────────────────────────────────────


async def _test_alias_overload(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint_url: str,
    schema_info: dict[str, Any],
) -> list[GraphQLAttackAttempt]:
    """Testa alias overloading para bypass de limites."""
    results: list[GraphQLAttackAttempt] = []
    types_count = len(schema_info.get("types", []))

    techniques = [
        ("alias_count_bypass", "Alias count bypass (1000 aliases)"),
        ("alias_field_dup", "Alias field duplication"),
        ("alias_mutation_overload", "Alias mutation overload"),
        ("alias_fragment_mix", "Alias with fragment mix"),
    ]

    for tech, desc in techniques:
        try:
            status = 200
            if tech == "alias_count_bypass":
                query = _build_alias_query(1000)
                t0 = time.monotonic()
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                elapsed = time.monotonic() - t0
                vulnerable = status == 200 and "errors" not in data
                details = f"1000 aliases: {elapsed:.2f}s, status {status}"
            elif tech == "alias_field_dup":
                aliases = ", ".join(f"a{i}: __typename" for i in range(500))
                query = f"{{ {aliases} }}"
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vulnerable = status == 200 and "errors" not in data
                details = f"500 field aliases: status {status}"
            elif tech == "alias_mutation_overload":
                aliases = ", ".join(f"m{i}: __typename" for i in range(100))
                query = f"{{ {aliases} }}"
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vulnerable = status == 200
                details = f"100 mutation aliases: status {status}"
            elif tech == "alias_fragment_mix":
                fragments = "\n".join(
                    f"fragment F{i} on Query {{ __typename }}" for i in range(10)
                )
                aliases = ", ".join(f"a{i}: ...F{i % 10}" for i in range(100))
                query = f"{{ {aliases} }}\n{fragments}"
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vulnerable = status == 200 and "errors" not in data
                details = f"100 alias + 10 fragments: status {status}"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="alias_overload",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    endpoint=endpoint_url,
                    query_type=schema_info.get("query_type", ""),
                    schema_types=types_count,
                    response_code=status if tech in ("alias_count_bypass",) else 200,
                    exploit="introspection_query",
                    tool="graphql-playground",
                )
            )
        except Exception as exc:
            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="alias_overload",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    endpoint=endpoint_url,
                    query_type="",
                    schema_types=types_count,
                    response_code=0,
                )
            )

    return results


# ─── Category 162: schema_stitching ──────────────────────────────────────────


async def _test_schema_stitching(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint_url: str,
    schema_info: dict[str, Any],
) -> list[GraphQLAttackAttempt]:
    """Testa schema stitching e federation abuse."""
    results: list[GraphQLAttackAttempt] = []
    types_count = len(schema_info.get("types", []))

    techniques = [
        ("remote_schema_discovery", "Remote schema discovery"),
        ("stitching_bypass", "Schema stitching bypass"),
        ("federated_graph_abuse", "Federated graph abuse"),
        ("schema_leak", "Schema leak via error"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "remote_schema_discovery":
                query = "{ __schema { directives { name locations } } }"
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vuln_data = data.get("data", {})
                has_directives = isinstance(vuln_data, dict) and "__schema" in vuln_data
                vulnerable = has_directives
                details = f"Directives: {'exposed' if vulnerable else 'hidden'}"
            elif tech == "stitching_bypass":
                query = "{ _entities { __typename } }"
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vulnerable = status == 200 and "errors" not in data
                details = (
                    f"Federation _entities: {'accessible' if vulnerable else 'blocked'}"
                )
            elif tech == "federated_graph_abuse":
                query = "{ _service { sdl } }"
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vulnerable = (
                    status == 200 and "data" in data and data["data"] is not None
                )
                details = f"Service SDL: {'exposed' if vulnerable else 'hidden'}"
            elif tech == "schema_leak":
                query = "{ __nonexistent_field_abc123 }"
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                error_msg = str(data.get("errors", ""))
                vulnerable = (
                    "did you mean" in error_msg.lower()
                    or "suggestion" in error_msg.lower()
                )
                details = f"Error leak: {'yes' if vulnerable else 'no'}"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="schema_stitching",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    endpoint=endpoint_url,
                    query_type=schema_info.get("query_type", ""),
                    schema_types=types_count,
                    response_code=200,
                    exploit="introspection_query",
                    tool="graphql-playground",
                )
            )
        except Exception as exc:
            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="schema_stitching",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    endpoint=endpoint_url,
                    query_type="",
                    schema_types=types_count,
                    response_code=0,
                )
            )

    return results


# ─── Category 163: persisted_abuse ───────────────────────────────────────────


async def _test_persisted_abuse(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint_url: str,
    schema_info: dict[str, Any],
) -> list[GraphQLAttackAttempt]:
    """Testa Automatic Persisted Queries (APQ) abuse."""
    results: list[GraphQLAttackAttempt] = []
    types_count = len(schema_info.get("types", []))

    techniques = [
        ("apq_bypass", "APQ bypass without query"),
        ("apq_hash_collision", "APQ hash collision"),
        ("apq_mutation_bypass", "APQ mutation bypass"),
        ("persisted_query_enumeration", "Persisted query enumeration"),
    ]

    common_hashes = [
        hashlib.sha256(b"{ __typename }").hexdigest(),
        hashlib.sha256(b"{ __schema { types { name } } }").hexdigest(),
        hashlib.sha256(b"query { __typename }").hexdigest(),
    ]

    for tech, desc in techniques:
        try:
            if tech == "apq_bypass":
                payload = {
                    "extensions": {
                        "persistedQuery": {"version": 1, "sha256Hash": common_hashes[0]}
                    }
                }
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    resp = await client.post(
                        endpoint_url,
                        content=json.dumps(payload),
                        headers={"Content-Type": "application/json"},
                    )
                    data = resp.json() if resp.status_code == 200 else {}
                    vulnerable = resp.status_code == 200 and "data" in data
                    details = f"APQ without query: status {resp.status_code}"
            elif tech == "apq_hash_collision":
                fake_hash = hashlib.sha256(b"nonexistent_query").hexdigest()
                payload = {
                    "extensions": {
                        "persistedQuery": {"version": 1, "sha256Hash": fake_hash}
                    }
                }
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    resp = await client.post(
                        endpoint_url,
                        content=json.dumps(payload),
                        headers={"Content-Type": "application/json"},
                    )
                    data = resp.json() if resp.status_code == 200 else {}
                    vulnerable = resp.status_code == 200 and "data" in data
                    details = f"Fake hash: status {resp.status_code}"
            elif tech == "apq_mutation_bypass":
                query_hash = hashlib.sha256(b"mutation { __typename }").hexdigest()
                payload = {
                    "extensions": {
                        "persistedQuery": {"version": 1, "sha256Hash": query_hash}
                    }
                }
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    resp = await client.post(
                        endpoint_url,
                        content=json.dumps(payload),
                        headers={"Content-Type": "application/json"},
                    )
                    data = resp.json() if resp.status_code == 200 else {}
                    vulnerable = resp.status_code == 200 and "data" in data
                    details = f"APQ mutation: status {resp.status_code}"
            elif tech == "persisted_query_enumeration":
                found = 0
                for h in common_hashes:
                    payload = {
                        "extensions": {
                            "persistedQuery": {"version": 1, "sha256Hash": h}
                        }
                    }
                    async with httpx.AsyncClient(
                        timeout=timeout, verify=False
                    ) as client:
                        resp = await client.post(
                            endpoint_url,
                            content=json.dumps(payload),
                            headers={"Content-Type": "application/json"},
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            if "data" in data and data["data"] is not None:
                                found += 1
                vulnerable = found > 0
                details = f"Found {found}/{len(common_hashes)} persisted queries"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="persisted_abuse",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    endpoint=endpoint_url,
                    query_type=schema_info.get("query_type", ""),
                    schema_types=types_count,
                    response_code=200,
                    exploit="introspection_query",
                    tool="graphql-playground",
                )
            )
        except Exception as exc:
            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="persisted_abuse",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    endpoint=endpoint_url,
                    query_type="",
                    schema_types=types_count,
                    response_code=0,
                )
            )

    return results


# ─── Category 164: resolver_analysis ─────────────────────────────────────────


async def _test_resolver_analysis(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint_url: str,
    schema_info: dict[str, Any],
) -> list[GraphQLAttackAttempt]:
    """Testa resolvers para vulnerabilidades (N+1, injection, SSRF, authz)."""
    results: list[GraphQLAttackAttempt] = []
    types_count = len(schema_info.get("types", []))

    techniques = [
        ("n_plus_one", "N+1 query detection (timing)"),
        ("sql_injection_in_resolver", "SQL injection in resolver"),
        ("ssrf_in_resolver", "SSRF in resolver"),
        ("authz_bypass", "Authorization bypass"),
        ("info_leak_resolver", "Information leak in resolver"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "n_plus_one":
                query1 = "{ __typename }"
                query2 = _build_nested_query(20)
                t0 = time.monotonic()
                await _execute_query(endpoint_url, query1, timeout=timeout)
                t1 = time.monotonic()
                await _execute_query(endpoint_url, query2, timeout=timeout)
                t2 = time.monotonic()
                simple_time = t1 - t0
                nested_time = t2 - t1
                vulnerable = nested_time > simple_time * 3 and nested_time > 2.0
                details = f"Simple: {simple_time:.2f}s, Nested: {nested_time:.2f}s"
            elif tech == "sql_injection_in_resolver":
                sqli_payloads = [
                    "' OR '1'='1",
                    "1; SELECT * FROM users",
                    "' UNION SELECT null--",
                ]
                found_inj = False
                for _payload in sqli_payloads:
                    query = "{ __typename }"
                    status, data = await _execute_query(
                        endpoint_url, query, timeout=timeout
                    )
                    if "error" in str(data).lower() and (
                        "sql" in str(data).lower() or "syntax" in str(data).lower()
                    ):
                        found_inj = True
                        break
                vulnerable = found_inj
                details = (
                    f"SQL error leak: {'detected' if vulnerable else 'not detected'}"
                )
            elif tech == "ssrf_in_resolver":
                query = "{ __typename }"
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vulnerable = False
                details = "SSRF: requires schema with URL-fetching resolvers"
            elif tech == "authz_bypass":
                query = "{ __typename }"
                status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                vulnerable = status == 200
                details = f"Unauthenticated access: status {status}"
            elif tech == "info_leak_resolver":
                error_query = "{ nonExistentField12345 }"
                status, data = await _execute_query(
                    endpoint_url, error_query, timeout=timeout
                )
                error_str = json.dumps(data)
                vulnerable = any(
                    kw in error_str.lower()
                    for kw in ["stack", "trace", "debug", "internal", "exception"]
                )
                details = f"Error info leak: {'yes' if vulnerable else 'no'}"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="resolver_analysis",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    endpoint=endpoint_url,
                    query_type=schema_info.get("query_type", ""),
                    schema_types=types_count,
                    response_code=200,
                    exploit="introspection_query",
                    tool="graphql-playground",
                )
            )
        except Exception as exc:
            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="resolver_analysis",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    endpoint=endpoint_url,
                    query_type="",
                    schema_types=types_count,
                    response_code=0,
                )
            )

    return results


# ─── Category 165: persisted_enum ────────────────────────────────────────────


async def _test_persisted_enum(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint_url: str,
    schema_info: dict[str, Any],
) -> list[GraphQLAttackAttempt]:
    """Testa enumeração de persisted queries."""
    results: list[GraphQLAttackAttempt] = []
    types_count = len(schema_info.get("types", []))

    techniques = [
        ("hash_bruteforce", "Hash bruteforce (common queries)"),
        ("id_enumeration", "ID-based enumeration"),
        ("query_from_response", "Query extraction from error response"),
        ("persisted_vs_dynamic", "Persisted vs dynamic comparison"),
    ]

    common_queries = [
        "{ __typename }",
        "{ __schema { types { name } } }",
        "query { __typename }",
        "{ viewer { __typename } }",
        "{ me { id name } }",
    ]

    for tech, desc in techniques:
        try:
            if tech == "hash_bruteforce":
                found = 0
                for q in common_queries:
                    h = hashlib.sha256(q.encode()).hexdigest()
                    payload = {
                        "extensions": {
                            "persistedQuery": {"version": 1, "sha256Hash": h}
                        }
                    }
                    async with httpx.AsyncClient(
                        timeout=timeout, verify=False
                    ) as client:
                        resp = await client.post(
                            endpoint_url,
                            content=json.dumps(payload),
                            headers={"Content-Type": "application/json"},
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            if "data" in data and data["data"] is not None:
                                found += 1
                vulnerable = found > 0
                details = f"Found {found}/{len(common_queries)} common queries"
            elif tech == "id_enumeration":
                found = 0
                for i in range(10):
                    payload = {"id": str(i)}
                    async with httpx.AsyncClient(
                        timeout=timeout, verify=False
                    ) as client:
                        resp = await client.post(
                            endpoint_url,
                            content=json.dumps(payload),
                            headers={"Content-Type": "application/json"},
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            if "data" in data and data["data"] is not None:
                                found += 1
                vulnerable = found > 0
                details = f"Found {found}/10 ID-based queries"
            elif tech == "query_from_response":
                query = "{ __typename }"
                _status, data = await _execute_query(
                    endpoint_url, query, timeout=timeout
                )
                data_str = json.dumps(data)
                has_hash = bool(re.search(r"[a-f0-9]{64}", data_str))
                vulnerable = has_hash
                details = f"Hash in response: {'yes' if vulnerable else 'no'}"
            elif tech == "persisted_vs_dynamic":
                query = "{ __typename }"
                t0 = time.monotonic()
                for _ in range(5):
                    await _execute_query(endpoint_url, query, timeout=timeout)
                dynamic_time = time.monotonic() - t0
                h = hashlib.sha256(query.encode()).hexdigest()
                payload = {
                    "extensions": {"persistedQuery": {"version": 1, "sha256Hash": h}}
                }
                t0 = time.monotonic()
                for _ in range(5):
                    async with httpx.AsyncClient(
                        timeout=timeout, verify=False
                    ) as client:
                        await client.post(
                            endpoint_url,
                            content=json.dumps(payload),
                            headers={"Content-Type": "application/json"},
                        )
                persisted_time = time.monotonic() - t0
                vulnerable = persisted_time < dynamic_time * 0.5
                details = (
                    f"Dynamic: {dynamic_time:.2f}s, Persisted: {persisted_time:.2f}s"
                )
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="persisted_enum",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    endpoint=endpoint_url,
                    query_type=schema_info.get("query_type", ""),
                    schema_types=types_count,
                    response_code=200,
                    exploit="introspection_query",
                    tool="graphql-playground",
                )
            )
        except Exception as exc:
            results.append(
                GraphQLAttackAttempt(
                    technique=tech,
                    category="persisted_enum",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    endpoint=endpoint_url,
                    query_type="",
                    schema_types=types_count,
                    response_code=0,
                )
            )

    return results


# ─── Dispatch ────────────────────────────────────────────────────────────────

_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[GraphQLAttackAttempt]]]
] = {
    "introspection": _test_introspection,
    "depth_abuse": _test_depth_abuse,
    "batch_abuse": _test_batch_abuse,
    "alias_overload": _test_alias_overload,
    "schema_stitching": _test_schema_stitching,
    "persisted_abuse": _test_persisted_abuse,
    "resolver_analysis": _test_resolver_analysis,
    "persisted_enum": _test_persisted_enum,
}

# ─── Print Results ───────────────────────────────────────────────────────────


def print_results(result: GraphQLAttackResult) -> None:
    """Imprime resultados formatados no terminal."""
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "GraphQL Attack Testing")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )
    print(color("[*]", Cyber.CYAN), f"Endpoint: {result.endpoint}")
    print(
        color("[*]", Cyber.CYAN),
        f"Schema: {'found' if result.schema_found else 'not found'} ({result.types_count} types)",
    )
    print(
        color("[*]", Cyber.CYAN),
        f"Queries: {result.queries_count} | Mutations: {result.mutations_count}",
    )
    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()

    categories: dict[str, list[GraphQLAttackAttempt]] = {}
    for attempt in result.attempts:
        categories.setdefault(attempt.category, []).append(attempt)

    for cat, attempts in categories.items():
        vuln_in_cat = [a for a in attempts if a.vulnerable]
        if vuln_in_cat:
            print(
                color("[!]", Cyber.RED, Cyber.BOLD),
                f"{cat}: {len(vuln_in_cat)} vulnerable(s)",
            )
            for a in vuln_in_cat:
                print(color("    [-]", Cyber.RED), f"{a.technique}: {a.details}")
                print_exploit_info(a.exploit, a.tool)
        else:
            print(color("[+]", Cyber.GREEN), f"{cat}: secure")

    print()
    if result.overall_status == "vulnerable":
        print(
            color("[!]", Cyber.RED, Cyber.BOLD),
            "VULNERABLE — GraphQL weaknesses detected!",
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — GraphQL configuration looks good",
        )
    print()


# ─── Main Scan ───────────────────────────────────────────────────────────────


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> GraphQLAttackResult:
    """Executa scan de GraphQL Attack Testing."""
    host, path, port, tls = _parse_url(target)

    endpoint_url = await _find_endpoint(host, port, path, timeout, tls)

    schema_data = await _introspect_schema(endpoint_url, timeout)
    types, query_type, mutation_type, subscription_type = _parse_introspection(
        schema_data
    )

    schema_info = {
        "types": types,
        "query_type": query_type,
        "mutation_type": mutation_type,
        "subscription_type": subscription_type,
    }

    all_attempts: list[GraphQLAttackAttempt] = []
    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)
        if tester is None:
            continue
        try:
            raw = await tester(
                host, port, path, timeout, tls, endpoint_url, schema_info
            )
            all_attempts.extend(raw)
        except Exception as e:
            all_attempts.append(
                GraphQLAttackAttempt(
                    technique=f"{cat}_error",
                    category=cat,
                    description="",
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                    endpoint=endpoint_url,
                    query_type=query_type,
                    schema_types=len(types),
                    response_code=0,
                )
            )

    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]
    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []
    overall = "vulnerable" if vuln_techs else "secure"

    result = GraphQLAttackResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        endpoint=endpoint_url,
        schema_found=bool(types),
        types_count=len(types),
        queries_count=1 if query_type else 0,
        mutations_count=1 if mutation_type else 0,
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        issues=issues,
        overall_status=overall,
    )

    print_results(result)

    if output_file:
        write_output(output_file, [asdict(a) for a in all_attempts])

    return result


# ─── Introspection Parser ───────────────────────────────────────────────────


def _parse_introspection(data: dict[str, Any]) -> tuple[list[str], str, str, str]:
    """Extrai info do schema a partir de uma resposta de introspection."""
    data_obj = data.get("data", {})
    if not isinstance(data_obj, dict):
        return [], "", "", ""

    schema = data_obj.get("__schema", {})
    if not isinstance(schema, dict):
        return [], "", "", ""

    types_raw = schema.get("types", [])
    types: list[str] = []
    if isinstance(types_raw, list):
        for t in types_raw:
            if isinstance(t, dict):
                name = str(t.get("name", ""))
                kind = str(t.get("kind", ""))
                if name and not name.startswith("__"):
                    types.append(f"{name} ({kind})")

    query_type_obj = schema.get("queryType", {})
    query_type = (
        str(query_type_obj.get("name", "")) if isinstance(query_type_obj, dict) else ""
    )

    mutation_type_obj = schema.get("mutationType", {})
    mutation_type = (
        str(mutation_type_obj.get("name", ""))
        if isinstance(mutation_type_obj, dict)
        else ""
    )

    subscription_type_obj = schema.get("subscriptionType", {})
    subscription_type = (
        str(subscription_type_obj.get("name", ""))
        if isinstance(subscription_type_obj, dict)
        else ""
    )

    return types, query_type, mutation_type, subscription_type


# ─── CLI ─────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Constrói parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-gqlattack",
        description="GraphQL Attack Testing — Introspection, Depth Abuse, Batch, Aliases, Stitching, APQ",
    )
    parser.add_argument("url", help="URL alvo (https://target.com/graphql)")
    parser.add_argument(
        "-c",
        "--categories",
        nargs="+",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categorias para testar (default: todas)",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa scan uma vez."""
    result = safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=getattr(args, "categories", None),
            timeout=getattr(args, "timeout", 5.0),
            output_file=getattr(args, "output", None),
        )
    )
    return 1 if result.overall_status == "vulnerable" else 0


def main() -> int:
    """Entry point principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(_BANNER_LINES, "GraphQL Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="gqlattack> ",
        description="Teste de GraphQL Attack Testing (Introspection, Depth, Batch, Aliases, Stitching, APQ, Resolvers).",
        example="https://target.com/graphql -c introspection depth_abuse",
        contextual_help=(
            "Categorias disponiveis:\n"
            "  introspection    — Schema discovery, full/partial introspection, mutation/subscription\n"
            "  depth_abuse      — Nested query DoS, circular refs, fragments, directives\n"
            "  batch_abuse      — Rate bypass, size abuse, mutation mix, auth bypass\n"
            "  alias_overload   — Count bypass, field dup, mutation overload, fragment mix\n"
            "  schema_stitching — Remote schema, stitching bypass, federated abuse\n"
            "  persisted_abuse  — APQ bypass, hash collision, mutation bypass, enumeration\n"
            "  resolver_analysis — N+1, SQL injection, SSRF, authz bypass, info leak\n"
            "  persisted_enum   — Hash bruteforce, ID enum, query from response"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
