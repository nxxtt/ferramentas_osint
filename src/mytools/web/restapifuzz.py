#!/usr/bin/env python3
"""Modulo de REST API Fuzzer.

Fuzzing generico de APIs REST testando:

  Auth Bypass:
    - Bearer token vazio/null/undefined
    - Headers X-Auth-Token, X-Api-Key vazios
    - X-Forwarded-For, X-Real-IP para bypass de IP restriction
    - Cookie manipulation (session vazia)

  Content-Type Switching:
    - JSON -> XML, form-urlencoded, text/plain
    - Charset fuzzing (UTF-7, UTF-16, ISO-8859-1)
    - Boundary injection em multipart

  Version Enumeration:
    - /v1, /v2, /v3, /api/v1, /api/v2
    - /v1.0, /v2.0, /beta, /latest, /draft
    - Numerical and date-based versions

  HATEOAS:
    - _method override (PUT, PATCH, DELETE)
    - X-HTTP-Method-Override headers
    - _format, format, output params
    - REST verb testing (PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE)

  Deteccao:
    - Status code anomalies (200 vs 401/403)
    - Response size anomalies
    - Content-type changes
"""

import argparse
import json
import logging
from collections.abc import Sequence
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
    print_exploit_info,
    print_json,
    run_concurrent,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.restapifuzz")

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

_OPENAPI_PROBE_PATHS_DEFAULT: list[str] = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/api/openapi.json",
]

_FALLBACK_ENDPOINTS_DEFAULT: list[str] = [
    "/api",
    "/users",
    "/products",
    "/orders",
    "/auth",
    "/login",
    "/register",
    "/search",
]

_AUTH_BEARER_TOKENS_DEFAULT: list[str] = [
    "",
    "null",
    "undefined",
    "false",
    "0",
    "admin",
    "test",
    "token",
    "Bearer ",
    "Bearer null",
    "Bearer undefined",
]

_AUTH_HEADERS_DEFAULT: list[tuple[str, str]] = [
    ("X-Auth-Token", ""),
    ("X-Auth-Token", "null"),
    ("X-Api-Key", ""),
    ("X-Api-Key", "null"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-For", "::1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
]

_AUTH_COOKIES_DEFAULT: list[tuple[str, str]] = [
    ("session", ""),
    ("session", "null"),
    ("token", ""),
    ("auth", ""),
    ("sid", ""),
]

_CONTENT_TYPE_SWITCH_DEFAULT: list[str] = [
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "application/json",
    "application/vnd.api+json",
    "application/hal+json",
    "application/ld+json",
]

_CONTENT_TYPE_CHARSET_DEFAULT: list[str] = [
    "application/json; charset=UTF-7",
    "application/json; charset=UTF-16",
    "application/json; charset=UTF-32",
    "application/json; charset=ISO-8859-1",
    "application/json; charset=Windows-1252",
]

_CONTENT_TYPE_BOUNDARY_DEFAULT: list[str] = [
    "------WebKitFormBoundary",
    "------=_Part_",
    "boundary=----",
    '"',
    "'",
    "\r\n\r\n",
    "%0d%0a%0d%0a",
]

_VERSION_PREFIXES_DEFAULT: list[str] = ["", "/api", "/v", "/api/v"]

_VERSIONS_DEFAULT: list[str] = [
    "1",
    "2",
    "3",
    "4",
    "5",
    "0",
    "1.0",
    "2.0",
    "beta",
    "latest",
    "stable",
    "draft",
]

_VERSION_SUFFIXES_DEFAULT: list[str] = ["", "/", ".json", ".xml"]

_HATEOAS_METHOD_OVERRIDE_DEFAULT: list[str] = [
    "_method",
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]

_HATEOAS_FORMAT_PARAMS_DEFAULT: list[str] = [
    "_format",
    "format",
    "output",
    "response_format",
]

_HATEOAS_REST_VERBS_DEFAULT: list[str] = [
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
    "TRACE",
    "CONNECT",
]


def _load_payloads() -> dict[str, object]:
    from mytools.data import load_payloads

    return load_payloads("web", "rest_api_fuzz", default={})


def _get_list(key: str, default: Sequence[object]) -> Sequence[object]:
    data = _load_payloads()
    raw = data.get(key, default)
    return list(raw) if isinstance(raw, list) else default


def _get_str_list(key: str, default: list[str]) -> list[str]:
    raw = _get_list(key, default)
    return [str(x) for x in raw]


def _get_tuple_list(key: str, default: list[tuple[str, str]]) -> list[tuple[str, str]]:
    raw = _get_list(key, default)
    result = [
        (str(item[0]), str(item[1]))
        for item in raw
        if isinstance(item, list) and len(item) >= 2
    ]
    return result if result else default


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RestFuzzAttempt:
    """Tentativa individual de fuzzing REST API."""

    technique: str
    category: str
    endpoint: str
    url: str
    payload: str
    method: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    content_type_changed: bool
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class RestFuzzResult:
    """Resultado consolidado do scan de REST API fuzzing."""

    target: str
    endpoints_tested: int
    baseline_status: int
    tls: bool
    attempts: list[RestFuzzAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


# ---------------------------------------------------------------------------
# Endpoint detection
# ---------------------------------------------------------------------------


async def _probe_openapi(
    client: httpx.AsyncClient,
    base_url: str,
) -> list[str] | None:
    """Tenta detectar endpoints via OpenAPI/Swagger spec."""
    probe_paths = _get_str_list("openapi_probe_paths", _OPENAPI_PROBE_PATHS_DEFAULT)

    for path in probe_paths:
        spec_url = f"{base_url.rstrip('/')}{path}"
        try:
            resp = await client.get(spec_url, follow_redirects=False)
            if resp.status_code != 200:
                continue
            content_type = resp.headers.get("content-type", "")
            if "json" not in content_type and not resp.content.strip().startswith(b"{"):
                continue
            spec = json.loads(resp.content)
            if not isinstance(spec, dict):
                continue
            paths = spec.get("paths")
            if not isinstance(paths, dict):
                continue
            endpoints = list(paths.keys())
            if endpoints:
                logger.info(
                    "OpenAPI spec encontrado em %s: %d endpoints", path, len(endpoints)
                )
                return endpoints
        except json.JSONDecodeError, httpx.RequestError:
            continue

    return None


async def _get_endpoints(
    client: httpx.AsyncClient | None,
    base_url: str,
    user_endpoints: list[str] | None,
) -> list[str]:
    """Retorna lista de endpoints para testar."""
    if user_endpoints:
        return user_endpoints
    if client is not None:
        detected = await _probe_openapi(client, base_url)
        if detected:
            return detected
    return list(_FALLBACK_ENDPOINTS_DEFAULT)


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


async def _test_endpoint_baseline(
    client: httpx.AsyncClient,
    url: str,
) -> tuple[int, int, str]:
    """Envia GET para endpoint e retorna (status, size, content_type)."""
    try:
        resp = await client.get(url, follow_redirects=False)
        ct = resp.headers.get("content-type", "")
        return resp.status_code, len(resp.content), ct
    except httpx.RequestError:
        return 0, 0, ""


# ---------------------------------------------------------------------------
# Auth Bypass testing
# ---------------------------------------------------------------------------


async def _test_auth_bypass(
    client: httpx.AsyncClient,
    endpoint: str,
    baseline: tuple[int, int, str],
) -> list[RestFuzzAttempt]:
    """Testa bypass de autenticacao em endpoint protegido."""
    attempts: list[RestFuzzAttempt] = []
    b_status, b_size, _b_ct = baseline
    base_url = str(client.base_url)
    url = f"{base_url.rstrip('/')}{endpoint}"

    if b_status not in (401, 403):
        return attempts

    bearer_tokens = _get_str_list("auth_bearer_tokens", _AUTH_BEARER_TOKENS_DEFAULT)
    for token in bearer_tokens:
        try:
            headers = {"Authorization": token} if token else {}
            resp = await client.get(url, headers=headers, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            vulnerable = t_status in (200, 201, 202, 204) and b_status in (401, 403)
            details = (
                f"Auth bypass: {b_status}->{t_status}"
                if vulnerable
                else f"Status {t_status}"
            )
            attempts.append(
                RestFuzzAttempt(
                    technique=f"bearer_{token or 'empty'}",
                    category="auth_bypass",
                    endpoint=endpoint,
                    url=url,
                    payload=f"Authorization: {token}",
                    method="GET",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    content_type_changed=False,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    exploit=f"curl -H 'Authorization: {token}' '{url}'"
                    if vulnerable
                    else "",
                    tool="curl" if vulnerable else "",
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                RestFuzzAttempt(
                    technique=f"bearer_{token or 'empty'}",
                    category="auth_bypass",
                    endpoint=endpoint,
                    url=url,
                    payload=f"Authorization: {token}",
                    method="GET",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    content_type_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    auth_headers = _get_tuple_list("auth_headers", _AUTH_HEADERS_DEFAULT)
    for hdr_name, hdr_value in auth_headers:
        try:
            resp = await client.get(
                url,
                headers={hdr_name: hdr_value},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            vulnerable = t_status in (200, 201, 202, 204) and b_status in (401, 403)
            details = (
                f"Auth bypass: {b_status}->{t_status}"
                if vulnerable
                else f"Status {t_status}"
            )
            attempts.append(
                RestFuzzAttempt(
                    technique=f"header_{hdr_name}",
                    category="auth_bypass",
                    endpoint=endpoint,
                    url=url,
                    payload=f"{hdr_name}: {hdr_value}",
                    method="GET",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    content_type_changed=False,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    exploit=f"curl -H '{hdr_name}: {hdr_value}' '{url}'"
                    if vulnerable
                    else "",
                    tool="curl" if vulnerable else "",
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                RestFuzzAttempt(
                    technique=f"header_{hdr_name}",
                    category="auth_bypass",
                    endpoint=endpoint,
                    url=url,
                    payload=f"{hdr_name}: {hdr_value}",
                    method="GET",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    content_type_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    auth_cookies = _get_tuple_list("auth_cookies", _AUTH_COOKIES_DEFAULT)
    for cookie_name, cookie_value in auth_cookies:
        try:
            resp = await client.get(
                url,
                cookies={cookie_name: cookie_value},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            vulnerable = t_status in (200, 201, 202, 204) and b_status in (401, 403)
            details = (
                f"Auth bypass: {b_status}->{t_status}"
                if vulnerable
                else f"Status {t_status}"
            )
            attempts.append(
                RestFuzzAttempt(
                    technique=f"cookie_{cookie_name}",
                    category="auth_bypass",
                    endpoint=endpoint,
                    url=url,
                    payload=f"Cookie: {cookie_name}={cookie_value}",
                    method="GET",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    content_type_changed=False,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    exploit=f"curl -b '{cookie_name}={cookie_value}' '{url}'"
                    if vulnerable
                    else "",
                    tool="curl" if vulnerable else "",
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                RestFuzzAttempt(
                    technique=f"cookie_{cookie_name}",
                    category="auth_bypass",
                    endpoint=endpoint,
                    url=url,
                    payload=f"Cookie: {cookie_name}={cookie_value}",
                    method="GET",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    content_type_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    return attempts


# ---------------------------------------------------------------------------
# Content-Type Switching testing
# ---------------------------------------------------------------------------


async def _test_content_type(
    client: httpx.AsyncClient,
    endpoint: str,
    baseline: tuple[int, int, str],
) -> list[RestFuzzAttempt]:
    """Testa content-type switching em endpoint."""
    attempts: list[RestFuzzAttempt] = []
    b_status, b_size, b_ct = baseline
    base_url = str(client.base_url)
    url = f"{base_url.rstrip('/')}{endpoint}"

    if b_status == 0:
        return attempts

    switch_types = _get_str_list("content_type_switch", _CONTENT_TYPE_SWITCH_DEFAULT)
    for ct in switch_types:
        try:
            if "xml" in ct:
                body = '<?xml version="1.0"?><root/>'
            elif "form-urlencoded" in ct:
                body = "test=1"
            elif "multipart" in ct:
                body = "test"
            else:
                body = '{"test":1}'

            resp = await client.post(
                url,
                content=body,
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            ct_changed = resp.headers.get("content-type", "") != b_ct
            vulnerable = t_status == 200 and b_status in (400, 415, 422)
            details = (
                f"Accepted {ct}: {b_status}->{t_status}"
                if vulnerable
                else f"Status {t_status}, CT changed: {ct_changed}"
            )
            attempts.append(
                RestFuzzAttempt(
                    technique=f"ct_switch_{ct.split('/')[1].split(';')[0]}",
                    category="content_type",
                    endpoint=endpoint,
                    url=url,
                    payload=ct,
                    method="POST",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    content_type_changed=ct_changed,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    exploit=f"curl -X POST -H 'Content-Type: {ct}' -d '{body[:50]}' '{url}'"
                    if vulnerable
                    else "",
                    tool="curl" if vulnerable else "",
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                RestFuzzAttempt(
                    technique=f"ct_switch_{ct.split('/')[1].split(';')[0]}",
                    category="content_type",
                    endpoint=endpoint,
                    url=url,
                    payload=ct,
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    content_type_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    charsets = _get_str_list("content_type_charset", _CONTENT_TYPE_CHARSET_DEFAULT)
    for ct in charsets:
        try:
            resp = await client.post(
                url,
                content='{"test":1}',
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            vulnerable = t_status == 200 and b_status in (400, 415, 422)
            details = (
                f"Charset accepted: {b_status}->{t_status}"
                if vulnerable
                else f"Status {t_status}"
            )
            attempts.append(
                RestFuzzAttempt(
                    technique=f"ct_charset_{ct.split('charset=')[1] if 'charset=' in ct else ct}",
                    category="content_type",
                    endpoint=endpoint,
                    url=url,
                    payload=ct,
                    method="POST",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    content_type_changed=False,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                RestFuzzAttempt(
                    technique=f"ct_charset_{ct.split('charset=')[1] if 'charset=' in ct else ct}",
                    category="content_type",
                    endpoint=endpoint,
                    url=url,
                    payload=ct,
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    content_type_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    boundaries = _get_str_list("content_type_boundary", _CONTENT_TYPE_BOUNDARY_DEFAULT)
    for boundary in boundaries:
        ct = f"multipart/form-data; boundary={boundary}"
        try:
            resp = await client.post(
                url,
                content=f"--{boundary}--",
                headers={"Content-Type": ct},
                follow_redirects=False,
            )
            t_status = resp.status_code
            t_size = len(resp.content)
            vulnerable = t_status == 200 and b_status in (400, 415, 422)
            details = (
                f"Boundary accepted: {b_status}->{t_status}"
                if vulnerable
                else f"Status {t_status}"
            )
            attempts.append(
                RestFuzzAttempt(
                    technique=f"ct_boundary_{boundary[:20]}",
                    category="content_type",
                    endpoint=endpoint,
                    url=url,
                    payload=ct,
                    method="POST",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    content_type_changed=False,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                RestFuzzAttempt(
                    technique=f"ct_boundary_{boundary[:20]}",
                    category="content_type",
                    endpoint=endpoint,
                    url=url,
                    payload=ct,
                    method="POST",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    content_type_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    return attempts


# ---------------------------------------------------------------------------
# Version Enumeration testing
# ---------------------------------------------------------------------------


async def _test_version_enum(
    client: httpx.AsyncClient,
    endpoint: str,
    base_url: str,
    baseline: tuple[int, int, str],
) -> list[RestFuzzAttempt]:
    """Testa enumeracao de versoes da API."""
    attempts: list[RestFuzzAttempt] = []
    b_status, b_size, _b_ct = baseline
    found = False

    prefixes = _get_str_list("version_prefixes", _VERSION_PREFIXES_DEFAULT)
    versions = _get_str_list("versions", _VERSIONS_DEFAULT)
    suffixes = _get_str_list("version_suffixes", _VERSION_SUFFIXES_DEFAULT)

    for prefix in prefixes:
        if found:
            break
        for version in versions:
            if found:
                break
            for suffix in suffixes:
                versioned = f"{prefix}{version}{suffix}"
                versioned_endpoint = f"{versioned}{endpoint}"
                url = f"{base_url.rstrip('/')}{versioned_endpoint}"
                try:
                    resp = await client.get(url, follow_redirects=False)
                    t_status = resp.status_code
                    t_size = len(resp.content)
                    vulnerable = t_status in (200, 201, 202, 204) and b_status in (
                        404,
                        405,
                    )
                    details = (
                        f"Version found: {versioned_endpoint} ({t_status})"
                        if vulnerable
                        else f"Status {t_status}"
                    )
                    if vulnerable:
                        found = True
                    attempts.append(
                        RestFuzzAttempt(
                            technique=f"version_{prefix}{version}{suffix}",
                            category="version_enum",
                            endpoint=versioned_endpoint,
                            url=url,
                            payload=versioned_endpoint,
                            method="GET",
                            status_baseline=b_status,
                            status_test=t_status,
                            size_baseline=b_size,
                            size_test=t_size,
                            content_type_changed=False,
                            vulnerable=vulnerable,
                            details=details,
                            error="",
                            exploit=f"curl '{url}'" if vulnerable else "",
                            tool="curl" if vulnerable else "",
                        )
                    )
                except httpx.RequestError as exc:
                    attempts.append(
                        RestFuzzAttempt(
                            technique=f"version_{prefix}{version}{suffix}",
                            category="version_enum",
                            endpoint=versioned_endpoint,
                            url=url,
                            payload=versioned_endpoint,
                            method="GET",
                            status_baseline=b_status,
                            status_test=0,
                            size_baseline=b_size,
                            size_test=0,
                            content_type_changed=False,
                            vulnerable=False,
                            details="",
                            error=str(exc),
                        )
                    )

    return attempts


# ---------------------------------------------------------------------------
# HATEOAS testing
# ---------------------------------------------------------------------------


async def _test_hateoas(
    client: httpx.AsyncClient,
    endpoint: str,
    baseline: tuple[int, int, str],
) -> list[RestFuzzAttempt]:
    """Testa HATEOAS e REST-specific manipulation."""
    attempts: list[RestFuzzAttempt] = []
    b_status, b_size, _b_ct = baseline
    base_url = str(client.base_url)
    url = f"{base_url.rstrip('/')}{endpoint}"

    if b_status == 0:
        return attempts

    method_overrides = _get_str_list(
        "hateoas_method_override",
        _HATEOAS_METHOD_OVERRIDE_DEFAULT,
    )
    for override_header in method_overrides:
        for method in ("PUT", "DELETE", "PATCH"):
            try:
                resp = await client.request(
                    method,
                    url,
                    headers={override_header: method},
                    follow_redirects=False,
                )
                t_status = resp.status_code
                t_size = len(resp.content)
                vulnerable = t_status in (200, 201, 202, 204) and b_status in (405, 404)
                details = (
                    f"Method override accepted: {override_header}={method}"
                    if vulnerable
                    else f"Status {t_status}"
                )
                attempts.append(
                    RestFuzzAttempt(
                        technique=f"hateoas_override_{override_header}",
                        category="hateoas",
                        endpoint=endpoint,
                        url=url,
                        payload=f"{override_header}: {method}",
                        method=method,
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        content_type_changed=False,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                        exploit=f"curl -X {method} -H '{override_header}: {method}' '{url}'"
                        if vulnerable
                        else "",
                        tool="curl" if vulnerable else "",
                    )
                )
            except httpx.RequestError as exc:
                attempts.append(
                    RestFuzzAttempt(
                        technique=f"hateoas_override_{override_header}",
                        category="hateoas",
                        endpoint=endpoint,
                        url=url,
                        payload=f"{override_header}: {method}",
                        method=method,
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        content_type_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    format_params = _get_str_list(
        "hateoas_format_params",
        _HATEOAS_FORMAT_PARAMS_DEFAULT,
    )
    for param in format_params:
        for fmt_value in ("json", "xml", "yaml", "csv", "text"):
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [fmt_value]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                resp = await client.get(test_url, follow_redirects=False)
                t_status = resp.status_code
                t_size = len(resp.content)
                ct_changed = resp.headers.get("content-type", "") != _b_ct
                vulnerable = ct_changed and t_status in (200, 201, 202, 204)
                details = (
                    f"Format param changed CT: {param}={fmt_value}"
                    if vulnerable
                    else f"Status {t_status}"
                )
                attempts.append(
                    RestFuzzAttempt(
                        technique=f"hateoas_format_{param}",
                        category="hateoas",
                        endpoint=endpoint,
                        url=test_url,
                        payload=f"{param}={fmt_value}",
                        method="GET",
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        content_type_changed=ct_changed,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                    )
                )
            except httpx.RequestError as exc:
                attempts.append(
                    RestFuzzAttempt(
                        technique=f"hateoas_format_{param}",
                        category="hateoas",
                        endpoint=endpoint,
                        url=url,
                        payload=f"{param}={fmt_value}",
                        method="GET",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        content_type_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    rest_verbs = _get_str_list("hateoas_rest_verbs", _HATEOAS_REST_VERBS_DEFAULT)
    for verb in rest_verbs:
        try:
            resp = await client.request(verb, url, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            vulnerable = t_status in (200, 201, 202, 204) and b_status in (405, 404)
            details = (
                f"Verb {verb} accepted: {b_status}->{t_status}"
                if vulnerable
                else f"Status {t_status}"
            )
            attempts.append(
                RestFuzzAttempt(
                    technique=f"hateoas_verb_{verb.lower()}",
                    category="hateoas",
                    endpoint=endpoint,
                    url=url,
                    payload=verb,
                    method=verb,
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    content_type_changed=False,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    exploit=f"curl -X {verb} '{url}'" if vulnerable else "",
                    tool="curl" if vulnerable else "",
                )
            )
        except httpx.RequestError as exc:
            attempts.append(
                RestFuzzAttempt(
                    technique=f"hateoas_verb_{verb.lower()}",
                    category="hateoas",
                    endpoint=endpoint,
                    url=url,
                    payload=verb,
                    method=verb,
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    content_type_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    return attempts


# ---------------------------------------------------------------------------
# run_scan — main scan function
# ---------------------------------------------------------------------------


async def run_scan(
    url: str,
    categories: list[str] | None = None,
    endpoints: list[str] | None = None,
    timeout: float = 10.0,
    concurrency: int = 5,
    output_file: str | None = None,
) -> RestFuzzResult:
    """Executa o scan de REST API fuzzing contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    cats = (
        ["auth_bypass", "content_type", "version_enum", "hateoas"]
        if not categories or categories == ["all"]
        else categories
    )

    async with create_async_client(
        user_agent="MyTools/restfuzz",
        timeout=timeout,
    ) as client:
        ep_list = await _get_endpoints(client, base_url, endpoints)

        all_attempts: list[RestFuzzAttempt] = []
        b_status = 0

        for endpoint in ep_list:
            ep_url = f"{base_url.rstrip('/')}{endpoint}"
            b_status, b_size, b_ct = await _test_endpoint_baseline(client, ep_url)
            baseline = (b_status, b_size, b_ct)

            if b_status == 0:
                logger.info("Endpoint %s inacessivel", endpoint)
                continue

            logger.info("Endpoint %s: baseline %d", endpoint, b_status)

            coros = []

            if "auth_bypass" in cats:
                coros.append(_test_auth_bypass(client, endpoint, baseline))
            if "content_type" in cats:
                coros.append(_test_content_type(client, endpoint, baseline))
            if "version_enum" in cats:
                coros.append(_test_version_enum(client, endpoint, base_url, baseline))
            if "hateoas" in cats:
                coros.append(_test_hateoas(client, endpoint, baseline))

            results = await run_concurrent(coros, concurrency)
            for r in results:
                if isinstance(r, list):
                    all_attempts.extend(r)

    vulnerable: list[str] = []
    issues: list[str] = []

    best: dict[str, RestFuzzAttempt] = {}
    for att in all_attempts:
        if att.technique not in best or (
            att.vulnerable and not best[att.technique].vulnerable
        ):
            best[att.technique] = att

    vulnerable = [att.technique for att in best.values() if att.vulnerable]

    if vulnerable:
        issues.append(f"{len(vulnerable)} tecnicas vulneraveis encontradas")

    overall = "vulnerable" if vulnerable else "secure"

    return RestFuzzResult(
        target=url,
        endpoints_tested=len(ep_list),
        baseline_status=b_status,
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=vulnerable,
        issues=issues,
        overall_status=overall,
    )


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


def print_results(result: RestFuzzResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  REST API FUZZER", Cyber.CYAN))
    print(color("=" * 60, Cyber.CYAN))
    print(color(f"  Target: {result.target}", Cyber.WHITE))
    print(color(f"  Endpoints: {result.endpoints_tested}", Cyber.GRAY))
    print(color(f"  TLS: {'Sim' if result.tls else 'Nao'}", Cyber.GRAY))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN
    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    if result.vulnerable_techniques:
        print(color("\n  [VULNERAVEL]", Cyber.RED))
        for tech in result.vulnerable_techniques:
            print(color(f"    - {tech}", Cyber.RED))
            a = next(
                (a for a in result.attempts if a.technique == tech and a.vulnerable),
                None,
            )
            if a:
                print(color(f"      Endpoint: {a.endpoint}", Cyber.GRAY))
                print(color(f"      Method: {a.method}", Cyber.GRAY))
                print(color(f"      Details: {a.details}", Cyber.GRAY))
                print_exploit_info(a.exploit, a.tool)

    categories = sorted({a.category for a in result.attempts})
    for cat in categories:
        cat_attempts = [a for a in result.attempts if a.category == cat]
        cat_vuln = [a for a in cat_attempts if a.vulnerable]
        if cat_vuln:
            print(
                color(
                    f"\n  [{cat.upper()}] {len(cat_vuln)}/{len(cat_attempts)} vulneraveis",
                    Cyber.YELLOW,
                )
            )

    if result.issues:
        print(color("\n  Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))

    print(color("=" * 60, Cyber.CYAN))


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

banner_art = create_banner(
    r"""
   _____ __  __ ____    ____  _______     __ ____  _____ __  __ ____    __  __ ______ _____
  |  __ \  \/  |  _ \  |  _ \| ____\ \   / /|  _ \| ____|  \/  |  _ \  |  \/  | ____| ____|
 | |__) | \  / | |_) | | | | |  _|  \ \ / / | |_) |  _| | |\/| | | | | | \  / |  _| |  _|
 |  ___/| |\/| |  __/  | |_| | |___  \ V /  |  __/| |___| |  | | |_| | | |\/| | |___| |___
 |_|    |_|  |_|_|     |____/|_____|  \_/   |_|   |_____|_|  |_|____/  |_|  |_|_____|_____|
    """,
    "REST API Fuzzer — auth bypass, content-type, version enum, HATEOAS",
)


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta parser CLI para mytools-restfuzz."""
    parser = argparse.ArgumentParser(
        prog="mytools-restfuzz",
        description="REST API Fuzzer — auth bypass, content-type switching, version enum, HATEOAS.",
    )
    parser.add_argument(
        "url", nargs="?", help="URL base da API (https://api.example.com)"
    )
    parser.add_argument(
        "-c",
        "--categories",
        nargs="+",
        choices=["auth_bypass", "content_type", "version_enum", "hateoas", "all"],
        default=["all"],
        help="Categorias para testar (default: all)",
    )
    parser.add_argument(
        "--endpoints",
        nargs="+",
        default=None,
        help="Endpoints para testar (default: auto-detect via /openapi.json)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Requisicoes simultaneas (default: 5)",
    )
    add_common_args(parser, "web")
    return parser


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan de REST API fuzzing a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("REST API Fuzzer iniciado para %s", args.url)

    categories = getattr(args, "categories", ["all"])
    if not categories:
        categories = ["all"]

    result = safe_asyncio_run(
        run_scan(
            url=args.url,
            categories=categories,
            endpoints=getattr(args, "endpoints", None),
            timeout=getattr(args, "timeout", 10.0),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
        ),
    )

    if getattr(args, "json_output", False):
        print_json(asdict(result))
    else:
        print_results(result)

    if getattr(args, "output", None):
        write_output(args.output, asdict(result))

    return 1 if result.overall_status != "secure" else 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="restfuzz> ",
        description="REST API Fuzzer interativo.",
        example="https://api.example.com -c auth_bypass hateoas",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://api.example.com\n"
            "  https://api.example.com -c auth_bypass\n"
            "  https://api.example.com -c content_type version_enum\n"
            "  https://api.example.com --endpoints /users /products\n"
            "  https://api.example.com -c hateoas --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
