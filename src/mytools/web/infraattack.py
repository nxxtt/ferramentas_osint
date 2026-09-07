#!/usr/bin/env python3
"""Infrastructure Attack Testing — Cloud and infrastructure security probing.

Testa seguranca de infraestrutura:
  - Infrastructure: terraform_state_leak, vault_exposed, cicd_pipeline_leak,
    cicd_secret_detection, elastic_exposed, redis_mongo_unauth,
    debug_endpoints, debug_mode_detection
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import socket
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

logger = logging.getLogger("mytools.infraattack")

_BANNER_LINES: str = (
    "  ___           _                       _ _              \n"
    " |_ _|_ __   __| | ___  _ __   ___  __| (_)_ __   __ _ \n"
    "  | || '_ \\ / _` |/ _ \\| '_ \\ / _ \\/ _` | | '_ \\ / _` |\n"
    "  | || | | | (_| | (_) | | | |  __/ (_| | | | | | (_| |\n"
    " |___|_| |_|\\__,_|\\___/|_| |_|\\___|\\__,_|_|_| |_|\\__, |\n"
    "                                                   |___/ \n"
)

_TERRAFORM_STATE_PATHS_DEFAULT: list[str] = [
    "/terraform.tfstate",
    "/env/terraform.tfstate",
    "/prod/terraform.tfstate",
    "/staging/terraform.tfstate",
    "/dev/terraform.tfstate",
    "/infra/terraform.tfstate",
    "/infrastructure/terraform.tfstate",
    "/tf/terraform.tfstate",
    "/tfstate/terraform.tfstate",
    "/.terraform/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/env/terraform.tfstate.backup",
    "/prod/terraform.tfstate.backup",
]


def _load_terraform_paths() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "infra_attack",
        default={"terraform_state_paths": _TERRAFORM_STATE_PATHS_DEFAULT},
    )
    return data.get("terraform_state_paths", _TERRAFORM_STATE_PATHS_DEFAULT)


_TERRAFORM_STATE_PATHS = _load_terraform_paths()

_TERRAFORM_SECRET_PATTERNS: list[str] = [
    r"aws_access_key_id",
    r"aws_secret_access_key",
    r"password",
    r"secret_key",
    r"private_key",
    r"api_key",
    r"access_token",
    r"connection_string",
    r"database_url",
    r"arn:aws:",
]

_VAULT_PATHS: list[dict[str, str]] = [
    {"path": "/v1/sys/health", "desc": "Vault health"},
    {"path": "/v1/sys/seal-status", "desc": "Seal status"},
    {"path": "/v1/sys/auth", "desc": "Auth methods"},
    {"path": "/v1/sys/mounts", "desc": "Secret engines"},
    {"path": "/v1/auth/token/lookup", "desc": "Token lookup"},
    {"path": "/v1/secret/", "desc": "Secret engine root"},
    {"path": "/v1/cubbyhole/", "desc": "Cubbyhole"},
    {"path": "/v1/identity/entity", "desc": "Identity entity"},
]

_CICD_PATHS_DEFAULT: list[dict[str, str]] = [
    {"path": "/.gitlab-ci.yml", "desc": "GitLab CI"},
    {"path": "/Jenkinsfile", "desc": "Jenkins"},
    {"path": "/.github/workflows/", "desc": "GitHub Actions"},
    {"path": "/.github/workflows/ci.yml", "desc": "GitHub Actions CI"},
    {"path": "/.github/workflows/main.yml", "desc": "GitHub Actions Main"},
    {"path": "/.circleci/config.yml", "desc": "CircleCI"},
    {"path": "/azure-pipelines.yml", "desc": "Azure Pipelines"},
    {"path": "/bitbucket-pipelines.yml", "desc": "Bitbucket Pipelines"},
    {"path": "/.travis.yml", "desc": "Travis CI"},
    {"path": "/appveyor.yml", "desc": "AppVeyor"},
    {"path": "/buildkite.yml", "desc": "Buildkite"},
    {"path": "/cloudbuild.yaml", "desc": "Google Cloud Build"},
]

_SECRET_PATTERNS: list[str] = [
    r"(?i)password\s*[=:]\s*['\"]?([^\s'\"]+)",
    r"(?i)secret\s*[=:]\s*['\"]?([^\s'\"]+)",
    r"(?i)token\s*[=:]\s*['\"]?([^\s'\"]+)",
    r"(?i)api_key\s*[=:]\s*['\"]?([^\s'\"]+)",
    r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([^\s'\"]+)",
    r"(?i)private_key\s*[=:]\s*['\"]?([^\s'\"]+)",
    r"(?i)access_token\s*[=:]\s*['\"]?([^\s'\"]+)",
    r"(?i)client_secret\s*[=:]\s*['\"]?([^\s'\"]+)",
    r"(?i)database_url\s*[=:]\s*['\"]?([^\s'\"]+)",
    r"(?i)connection_string\s*[=:]\s*['\"]?([^\s'\"]+)",
]

_ELASTIC_PATHS: list[dict[str, str]] = [
    {"path": "/_cluster/health", "desc": "Cluster health"},
    {"path": "/_cat/indices", "desc": "Index listing"},
    {"path": "/_cat/nodes", "desc": "Node listing"},
    {"path": "/_cat/shards", "desc": "Shard listing"},
    {"path": "/_all", "desc": "All indices"},
    {"path": "/_mapping", "desc": "Index mappings"},
    {"path": "/_nodes", "desc": "Node info"},
    {"path": "/_stats", "desc": "Cluster stats"},
]

_KIBANA_PATHS: list[dict[str, str]] = [
    {"path": "/app/kibana", "desc": "Kibana app"},
    {"path": "/app/discover", "desc": "Kibana discover"},
    {"path": "/app/management", "desc": "/app/management"},
    {"path": "/app/dev_tools", "desc": "Dev tools"},
    {"path": "/app/visualize", "desc": "Visualize"},
    {"path": "/app/dashboard", "desc": "Dashboard"},
    {"path": "/status", "desc": "Kibana status"},
    {"path": "/api/status", "desc": "Kibana API status"},
]

_DEBUG_PATHS_DEFAULT: list[dict[str, str]] = [
    {"path": "/debug/", "desc": "Debug root"},
    {"path": "/debug/vars", "desc": "Debug vars (Go)"},
    {"path": "/debug/pprof/", "desc": "Go pprof"},
    {"path": "/debug/pprof/goroutine?debug=1", "desc": "Go goroutines"},
    {"path": "/actuator", "desc": "Spring Boot Actuator"},
    {"path": "/actuator/health", "desc": "Actuator health"},
    {"path": "/actuator/env", "desc": "Actuator env"},
    {"path": "/actuator/beans", "desc": "Actuator beans"},
    {"path": "/actuator/configprops", "desc": "Actuator config props"},
    {"path": "/actuator/mappings", "desc": "Actuator mappings"},
    {"path": "/console", "desc": "Console"},
    {"path": "/adminer", "desc": "Adminer"},
    {"path": "/phpmyadmin", "desc": "phpMyAdmin"},
    {"path": "/pma", "desc": "phpMyAdmin alt"},
    {"path": "/mysql", "desc": "MySQL admin"},
    {"path": "/_debug/", "desc": "Django debug"},
    {"path": "/__debug__/", "desc": "Django debug toolbar"},
]


def _load_infra_payloads() -> dict[str, object]:
    from mytools.data import load_payloads

    return load_payloads(
        "web",
        "infra_attack",
        default={
            "cicd_paths": _CICD_PATHS_DEFAULT,
            "debug_paths": _DEBUG_PATHS_DEFAULT,
        },
    )


def _load_infra_paths(key: str, default: list[dict[str, str]]) -> list[dict[str, str]]:
    raw = _load_infra_payloads().get(key, default)
    if not isinstance(raw, list):
        return default
    return [{"path": p[0], "desc": p[1]} if isinstance(p, list) else p for p in raw]


_CICD_PATHS = _load_infra_paths("cicd_paths", _CICD_PATHS_DEFAULT)
_DEBUG_PATHS = _load_infra_paths("debug_paths", _DEBUG_PATHS_DEFAULT)

_DEBUG_MODE_SIGNATURES: list[dict[str, str]] = [
    {"pattern": r"X-Debug-Toolbar", "desc": "Django Debug Toolbar"},
    {"pattern": r"X-Generated-By", "desc": "Generated header"},
    {"pattern": r"X-Debug-Token", "desc": "Symfony debug"},
    {"pattern": r"X-Debug-Token-Link", "desc": "Symfony profiler"},
    {"pattern": r"debugger", "desc": "Flask debugger"},
    {"pattern": r"Traceback \(most recent call last\)", "desc": "Python traceback"},
    {"pattern": r"DEBUG\s*=\s*True", "desc": "Django DEBUG=True"},
    {"pattern": r"app\.debug\s*=\s*True", "desc": "Flask debug mode"},
    {"pattern": r"ASP\.NET", "desc": "ASP.NET"},
    {"pattern": r"elmah\.axd", "desc": "ELMAH error log"},
    {"pattern": r"trace\.axd", "desc": "ASP.NET trace"},
    {"pattern": r"WebException", "desc": "ASP.NET exception"},
]


@dataclass(frozen=True, slots=True)
class InfraAttackAttempt:
    technique: str
    category: str
    description: str
    vulnerable: bool
    details: str
    error: str
    endpoint: str
    service_type: str
    response_code: int
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class InfraAttackResult:
    target: str
    host: str
    port: int
    tls: bool
    endpoint: str
    service_detected: str
    techniques_count: int
    attempts: list[InfraAttackAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


_CATEGORY_MAP: dict[str, list[str]] = {
    "infrastructure": [
        "terraform_state_leak",
        "vault_exposed",
        "cicd_pipeline_leak",
        "cicd_secret_detection",
        "elastic_exposed",
        "redis_mongo_unauth",
        "debug_endpoints",
        "debug_mode_detection",
    ],
}


def _parse_url(target: str) -> tuple[str, str, int, bool]:
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.hostname or ""
    path = parsed.path or ""
    tls = parsed.scheme in ("https", "grpcs")
    default_port = 443 if tls else 80
    port = parsed.port or default_port
    return host, path, port, tls


def _make_attempt(
    tech: str,
    cat: str,
    desc: str,
    vuln: bool,
    details: str,
    error: str,
    endpoint: str,
    service_type: str,
    code: int,
) -> InfraAttackAttempt:
    return InfraAttackAttempt(
        exploit="curl <TARGET>:9200/_cat/indices",
        tool="curl",
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        endpoint=endpoint,
        service_type=service_type,
        response_code=code,
    )


def _extract_secrets(body: str) -> list[str]:
    found: list[str] = [
        f"{pattern.split('(')[0].split('(?i)')[-1].strip()}: {match[:20]}..."
        for pattern in _SECRET_PATTERNS
        for match in re.findall(pattern, body)
        if len(match) > 3 and match not in ("true", "false", "null", "undefined", "xxx")
    ]
    return list(set(found))


async def _test_terraform_state_leak(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> InfraAttackAttempt:
    leaked_files: list[str] = []
    secrets_found: list[str] = []
    last_code = 0

    for state_path in _TERRAFORM_STATE_PATHS:
        try:
            full_url = url.rstrip("/") + state_path
            resp = await client.get(full_url)
            last_code = resp.status_code
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if (
                        "resources" in data
                        or "terraform_version" in data
                        or "serial" in data
                    ):
                        leaked_files.append(state_path)
                        body = json.dumps(data)
                        secrets_found.extend(
                            pattern
                            for pattern in _TERRAFORM_SECRET_PATTERNS
                            if re.search(pattern, body, re.IGNORECASE)
                        )
                except json.JSONDecodeError, ValueError:
                    if "terraform" in resp.text.lower():
                        leaked_files.append(state_path)
        except Exception:
            pass

    unique_secrets = list(set(secrets_found))
    vuln = len(leaked_files) > 0
    details = f"Files: {len(leaked_files)}"
    if unique_secrets:
        details += f", Secrets: {', '.join(unique_secrets[:5])}"
    return _make_attempt(
        "terraform_state_leak",
        "infrastructure",
        "Terraform state file leak",
        vuln,
        details,
        "",
        url,
        "terraform",
        last_code,
    )


async def _test_vault_exposed(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> InfraAttackAttempt:
    accessible: list[str] = []
    last_code = 0
    vault_detected = False

    for path_info in _VAULT_PATHS:
        try:
            full_url = url.rstrip("/") + path_info["path"]
            resp = await client.get(full_url)
            last_code = resp.status_code
            if resp.status_code in (200, 400, 404):
                vault_detected = True
                if resp.status_code == 200:
                    accessible.append(path_info["desc"])
            lower = resp.text.lower()
            if "vault" in lower or "sealed" in lower:
                vault_detected = True
        except Exception:
            pass

    vuln = vault_detected and len(accessible) > 0
    details = f"Vault: {'detected' if vault_detected else 'not found'}"
    if accessible:
        details += f", {len(accessible)} accessible ({', '.join(accessible[:3])})"
    return _make_attempt(
        "vault_exposed",
        "infrastructure",
        "HashiCorp Vault exposed",
        vuln,
        details,
        "",
        url,
        "vault",
        last_code,
    )


async def _test_cicd_pipeline_leak(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> InfraAttackAttempt:
    found_pipelines: list[str] = []
    last_code = 0

    for path_info in _CICD_PATHS:
        try:
            full_url = url.rstrip("/") + path_info["path"]
            resp = await client.get(full_url)
            last_code = resp.status_code
            if resp.status_code == 200 and len(resp.text) > 10:
                lower = resp.text.lower()
                keywords = (
                    "stages:",
                    "jobs:",
                    "pipeline",
                    "script:",
                    "image:",
                    "services:",
                    "before_script:",
                    "deploy:",
                    "build:",
                )
                if any(kw in lower for kw in keywords):
                    found_pipelines.append(path_info["desc"])
        except Exception:
            pass

    vuln = len(found_pipelines) > 0
    details = (
        f"Pipelines: {', '.join(found_pipelines[:5])}"
        if vuln
        else "No exposed pipelines"
    )
    return _make_attempt(
        "cicd_pipeline_leak",
        "infrastructure",
        "CI/CD pipeline file leak",
        vuln,
        details,
        "",
        url,
        "cicd",
        last_code,
    )


async def _test_cicd_secret_detection(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> InfraAttackAttempt:
    secrets_per_pipeline: dict[str, list[str]] = {}
    last_code = 0

    for path_info in _CICD_PATHS:
        try:
            full_url = url.rstrip("/") + path_info["path"]
            resp = await client.get(full_url)
            last_code = resp.status_code
            if resp.status_code == 200:
                secrets = _extract_secrets(resp.text)
                if secrets:
                    secrets_per_pipeline[path_info["desc"]] = secrets
        except Exception:
            pass

    all_secrets: list[str] = []
    for pipeline, secrets in secrets_per_pipeline.items():
        all_secrets.extend(f"{pipeline}:{s}" for s in secrets)

    vuln = len(all_secrets) > 0
    details = (
        f"Secrets: {len(all_secrets)} found" if vuln else "No secrets in pipelines"
    )
    if all_secrets:
        details += f" ({', '.join(all_secrets[:5])})"
    return _make_attempt(
        "cicd_secret_detection",
        "infrastructure",
        "CI/CD secret detection",
        vuln,
        details,
        "",
        url,
        "cicd",
        last_code,
    )


async def _test_elastic_exposed(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> InfraAttackAttempt:
    accessible: list[str] = []
    last_code = 0
    elastic_detected = False

    for path_info in _ELASTIC_PATHS:
        try:
            full_url = url.rstrip("/") + path_info["path"]
            resp = await client.get(full_url)
            last_code = resp.status_code
            if resp.status_code == 200:
                elastic_detected = True
                accessible.append(path_info["desc"])
        except Exception:
            pass

    for path_info in _KIBANA_PATHS:
        try:
            full_url = url.rstrip("/") + path_info["path"]
            resp = await client.get(full_url)
            last_code = resp.status_code
            if resp.status_code == 200:
                accessible.append(f"Kibana: {path_info['desc']}")
        except Exception:
            pass

    vuln = elastic_detected and len(accessible) > 0
    details = f"Elastic/Kibana: {'detected' if elastic_detected else 'not found'}"
    if accessible:
        details += f", {len(accessible)} accessible ({', '.join(accessible[:3])})"
    return _make_attempt(
        "elastic_exposed",
        "infrastructure",
        "Elastic/Kibana exposed",
        vuln,
        details,
        "",
        url,
        "elastic",
        last_code,
    )


async def _test_redis_mongo_unauth(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> InfraAttackAttempt:
    services_found: list[str] = []
    last_code = 0
    host = urlparse(url).hostname or ""

    redis_port = 6379
    mongo_port = 27017

    for svc_port, svc_name, probe in [
        (redis_port, "Redis", b"INFO\r\n"),
        (mongo_port, "MongoDB", b'{"isMaster":1}\r\n'),
    ]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(timeout, 3.0))
            result = sock.connect_ex((host, svc_port))
            if result == 0:
                try:
                    sock.send(probe)
                    response = sock.recv(1024)
                    response_str = response.decode("utf-8", errors="ignore").lower()
                    if svc_name == "Redis" and (
                        "redis_version" in response_str
                        or "connected_clients" in response_str
                    ):
                        services_found.append(f"Redis:{svc_port}")
                    elif svc_name == "MongoDB" and (
                        "ismaster" in response_str or "ok" in response_str
                    ):
                        services_found.append(f"MongoDB:{svc_port}")
                except Exception:
                    pass
            sock.close()
        except Exception:
            pass

    vuln = len(services_found) > 0
    details = (
        f"Unauth services: {', '.join(services_found)}"
        if vuln
        else "No unauth Redis/MongoDB found"
    )
    return _make_attempt(
        "redis_mongo_unauth",
        "infrastructure",
        "Redis/MongoDB unauth access",
        vuln,
        details,
        "",
        url,
        "database",
        last_code,
    )


async def _test_debug_endpoints(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> InfraAttackAttempt:
    found_endpoints: list[str] = []
    last_code = 0

    for path_info in _DEBUG_PATHS:
        try:
            full_url = url.rstrip("/") + path_info["path"]
            resp = await client.get(full_url)
            last_code = resp.status_code
            if resp.status_code == 200 and len(resp.text) > 50:
                lower = resp.text.lower()
                if any(
                    kw in lower
                    for kw in (
                        "debug",
                        "actuator",
                        "adminer",
                        "phpmyadmin",
                        "pprof",
                        "console",
                        "stack",
                        "trace",
                    )
                ):
                    found_endpoints.append(path_info["desc"])
        except Exception:
            pass

    vuln = len(found_endpoints) > 0
    details = (
        f"Debug endpoints: {', '.join(found_endpoints[:5])}"
        if vuln
        else "No exposed debug endpoints"
    )
    return _make_attempt(
        "debug_endpoints",
        "infrastructure",
        "Exposed debug endpoints",
        vuln,
        details,
        "",
        url,
        "debug",
        last_code,
    )


async def _test_debug_mode_detection(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> InfraAttackAttempt:
    detected_modes: list[str] = []
    last_code = 0

    try:
        resp = await client.get(url)
        last_code = resp.status_code
        headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
        combined = resp.text + " " + headers_str

        detected_modes.extend(
            sig_info["desc"]
            for sig_info in _DEBUG_MODE_SIGNATURES
            if re.search(sig_info["pattern"], combined, re.IGNORECASE)
        )
    except Exception:
        pass

    debug_paths = ["/debug", "/debug/", "/__debug__/", "/actuator", "/actuator/env"]
    for path in debug_paths:
        try:
            full_url = url.rstrip("/") + path
            resp = await client.get(full_url)
            if resp.status_code == 200:
                detected_modes.extend(
                    f"{sig_info['desc']} ({path})"
                    for sig_info in _DEBUG_MODE_SIGNATURES
                    if re.search(sig_info["pattern"], resp.text, re.IGNORECASE)
                )
        except Exception:
            pass

    unique = list(set(detected_modes))
    vuln = len(unique) > 0
    details = (
        f"Debug modes: {', '.join(unique[:5])}" if vuln else "No debug mode detected"
    )
    return _make_attempt(
        "debug_mode_detection",
        "infrastructure",
        "Debug mode detection",
        vuln,
        details,
        "",
        url,
        "debug",
        last_code,
    )


async def _test_infrastructure(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
) -> list[InfraAttackAttempt]:
    results: list[InfraAttackAttempt] = []
    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True
    ) as client:
        for tech, fn in [
            ("terraform_state_leak", _test_terraform_state_leak),
            ("vault_exposed", _test_vault_exposed),
            ("cicd_pipeline_leak", _test_cicd_pipeline_leak),
            ("cicd_secret_detection", _test_cicd_secret_detection),
            ("elastic_exposed", _test_elastic_exposed),
            ("redis_mongo_unauth", _test_redis_mongo_unauth),
            ("debug_endpoints", _test_debug_endpoints),
            ("debug_mode_detection", _test_debug_mode_detection),
        ]:
            try:
                result = await fn(endpoint, timeout, client)
                results.append(result)
            except Exception as exc:
                results.append(
                    _make_attempt(
                        tech,
                        "infrastructure",
                        "",
                        False,
                        "",
                        str(exc)[:100],
                        endpoint,
                        "unknown",
                        0,
                    )
                )
    return results


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[InfraAttackAttempt]]]
] = {
    "infrastructure": _test_infrastructure,
}


def print_results(result: InfraAttackResult) -> None:
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Infrastructure Attack Testing")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )
    print(color("[*]", Cyber.CYAN), f"Endpoint: {result.endpoint}")
    print(color("[*]", Cyber.CYAN), f"Service: {result.service_detected}")
    print(color("[*]", Cyber.CYAN), f"Techniques: {result.techniques_count}")
    print()
    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()
    categories: dict[str, list[InfraAttackAttempt]] = {}
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
            "VULNERABLE — Infrastructure weaknesses detected!",
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — Infrastructure configuration looks good",
        )
    print()


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> InfraAttackResult:
    host, path, port, tls = _parse_url(target)
    scheme = "https" if tls else "http"
    endpoint = (
        f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    )
    if path:
        endpoint = endpoint.rstrip("/") + path
    service_detected = "unknown"
    all_attempts: list[InfraAttackAttempt] = []
    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())
    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)
        if tester is None:
            continue
        try:
            raw = await tester(host, port, path, timeout, tls, endpoint)
            all_attempts.extend(raw)
            services = [a.service_type for a in raw if a.service_type != "unknown"]
            if services:
                service_detected = max(set(services), key=services.count)
        except Exception as e:
            all_attempts.append(
                _make_attempt(
                    f"{cat}_error",
                    cat,
                    "",
                    False,
                    "",
                    str(e)[:100],
                    endpoint,
                    "unknown",
                    0,
                )
            )
    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]
    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []
    overall = "vulnerable" if vuln_techs else "secure"
    result = InfraAttackResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        endpoint=endpoint,
        service_detected=service_detected,
        techniques_count=len(all_attempts),
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        issues=issues,
        overall_status=overall,
    )
    print_results(result)
    if output_file:
        write_output(output_file, [asdict(a) for a in all_attempts])
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mytools-infra",
        description="Infrastructure Attack Testing — Terraform, Vault, CI/CD, Elastic, Redis/MongoDB, Debug",
    )
    parser.add_argument("url", help="URL alvo (https://target.com)")
    parser.add_argument(
        "-c",
        "--categories",
        nargs="+",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categorias para testar",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
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
    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(_BANNER_LINES, "Infrastructure Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="infra> ",
        description="Infrastructure Attack Testing — Terraform, Vault, CI/CD, Elastic, Redis/MongoDB, Debug",
        example="mytools-infra https://target.com",
        contextual_help="infrastructure: terraform_state_leak, vault_exposed, cicd_pipeline_leak, cicd_secret_detection, elastic_exposed, redis_mongo_unauth, debug_endpoints, debug_mode_detection",
    )


if __name__ == "__main__":
    raise SystemExit(main())
