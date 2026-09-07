#!/usr/bin/env python3
"""Kubernetes Attack Testing — K8s API and Dashboard security probing.

Testa seguranca de endpoints Kubernetes:
  - Kubernetes: api_enumeration, dashboard_exposed
"""

from __future__ import annotations

import argparse
import logging
import re
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

logger = logging.getLogger("mytools.k8sattack")

_BANNER_LINES: str = (
    "                                    _   __  __           _     _       \n"
    "                                   | | |  \\/  |         | |   (_)      \n"
    "  _ __   __ _ _ __ __ _ _ __   __ _| | | \\  / | ___  ___| |__  _ _ __  \n"
    " | '_ \\ / _` | '__/ _` | '_ \\ / _` | | | |\\/| |/ _ \\/ __| '_ \\| | '_ \\ \n"
    " | | | | (_| | | | (_| | | | | (_| | | | |  | |  __/\\__ \\ | | | | |_) |\n"
    " |_| |_|\\__,_|_|  \\__,_|_| |_|\\__,_|_|_|_|  |_|\\___||___/_| |_|_| .__/ \n"
    "                                                                  | |    \n"
    "                                                                  |_|    \n"
)

_K8S_API_PATHS_DEFAULT: list[dict[str, Any]] = [
    {"path": "/version", "desc": "Version info"},
    {"path": "/healthz", "desc": "Health check"},
    {"path": "/readyz", "desc": "Readiness check"},
    {"path": "/livez", "desc": "Liveness check"},
    {"path": "/metrics", "desc": "Metrics endpoint"},
    {"path": "/api", "desc": "API versions"},
    {"path": "/api/v1", "desc": "Core API v1"},
    {"path": "/apis", "desc": "API groups"},
    {"path": "/api/v1/namespaces", "desc": "Namespaces"},
    {"path": "/api/v1/pods", "desc": "Pods"},
    {"path": "/api/v1/services", "desc": "Services"},
    {"path": "/api/v1/secrets", "desc": "Secrets"},
    {"path": "/api/v1/configmaps", "desc": "ConfigMaps"},
    {"path": "/api/v1/namespaces/default/pods", "desc": "Default namespace pods"},
    {"path": "/api/v1/namespaces/kube-system/pods", "desc": "kube-system pods"},
    {"path": "/apis/apps/v1/deployments", "desc": "Deployments"},
    {"path": "/apis/apps/v1/daemonsets", "desc": "DaemonSets"},
    {"path": "/apis/apps/v1/statefulsets", "desc": "StatefulSets"},
    {"path": "/apis/batch/v1/jobs", "desc": "Jobs"},
    {"path": "/apis/batch/v1/cronjobs", "desc": "CronJobs"},
    {"path": "/apis/networking.k8s.io/v1/networkpolicies", "desc": "NetworkPolicies"},
    {"path": "/apis/rbac.authorization.k8s.io/v1/clusterroles", "desc": "ClusterRoles"},
    {
        "path": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "desc": "ClusterRoleBindings",
    },
    {"path": "/apis/storage.k8s.io/v1/storageclasses", "desc": "StorageClasses"},
]


def _load_k8s_paths() -> list[dict[str, Any]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "k8s_attack", default={"api_paths": _K8S_API_PATHS_DEFAULT}
    )
    paths = data.get("api_paths", _K8S_API_PATHS_DEFAULT)
    return [{"path": p[0], "desc": p[1]} if isinstance(p, list) else p for p in paths]


_K8S_API_PATHS = _load_k8s_paths()

_DASHBOARD_PATHS_DEFAULT: list[dict[str, str]] = [
    {
        "path": "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
        "desc": "Dashboard via API proxy",
    },
    {
        "path": "/api/v1/namespaces/kubernetes-dashboard/services/http:kubernetes-dashboard:/proxy/",
        "desc": "Dashboard via API proxy (HTTP)",
    },
    {
        "path": "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/",
        "desc": "Dashboard in kube-system",
    },
    {"path": "/dashboard/", "desc": "Dashboard root"},
    {"path": "/dashboard/#/login", "desc": "Dashboard login"},
    {
        "path": "/api/v1/ namespaces/kubernetes-dashboard/endpoints",
        "desc": "Dashboard endpoints",
    },
    {
        "path": "/apis/dashboard.k8s.io/v1alpha1/namespaces/kubernetes-dashboard/dashboards",
        "desc": "Dashboard CRD",
    },
]

_K8S_AUTH_HEADERS_DEFAULT: list[dict[str, str]] = [
    {},
    {"Authorization": "Bearer "},
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
    {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"},
]

_K8S_SIGNATURES_DEFAULT: list[str] = [
    "kubectl",
    "kubernetes",
    "kube-",
    "apiserver",
    "etcd",
    "coredns",
    "kube-proxy",
    "kubelet",
    "X-Content-Type-Options",
    "X-Kubernetes-Api-Version",
]


def _load_k8s_extras() -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "k8s_attack",
        default={
            "dashboard_paths": _DASHBOARD_PATHS_DEFAULT,
            "auth_headers": _K8S_AUTH_HEADERS_DEFAULT,
            "signatures": _K8S_SIGNATURES_DEFAULT,
        },
    )
    dash = data.get("dashboard_paths", _DASHBOARD_PATHS_DEFAULT)
    auth = data.get("auth_headers", _K8S_AUTH_HEADERS_DEFAULT)
    sigs = data.get("signatures", _K8S_SIGNATURES_DEFAULT)
    return (
        [{"path": p[0], "desc": p[1]} if isinstance(p, list) else p for p in dash]
        if isinstance(dash, list)
        else _DASHBOARD_PATHS_DEFAULT,
        auth if isinstance(auth, list) else _K8S_AUTH_HEADERS_DEFAULT,
        sigs if isinstance(sigs, list) else _K8S_SIGNATURES_DEFAULT,
    )


_DASHBOARD_PATHS, _K8S_AUTH_HEADERS, _K8S_SIGNATURES = _load_k8s_extras()


@dataclass(frozen=True, slots=True)
class K8sAttackAttempt:
    technique: str
    category: str
    description: str
    vulnerable: bool
    details: str
    error: str
    endpoint: str
    api_version: str
    response_code: int
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class K8sAttackResult:
    target: str
    host: str
    port: int
    tls: bool
    endpoint: str
    k8s_detected: bool
    api_versions: list[str]
    attempts: list[K8sAttackAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


_CATEGORY_MAP: dict[str, list[str]] = {
    "kubernetes": ["api_enumeration", "dashboard_exposed"],
}


def _parse_url(target: str) -> tuple[str, str, int, bool]:
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.hostname or ""
    path = parsed.path or ""
    tls = parsed.scheme in ("https", "grpcs")
    default_port = 6443 if tls else 8080
    port = parsed.port or default_port
    return host, path, port, tls


def _detect_k8s(body: str, headers: dict[str, str]) -> bool:
    combined = body + " ".join(f"{k}: {v}" for k, v in headers.items())
    lower = combined.lower()
    return any(sig.lower() in lower for sig in _K8S_SIGNATURES)


def _extract_api_version(body: str) -> str:
    match = re.search(
        r'"serverAddressByClientCIDRs"|"major"|"minor"|"gitVersion"', body
    )
    if match:
        ver_match = re.search(r'"gitVersion"\s*:\s*"([^"]+)"', body)
        if ver_match:
            return ver_match.group(1)
        major = re.search(r'"major"\s*:\s*"(\d+)"', body)
        minor = re.search(r'"minor"\s*:\s*"(\d+)"', body)
        if major and minor:
            return f"v{major.group(1)}.{minor.group(1)}"
    return ""


def _make_attempt(
    tech: str,
    cat: str,
    desc: str,
    vuln: bool,
    details: str,
    error: str,
    endpoint: str,
    api_version: str,
    code: int,
) -> K8sAttackAttempt:
    return K8sAttackAttempt(
        exploit="kubectl get secrets --all-namespaces",
        tool="kubectl",
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        endpoint=endpoint,
        api_version=api_version,
        response_code=code,
    )


_K8S_PUBLIC_PATHS = frozenset({"/version", "/healthz", "/readyz", "/livez"})


async def _test_api_enumeration(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> K8sAttackAttempt:
    accessible_paths: list[str] = []
    public_paths: list[str] = []
    api_versions: list[str] = []
    last_code = 0

    for auth_headers in _K8S_AUTH_HEADERS:
        for endpoint_info in _K8S_API_PATHS:
            try:
                full_url = url.rstrip("/") + endpoint_info["path"]
                resp = await client.get(full_url, headers=auth_headers)
                last_code = resp.status_code
                if resp.status_code == 200:
                    if endpoint_info["path"] in _K8S_PUBLIC_PATHS:
                        public_paths.append(endpoint_info["path"])
                        continue
                    accessible_paths.append(endpoint_info["path"])
                    ver = _extract_api_version(resp.text)
                    if ver:
                        api_versions.append(ver)
                elif resp.status_code in (401, 403):
                    accessible_paths.append(f"{endpoint_info['path']} (auth_required)")
            except Exception:
                pass

    unique_paths = list(set(accessible_paths))
    vuln = len([p for p in unique_paths if "auth_required" not in p]) > 0
    details = (
        f"Accessible: {len(unique_paths)} paths"
        if unique_paths
        else "No accessible paths"
    )
    if public_paths:
        details += f" (public endpoints only: {len(set(public_paths))})"
    if api_versions:
        unique_versions = list(set(api_versions))
        details += f" (versions: {', '.join(unique_versions[:3])})"
    return _make_attempt(
        "api_enumeration",
        "kubernetes",
        "Kubernetes API enumeration",
        vuln,
        details,
        "",
        url,
        ",".join(set(api_versions)),
        last_code,
    )


async def _test_dashboard_exposed(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> K8sAttackAttempt:
    dashboard_found: list[str] = []
    last_code = 0

    for path_info in _DASHBOARD_PATHS:
        for auth_headers in _K8S_AUTH_HEADERS:
            try:
                full_url = url.rstrip("/") + path_info["path"]
                resp = await client.get(full_url, headers=auth_headers)
                last_code = resp.status_code
                if resp.status_code == 200:
                    lower = resp.text.lower()
                    if any(
                        kw in lower
                        for kw in ("dashboard", "kubernetes", "login", "token")
                    ):
                        dashboard_found.append(f"{path_info['desc']} (no auth)")
                elif resp.status_code in (401, 403):
                    dashboard_found.append(f"{path_info['desc']} (auth_required)")
            except Exception:
                pass

    unique = list(set(dashboard_found))
    no_auth = [d for d in unique if "no auth" in d]
    vuln = len(no_auth) > 0
    details = (
        f"Dashboard: {len(no_auth)} accessible without auth"
        if vuln
        else f"Dashboard: {len(unique)} endpoints found"
    )
    return _make_attempt(
        "dashboard_exposed",
        "kubernetes",
        "Kubernetes Dashboard exposed",
        vuln,
        details,
        "",
        url,
        "",
        last_code,
    )


async def _test_kubernetes(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
) -> list[K8sAttackAttempt]:
    results: list[K8sAttackAttempt] = []
    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True
    ) as client:
        for tech, fn in [
            ("api_enumeration", _test_api_enumeration),
            ("dashboard_exposed", _test_dashboard_exposed),
        ]:
            try:
                result = await fn(endpoint, timeout, client)
                results.append(result)
            except Exception as exc:
                results.append(
                    _make_attempt(
                        tech,
                        "kubernetes",
                        "",
                        False,
                        "",
                        str(exc)[:100],
                        endpoint,
                        "",
                        0,
                    )
                )
    return results


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[K8sAttackAttempt]]]
] = {
    "kubernetes": _test_kubernetes,
}


def print_results(result: K8sAttackResult) -> None:
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Kubernetes Attack Testing")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )
    print(color("[*]", Cyber.CYAN), f"Endpoint: {result.endpoint}")
    print(
        color("[*]", Cyber.CYAN),
        f"Kubernetes detected: {'yes' if result.k8s_detected else 'no'}",
    )
    if result.api_versions:
        print(
            color("[*]", Cyber.CYAN),
            f"API versions: {', '.join(result.api_versions[:3])}",
        )
    print()
    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()
    categories: dict[str, list[K8sAttackAttempt]] = {}
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
            "VULNERABLE — Kubernetes weaknesses detected!",
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — Kubernetes configuration looks good",
        )
    print()


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> K8sAttackResult:
    host, path, port, tls = _parse_url(target)
    scheme = "https" if tls else "http"
    endpoint = (
        f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    )
    if path:
        endpoint = endpoint.rstrip("/") + path
    k8s_detected = False
    all_api_versions: list[str] = []
    all_attempts: list[K8sAttackAttempt] = []
    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())
    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)
        if tester is None:
            continue
        try:
            raw = await tester(host, port, path, timeout, tls, endpoint)
            all_attempts.extend(raw)
            for a in raw:
                if a.vulnerable:
                    k8s_detected = True
                if a.api_version:
                    all_api_versions.append(a.api_version)
        except Exception as e:
            all_attempts.append(
                _make_attempt(
                    f"{cat}_error", cat, "", False, "", str(e)[:100], endpoint, "", 0
                )
            )
    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]
    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []
    overall = "vulnerable" if vuln_techs else "secure"
    result = K8sAttackResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        endpoint=endpoint,
        k8s_detected=k8s_detected,
        api_versions=list(set(all_api_versions)),
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
        prog="mytools-k8s",
        description="Kubernetes Attack Testing — API enumeration and Dashboard detection",
    )
    parser.add_argument("url", help="URL alvo (https://target.com:6443)")
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
        banner_fn=create_banner(_BANNER_LINES, "Kubernetes Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="k8s> ",
        description="Kubernetes Attack Testing — API enumeration and Dashboard detection",
        example="mytools-k8s https://target.com:6443",
        contextual_help="kubernetes: api_enumeration, dashboard_exposed",
    )


if __name__ == "__main__":
    raise SystemExit(main())
