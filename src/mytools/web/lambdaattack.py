#!/usr/bin/env python3
"""Lambda Attack Testing — AWS Lambda security probing via HTTP.

Testa seguranca de endpoints AWS Lambda:
  - Lambda: env_var_leak, layer_enumeration, temp_file_persistence
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import re
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any, cast
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

logger = logging.getLogger("mytools.lambdaattack")

_BANNER_LINES: str = (
    "  _                      _               _____ _              \n"
    " | |    ___   ___ __ _  / \\   _ __  __ _|  ___| | __ _ _ __  \n"
    " | |   / _ \\ / __/ _` |/ _ \\ | '__|/ _` | |_  | |/ _` | '__| \n"
    " | |__| (_) | (_| (_| / ___ \\| |  | (_| |  _| | | (_| | |    \n"
    " |_____\\___/ \\___\\__,_/_/   \\_\\_|   \\__,_|_|   |_|\\__,_|_|    \n"
)

_ENV_VAR_PATTERNS_DEFAULT: list[str] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_LAMBDA_",
    "SECRET_",
    "API_KEY",
    "DATABASE_URL",
    "CONNECTION_STRING",
    "PASSWORD",
    "TOKEN",
    "PRIVATE_KEY",
    "arn:aws:",
]


def _load_lambda_patterns() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "lambda_attack", default={"env_var_patterns": _ENV_VAR_PATTERNS_DEFAULT}
    )
    return data.get("env_var_patterns", _ENV_VAR_PATTERNS_DEFAULT)


_ENV_VAR_PATTERNS = _load_lambda_patterns()

_LAYER_ARN_PATTERN: re.Pattern[str] = re.compile(
    r"arn:aws:lambda:[a-z0-9-]+:\d{12}:layer:[a-zA-Z0-9_-]+:\d+"
)

_LAMBDA_ERROR_SIGNATURES_DEFAULT: list[str] = [
    "Traceback (most recent call last)",
    "RuntimeError",
    "Type error",
    "ImportError",
    "ModuleNotFoundError",
    "KeyError",
    "ValueError",
    "lambda_handler",
    "handler",
    "Task timed out after",
    "Process exited before completing",
    "END RequestId",
    "REPORT RequestId",
    "START RequestId",
    "X-Ray Trace-Id",
    "errorMessage",
    "errorType",
    "stackTrace",
    "/var/task/",
    "/opt/",
    "/var/runtime/",
    "/var/task",
    "Unable to import module",
]


def _load_lambda_error_signatures() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "lambda_attack",
        default={
            "env_var_patterns": _ENV_VAR_PATTERNS_DEFAULT,
            "error_signatures": _LAMBDA_ERROR_SIGNATURES_DEFAULT,
        },
    )
    raw = data.get("error_signatures", _LAMBDA_ERROR_SIGNATURES_DEFAULT)
    return raw if isinstance(raw, list) else _LAMBDA_ERROR_SIGNATURES_DEFAULT


_LAMBDA_ERROR_SIGNATURES = _load_lambda_error_signatures()


@dataclass(frozen=True, slots=True)
class LambdaAttackAttempt:
    technique: str
    category: str
    description: str
    vulnerable: bool
    details: str
    error: str
    endpoint: str
    response_code: int
    leaked_vars: list[str]
    leak_count: int
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class LambdaAttackResult:
    target: str
    host: str
    port: int
    tls: bool
    endpoint: str
    lambda_detected: bool
    attempts: list[LambdaAttackAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


_CATEGORY_MAP: dict[str, list[str]] = {
    "lambda": ["env_var_leak", "layer_enumeration", "temp_file_persistence"],
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
    code: int,
    leaked_vars: list[str] | None = None,
) -> LambdaAttackAttempt:
    return LambdaAttackAttempt(
        exploit="curl <TARGET>/api/endpoint",
        tool="curl",
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        endpoint=endpoint,
        response_code=code,
        leaked_vars=leaked_vars or [],
        leak_count=len(leaked_vars or []),
    )


def _extract_env_vars(body: str, headers: dict[str, str]) -> list[str]:
    found: list[str] = []
    combined = body + " ".join(f"{k}: {v}" for k, v in headers.items())
    for pattern in _ENV_VAR_PATTERNS:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        found.extend(matches)
    return list(set(found))


def _is_lambda_response(headers: dict[str, str], body: str) -> bool:
    for sig in ("x-amz-invocation-type", "x-amzn-requestid", "x-amz-executed-version"):
        if sig in {k.lower() for k in headers}:
            return True
    for sig in ("Lambda", "aws-lambda", "amzn"):
        if sig.lower() in headers.get("server", "").lower():
            return True
    return any(sig in body for sig in ("RequestId", "REPORT RequestId", "errorMessage"))


def _extract_error_details(body: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "raw": body[:2000],
        "has_traceback": False,
        "signatures_found": [],
    }
    for sig in _LAMBDA_ERROR_SIGNATURES:
        if sig.lower() in body.lower():
            result["signatures_found"].append(sig)
    result["has_traceback"] = "Traceback (most recent call last)" in body
    arn_matches = re.findall(
        r"arn:aws:[a-zA-Z0-9_-]+:[a-zA-Z0-9-]+:\d{12}:[a-zA-Z0-9_/-]+", body
    )
    if arn_matches:
        result["arns_found"] = arn_matches
    return result


async def _test_env_var_leak(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> LambdaAttackAttempt:
    all_leaked: list[str] = []
    payloads = [
        {"body": b"{invalid json", "desc": "Malformed JSON"},
        {"body": b'{"__proto__":{"admin":true}}', "desc": "Prototype pollution"},
        {"body": b"\x00\x01\x02", "desc": "Binary payload"},
        {"body": b'{"key":"' + b"A" * 10000 + b'"}', "desc": "Large payload"},
        {
            "body": b'{"event":{"body":"<script>alert(1)</script>"}}',
            "desc": "XSS in event",
        },
        {"body": b'{"body":"admin\' OR 1=1--"}', "desc": "SQL injection in event"},
        {
            "headers": {"Content-Type": "application/x-yaml"},
            "body": "test: value",
            "desc": "YAML content type",
        },
        {
            "headers": {"X-Amz-Invocation-Type": "RequestResponse"},
            "body": b"{}",
            "desc": "Lambda invocation header",
        },
        {
            "headers": {"X-Amz-Lambda-Function-Name": "test"},
            "body": b"{}",
            "desc": "Lambda function name header",
        },
        {
            "body": b'{"queryStringParameters":{"debug":"true","admin":"1"}}',
            "desc": "API Gateway debug params",
        },
    ]

    last_code = 0
    for payload in payloads:
        try:
            headers = cast(dict[str, str], payload.get("headers", {}))
            resp = await client.post(
                url, content=cast(bytes, payload["body"]), headers=headers
            )
            last_code = resp.status_code
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            leaked = _extract_env_vars(resp.text, resp_headers)
            all_leaked.extend(leaked)
            if _is_lambda_response(dict(resp.headers), resp.text):
                all_leaked.extend(_extract_env_vars(resp.text, resp_headers))
        except Exception:
            pass

    unique_leaked = list(set(all_leaked))
    vuln = len(unique_leaked) > 0
    details = (
        f"Leaked: {', '.join(unique_leaked[:5])}" if vuln else "No env vars detected"
    )
    return _make_attempt(
        "env_var_leak",
        "lambda",
        "Lambda env var leak via errors",
        vuln,
        details,
        "",
        url,
        last_code,
        unique_leaked,
    )


async def _test_layer_enumeration(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> LambdaAttackAttempt:
    layers_found: list[str] = []
    payloads = [
        {"body": b'{"body":"test"}', "desc": "Basic invoke"},
        {
            "body": b'{"httpMethod":"POST","path":"/","body":"{}"}',
            "desc": "API Gateway event",
        },
        {"body": b'{"Records":[]}', "desc": "S3 event"},
        {"body": b'{"detail-type":"Scheduled Event"}', "desc": "EventBridge event"},
    ]

    last_code = 0
    for payload in payloads:
        try:
            resp = await client.post(url, content=payload["body"])
            last_code = resp.status_code
            layer_matches = _LAYER_ARN_PATTERN.findall(resp.text)
            layers_found.extend(layer_matches)
            body_lower = resp.text.lower()
            layers_found.extend(
                keyword
                for keyword in ("/opt/", "layer", "layers", "/opt/lib/", "/opt/python/")
                if keyword in body_lower
            )
        except Exception:
            pass

    unique_layers = list(set(layers_found))
    vuln = len(unique_layers) > 0
    details = (
        f"Layers found: {len(unique_layers)} ({', '.join(unique_layers[:3])})"
        if vuln
        else "No layer info leaked"
    )
    return _make_attempt(
        "layer_enumeration",
        "lambda",
        "Lambda layer enumeration",
        vuln,
        details,
        "",
        url,
        last_code,
        unique_layers,
    )


async def _test_temp_file_persistence(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> LambdaAttackAttempt:
    marker = f"persistence_test_{uuid.uuid4().hex[:12]}"
    last_code = 0
    with contextlib.suppress(Exception):
        await client.post(url, content=f'{{"body":"create {marker}"}}'.encode())

    persist_signals: list[str] = []
    for _ in range(5):
        try:
            resp = await client.post(
                url, content=f'{{"body":"read {marker}"}}'.encode()
            )
            last_code = resp.status_code
            if marker in resp.text:
                persist_signals.append("marker_in_response")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            leaked = _extract_env_vars(resp.text, resp_headers)
            persist_signals.extend(f"leak:{v}" for v in leaked)
            err_details = _extract_error_details(resp.text)
            arns = err_details.get("arns_found", [])
            if arns:
                persist_signals.append(f"arns:{arns[0]}")
        except Exception:
            pass

    try:
        resp = await client.post(url, content=b'{"body":"list /tmp/"}')
        last_code = resp.status_code
        if "/tmp/" in resp.text or "tmp" in resp.text.lower():
            persist_signals.append("tmp_dir_reference")
    except Exception:
        pass

    unique_signals = list(set(persist_signals))
    vuln = len(unique_signals) > 0
    details = (
        f"Signals: {', '.join(unique_signals[:5])}"
        if vuln
        else "No persistence signals detected"
    )
    return _make_attempt(
        "temp_file_persistence",
        "lambda",
        "Lambda temp file persistence",
        vuln,
        details,
        "",
        url,
        last_code,
    )


TestCategoryMap = dict  # placeholder for test imports


async def _test_lambda(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
) -> list[LambdaAttackAttempt]:
    results: list[LambdaAttackAttempt] = []
    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True
    ) as client:
        for tech, fn in [
            ("env_var_leak", _test_env_var_leak),
            ("layer_enumeration", _test_layer_enumeration),
            ("temp_file_persistence", _test_temp_file_persistence),
        ]:
            try:
                result = await fn(endpoint, timeout, client)
                results.append(result)
            except Exception as exc:
                results.append(
                    _make_attempt(
                        tech, "lambda", "", False, "", str(exc)[:100], endpoint, 0
                    )
                )
    return results


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[LambdaAttackAttempt]]]
] = {
    "lambda": _test_lambda,
}


def print_results(result: LambdaAttackResult) -> None:
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Lambda Attack Testing")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )
    print(color("[*]", Cyber.CYAN), f"Endpoint: {result.endpoint}")
    print(
        color("[*]", Cyber.CYAN),
        f"Lambda detected: {'yes' if result.lambda_detected else 'no'}",
    )
    print()
    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()
    categories: dict[str, list[LambdaAttackAttempt]] = {}
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
            "VULNERABLE — Lambda weaknesses detected!",
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — Lambda configuration looks good",
        )
    print()


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> LambdaAttackResult:
    host, path, port, tls = _parse_url(target)
    scheme = "https" if tls else "http"
    endpoint = (
        f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    )
    if path:
        endpoint = endpoint.rstrip("/") + path
    lambda_detected = False
    all_attempts: list[LambdaAttackAttempt] = []
    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())
    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)
        if tester is None:
            continue
        try:
            raw = await tester(host, port, path, timeout, tls, endpoint)
            all_attempts.extend(raw)
            if any(a.leak_count > 0 or a.vulnerable for a in raw):
                lambda_detected = True
        except Exception as e:
            all_attempts.append(
                _make_attempt(
                    f"{cat}_error", cat, "", False, "", str(e)[:100], endpoint, 0
                )
            )
    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]
    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []
    overall = "vulnerable" if vuln_techs else "secure"
    result = LambdaAttackResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        endpoint=endpoint,
        lambda_detected=lambda_detected,
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
        prog="mytools-lambda",
        description="Lambda Attack Testing — AWS Lambda security probing via HTTP",
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
        banner_fn=create_banner(_BANNER_LINES, "Lambda Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="lambda> ",
        description="Lambda Attack Testing — AWS Lambda security probing via HTTP",
        example="mytools-lambda https://target.com/api/endpoint",
        contextual_help="lambda: env_var_leak, layer_enumeration, temp_file_persistence",
    )


if __name__ == "__main__":
    raise SystemExit(main())
