#!/usr/bin/env python3

"""Serverless Attack Testing — Generic serverless security probing.



Testa seguranca generica de endpoints serverless:

  - Generic: cold_start_leak, timeout_abuse

"""

from __future__ import annotations

import argparse
import logging
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

logger = logging.getLogger("mytools.serverlessattack")

_BANNER_LINES: str = (
    "  ____                                    _ _              \n"
    " / ___|  ___ _ __ __ _ _ __  _ __   ___ | | |_ ___  _ __ \n"
    " \\___ \\ / __| '__/ _` | '_ \\| '_ \\ / _ \\| | __/ _ \\| '__|\n"
    "  ___) | (__| | | (_| | |_) | |_) | (_) | | || (_) | |   \n"
    " |____/ \\___|_|  \\__,_| .__/| .__/ \\___/|_|\\__\\___/|_|   \n"
    "                       |_|   |_|                         \n"
)


_COLD_START_INDICATORS_DEFAULT: list[str] = [
    "X-Cache",
    "X-Cold-Start",
    "X-Startup-Time",
    "X-Lambda-Initialization",
    "X-Init-Duration",
    "X-Request-Start",
    "Server-Timing",
    "X-Response-Time",
    "X-Processing-Time",
    "X-Execution-Start",
    "X-Amz-Executed-Version",
    "X-Amz-Invocation-Type",
    "x-amz-cold-start",
]


def _load_cold_start_indicators() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "serverless_attack",
        default={"cold_start_indicators": _COLD_START_INDICATORS_DEFAULT},
    )
    return data.get("cold_start_indicators", _COLD_START_INDICATORS_DEFAULT)


_COLD_START_INDICATORS = _load_cold_start_indicators()


_COLD_START_BODY_SIGNATURES_DEFAULT: list[str] = [
    "cold start",
    "coldstart",
    "initialization",
    "init duration",
    "runtime init",
    "starting",
    "warming",
    "warmup",
    "first request",
]


def _load_cold_start_body_signatures() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "serverless_attack",
        default={
            "cold_start_indicators": _COLD_START_INDICATORS_DEFAULT,
            "cold_start_body_signatures": _COLD_START_BODY_SIGNATURES_DEFAULT,
        },
    )
    raw = data.get("cold_start_body_signatures", _COLD_START_BODY_SIGNATURES_DEFAULT)
    return raw if isinstance(raw, list) else _COLD_START_BODY_SIGNATURES_DEFAULT


_COLD_START_BODY_SIGNATURES = _load_cold_start_body_signatures()


_TIMEOUT_PATTERNS: list[str] = [
    "Task timed out after",
    "Timeout",
    "timed out",
    "deadline exceeded",
    "FUNCTION_INVOCATION_TIMEOUT",
    "UNIMPLEMENTED",
    "Connection reset",
    "upstream request timeout",
    "504 Gateway Timeout",
    "502 Bad Gateway",
    "503 Service Unavailable",
    "worker timed out",
    "exceeded time limit",
    "request timeout",
]


@dataclass(frozen=True, slots=True)
class ServerlessAttackAttempt:
    technique: str

    category: str

    description: str

    vulnerable: bool

    details: str

    error: str

    endpoint: str

    response_code: int

    timing_ms: float

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class ServerlessAttackResult:
    target: str

    host: str

    port: int

    tls: bool

    endpoint: str

    techniques_count: int

    attempts: list[ServerlessAttackAttempt]

    vulnerable_techniques: list[str]

    issues: list[str]

    overall_status: str


_CATEGORY_MAP: dict[str, list[str]] = {
    "generic": ["cold_start_leak", "timeout_abuse"],
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
    timing_ms: float = 0.0,
) -> ServerlessAttackAttempt:

    return ServerlessAttackAttempt(
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        endpoint=endpoint,
        response_code=code,
        timing_ms=timing_ms,
        exploit="cold_start_abuse_payload" if vuln else "",
        tool="curl",
    )


def _measure_timing(response_time: float) -> float:

    return response_time * 1000


async def _test_cold_start_leak(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> ServerlessAttackAttempt:

    leak_signals: list[str] = []

    timings: list[float] = []

    for i in range(8):
        try:
            start = time.monotonic()

            resp = await client.get(url)

            elapsed_ms = _measure_timing(time.monotonic() - start)

            timings.append(elapsed_ms)

            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            leak_signals.extend(
                f"header:{indicator}"
                for indicator in _COLD_START_INDICATORS
                if indicator.lower() in resp_headers
            )

            body_lower = resp.text.lower()

            leak_signals.extend(
                f"body:{sig}"
                for sig in _COLD_START_BODY_SIGNATURES
                if sig in body_lower
            )

            if timings[-1] > 3000 and i == 0:
                leak_signals.append("slow_first_request")

        except Exception:
            pass

    if len(timings) >= 2:
        first = timings[0]

        avg_rest = sum(timings[1:]) / len(timings[1:]) if len(timings) > 1 else 0

        if first > avg_rest * 2 and first > 1000:
            leak_signals.append(f"timing_diff:{first:.0f}ms_vs_{avg_rest:.0f}ms")

    unique = list(set(leak_signals))

    avg_ms = sum(timings) / len(timings) if timings else 0

    vuln = len(unique) > 0

    details = (
        f"Signals: {', '.join(unique[:5])} (avg {avg_ms:.0f}ms)"
        if vuln
        else f"No cold start signals (avg {avg_ms:.0f}ms)"
    )

    return _make_attempt(
        "cold_start_leak",
        "generic",
        "Serverless cold start info leak",
        vuln,
        details,
        "",
        url,
        200,
        avg_ms,
    )


async def _test_timeout_abuse(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> ServerlessAttackAttempt:

    timeout_signals: list[str] = []

    payloads = [
        (b'{"sleep":30}', "30s sleep request"),
        (b'{"loop":"infinite","iterations":999999}', "Infinite loop"),
        (b"\x00" * (1024 * 1024), "1MB payload"),
        (b'{"recursive":true,"depth":10000}', "Deep recursion"),
        (b'{"file":"../../dev/urandom","size":1048576}', "File read attempt"),
        (b'{"fork":true,"count":100}', "Fork bomb"),
    ]

    last_code = 0

    total_time = 0.0

    for payload, desc in payloads:
        try:
            start = time.monotonic()

            resp = await client.post(url, content=payload)

            elapsed = time.monotonic() - start

            total_time += elapsed

            last_code = resp.status_code

            body_lower = resp.text.lower()

            timeout_signals.extend(
                f"timeout_msg:{pattern}"
                for pattern in _TIMEOUT_PATTERNS
                if pattern.lower() in body_lower
            )

            if resp.status_code in (502, 503, 504):
                timeout_signals.append(f"status:{resp.status_code}")

            if elapsed > 10:
                timeout_signals.append(f"slow_response:{elapsed:.1f}s")

        except httpx.TimeoutException:
            timeout_signals.append(f"client_timeout:{desc}")

        except Exception:
            timeout_signals.append(f"connection_error:{desc}")

    try:
        start = time.monotonic()

        resp = await client.post(
            url,
            content=b'{"stream":true}',
            headers={"Transfer-Encoding": "chunked", "Content-Length": "0"},
        )

        elapsed = time.monotonic() - start

        if elapsed > 5:
            timeout_signals.append(f"chunked_slow:{elapsed:.1f}s")

    except Exception:
        pass

    unique = list(set(timeout_signals))

    vuln = len(unique) > 0

    details = (
        f"Timeout signals: {', '.join(unique[:5])} (total: {total_time:.1f}s)"
        if vuln
        else f"No timeout abuse signals (total: {total_time:.1f}s)"
    )

    return _make_attempt(
        "timeout_abuse",
        "generic",
        "Serverless timeout resource abuse",
        vuln,
        details,
        "",
        url,
        last_code,
        total_time * 1000,
    )


async def _test_generic(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
) -> list[ServerlessAttackAttempt]:

    results: list[ServerlessAttackAttempt] = []

    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True
    ) as client:
        for tech, fn in [
            ("cold_start_leak", _test_cold_start_leak),
            ("timeout_abuse", _test_timeout_abuse),
        ]:
            try:
                result = await fn(endpoint, timeout, client)

                results.append(result)

            except Exception as exc:
                results.append(
                    _make_attempt(
                        tech, "generic", "", False, "", str(exc)[:100], endpoint, 0
                    )
                )

    return results


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[ServerlessAttackAttempt]]]
] = {
    "generic": _test_generic,
}


def print_results(result: ServerlessAttackResult) -> None:

    print()

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Serverless Attack Testing")

    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")

    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )

    print(color("[*]", Cyber.CYAN), f"Endpoint: {result.endpoint}")

    print(color("[*]", Cyber.CYAN), f"Techniques: {result.techniques_count}")

    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")

        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)

        print()

    categories: dict[str, list[ServerlessAttackAttempt]] = {}

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
            "VULNERABLE — Serverless weaknesses detected!",
        )

    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — Serverless configuration looks good",
        )

    print()


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> ServerlessAttackResult:

    host, path, port, tls = _parse_url(target)

    scheme = "https" if tls else "http"

    endpoint = (
        f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    )

    if path:
        endpoint = endpoint.rstrip("/") + path

    all_attempts: list[ServerlessAttackAttempt] = []

    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)

        if tester is None:
            continue

        try:
            raw = await tester(host, port, path, timeout, tls, endpoint)

            all_attempts.extend(raw)

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

    result = ServerlessAttackResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        endpoint=endpoint,
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
        prog="mytools-serverless",
        description="Serverless Attack Testing — Generic serverless security probing",
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
        banner_fn=create_banner(_BANNER_LINES, "Serverless Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="serverless> ",
        description="Serverless Attack Testing — Generic serverless security probing",
        example="mytools-serverless https://target.com/api/endpoint",
        contextual_help="generic: cold_start_leak, timeout_abuse",
    )


if __name__ == "__main__":
    raise SystemExit(main())
