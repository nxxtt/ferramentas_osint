#!/usr/bin/env python3

"""Timing Attack Testing — Detecção de timing side-channels.



Testa vulnerabilidades de timing em aplicações web:

  - Login: inferir usuário existente via timing de respostas

  - Token: comparar tokens com timing variável (byte-by-byte)

  - Cache: inferir conteúdo servido do cache via timing

  - DNS: inferir informações via tempo de resolução DNS



Timing attacks exploram diferenças sutis de tempo para

inferir informações que não deveriam estar acessíveis.

"""

from __future__ import annotations

import argparse
import contextlib
import logging
import statistics
import time
from dataclasses import asdict, dataclass

import dns.exception
import dns.name
import dns.resolver
import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.timingattack")

_BANNER_LINES: str = (
    "  _____ _                    _   _  __ _          _ _ \n"
    " |_   _| |__  _ __ ___  __ _| |_| |/ _(_)_ __ __| | |\n"
    "   | | | '_ \\| '__/ _ \\/ _` | __| | |_| | '__/ _` | |\n"
    "   | | | | | | | |  __/ (_| | |_| |  _| | | | (_| | |\n"
    "   |_| |_| |_|_|  \\___|\\__,_|\\__|_| |_| |_|  \\__,_|_|\n"
)


_CATEGORY_MAP: dict[str, list[str]] = {
    "timing": [
        "login_timing",
        "token_timing",
        "cache_timing",
        "dns_timing",
    ],
}


@dataclass(frozen=True, slots=True)
class TimingAttempt:
    technique: str

    category: str

    description: str

    vulnerable: bool

    details: str

    error: str

    endpoint: str

    timing_ms: float

    threshold_ms: float

    samples: int

    stdev_ms: float

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class TimingResult:
    target: str

    url: str

    attempts: list[TimingAttempt]

    vulnerable_techniques: list[str]

    issues: list[str]

    overall_status: str


def _make_attempt(
    tech: str,
    cat: str,
    desc: str,
    vuln: bool,
    details: str,
    error: str,
    endpoint: str,
    timing: float,
    threshold: float,
    samples: int,
    stdev: float,
    exploit: str = "",
    tool: str = "",
) -> TimingAttempt:
    return TimingAttempt(
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        endpoint=endpoint,
        timing_ms=round(timing, 2),
        threshold_ms=round(threshold, 2),
        samples=samples,
        stdev_ms=round(stdev, 2),
        exploit=exploit,
        tool=tool,
    )


async def _measure_login_timing(
    client: httpx.AsyncClient,
    url: str,
    usernames: list[str],
    delay: float,
    timeout: float,
) -> TimingAttempt:

    times: dict[str, list[float]] = {}

    for user in usernames:
        timings: list[float] = []

        for _ in range(3):
            payload = f"username={user}&password=wrongpass123"

            start = time.monotonic()

            try:
                resp = await client.post(
                    url,
                    content=payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=timeout,
                    follow_redirects=False,
                )

                _ = resp.status_code

            except httpx.TimeoutException:
                pass

            except httpx.RequestError:
                pass

            elapsed = (time.monotonic() - start) * 1000

            timings.append(elapsed)

            if delay > 0:
                import asyncio

                await asyncio.sleep(delay)

        times[user] = timings

    user_means: dict[str, float] = {}

    for user, t in times.items():
        if t:  # pragma: no cover
            user_means[user] = statistics.mean(t)

    if len(user_means) < 2:
        return _make_attempt(
            "login_timing",
            "timing",
            "Login timing user enumeration",
            False,
            "Insufficient data",
            "",
            url,
            0,
            50,
            0,
            0,
        )

    sorted_users = sorted(user_means.items(), key=lambda x: x[1])

    fastest = sorted_users[0][1]

    slowest = sorted_users[-1][1]

    diff = slowest - fastest

    global_stdev = 0.0

    all_times_flat = [t for ts in times.values() for t in ts]

    if len(all_times_flat) > 1:  # pragma: no cover
        global_stdev = statistics.stdev(all_times_flat)

    vuln = diff > 50

    details = f"Timing diff: {diff:.1f}ms"

    if vuln:
        details += f" (fastest: {sorted_users[0][0]}={fastest:.1f}ms, slowest: {sorted_users[-1][0]}={slowest:.1f}ms)"

    return _make_attempt(
        "login_timing",
        "timing",
        "Login timing user enumeration",
        vuln,
        details,
        "",
        url,
        diff,
        50,
        len(all_times_flat),
        global_stdev,
        exploit="hydra -L users.txt -P pass.txt <TARGET> -t 1" if vuln else "",
        tool="hydra",
    )


async def _measure_token_timing(
    client: httpx.AsyncClient,
    url: str,
    token: str,
    delay: float,
    timeout: float,
) -> TimingAttempt:

    char_times: dict[int, list[float]] = {}

    for pos in range(min(len(token), 16)):
        timings: list[float] = []

        for _ in range(3):
            payload = token[:pos] + chr((ord(token[pos]) + 1) % 128) + token[pos + 1 :]

            start = time.monotonic()

            try:
                resp = await client.get(
                    f"{url}?token={payload}",
                    timeout=timeout,
                    follow_redirects=False,
                )

                _ = resp.status_code

            except httpx.TimeoutException, httpx.RequestError:
                pass

            elapsed = (time.monotonic() - start) * 1000

            timings.append(elapsed)

            if delay > 0:
                import asyncio

                await asyncio.sleep(delay)

        char_times[pos] = timings

    pos_means: list[float] = []

    pos_means = [
        statistics.mean(char_times[pos])
        for pos in sorted(char_times.keys())
        if char_times[pos]
    ]

    if len(pos_means) < 2:
        return _make_attempt(
            "token_timing",
            "timing",
            "Token comparison timing",
            False,
            "Insufficient data",
            "",
            url,
            0,
            10,
            0,
            0,
        )

    stdev_val = statistics.stdev(pos_means) if len(pos_means) > 1 else 0

    max_diff = max(pos_means) - min(pos_means)

    vuln = stdev_val > 10

    details = f"Position timing stdev: {stdev_val:.2f}ms"

    if vuln:
        details += f" (range: {min(pos_means):.1f}ms - {max(pos_means):.1f}ms)"

    return _make_attempt(
        "token_timing",
        "timing",
        "Token comparison timing",
        vuln,
        details,
        "",
        url,
        max_diff,
        10,
        len(pos_means) * 3,
        stdev_val,
        exploit="jwt_tool <token> -C -d wordlist.txt" if vuln else "",
        tool="hydra",
    )


async def _measure_cache_timing(
    client: httpx.AsyncClient,
    url: str,
    rounds: int,
    delay: float,
    timeout: float,
) -> TimingAttempt:

    first_times: list[float] = []

    cached_times: list[float] = []

    for _ in range(rounds):
        try:
            start = time.monotonic()

            await client.get(url, timeout=timeout, follow_redirects=True)

            elapsed1 = (time.monotonic() - start) * 1000

            first_times.append(elapsed1)

        except httpx.TimeoutException, httpx.RequestError:
            pass

        if delay > 0:
            import asyncio

            await asyncio.sleep(delay)

        try:
            start = time.monotonic()

            await client.get(url, timeout=timeout, follow_redirects=True)

            elapsed2 = (time.monotonic() - start) * 1000

            cached_times.append(elapsed2)

        except httpx.TimeoutException, httpx.RequestError:
            pass

        if delay > 0:
            import asyncio

            await asyncio.sleep(delay)

    if not first_times or not cached_times:
        return _make_attempt(
            "cache_timing",
            "timing",
            "Cache timing detection",
            False,
            "No responses received",
            "",
            url,
            0,
            0,
            0,
            0,
        )

    first_mean = statistics.mean(first_times)

    cached_mean = statistics.mean(cached_times)

    speedup = first_mean - cached_mean

    stdev_val = statistics.stdev(cached_times) if len(cached_times) > 1 else 0

    has_cache_headers = False

    cache_control = ""

    try:
        resp = await client.get(url, timeout=timeout, follow_redirects=True)

        cache_control = resp.headers.get("cache-control", "")

        etag = resp.headers.get("etag", "")

        last_modified = resp.headers.get("last-modified", "")

        has_cache_headers = bool(cache_control or etag or last_modified)

    except httpx.TimeoutException, httpx.RequestError:
        pass

    vuln = speedup > 20 and has_cache_headers

    details = (
        f"First: {first_mean:.1f}ms, Cached: {cached_mean:.1f}ms, Diff: {speedup:.1f}ms"
    )

    if vuln:
        details += f", Cache-Control: {cache_control}"

    return _make_attempt(
        "cache_timing",
        "timing",
        "Cache timing detection",
        vuln,
        details,
        "",
        url,
        speedup,
        20,
        len(first_times) + len(cached_times),
        stdev_val,
        exploit="curl -H 'Cache-Control: no-cache' <TARGET>" if vuln else "",
        tool="hydra",
    )


async def _measure_dns_timing(
    domains: list[str],
    timeout: float,
) -> TimingAttempt:

    resolver = dns.resolver.Resolver()

    resolver.timeout = timeout

    resolver.lifetime = timeout

    domain_times: dict[str, list[float]] = {}

    for domain in domains:
        timings: list[float] = []

        for _ in range(3):
            start = time.monotonic()

            with contextlib.suppress(
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                dns.exception.DNSException,
            ):
                resolver.resolve(domain, "A")

            elapsed = (time.monotonic() - start) * 1000

            timings.append(elapsed)

        domain_times[domain] = timings

    all_means: list[float] = []

    domain_means: dict[str, float] = {}

    for domain, t in domain_times.items():
        if t:  # pragma: no cover
            m = statistics.mean(t)

            domain_means[domain] = m

            all_means.append(m)

    if len(all_means) < 2:
        return _make_attempt(
            "dns_timing",
            "timing",
            "DNS timing analysis",
            False,
            "Insufficient data",
            "",
            "",
            0,
            0,
            0,
            0,
        )

    global_stdev = statistics.stdev(all_means) if len(all_means) > 1 else 0

    max_diff = max(all_means) - min(all_means)

    sorted_d = sorted(domain_means.items(), key=lambda x: x[1])

    vuln = global_stdev > 50

    details = f"DNS timing stdev: {global_stdev:.1f}ms"

    if vuln:
        details += f" (fastest: {sorted_d[0][0]}={sorted_d[0][1]:.1f}ms, slowest: {sorted_d[-1][0]}={sorted_d[-1][1]:.1f}ms)"

    return _make_attempt(
        "dns_timing",
        "timing",
        "DNS timing analysis",
        vuln,
        details,
        "",
        "",
        max_diff,
        50,
        len(all_means) * 3,
        global_stdev,
        exploit="dnscat2 <TARGET>" if vuln else "",
        tool="hydra",
    )


async def _test_timing(
    url: str,
    timeout: float,
    delay: float,
    usernames: list[str] | None,
    token: str | None,
    cache_rounds: int,
    dns_domains: list[str] | None,
) -> list[TimingAttempt]:

    results: list[TimingAttempt] = []

    async with create_async_client(timeout=timeout) as client:
        try:
            login_url = f"{url}/login" if not url.endswith("/login") else url

            result = await _measure_login_timing(
                client,
                login_url,
                usernames or ["admin", "root", "user", "test"],
                delay,
                timeout,
            )

            results.append(result)

        except Exception as exc:
            results.append(
                _make_attempt(
                    "login_timing",
                    "timing",
                    "",
                    False,
                    "",
                    str(exc)[:100],
                    url,
                    0,
                    50,
                    0,
                    0,
                )
            )

        try:
            result = await _measure_token_timing(
                client,
                url,
                token or "abcdefgh12345678",
                delay,
                timeout,
            )

            results.append(result)

        except Exception as exc:
            results.append(
                _make_attempt(
                    "token_timing",
                    "timing",
                    "",
                    False,
                    "",
                    str(exc)[:100],
                    url,
                    0,
                    10,
                    0,
                    0,
                )
            )

        try:
            result = await _measure_cache_timing(
                client,
                url,
                cache_rounds,
                delay,
                timeout,
            )

            results.append(result)

        except Exception as exc:
            results.append(
                _make_attempt(
                    "cache_timing",
                    "timing",
                    "",
                    False,
                    "",
                    str(exc)[:100],
                    url,
                    0,
                    20,
                    0,
                    0,
                )
            )

    try:
        result = await _measure_dns_timing(
            dns_domains or ["example.com", "google.com", "cloudflare.com"],
            timeout,
        )

        results.append(result)

    except Exception as exc:
        results.append(
            _make_attempt(
                "dns_timing",
                "timing",
                "",
                False,
                "",
                str(exc)[:100],
                "",
                0,
                50,
                0,
                0,
            )
        )

    return results


def print_results(result: TimingResult) -> None:

    print()

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Timing Attack Testing")

    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")

    if result.url:
        print(color("[*]", Cyber.CYAN), f"URL: {result.url}")

    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")

        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)

        print()

    categories: dict[str, list[TimingAttempt]] = {}

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
            "VULNERABLE — Timing side-channels detected!",
        )

    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — No timing vulnerabilities found",
        )

    print()


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="mytools-timing",
        description="Timing Attack Testing — Detecção de timing side-channels",
    )

    parser.add_argument("url", help="URL alvo (ex: https://target.com/login)")

    parser.add_argument(
        "-c",
        "--categories",
        nargs="+",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categorias para testar",
    )

    parser.add_argument(
        "--usernames",
        nargs="+",
        help="Usernames para login timing (default: admin root user test)",
    )

    parser.add_argument("--token", help="Token para testar token timing")

    parser.add_argument(
        "--cache-rounds",
        type=int,
        default=5,
        help="Rounds para cache timing (default: 5)",
    )

    parser.add_argument("--dns-domains", nargs="+", help="Domínios para DNS timing")

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:

    result = safe_asyncio_run(_run_scan(args))

    print_results(result)

    if getattr(args, "output", None):
        write_output(args.output, [asdict(a) for a in result.attempts])

    return 1 if result.overall_status == "vulnerable" else 0


async def _run_scan(args: argparse.Namespace) -> TimingResult:

    url = str(getattr(args, "url", ""))

    timeout = float(getattr(args, "timeout", 5.0))

    delay = float(getattr(args, "delay", 0.0))

    categories = getattr(args, "categories", None)

    usernames = getattr(args, "usernames", None)

    token = getattr(args, "token", None)

    cache_rounds = int(getattr(args, "cache_rounds", 5))

    dns_domains = getattr(args, "dns_domains", None)

    attempts: list[TimingAttempt] = []

    cats = categories if categories else list(_CATEGORY_MAP.keys())

    if "timing" in cats:
        raw = await _test_timing(
            url, timeout, delay, usernames, token, cache_rounds, dns_domains
        )

        attempts.extend(raw)

    vuln_techs = [a.technique for a in attempts if a.vulnerable]

    issues = [f"{a.technique}: {a.error}" for a in attempts if a.error]

    overall = "vulnerable" if vuln_techs else "secure"

    return TimingResult(
        target=url,
        url=url,
        attempts=attempts,
        vulnerable_techniques=vuln_techs,
        issues=issues,
        overall_status=overall,
    )


def main() -> int:

    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(_BANNER_LINES, "Timing Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="timing> ",
        description="Timing Attack Testing — Detecção de timing side-channels",
        example="mytools-timing https://target.com/login",
        contextual_help="timing: login_timing, token_timing, cache_timing, dns_timing",
    )


if __name__ == "__main__":
    raise SystemExit(main())
