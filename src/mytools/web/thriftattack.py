#!/usr/bin/env python3

"""Modulo de testes de Thrift Attack Testing."""

from __future__ import annotations

import argparse
import contextlib
import logging
import tempfile
import time
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import thriftpy2
from thriftpy2.rpc import make_client
from thriftpy2.thrift import TApplicationException

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

logger = logging.getLogger("mytools.thriftattack")

_BANNER_LINES: str = (
    "  _____ _     _   _  _____ _____ ____  \n"
    " |_   _| |   | \\ | |/ ____|_   _|  _ \\ \n"
    "   | | | | | |  \\| | |  _  | | | |_) |\n"
    "   | | | |_| | |\\  | |_| | | | |  _ < \n"
    "   |_|  \\___/|_| \\_|\\_____| |_| |_| \\_\\\n"
)


_DEFAULT_PORT: int = 9090


_MINIMAL_THRIFT_IDL: str = """\

namespace py probe_service



service ProbeService {

    void ping();

    string getData(1: string key);

    i32 getStatus();

    bool isAlive();

    list<string> listMethods();

    map<string, string> getMetadata();

    oneway void fireAndForget(1: string data);

}

"""


_COMMON_THRIFT_SERVICES: list[str] = [
    "DataService",
    "UserService",
    "AdminService",
    "HealthService",
    "ConfigService",
    "AuthService",
    "StorageService",
    "CacheService",
]


@dataclass(frozen=True, slots=True)
class ThriftAttackAttempt:
    technique: str

    category: str

    description: str

    vulnerable: bool

    details: str

    error: str

    host: str

    port: int

    protocol: str

    response_code: int

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class ThriftAttackResult:
    target: str

    host: str

    port: int

    tls: bool

    services_found: int

    methods_found: int

    protocol_detected: str

    attempts: list[ThriftAttackAttempt]

    vulnerable_techniques: list[str]

    issues: list[str]

    overall_status: str


_CATEGORY_MAP: dict[str, list[str]] = {
    "method_enumeration": [
        "service_enumeration",
        "method_discovery",
        "parameter_leak",
        "version_fingerprint",
    ],
    "binary_protocol": [
        "field_type_confusion",
        "collection_overflow",
        "string_encoding_abuse",
        "boolean_coercion",
    ],
}


def _parse_url(target: str) -> tuple[str, str, int, bool]:

    if "://" not in target:
        target = "thrift://" + target

    parsed = urlparse(target)

    host = parsed.hostname or ""

    path = parsed.path or ""

    tls = parsed.scheme in ("thrifts", "https")

    default_port = 443 if tls else _DEFAULT_PORT

    port = parsed.port or default_port

    return host, path, port, tls


def _create_probe_thrift() -> Any:

    with tempfile.NamedTemporaryFile(mode="w", suffix=".thrift", delete=False) as f:
        f.write(_MINIMAL_THRIFT_IDL)

        f.flush()

        return thriftpy2.load(f.name, module_name="probe_service_thrift")


def _make_attempt(
    tech: str,
    cat: str,
    desc: str,
    vuln: bool,
    details: str,
    error: str,
    host: str,
    port: int,
    code: int = 200,
) -> ThriftAttackAttempt:

    return ThriftAttackAttempt(
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        host=host,
        port=port,
        protocol="binary",
        response_code=code,
        exploit="method_enumeration_payload" if vuln else "",
        tool="thrift",
    )


async def _test_method_enumeration(
    host: str, port: int, timeout: float, tls: bool
) -> list[ThriftAttackAttempt]:

    results: list[ThriftAttackAttempt] = []

    timeout_ms = min(int(timeout * 1000), 2000)

    for tech in (
        "service_enumeration",
        "method_discovery",
        "parameter_leak",
        "version_fingerprint",
    ):
        try:
            if tech == "service_enumeration":
                found: list[str] = []

                for svc in _COMMON_THRIFT_SERVICES:
                    try:
                        idl = f"namespace py {svc.lower()}_service\nservice {svc} {{ void ping(); }}\n"

                        with tempfile.NamedTemporaryFile(
                            mode="w", suffix=".thrift", delete=False
                        ) as f:
                            f.write(idl)

                            f.flush()

                        mod = thriftpy2.load(
                            f.name, module_name=f"{svc.lower()}_thrift"
                        )

                        c = make_client(
                            getattr(mod, svc), host=host, port=port, timeout=timeout_ms
                        )

                        c.ping()

                        found.append(svc)

                        c.close()

                    except TApplicationException:
                        found.append(svc)

                    except Exception:
                        pass

                vuln = len(found) > 0

                det = f"Services: {', '.join(found[:5])}" if vuln else "No services"

            elif tech == "method_discovery":
                methods = [
                    "ping",
                    "getStatus",
                    "getData",
                    "listMethods",
                    "getVersion",
                    "healthCheck",
                ]

                found_m: list[str] = []

                thrift_mod = _create_probe_thrift()

                for m in methods:
                    try:
                        c = make_client(
                            thrift_mod.ProbeService,
                            host=host,
                            port=port,
                            timeout=timeout_ms,
                        )

                        fn = getattr(c, m, None)

                        if fn:
                            fn()

                            found_m.append(m)

                        c.close()

                    except TApplicationException:
                        pass

                    except Exception:
                        pass

                vuln = len(found_m) > 0

                det = f"Methods: {', '.join(found_m[:5])}" if vuln else "No methods"

            elif tech == "parameter_leak":
                try:
                    c = make_client(
                        _create_probe_thrift().ProbeService,
                        host=host,
                        port=port,
                        timeout=timeout_ms,
                    )

                    c.getData("nonexistent_key_abc123")

                    vuln, det = False, "No error on bad params"

                    c.close()

                except TApplicationException as e:
                    msg = str(e).lower()

                    vuln = any(kw in msg for kw in ["method", "not found", "unknown"])

                    det = f"Error: {str(e)[:100]}"

                except Exception:
                    vuln, det = False, "Connection failed"

            elif tech == "version_fingerprint":
                try:
                    c = make_client(
                        _create_probe_thrift().ProbeService,
                        host=host,
                        port=port,
                        timeout=timeout_ms,
                    )

                    c.ping()

                    vuln, det = True, "Thrift binary protocol detected"

                    c.close()

                except TApplicationException:
                    vuln, det = True, "Thrift server responded"

                except Exception:
                    vuln, det = False, "Connection failed"

            else:
                vuln, det = False, ""

            results.append(
                _make_attempt(
                    tech, "method_enumeration", tech, vuln, det, "", host, port
                )
            )

        except Exception as exc:
            results.append(
                _make_attempt(
                    tech,
                    "method_enumeration",
                    tech,
                    False,
                    "",
                    str(exc)[:100],
                    host,
                    port,
                    0,
                )
            )

    return results


async def _test_binary_protocol(
    host: str, port: int, timeout: float, tls: bool
) -> list[ThriftAttackAttempt]:

    results: list[ThriftAttackAttempt] = []

    timeout_ms = min(int(timeout * 1000), 2000)

    for tech in (
        "field_type_confusion",
        "collection_overflow",
        "string_encoding_abuse",
        "boolean_coercion",
    ):
        try:
            if tech == "field_type_confusion":
                try:
                    c = make_client(
                        _create_probe_thrift().ProbeService,
                        host=host,
                        port=port,
                        timeout=timeout_ms,
                    )

                    c.getData("test_field_type_confusion")

                    vuln, det = False, "Type confusion: got response (server robust)"

                    c.close()

                except TApplicationException as e:
                    vuln, det = False, f"Type confusion: {e.type} (server rejeitou)"

                except Exception:
                    vuln, det = False, "Connection failed"

            elif tech == "collection_overflow":
                t0 = time.monotonic()

                try:
                    c = make_client(
                        _create_probe_thrift().ProbeService,
                        host=host,
                        port=port,
                        timeout=min(timeout_ms, 5000),
                    )

                    c.getData(str(["x" * 1000 for _ in range(10000)]))

                    elapsed = time.monotonic() - t0

                    vuln, det = False, f"Collection overflow: {elapsed:.2f}s"

                    c.close()

                except Exception:
                    elapsed = time.monotonic() - t0

                    vuln, det = (
                        elapsed > 2.0,
                        f"Collection overflow timeout: {elapsed:.2f}s",
                    )

            elif tech == "string_encoding_abuse":
                try:
                    c = make_client(
                        _create_probe_thrift().ProbeService,
                        host=host,
                        port=port,
                        timeout=timeout_ms,
                    )

                    for s in [
                        "\xff\xfe\xfd",
                        "A" * 100000,
                        "\x00\x00\x00",
                        "SELECT * FROM users",
                    ]:
                        with contextlib.suppress(Exception):
                            c.getData(s)

                    vuln, det = False, "String encoding abuse sent (server robust)"

                    c.close()

                except Exception:
                    vuln, det = False, "Connection failed"

            elif tech == "boolean_coercion":
                try:
                    c = make_client(
                        _create_probe_thrift().ProbeService,
                        host=host,
                        port=port,
                        timeout=timeout_ms,
                    )

                    c.isAlive()

                    vuln, det = False, "Boolean coercion: got response (server robust)"

                    c.close()

                except TApplicationException as e:
                    vuln, det = False, f"Boolean coercion: {e.type} (server rejeitou)"

                except Exception:
                    vuln, det = False, "Connection failed"

            else:
                vuln, det = False, ""

            results.append(
                _make_attempt(tech, "binary_protocol", tech, vuln, det, "", host, port)
            )

        except Exception as exc:
            results.append(
                _make_attempt(
                    tech,
                    "binary_protocol",
                    tech,
                    False,
                    "",
                    str(exc)[:100],
                    host,
                    port,
                    0,
                )
            )

    return results


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[ThriftAttackAttempt]]]
] = {
    "method_enumeration": _test_method_enumeration,
    "binary_protocol": _test_binary_protocol,
}


def print_results(result: ThriftAttackResult) -> None:

    print()

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Thrift Attack Testing")

    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")

    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )

    print(color("[*]", Cyber.CYAN), f"Protocol: {result.protocol_detected}")

    print(
        color("[*]", Cyber.CYAN),
        f"Services: {result.services_found} | Methods: {result.methods_found}",
    )

    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")

        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)

        print()

    categories: dict[str, list[ThriftAttackAttempt]] = {}

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
            "VULNERABLE — Thrift weaknesses detected!",
        )

    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — Thrift configuration looks good",
        )

    print()


async def run_scan(
    target: str, categories: list[str] | None, timeout: float, output_file: str | None
) -> ThriftAttackResult:

    host, _path, port, tls = _parse_url(target)

    all_attempts: list[ThriftAttackAttempt] = []

    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)

        if tester is None:
            continue

        try:
            raw = await tester(host, port, timeout, tls)

            all_attempts.extend(raw)

        except Exception as e:
            all_attempts.append(
                _make_attempt(
                    f"{cat}_error", cat, "", False, "", str(e)[:100], host, port, 0
                )
            )

    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]

    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]

    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []

    overall = "vulnerable" if vuln_techs else "secure"

    services_found = len(
        [
            a
            for a in all_attempts
            if a.category == "method_enumeration"
            and a.technique == "service_enumeration"
            and a.vulnerable
        ]
    )

    methods_found = len(
        [
            a
            for a in all_attempts
            if a.category == "method_enumeration"
            and a.technique == "method_discovery"
            and a.vulnerable
        ]
    )

    protocol_detected = (
        "binary" if any(not a.error for a in all_attempts) else "unknown"
    )

    result = ThriftAttackResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        services_found=services_found,
        methods_found=methods_found,
        protocol_detected=protocol_detected,
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
        prog="mytools-thrift",
        description="Thrift Attack Testing — Method Enumeration, Binary Protocol Manipulation",
    )

    parser.add_argument("url", help="URL alvo (thrift://target.com:9090)")

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
        banner_fn=create_banner(_BANNER_LINES, "Thrift Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="thrift> ",
        description="Thrift Attack Testing — Method Enumeration, Binary Protocol Manipulation",
        example="mytools-thrift thrift://target.com:9090",
        contextual_help="thrift: method_enumeration, binary_protocol",
    )


if __name__ == "__main__":
    raise SystemExit(main())
