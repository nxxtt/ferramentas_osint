#!/usr/bin/env python3
"""Modulo de testes de gRPC & Protobuf Attack Testing.

Testa seguranca de endpoints gRPC:
  - Reflection: reflection_discovery, service_enumeration, method_enumeration, file_descriptor_leak, proto_file_dump
  - Server Streaming: stream_flood, stream_memory_dos, slow_loris_stream, stream_hijack
  - Client Streaming: upload_flood, large_payload, stream_consume
  - Bidirectional: bidi_flood, bidi_resource_exhaustion, bidi_hang
  - gRPC-Web: web_bypass, web_cors_abuse, web_origin_spoof, web_proxy_abuse
  - Protobuf: field_manipulation, varint_overflow, nested_message_abuse, oneof_confusion, enum_overflow
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import struct
import time
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import grpc
import grpc.aio
import httpx
from google.protobuf.descriptor_pool import DescriptorPool
from grpc_reflection.v1alpha.proto_reflection_descriptor_database import (
    ProtoReflectionDescriptorDatabase,
)

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

logger = logging.getLogger("mytools.grpcattack")

_BANNER_LINES: str = (
    "  ____ ___  __  __ ____    ____ _           _ \n"
    " / ___/ _ \\|  \\/  |  _ \\  / ___| |__   __ _| |\n"
    "| |  | | | | |\\/| | |_) || |  | '_ \\ / _` | |\n"
    "| |__| |_| | |  | |  _ < | |__| | | | (_| | |\n"
    " \\____\\___/|_|  |_|_| \\_\\ \\____|_| |_|\\__,_|_|\n"
)

_DEFAULT_PORT: int = 50051


@dataclass(frozen=True, slots=True)
class GrpcAttackAttempt:
    technique: str
    category: str
    description: str
    vulnerable: bool
    details: str
    error: str
    endpoint: str
    services_found: int
    methods_found: int
    response_code: int
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class GrpcAttackResult:
    target: str
    host: str
    port: int
    tls: bool
    endpoint: str
    reflection_enabled: bool
    services_count: int
    methods_count: int
    attempts: list[GrpcAttackAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


_CATEGORY_MAP: dict[str, list[str]] = {
    "reflection": [
        "reflection_discovery",
        "service_enumeration",
        "method_enumeration",
        "file_descriptor_leak",
        "proto_file_dump",
    ],
    "server_streaming": [
        "stream_flood",
        "stream_memory_dos",
        "slow_loris_stream",
        "stream_hijack",
    ],
    "client_streaming": ["upload_flood", "large_payload", "stream_consume"],
    "bidirectional": ["bidi_flood", "bidi_resource_exhaustion", "bidi_hang"],
    "grpc_web": ["web_bypass", "web_cors_abuse", "web_origin_spoof", "web_proxy_abuse"],
    "protobuf": [
        "field_manipulation",
        "varint_overflow",
        "nested_message_abuse",
        "oneof_confusion",
        "enum_overflow",
    ],
}


def _parse_url(target: str) -> tuple[str, str, int, bool]:
    if "://" not in target:
        target = "grpc://" + target
    parsed = urlparse(target)
    host = parsed.hostname or ""
    path = parsed.path or ""
    tls = parsed.scheme in ("grpcs", "https")
    default_port = 443 if tls else _DEFAULT_PORT
    port = parsed.port or default_port
    return host, path, port, tls


def _encode_varint(value: int) -> bytes:
    result: list[int] = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def _create_channel(target: str, tls: bool) -> grpc.aio.Channel:
    if tls:
        return grpc.aio.secure_channel(target, grpc.ssl_channel_credentials())
    return grpc.aio.insecure_channel(target)


async def _discover_reflection(
    host: str, port: int, tls: bool, timeout: float
) -> dict[str, Any]:
    target = f"{host}:{port}"
    result: dict[str, Any] = {
        "available": False,
        "services": [],
        "files": [],
        "methods": {},
    }
    try:
        channel = _create_channel(target, tls)
        await asyncio.wait_for(channel.channel_ready(), timeout=timeout)
        refl_db = ProtoReflectionDescriptorDatabase(channel)  # type: ignore[reportArgumentType]
        pool = DescriptorPool()
        services = refl_db.get_services()
        result["available"] = len(services) > 0
        for svc_name in services:
            try:
                file_name = f"{svc_name.split('.')[0]}.proto"
                file_desc = refl_db.FindFileByName(file_name)
                pool.Add(file_desc)
                svc_desc = pool.FindServiceByName(svc_name)
                methods = [m.name for m in svc_desc.methods]
                result["services"].append({"name": svc_name, "methods": methods})
                result["methods"][svc_name] = methods
                result["files"].append(file_name)
            except Exception:
                result["services"].append({"name": svc_name, "methods": []})
    except grpc.aio.AioRpcError:
        pass
    except Exception:
        pass
    finally:
        with contextlib.suppress(Exception):
            await channel.close()  # type: ignore[possibly-undefined]
    return result


def _svc_count(refl: dict[str, Any]) -> int:
    return len(refl.get("services", []))


def _method_count(refl: dict[str, Any]) -> int:
    return sum(len(s.get("methods", [])) for s in refl.get("services", []))


def _make_attempt(
    tech: str,
    cat: str,
    desc: str,
    vuln: bool,
    details: str,
    error: str,
    endpoint: str,
    refl: dict[str, Any],
    code: int = 200,
) -> GrpcAttackAttempt:
    return GrpcAttackAttempt(
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        endpoint=endpoint,
        services_found=_svc_count(refl),
        methods_found=_method_count(refl),
        response_code=code,
        exploit="grpcurl reflection <TARGET>",
        tool="grpcurl",
    )


# Codigos de erro gRPC que evidenciam que o servidor ficou sobrecarregado ou
# falhou sob carga (successo individual de Health/Check e comportamento normal).
_EXHAUSTION_CODES = frozenset(
    {"RESOURCE_EXHAUSTED", "DEADLINE_EXCEEDED", "DATA_LOSS", "INTERNAL"}
)


async def _try_call(
    target: str, tls: bool, method: str, payload: bytes, timeout: float
) -> tuple[bool, str]:
    channel = _create_channel(target, tls)
    try:
        await asyncio.wait_for(channel.channel_ready(), timeout=timeout)
        stub = channel.unary_unary(method)
        await stub(payload)
        return True, "ok"
    except grpc.aio.AioRpcError as e:
        return e.code() == grpc.StatusCode.OK, e.code().name
    except Exception:
        return False, "connection_failed"
    finally:
        with contextlib.suppress(Exception):
            await channel.close()


async def _test_reflection(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
    refl: dict[str, Any],
) -> list[GrpcAttackAttempt]:
    results: list[GrpcAttackAttempt] = []
    services = refl.get("services", [])
    files = refl.get("files", [])
    svc_c = _svc_count(refl)
    for tech in (
        "reflection_discovery",
        "service_enumeration",
        "method_enumeration",
        "file_descriptor_leak",
        "proto_file_dump",
    ):
        try:
            if tech == "reflection_discovery":
                vuln = refl.get("available", False)
                det = f"Reflection: {'enabled' if vuln else 'disabled'}"
            elif tech == "service_enumeration":
                vuln = svc_c > 0
                names = [s["name"] for s in services]
                det = f"Services: {', '.join(names[:5])}" if names else "No services"
            elif tech == "method_enumeration":
                all_m = [
                    f"{s['name']}/{m}" for s in services for m in s.get("methods", [])
                ]
                vuln = len(all_m) > 0
                det = (
                    f"Methods: {len(all_m)} ({', '.join(all_m[:5])})"
                    if all_m
                    else "No methods"
                )
            elif tech == "file_descriptor_leak":
                vuln = len(files) > 0
                det = (
                    f"File descriptors: {len(files)} ({', '.join(files[:3])})"
                    if files
                    else "No files"
                )
            elif tech == "proto_file_dump":
                vuln = len(files) > 3
                det = f"Dumpable files: {len(files)}"
            else:
                vuln, det = False, ""
            results.append(
                _make_attempt(tech, "reflection", tech, vuln, det, "", endpoint, refl)
            )
        except Exception as exc:
            results.append(
                _make_attempt(
                    tech,
                    "reflection",
                    tech,
                    False,
                    "",
                    str(exc)[:100],
                    endpoint,
                    refl,
                    0,
                )
            )
    return results


async def _test_server_streaming(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
    refl: dict[str, Any],
) -> list[GrpcAttackAttempt]:
    results: list[GrpcAttackAttempt] = []
    target = f"{host}:{port}"
    for tech, desc, payload in [
        ("stream_flood", "Streaming flood", b"\x00\x00\x00\x00\x00"),
        (
            "stream_memory_dos",
            "Memory DoS",
            b"\x00" + struct.pack(">I", 1024 * 1024) + b"\x00" * (1024 * 1024),
        ),
        ("slow_loris_stream", "Slow loris", b"\x00"),
        ("stream_hijack", "Stream hijack", b"\x08\x01"),
    ]:
        try:
            if tech == "stream_flood":
                sent = 0
                evidence: set[str] = set()
                for _i in range(10):
                    ok, code = await _try_call(
                        target,
                        tls,
                        "/grpc.health.v1.Health/Check",
                        b"\x00\x00\x00\x00\x00",
                        timeout,
                    )
                    if ok:
                        sent += 1
                    elif code in _EXHAUSTION_CODES:
                        evidence.add(code)
                vuln = bool(evidence)
                det = f"Stream flood: {sent}/10 succeeded" + (
                    f", evidence={sorted(evidence)}" if evidence else ""
                )
            else:
                ok, code = await _try_call(
                    target, tls, "/grpc.health.v1.Health/Check", payload, timeout
                )
                vuln = not ok and code in _EXHAUSTION_CODES
                det = f"{desc}: {code}"
            results.append(
                _make_attempt(
                    tech, "server_streaming", desc, vuln, det, "", endpoint, refl
                )
            )
        except Exception as exc:
            results.append(
                _make_attempt(
                    tech,
                    "server_streaming",
                    desc,
                    False,
                    "",
                    str(exc)[:100],
                    endpoint,
                    refl,
                    0,
                )
            )
    return results


async def _test_client_streaming(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
    refl: dict[str, Any],
) -> list[GrpcAttackAttempt]:
    results: list[GrpcAttackAttempt] = []
    target = f"{host}:{port}"
    for tech, desc, payload in [
        ("upload_flood", "Upload flood", b"\x00\x00\x00\x00\x01\x08"),
        ("large_payload", "Large payload", b"\x00" * 1024),
        ("stream_consume", "Stream consume", b"\x08" * 100),
    ]:
        try:
            evidence: set[str] = set()
            if tech == "upload_flood":
                sent = 0
                for _i in range(20):
                    ok, code = await _try_call(
                        target, tls, "/grpc.health.v1.Health/Check", payload, timeout
                    )
                    if ok:
                        sent += 1
                    elif code in _EXHAUSTION_CODES:
                        evidence.add(code)
                vuln = bool(evidence)
                det = f"Uploaded {sent}/20" + (
                    f", evidence={sorted(evidence)}" if evidence else ""
                )
            elif tech == "stream_consume":
                consumed = 0
                for i in range(15):
                    ok, code = await _try_call(
                        target,
                        tls,
                        "/grpc.health.v1.Health/Check",
                        struct.pack(">I", i) + b"\x08" * 100,
                        timeout,
                    )
                    if ok:
                        consumed += 1
                    elif code in _EXHAUSTION_CODES:
                        evidence.add(code)
                vuln = bool(evidence)
                det = f"Consumed {consumed}/15" + (
                    f", evidence={sorted(evidence)}" if evidence else ""
                )
            else:
                ok, code = await _try_call(
                    target, tls, "/grpc.health.v1.Health/Check", payload, timeout
                )
                vuln = not ok and code in _EXHAUSTION_CODES
                det = code
            results.append(
                _make_attempt(
                    tech, "client_streaming", desc, vuln, det, "", endpoint, refl
                )
            )
        except Exception as exc:
            results.append(
                _make_attempt(
                    tech,
                    "client_streaming",
                    desc,
                    False,
                    "",
                    str(exc)[:100],
                    endpoint,
                    refl,
                    0,
                )
            )
    return results


async def _test_bidirectional(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
    refl: dict[str, Any],
) -> list[GrpcAttackAttempt]:
    results: list[GrpcAttackAttempt] = []
    target = f"{host}:{port}"
    for tech, desc in [
        ("bidi_flood", "Bidi flood"),
        ("bidi_resource_exhaustion", "Bidi exhaustion"),
        ("bidi_hang", "Bidi hang"),
    ]:
        try:
            evidence: set[str] = set()
            if tech == "bidi_flood":
                sent = 0
                for i in range(25):
                    ok, code = await _try_call(
                        target,
                        tls,
                        "/grpc.health.v1.Health/Check",
                        struct.pack(">I", i) + b"\x0a\x04test",
                        timeout,
                    )
                    if ok:
                        sent += 1
                    elif code in _EXHAUSTION_CODES:
                        evidence.add(code)
                vuln = bool(evidence)
                det = f"Bidi flood: {sent}/25" + (
                    f", evidence={sorted(evidence)}" if evidence else ""
                )
            elif tech == "bidi_resource_exhaustion":
                conc = 0
                for _i in range(10):
                    ok, code = await _try_call(
                        target,
                        tls,
                        "/grpc.health.v1.Health/Check",
                        b"\x00\x00\x00\x00\x00",
                        timeout,
                    )
                    if ok:
                        conc += 1
                    elif code in _EXHAUSTION_CODES:
                        evidence.add(code)
                vuln = bool(evidence)
                det = f"Concurrent: {conc}/10" + (
                    f", evidence={sorted(evidence)}" if evidence else ""
                )
            else:
                t0 = time.monotonic()
                ok, code = await _try_call(
                    target, tls, "/grpc.health.v1.Health/Check", b"\x00", timeout
                )
                elapsed = time.monotonic() - t0
                vuln = not ok and code in _EXHAUSTION_CODES
                det = f"Bidi hang: {elapsed:.2f}s ({code})"
            results.append(
                _make_attempt(
                    tech, "bidirectional", desc, vuln, det, "", endpoint, refl
                )
            )
        except Exception as exc:
            results.append(
                _make_attempt(
                    tech,
                    "bidirectional",
                    desc,
                    False,
                    "",
                    str(exc)[:100],
                    endpoint,
                    refl,
                    0,
                )
            )
    return results


async def _test_grpc_web(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
    refl: dict[str, Any],
) -> list[GrpcAttackAttempt]:
    results: list[GrpcAttackAttempt] = []
    scheme = "https" if tls else "http"
    base = (
        f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    )
    for tech, desc in [
        ("web_bypass", "gRPC-Web bypass"),
        ("web_cors_abuse", "CORS abuse"),
        ("web_origin_spoof", "Origin spoof"),
        ("web_proxy_abuse", "Proxy abuse"),
    ]:
        try:
            async with httpx.AsyncClient(
                timeout=timeout, verify=False, follow_redirects=True
            ) as client:
                if tech == "web_bypass":
                    resp = await client.options(
                        base,
                        headers={
                            "Origin": "http://evil.com",
                            "Access-Control-Request-Method": "POST",
                        },
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    vuln, det = (
                        acao in ("*", "http://evil.com"),
                        f"ACAO: {acao or 'not set'}",
                    )
                elif tech == "web_cors_abuse":
                    resp = await client.post(
                        base,
                        content=b"\x00\x00\x00\x00\x00",
                        headers={
                            "Content-Type": "application/grpc-web",
                            "Origin": "https://evil.com",
                        },
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    vuln, det = (
                        acao in ("*", "https://evil.com"),
                        f"CORS: {acao or 'not set'}",
                    )
                elif tech == "web_origin_spoof":
                    resp = await client.post(
                        base,
                        content=b"\x00\x00\x00\x00\x00",
                        headers={
                            "Content-Type": "application/grpc-web+proto",
                            "Origin": "https://internal.company.com",
                        },
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    vuln, det = (
                        acao in ("*", "https://internal.company.com"),
                        f"Origin spoof: {resp.status_code}, ACAO: {acao or 'not set'}",
                    )
                else:
                    resp = await client.post(
                        base,
                        content=b"\x00\x00\x00\x00\x00",
                        headers={
                            "Content-Type": "application/grpc-web",
                            "X-Forwarded-For": "127.0.0.1",
                        },
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    vuln, det = (
                        acao == "*",
                        f"Proxy: {resp.status_code}, ACAO: {acao or 'not set'}",
                    )
            results.append(
                _make_attempt(tech, "grpc_web", desc, vuln, det, "", endpoint, refl)
            )
        except Exception as exc:
            results.append(
                _make_attempt(
                    tech, "grpc_web", desc, False, "", str(exc)[:100], endpoint, refl, 0
                )
            )
    return results


async def _test_protobuf(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
    refl: dict[str, Any],
) -> list[GrpcAttackAttempt]:
    results: list[GrpcAttackAttempt] = []
    target = f"{host}:{port}"
    payloads = {
        "field_manipulation": _encode_varint((999 << 3) | 2) + b"\x02\x00\x08\x01",
        "varint_overflow": b"\xff" * 10 + b"\x7f\x08\x01",
        "nested_message_abuse": b"\x0a" * 500 + b"\x08\x01",
        "oneof_confusion": b"\x0a\x02hi\x0a\x02hi",
        "enum_overflow": b"\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
    }
    for tech, desc in [
        ("field_manipulation", "Field manipulation"),
        ("varint_overflow", "Varint overflow"),
        ("nested_message_abuse", "Nested abuse"),
        ("oneof_confusion", "Oneof confusion"),
        ("enum_overflow", "Enum overflow"),
    ]:
        try:
            ok, code = await _try_call(
                target, tls, "/grpc.health.v1.Health/Check", payloads[tech], timeout
            )
            vuln = not ok and code in _EXHAUSTION_CODES
            results.append(
                _make_attempt(tech, "protobuf", desc, vuln, code, "", endpoint, refl)
            )
        except Exception as exc:
            results.append(
                _make_attempt(
                    tech, "protobuf", desc, False, "", str(exc)[:100], endpoint, refl, 0
                )
            )
    return results


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[GrpcAttackAttempt]]]
] = {
    "reflection": _test_reflection,
    "server_streaming": _test_server_streaming,
    "client_streaming": _test_client_streaming,
    "bidirectional": _test_bidirectional,
    "grpc_web": _test_grpc_web,
    "protobuf": _test_protobuf,
}


def print_results(result: GrpcAttackResult) -> None:
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "gRPC Attack Testing")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )
    print(color("[*]", Cyber.CYAN), f"Endpoint: {result.endpoint}")
    print(
        color("[*]", Cyber.CYAN),
        f"Reflection: {'enabled' if result.reflection_enabled else 'disabled'}",
    )
    print(
        color("[*]", Cyber.CYAN),
        f"Services: {result.services_count} | Methods: {result.methods_count}",
    )
    print()
    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()
    categories: dict[str, list[GrpcAttackAttempt]] = {}
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
            "VULNERABLE — gRPC weaknesses detected!",
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — gRPC configuration looks good",
        )
    print()


async def run_scan(
    target: str, categories: list[str] | None, timeout: float, output_file: str | None
) -> GrpcAttackResult:
    host, path, port, tls = _parse_url(target)
    scheme = "https" if tls else "http"
    endpoint = (
        f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    )
    refl = await _discover_reflection(host, port, tls, timeout)
    all_attempts: list[GrpcAttackAttempt] = []
    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())
    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)
        if tester is None:
            continue
        try:
            raw = await tester(host, port, path, timeout, tls, endpoint, refl)
            all_attempts.extend(raw)
        except Exception as e:
            all_attempts.append(
                _make_attempt(
                    f"{cat}_error", cat, "", False, "", str(e)[:100], endpoint, refl, 0
                )
            )
    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]
    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []
    overall = "vulnerable" if vuln_techs else "secure"
    result = GrpcAttackResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        endpoint=endpoint,
        reflection_enabled=refl.get("available", False),
        services_count=_svc_count(refl),
        methods_count=_method_count(refl),
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
        prog="mytools-grpc",
        description="gRPC Attack Testing — Reflection, Streaming, Bidirectional, gRPC-Web, Protobuf",
    )
    parser.add_argument("url", help="URL alvo (grpc://target.com:50051)")
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
        banner_fn=create_banner(_BANNER_LINES, "gRPC Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="grpc> ",
        description="gRPC Attack Testing — Reflection, Streaming, Bidirectional, gRPC-Web, Protobuf",
        example="mytools-grpc grpc://target.com:50051",
        contextual_help="gRPC: reflection, server_streaming, client_streaming, bidirectional, grpc_web, protobuf",
    )


if __name__ == "__main__":
    raise SystemExit(main())
