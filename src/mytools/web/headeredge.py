#!/usr/bin/env python3
"""Modulo de testes de Header & Parsing Edge Cases.

Testa como servidores/proxies lidam com requests HTTP malformed:
  - Duplicate Headers: Host duplicado, Content-Length duplicado
  - Malformed HTTP Version: HTTP/1.3, HTTP/2.0, HTTP/9.9
  - Null Request Byte: byte null no request para confundir parser
  - Whitespace in Header Names: espaco extra antes do dois-pontos
  - Header Name Case Sensitivity: CONTENT-TYPE vs Content-Type
  - Absolute URI in Request: GET http://b.com/path HTTP/1.1
  - HTTP/0.9 Request: request sem headers/versao

IMPORTANTE: Usa raw sockets porque httpx normaliza headers.
"""

from __future__ import annotations

import argparse
import logging
import re
import socket
import ssl
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

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

logger = logging.getLogger("mytools.headeredge")

# ─── Banner ──────────────────────────────────────────────────────────────────

_BANNER_LINES: str = (
    "  _   _  ___  ___  _   _ _____    _    _   _  ____  ____     _  _______  _\n"
    " | | | |/ _ \\/ _ \\| | | |_   _|  / \\  | | | |/ ___||  _ \\   / \\|_   _\\/ \\\n"
    " | |_| | | | | | | | | | | | |  / _ \\ | | | | |  _ | |_) | / _ \\ | | / _ \\\n"
    " |  _  | |_| | |_| | |_| | | | / ___ \\| |_| | |_| ||  __/ / ___ \\| |/ ___ \\\n"
    " |_| |_|\\___/ \\___/ \\___/  |_|/_/   \\_\\\\___/ \\____||_|  /_/   \\_\\_/_/   \\_\\\n"
)

# ─── Category Map ────────────────────────────────────────────────────────────

_CATEGORY_MAP: dict[str, list[str]] = {
    "duplicate_headers": [
        "dup_host",
        "dup_content_length",
        "dup_transfer_encoding",
        "dup_user_agent",
        "dup_cookie",
    ],
    "malformed_version": [
        "http_1_3",
        "http_2_0",
        "http_9_9",
        "http_no_version",
        "http_3_0",
    ],
    "null_request_byte": [
        "null_start",
        "null_after_method",
        "null_in_path",
        "null_after_headers",
        "null_in_host",
    ],
    "header_whitespace": [
        "space_before_colon",
        "tab_before_colon",
        "space_after_name",
        "tab_after_name",
        "trailing_space",
    ],
    "header_case": [
        "lower_method",
        "lower_host",
        "mixed_host",
        "upper_path",
        "random_case",
    ],
    "absolute_uri": [
        "absolute_http",
        "absolute_https",
        "absolute_host_mismatch",
        "absolute_port",
        "absolute_path",
    ],
    "http09_request": [
        "get_no_headers",
        "get_no_version",
        "post_no_headers",
        "minimal_request",
        "empty_request",
    ],
}

# ─── Connection Helpers ──────────────────────────────────────────────────────


def _parse_url(url: str) -> tuple[str, str, int, bool]:
    """Extrai host, path, port, tls de uma URL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    tls = parsed.scheme == "https"
    port = parsed.port or (443 if tls else 80)
    return host, path, port, tls


def _create_connection(
    host: str,
    port: int,
    timeout: float,
    tls: bool = False,
) -> socket.socket:
    """Cria conexao TCP (ou TLS) com o alvo."""
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
            if b"\r\n\r\n" in response:
                header_end = response.index(b"\r\n\r\n") + 4
                headers_raw = response[:header_end]
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
                    if response.endswith(b"0\r\n\r\n"):
                        break
                    if len(response) > 65536:
                        break
        except TimeoutError, OSError:
            break

    status = 0
    if response:
        first_line = response.split(b"\r\n", 1)[0]
        status_match = re.match(rb"HTTP/[\d.]+ (\d+)", first_line)
        if status_match:
            status = int(status_match.group(1))
        elif response.startswith(b"HTTP/0.9"):
            status = 200

    return status, response


def _build_request(
    method: str,
    path: str,
    host: str,
    extra_headers: list[tuple[str, str]] | None = None,
    version: str = "HTTP/1.1",
    body: bytes | None = None,
) -> bytes:
    """Constrói request HTTP raw."""
    lines = [f"{method} {path} {version}"]
    lines.append(f"Host: {host}")
    if extra_headers:
        for name, value in extra_headers:
            lines.append(f"{name}: {value}")
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    request = "\r\n".join(lines) + "\r\n\r\n"
    result = request.encode("latin-1", errors="replace")
    if body:
        result += body
    return result


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class HeaderEdgeAttempt:
    """Tentativa individual de header/parsing edge case."""

    technique: str
    category: str
    raw_request: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class HeaderEdgeResult:
    """Resultado consolidado do scan."""

    target: str
    host: str
    port: int
    tls: bool
    baseline_status: int
    baseline_size: int
    attempts: list[HeaderEdgeAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


# ─── Baseline ────────────────────────────────────────────────────────────────


def _get_baseline(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
) -> tuple[int, int]:
    """Obtem baseline: (status, size)."""
    try:
        sock = _create_connection(host, port, timeout, tls)
        try:
            host_header = host if port in (80, 443) else f"{host}:{port}"
            request = _build_request("GET", path, host_header)
            status, response = _send_raw(sock, request, timeout)
            return status, len(response)
        finally:
            sock.close()
    except Exception:
        return 0, 0


# ─── Category 136: duplicate_headers ────────────────────────────────────────


async def _test_duplicate_headers(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[HeaderEdgeAttempt]:
    """Testa headers duplicados."""
    results: list[HeaderEdgeAttempt] = []

    payloads: list[tuple[str, str, str, list[tuple[str, str]]]] = [
        (
            "dup_host",
            "Host duplicado com host diferente",
            "Host: target.com\r\nHost: evil.com",
            [("Host", "target.com"), ("Host", "evil.com")],
        ),
        (
            "dup_content_length",
            "Content-Length duplicado (ambiguidade)",
            "Content-Length: 0\r\nContent-Length: 5",
            [("Content-Length", "0"), ("Content-Length", "5")],
        ),
        (
            "dup_transfer_encoding",
            "Transfer-Encoding duplicado",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            [("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "identity")],
        ),
        (
            "dup_user_agent",
            "User-Agent duplicado",
            "User-Agent: A\r\nUser-Agent: B",
            [("User-Agent", "A"), ("User-Agent", "B")],
        ),
        (
            "dup_cookie",
            "Cookie duplicado",
            "Cookie: a=1\r\nCookie: b=2",
            [("Cookie", "a=1"), ("Cookie", "b=2")],
        ),
    ]

    for technique, _desc, raw_headers, header_pairs in payloads:
        try:
            sock = _create_connection(host, port, timeout, tls)
            try:
                lines = [f"GET {path} HTTP/1.1"]
                lines.append(f"Host: {host}")
                for name, value in header_pairs:
                    lines.append(f"{name}: {value}")
                request = "\r\n".join(lines) + "\r\n\r\n"
                raw_req = request
                status, response = _send_raw(
                    sock, request.encode("latin-1", errors="replace"), timeout
                )
                vulnerable = (status != b_status) or (len(response) != b_size)
                results.append(
                    HeaderEdgeAttempt(
                        exploit="header_smuggling_payload",
                        tool="curl",
                        technique=technique,
                        category="duplicate_headers",
                        raw_request=raw_req,
                        status_baseline=b_status,
                        status_test=status,
                        size_baseline=b_size,
                        size_test=len(response),
                        vulnerable=vulnerable,
                        details=f"Status: {status} (baseline: {b_status}), size: {len(response)} (baseline: {b_size})",
                        error="",
                    )
                )
            finally:
                sock.close()
        except Exception as e:
            results.append(
                HeaderEdgeAttempt(
                    technique=technique,
                    category="duplicate_headers",
                    raw_request=raw_headers,
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── Category 137: malformed_version ────────────────────────────────────────


async def _test_malformed_version(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[HeaderEdgeAttempt]:
    """Testa versoes HTTP malformadas."""
    results: list[HeaderEdgeAttempt] = []

    versions: list[tuple[str, str, str]] = [
        ("http_1_3", "HTTP/1.3", "GET /path HTTP/1.3\r\nHost: target.com\r\n\r\n"),
        ("http_2_0", "HTTP/2.0", "GET /path HTTP/2.0\r\nHost: target.com\r\n\r\n"),
        ("http_9_9", "HTTP/9.9", "GET /path HTTP/9.9\r\nHost: target.com\r\n\r\n"),
        ("http_no_version", "sem versao", "GET /path\r\nHost: target.com\r\n\r\n"),
        ("http_3_0", "HTTP/3.0", "GET /path HTTP/3.0\r\nHost: target.com\r\n\r\n"),
    ]

    for technique, desc, raw_req in versions:
        try:
            sock = _create_connection(host, port, timeout, tls)
            try:
                status, response = _send_raw(
                    sock, raw_req.encode("latin-1", errors="replace"), timeout
                )
                vulnerable = (status != b_status) and status != 0
                results.append(
                    HeaderEdgeAttempt(
                        exploit="header_smuggling_payload",
                        tool="curl",
                        technique=technique,
                        category="malformed_version",
                        raw_request=raw_req,
                        status_baseline=b_status,
                        status_test=status,
                        size_baseline=b_size,
                        size_test=len(response),
                        vulnerable=vulnerable,
                        details=f"Version: {desc}, status: {status} (baseline: {b_status})",
                        error="",
                    )
                )
            finally:
                sock.close()
        except Exception as e:
            results.append(
                HeaderEdgeAttempt(
                    technique=technique,
                    category="malformed_version",
                    raw_request=raw_req,
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── Category 138: null_request_byte ────────────────────────────────────────


async def _test_null_request_byte(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[HeaderEdgeAttempt]:
    """Testa injecao de byte null no request."""
    results: list[HeaderEdgeAttempt] = []

    null_payloads: list[tuple[str, str, bytes]] = [
        (
            "null_start",
            "Null byte no inicio do request",
            b"\x00GET / HTTP/1.1\r\nHost: target.com\r\n\r\n",
        ),
        (
            "null_after_method",
            "Null byte apos metodo",
            b"GET\x00 / HTTP/1.1\r\nHost: target.com\r\n\r\n",
        ),
        (
            "null_in_path",
            "Null byte no path",
            b"GET /\x00 HTTP/1.1\r\nHost: target.com\r\n\r\n",
        ),
        (
            "null_after_headers",
            "Null byte apos headers",
            b"GET / HTTP/1.1\r\nHost: target.com\r\n\x00\r\n\r\n",
        ),
        (
            "null_in_host",
            "Null byte no Host header",
            b"GET / HTTP/1.1\r\nHost: target\x00.com\r\n\r\n",
        ),
    ]

    for technique, desc, raw_req in null_payloads:
        try:
            sock = _create_connection(host, port, timeout, tls)
            try:
                status, response = _send_raw(sock, raw_req, timeout)
                vulnerable = (status != b_status) and status != 0
                results.append(
                    HeaderEdgeAttempt(
                        exploit="header_smuggling_payload",
                        tool="curl",
                        technique=technique,
                        category="null_request_byte",
                        raw_request=repr(raw_req),
                        status_baseline=b_status,
                        status_test=status,
                        size_baseline=b_size,
                        size_test=len(response),
                        vulnerable=vulnerable,
                        details=f"{desc}, status: {status} (baseline: {b_status})",
                        error="",
                    )
                )
            finally:
                sock.close()
        except Exception as e:
            results.append(
                HeaderEdgeAttempt(
                    technique=technique,
                    category="null_request_byte",
                    raw_request=desc,
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── Category 139: header_whitespace ────────────────────────────────────────


async def _test_header_whitespace(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[HeaderEdgeAttempt]:
    """Testa whitespace extra em nomes de headers."""
    results: list[HeaderEdgeAttempt] = []

    ws_payloads: list[tuple[str, str, str]] = [
        (
            "space_before_colon",
            "Espaco antes dos dois-pontos",
            "GET / HTTP/1.1\r\nHost : target.com\r\n\r\n",
        ),
        (
            "tab_before_colon",
            "Tab antes dos dois-pontos",
            "GET / HTTP/1.1\r\nHost\t: target.com\r\n\r\n",
        ),
        (
            "space_after_name",
            "Espaco no nome do header",
            "GET / HTTP/1.1\r\nH ost: target.com\r\n\r\n",
        ),
        (
            "tab_after_name",
            "Tab no nome do header",
            "GET / HTTP/1.1\r\nH\\ost: target.com\r\n\r\n",
        ),
        (
            "trailing_space",
            "Espaco trailing no valor",
            "GET / HTTP/1.1\r\nHost: target.com \r\n\r\n",
        ),
    ]

    for technique, desc, raw_req in ws_payloads:
        try:
            sock = _create_connection(host, port, timeout, tls)
            try:
                status, response = _send_raw(
                    sock, raw_req.encode("latin-1", errors="replace"), timeout
                )
                vulnerable = (status != b_status) and status != 0
                results.append(
                    HeaderEdgeAttempt(
                        exploit="header_smuggling_payload",
                        tool="curl",
                        technique=technique,
                        category="header_whitespace",
                        raw_request=raw_req,
                        status_baseline=b_status,
                        status_test=status,
                        size_baseline=b_size,
                        size_test=len(response),
                        vulnerable=vulnerable,
                        details=f"{desc}, status: {status} (baseline: {b_status})",
                        error="",
                    )
                )
            finally:
                sock.close()
        except Exception as e:
            results.append(
                HeaderEdgeAttempt(
                    technique=technique,
                    category="header_whitespace",
                    raw_request=raw_req,
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── Category 140: header_case ──────────────────────────────────────────────


async def _test_header_case(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[HeaderEdgeAttempt]:
    """Testa case sensitivity em headers e metodo."""
    results: list[HeaderEdgeAttempt] = []

    case_payloads: list[tuple[str, str, str]] = [
        (
            "lower_method",
            "metodo em minusculo",
            f"get {path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        ),
        (
            "lower_host",
            "Host em minusculo",
            f"GET {path} HTTP/1.1\r\nhost: {host}\r\n\r\n",
        ),
        (
            "mixed_host",
            "Host com mixed case",
            f"GET {path} HTTP/1.1\r\nHoSt: {host}\r\n\r\n",
        ),
        (
            "upper_path",
            "path em maiusculo",
            f"GET {path.upper()} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        ),
        (
            "random_case",
            "Random case em todos os campos",
            f"GeT {path} hTtP/1.1\r\nhOsT: {host}\r\n\r\n",
        ),
    ]

    for technique, desc, raw_req in case_payloads:
        try:
            sock = _create_connection(host, port, timeout, tls)
            try:
                status, response = _send_raw(
                    sock, raw_req.encode("latin-1", errors="replace"), timeout
                )
                vulnerable = (status != b_status) and status != 0
                results.append(
                    HeaderEdgeAttempt(
                        exploit="header_smuggling_payload",
                        tool="curl",
                        technique=technique,
                        category="header_case",
                        raw_request=raw_req,
                        status_baseline=b_status,
                        status_test=status,
                        size_baseline=b_size,
                        size_test=len(response),
                        vulnerable=vulnerable,
                        details=f"{desc}, status: {status} (baseline: {b_status})",
                        error="",
                    )
                )
            finally:
                sock.close()
        except Exception as e:
            results.append(
                HeaderEdgeAttempt(
                    technique=technique,
                    category="header_case",
                    raw_request=raw_req,
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── Category 141: absolute_uri ─────────────────────────────────────────────


async def _test_absolute_uri(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[HeaderEdgeAttempt]:
    """Testa absolute URI no request line (comportamento proxy)."""
    results: list[HeaderEdgeAttempt] = []

    scheme = "https" if tls else "http"
    absolute_payloads: list[tuple[str, str, str, str]] = [
        (
            "absolute_http",
            "Absolute URI com HTTP",
            f"GET http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            "absolute http://",
        ),
        (
            "absolute_https",
            "Absolute URI com HTTPS",
            f"GET https://{host}:{port}{path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            "absolute https://",
        ),
        (
            "absolute_host_mismatch",
            "Absolute URI com host diferente",
            f"GET http://evil.com{path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            "mismatched host",
        ),
        (
            "absolute_port",
            "Absolute URI com porta",
            f"GET {scheme}://{host}:{port}{path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            "absolute with port",
        ),
        (
            "absolute_path",
            "Absolute URI com path completo",
            f"GET {scheme}://{host}:{port}{path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            "absolute full path",
        ),
    ]

    for technique, desc, raw_req, _label in absolute_payloads:
        try:
            sock = _create_connection(host, port, timeout, tls)
            try:
                status, response = _send_raw(
                    sock, raw_req.encode("latin-1", errors="replace"), timeout
                )
                vulnerable = (status != b_status) and status != 0
                results.append(
                    HeaderEdgeAttempt(
                        exploit="header_smuggling_payload",
                        tool="curl",
                        technique=technique,
                        category="absolute_uri",
                        raw_request=raw_req,
                        status_baseline=b_status,
                        status_test=status,
                        size_baseline=b_size,
                        size_test=len(response),
                        vulnerable=vulnerable,
                        details=f"{desc}, status: {status} (baseline: {b_status})",
                        error="",
                    )
                )
            finally:
                sock.close()
        except Exception as e:
            results.append(
                HeaderEdgeAttempt(
                    technique=technique,
                    category="absolute_uri",
                    raw_request=raw_req,
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── Category 142: http09_request ───────────────────────────────────────────


async def _test_http09_request(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[HeaderEdgeAttempt]:
    """Testa HTTP/0.9 e requests minimos."""
    results: list[HeaderEdgeAttempt] = []

    http09_payloads: list[tuple[str, str, bytes]] = [
        (
            "get_no_headers",
            "GET sem headers",
            f"GET {path}\r\n".encode(),
        ),
        (
            "get_no_version",
            "GET sem versao no request line",
            f"GET {path} HTTP/0.9\r\n".encode(),
        ),
        (
            "post_no_headers",
            "POST sem headers com body",
            f"POST {path}\r\n\r\nhello".encode(),
        ),
        (
            "minimal_request",
            "Request minimimo (method path)",
            f"GET {path}".encode(),
        ),
        (
            "empty_request",
            "Request vazio",
            b"\r\n\r\n",
        ),
    ]

    for technique, desc, raw_req in http09_payloads:
        try:
            sock = _create_connection(host, port, timeout, tls)
            try:
                status, response = _send_raw(sock, raw_req, timeout)
                vulnerable = (status != b_status) and status != 0
                results.append(
                    HeaderEdgeAttempt(
                        exploit="header_smuggling_payload",
                        tool="curl",
                        technique=technique,
                        category="http09_request",
                        raw_request=repr(raw_req),
                        status_baseline=b_status,
                        status_test=status,
                        size_baseline=b_size,
                        size_test=len(response),
                        vulnerable=vulnerable,
                        details=f"{desc}, status: {status} (baseline: {b_status})",
                        error="",
                    )
                )
            finally:
                sock.close()
        except Exception as e:
            results.append(
                HeaderEdgeAttempt(
                    technique=technique,
                    category="http09_request",
                    raw_request=desc,
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── Dispatch ────────────────────────────────────────────────────────────────

_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[HeaderEdgeAttempt]]]
] = {
    "duplicate_headers": _test_duplicate_headers,
    "malformed_version": _test_malformed_version,
    "null_request_byte": _test_null_request_byte,
    "header_whitespace": _test_header_whitespace,
    "header_case": _test_header_case,
    "absolute_uri": _test_absolute_uri,
    "http09_request": _test_http09_request,
}

# ─── Print Results ───────────────────────────────────────────────────────────


def print_results(result: HeaderEdgeResult) -> None:
    """Imprime resultados formatados no terminal."""
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Header & Parsing Edge Cases Test")
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

    categories: dict[str, list[HeaderEdgeAttempt]] = {}
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
            "VULNERABLE — Header/parsing edge cases detected!",
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — No parsing anomalies detected",
        )
    print()


# ─── Main Scan ───────────────────────────────────────────────────────────────


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> HeaderEdgeResult:
    """Executa scan de Header & Parsing Edge Cases."""
    host, path, port, tls = _parse_url(target)

    b_status, b_size = _get_baseline(host, port, path, timeout, tls)

    all_attempts: list[HeaderEdgeAttempt] = []
    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)
        if tester is None:
            continue
        try:
            raw = await tester(host, port, path, timeout, tls, b_status, b_size)
            all_attempts.extend(raw)
        except Exception as e:
            all_attempts.append(
                HeaderEdgeAttempt(
                    technique=f"{cat}_error",
                    category=cat,
                    raw_request="",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]
    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []
    overall = "vulnerable" if vuln_techs else "secure"

    result = HeaderEdgeResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        baseline_status=b_status,
        baseline_size=b_size,
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        issues=issues,
        overall_status=overall,
    )

    print_results(result)

    if output_file:
        write_output(output_file, [asdict(a) for a in all_attempts])

    return result


# ─── CLI ─────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Constrói parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-headeredge",
        description="Header & Parsing Edge Cases — Duplicate, Malformed, Null, Whitespace, Case, Absolute, HTTP/0.9",
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
        banner_fn=create_banner(_BANNER_LINES, "Header & Parsing Edge Cases"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="headeredge> ",
        description="Teste de Header & Parsing Edge Cases (Duplicate, Malformed, Null, Whitespace, Case, Absolute, HTTP/0.9).",
        example="https://target.com -c duplicate_headers null_request_byte",
        contextual_help=(
            "Categorias disponiveis:\n"
            "  duplicate_headers  — Host/CL/TE duplicado\n"
            "  malformed_version  — HTTP/1.3, 2.0, 9.9\n"
            "  null_request_byte  — byte null no request\n"
            "  header_whitespace  — espaco extra em headers\n"
            "  header_case        — case sensitivity\n"
            "  absolute_uri       — GET http://b.com/path\n"
            "  http09_request     — request sem headers/versao"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
