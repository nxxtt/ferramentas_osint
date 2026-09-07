#!/usr/bin/env python3

"""Modulo de testes de TLS Fingerprinting.



Testa fingerprinting TLS via construcao raw de ClientHello:

  - TLS Fingerprint: JA3/JA4 hash, cipher order, extensions, ALPN

  - TLS Replay: ClientHello de browsers conhecidos (Chrome, Firefox, Safari, Edge)

  - Key Exchange: RSA, DHE, ECDHE, DH fraco, X25519

  - Cipher Audit: deprecated, export, null, MAC fraco, key size



IMPORTANTE: Usa raw sockets com struct.pack para construir ClientHello

e parsear ServerHello — sem biblioteca TLS externa.

"""

from __future__ import annotations

import argparse
import hashlib
import logging
import secrets
import socket
import ssl
import struct
import time
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_banner,
    init_scanner,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.tlsfingerprint")

# ─── Banner ──────────────────────────────────────────────────────────────────


_BANNER_LINES: str = (
    "  ______                _                      __   __  _           \n"
    " /_  __/__  _________ (_)___  ___  ____ _____/ /__/ /_(_)_________\n"
    "  / / / _ \\/ ___/ __ \\/ / __ \\/ _ \\/ __ `/ __/ __/ / ___/ ___/ _ \\\n"
    " / / /  __/ /  / /_/ / / / / /  __/ /_/ / /_/ /_/ / /__(__  )  __/\n"
    "/_/  \\___/_/   \\____/_/_/ /_/\\___/\\__,_/\\__/\\__/_/\\___/____/\\___/ \n"
)


# ─── TLS Constants ──────────────────────────────────────────────────────────


_GREASE_VALUES = frozenset(
    {
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    }
)


# TLS 1.3 Cipher Suites

TLS_AES_128_GCM_SHA256 = 0x1301

TLS_AES_256_GCM_SHA384 = 0x1302

TLS_CHACHA20_POLY1305_SHA256 = 0x1303

TLS_AES_128_CCM_SHA256 = 0x1304

TLS_AES_128_CCM_8_SHA256 = 0x1305


# TLS 1.2 ECDHE Cipher Suites

ECDHE_ECDSA_AES_128_GCM_SHA256 = 0xC02B

ECDHE_RSA_AES_128_GCM_SHA256 = 0xC02F

ECDHE_ECDSA_AES_256_GCM_SHA384 = 0xC02C

ECDHE_RSA_AES_256_GCM_SHA384 = 0xC030

ECDHE_RSA_CHACHA20_POLY1305 = 0xCCA8

ECDHE_ECDSA_CHACHA20_POLY1305 = 0xCCA9

ECDHE_RSA_AES_128_CBC_SHA256 = 0xC027

ECDHE_RSA_AES_128_CBC_SHA = 0xC013

ECDHE_ECDSA_AES_128_CBC_SHA256 = 0xC023

ECDHE_ECDSA_AES_128_CBC_SHA = 0xC009

DHE_RSA_AES_128_GCM_SHA256 = 0x009E

DHE_RSA_AES_256_GCM_SHA384 = 0x009F

DHE_RSA_AES_128_CBC_SHA256 = 0x0067

DHE_RSA_AES_128_CBC_SHA = 0x0033

RSA_AES_128_GCM_SHA256 = 0x009C

RSA_AES_256_GCM_SHA384 = 0x009D

RSA_AES_128_CBC_SHA256 = 0x003C

RSA_AES_128_CBC_SHA = 0x002F

RSA_AES_256_CBC_SHA256 = 0x003D

RSA_AES_256_CBC_SHA = 0x0035

RSA_3DES_EDE_CBC_SHA = 0x000A

RSA_RC4_128_SHA = 0x0005

RSA_RC4_128_MD5 = 0x0004

RSA_NULL_SHA = 0x00FF

RSA_NULL_MD5 = 0x00FE

RSA_EXPORT_RC4_40_MD5 = 0x0003

RSA_EXPORT_RC2_CBC_40_MD5 = 0x0006


# Named Groups

NAMED_GROUP_X25519 = 0x001D

NAMED_GROUP_SECP256R1 = 0x0017

NAMED_GROUP_SECP384R1 = 0x0018

NAMED_GROUP_SECP521R1 = 0x0019

NAMED_GROUP_X448 = 0x001E

NAMED_GROUP_FFDHE2048 = 0x0100

NAMED_GROUP_FFDHE3072 = 0x0101

NAMED_GROUP_FFDHE4096 = 0x0102


# Weak cipher sets

_WEAK_CIPHERS = frozenset(
    {
        RSA_RC4_128_SHA,
        RSA_RC4_128_MD5,
        RSA_3DES_EDE_CBC_SHA,
        RSA_EXPORT_RC4_40_MD5,
        RSA_EXPORT_RC2_CBC_40_MD5,
    }
)

_NULL_CIPHERS = frozenset({RSA_NULL_SHA, RSA_NULL_MD5})

_EXPORT_CIPHERS = frozenset({RSA_EXPORT_RC4_40_MD5, RSA_EXPORT_RC2_CBC_40_MD5})

_DES_CIPHERS = frozenset({RSA_3DES_EDE_CBC_SHA})


# Cipher metadata: (name, bits, forward_secrecy, mac_strength)

_CIPHER_INFO: dict[int, tuple[str, int, bool, str]] = {
    TLS_AES_128_GCM_SHA256: ("TLS_AES_128_GCM_SHA256", 128, True, "AEAD"),
    TLS_AES_256_GCM_SHA384: ("TLS_AES_256_GCM_SHA384", 256, True, "AEAD"),
    TLS_CHACHA20_POLY1305_SHA256: ("TLS_CHACHA20_POLY1305_SHA256", 256, True, "AEAD"),
    ECDHE_ECDSA_AES_128_GCM_SHA256: (
        "ECDHE_ECDSA_AES_128_GCM_SHA256",
        128,
        True,
        "AEAD",
    ),
    ECDHE_RSA_AES_128_GCM_SHA256: ("ECDHE_RSA_AES_128_GCM_SHA256", 128, True, "AEAD"),
    ECDHE_ECDSA_AES_256_GCM_SHA384: (
        "ECDHE_ECDSA_AES_256_GCM_SHA384",
        256,
        True,
        "AEAD",
    ),
    ECDHE_RSA_AES_256_GCM_SHA384: ("ECDHE_RSA_AES_256_GCM_SHA384", 256, True, "AEAD"),
    ECDHE_RSA_CHACHA20_POLY1305: ("ECDHE_RSA_CHACHA20_POLY1305", 256, True, "AEAD"),
    ECDHE_ECDSA_CHACHA20_POLY1305: ("ECDHE_ECDSA_CHACHA20_POLY1305", 256, True, "AEAD"),
    ECDHE_RSA_AES_128_CBC_SHA256: ("ECDHE_RSA_AES_128_CBC_SHA256", 128, True, "SHA256"),
    ECDHE_RSA_AES_128_CBC_SHA: ("ECDHE_RSA_AES_128_CBC_SHA", 128, True, "SHA1"),
    ECDHE_ECDSA_AES_128_CBC_SHA256: (
        "ECDHE_ECDSA_AES_128_CBC_SHA256",
        128,
        True,
        "SHA256",
    ),
    ECDHE_ECDSA_AES_128_CBC_SHA: ("ECDHE_ECDSA_AES_128_CBC_SHA", 128, True, "SHA1"),
    DHE_RSA_AES_128_GCM_SHA256: ("DHE_RSA_AES_128_GCM_SHA256", 128, True, "AEAD"),
    DHE_RSA_AES_256_GCM_SHA384: ("DHE_RSA_AES_256_GCM_SHA384", 256, True, "AEAD"),
    DHE_RSA_AES_128_CBC_SHA256: ("DHE_RSA_AES_128_CBC_SHA256", 128, True, "SHA256"),
    DHE_RSA_AES_128_CBC_SHA: ("DHE_RSA_AES_128_CBC_SHA", 128, True, "SHA1"),
    RSA_AES_128_GCM_SHA256: ("RSA_AES_128_GCM_SHA256", 128, False, "AEAD"),
    RSA_AES_256_GCM_SHA384: ("RSA_AES_256_GCM_SHA384", 256, False, "AEAD"),
    RSA_AES_128_CBC_SHA256: ("RSA_AES_128_CBC_SHA256", 128, False, "SHA256"),
    RSA_AES_128_CBC_SHA: ("RSA_AES_128_CBC_SHA", 128, False, "SHA1"),
    RSA_AES_256_CBC_SHA256: ("RSA_AES_256_CBC_SHA256", 256, False, "SHA256"),
    RSA_AES_256_CBC_SHA: ("RSA_AES_256_CBC_SHA", 256, False, "SHA1"),
    RSA_3DES_EDE_CBC_SHA: ("RSA_3DES_EDE_CBC_SHA", 112, False, "SHA1"),
    RSA_RC4_128_SHA: ("RSA_RC4_128_SHA", 128, False, "SHA1"),
    RSA_RC4_128_MD5: ("RSA_RC4_128_MD5", 128, False, "MD5"),
    RSA_NULL_SHA: ("RSA_NULL_SHA", 0, False, "SHA1"),
    RSA_NULL_MD5: ("RSA_NULL_MD5", 0, False, "MD5"),
    RSA_EXPORT_RC4_40_MD5: ("RSA_EXPORT_RC4_40_MD5", 40, False, "MD5"),
    RSA_EXPORT_RC2_CBC_40_MD5: ("RSA_EXPORT_RC2_CBC_40_MD5", 40, False, "MD5"),
}


# ─── Browser Profiles ───────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class BrowserProfile:
    """Perfil de ClientHello de um browser."""

    name: str

    ciphers: list[int]

    extensions: list[int]

    groups: list[int]

    point_formats: list[int]

    sig_algorithms: list[int]

    alpn: list[str]


CHROME_PROFILE = BrowserProfile(
    name="Chrome 120+",
    ciphers=[
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        ECDHE_ECDSA_AES_128_GCM_SHA256,
        ECDHE_RSA_AES_128_GCM_SHA256,
        ECDHE_ECDSA_AES_256_GCM_SHA384,
        ECDHE_RSA_AES_256_GCM_SHA384,
        ECDHE_ECDSA_CHACHA20_POLY1305,
        ECDHE_RSA_CHACHA20_POLY1305,
        ECDHE_RSA_AES_128_CBC_SHA256,
        ECDHE_ECDSA_AES_128_CBC_SHA256,
        ECDHE_RSA_AES_128_CBC_SHA,
        ECDHE_ECDSA_AES_128_CBC_SHA,
    ],
    extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513],
    groups=[NAMED_GROUP_X25519, NAMED_GROUP_SECP256R1, NAMED_GROUP_SECP384R1],
    point_formats=[0],
    sig_algorithms=[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
    alpn=["h2", "http/1.1"],
)


FIREFOX_PROFILE = BrowserProfile(
    name="Firefox 121+",
    ciphers=[
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        ECDHE_ECDSA_AES_128_GCM_SHA256,
        ECDHE_RSA_AES_128_GCM_SHA256,
        ECDHE_ECDSA_AES_256_GCM_SHA384,
        ECDHE_RSA_AES_256_GCM_SHA384,
        ECDHE_ECDSA_CHACHA20_POLY1305,
        ECDHE_RSA_CHACHA20_POLY1305,
        ECDHE_RSA_AES_128_CBC_SHA256,
        ECDHE_ECDSA_AES_128_CBC_SHA256,
        ECDHE_RSA_AES_128_CBC_SHA,
        ECDHE_ECDSA_AES_128_CBC_SHA,
    ],
    extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 27, 17513, 28, 29],
    groups=[NAMED_GROUP_X25519, NAMED_GROUP_SECP256R1, NAMED_GROUP_SECP384R1],
    point_formats=[0],
    sig_algorithms=[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
    alpn=["h2", "http/1.1"],
)


SAFARI_PROFILE = BrowserProfile(
    name="Safari 17+",
    ciphers=[
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        ECDHE_ECDSA_AES_128_GCM_SHA256,
        ECDHE_RSA_AES_128_GCM_SHA256,
        ECDHE_ECDSA_AES_256_GCM_SHA384,
        ECDHE_RSA_AES_256_GCM_SHA384,
        ECDHE_ECDSA_CHACHA20_POLY1305,
        ECDHE_RSA_CHACHA20_POLY1305,
    ],
    extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27],
    groups=[NAMED_GROUP_X25519, NAMED_GROUP_SECP256R1, NAMED_GROUP_SECP384R1],
    point_formats=[0],
    sig_algorithms=[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
    alpn=["h2", "http/1.1"],
)


EDGE_PROFILE = BrowserProfile(
    name="Edge 120+",
    ciphers=[
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        ECDHE_ECDSA_AES_128_GCM_SHA256,
        ECDHE_RSA_AES_128_GCM_SHA256,
        ECDHE_ECDSA_AES_256_GCM_SHA384,
        ECDHE_RSA_AES_256_GCM_SHA384,
        ECDHE_ECDSA_CHACHA20_POLY1305,
        ECDHE_RSA_CHACHA20_POLY1305,
        ECDHE_RSA_AES_128_CBC_SHA256,
        ECDHE_ECDSA_AES_128_CBC_SHA256,
        ECDHE_RSA_AES_128_CBC_SHA,
        ECDHE_ECDSA_AES_128_CBC_SHA,
    ],
    extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513],
    groups=[NAMED_GROUP_X25519, NAMED_GROUP_SECP256R1, NAMED_GROUP_SECP384R1],
    point_formats=[0],
    sig_algorithms=[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
    alpn=["h2", "http/1.1"],
)


CURL_PROFILE = BrowserProfile(
    name="curl/OpenSSL",
    ciphers=[
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        ECDHE_ECDSA_AES_128_GCM_SHA256,
        ECDHE_RSA_AES_128_GCM_SHA256,
        ECDHE_ECDSA_AES_256_GCM_SHA384,
        ECDHE_RSA_AES_256_GCM_SHA384,
        ECDHE_ECDSA_CHACHA20_POLY1305,
        ECDHE_RSA_CHACHA20_POLY1305,
        DHE_RSA_AES_128_GCM_SHA256,
        DHE_RSA_AES_256_GCM_SHA384,
    ],
    extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43],
    groups=[
        NAMED_GROUP_X25519,
        NAMED_GROUP_SECP256R1,
        NAMED_GROUP_SECP384R1,
        NAMED_GROUP_FFDHE2048,
    ],
    point_formats=[0],
    sig_algorithms=[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
    alpn=["h2", "http/1.1"],
)


_DEFAULT_CIPHERS = [
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    ECDHE_ECDSA_AES_128_GCM_SHA256,
    ECDHE_RSA_AES_128_GCM_SHA256,
    ECDHE_ECDSA_AES_256_GCM_SHA384,
    ECDHE_RSA_AES_256_GCM_SHA384,
    ECDHE_ECDSA_CHACHA20_POLY1305,
    ECDHE_RSA_CHACHA20_POLY1305,
    ECDHE_RSA_AES_128_CBC_SHA256,
    ECDHE_ECDSA_AES_128_CBC_SHA256,
    ECDHE_RSA_AES_128_CBC_SHA,
    ECDHE_ECDSA_AES_128_CBC_SHA,
    DHE_RSA_AES_128_GCM_SHA256,
    DHE_RSA_AES_256_GCM_SHA384,
    RSA_AES_128_GCM_SHA256,
    RSA_AES_256_GCM_SHA384,
    RSA_AES_128_CBC_SHA256,
    RSA_AES_128_CBC_SHA,
]


# ─── Category Map ────────────────────────────────────────────────────────────


_CATEGORY_MAP: dict[str, list[str]] = {
    "tls_fingerprint": [
        "ja3_hash",
        "ja4_draft",
        "cipher_order",
        "extensions_list",
        "alpn_fingerprint",
    ],
    "tls_replay": [
        "chrome_profile",
        "firefox_profile",
        "safari_profile",
        "edge_profile",
        "curl_default",
    ],
    "key_exchange": [
        "rsa_keyexchange",
        "dhe_keyexchange",
        "ecdhe_keyexchange",
        "weak_dh_group",
        "x25519_support",
    ],
    "cipher_audit": [
        "deprecated_ciphers",
        "export_ciphers",
        "null_ciphers",
        "weak_mac",
        "large_key_check",
    ],
}


# ─── TLS Extension Builders ─────────────────────────────────────────────────


def _sni_extension(hostname: str) -> bytes:
    """Constrói extensão SNI (server_name)."""

    name = hostname.encode("ascii")

    server_name = b"\x00" + struct.pack(">H", len(name)) + name

    sni_list = struct.pack(">H", len(server_name)) + server_name

    return struct.pack(">HH", 0x0000, len(sni_list)) + sni_list


def _supported_groups_extension(groups: list[int]) -> bytes:
    """Constrói extensão supported_groups (elliptic curves)."""

    data = b"".join(struct.pack(">H", g) for g in groups)

    return struct.pack(">HH", 0x000A, len(data)) + data


def _ec_point_formats_extension(formats: list[int] | None = None) -> bytes:
    """Constrói extensão ec_point_formats."""

    fmts = formats if formats else [0]

    data = bytes([len(fmts)]) + bytes(fmts)

    return struct.pack(">HH", 0x000B, len(data)) + data


def _signature_algorithms_extension(sig_algs: list[int]) -> bytes:
    """Constrói extensão signature_algorithms."""

    data = b"".join(struct.pack(">H", sa) for sa in sig_algs)

    wrapped = struct.pack(">H", len(data)) + data

    return struct.pack(">HH", 0x000D, len(wrapped)) + wrapped


def _supported_versions_extension(versions: list[int] | None = None) -> bytes:
    """Constrói extensão supported_versions."""

    vers = versions or [0x0304, 0x0303]  # TLS 1.3, TLS 1.2

    data = bytes([len(vers) * 2]) + b"".join(struct.pack(">H", v) for v in vers)

    return struct.pack(">HH", 0x002B, len(data)) + data


def _key_share_extension(groups: list[tuple[int, bytes]]) -> bytes:
    """Constrói extensão key_share."""

    entries = b""

    for group_id, pubkey in groups:
        entries += struct.pack(">HH", group_id, len(pubkey)) + pubkey

    return struct.pack(">HH", 0x0033, len(entries)) + entries


def _alpn_extension(protocols: list[str]) -> bytes:
    """Constrói extensão ALPN."""

    alpn_list = b""

    for proto in protocols:
        p = proto.encode("ascii")

        alpn_list += bytes([len(p)]) + p

    wrapped = struct.pack(">H", len(alpn_list)) + alpn_list

    return struct.pack(">HH", 0x0010, len(wrapped)) + wrapped


def _padding_extension(target_len: int, current_len: int) -> bytes:
    """Constrói extensão de padding para atingir tamanho alvo."""

    if current_len >= target_len:
        return b""

    pad_len = target_len - current_len - 4

    if pad_len <= 0:
        return b""

    data = b"\x00" * pad_len

    return struct.pack(">HH", 0x0015, len(data)) + data


# ─── ClientHello Builder ────────────────────────────────────────────────────


def _build_client_hello(
    hostname: str,
    ciphers: list[int] | None = None,
    extensions: list[int] | None = None,
    groups: list[int] | None = None,
    sig_algorithms: list[int] | None = None,
    alpn: list[str] | None = None,
    tls_version: int = 0x0304,
) -> tuple[bytes, dict[str, Any]]:
    """Constrói ClientHello raw. Retorna (bytes, metadata_dict)."""

    cipher_list = ciphers or _DEFAULT_CIPHERS

    group_list = groups or [
        NAMED_GROUP_X25519,
        NAMED_GROUP_SECP256R1,
        NAMED_GROUP_SECP384R1,
    ]

    sig_alg_list = sig_algorithms or [
        0x0403,
        0x0804,
        0x0401,
        0x0503,
        0x0805,
        0x0501,
        0x0806,
        0x0601,
    ]

    alpn_list = alpn or ["h2", "http/1.1"]

    # Client Version (TLS 1.2 for compat, real version in extension)

    client_version = struct.pack(">H", 0x0303)

    # Random (32 bytes)

    client_random = secrets.token_bytes(32)

    # Session ID (32 bytes random)

    session_id = secrets.token_bytes(32)

    session_id_field = bytes([len(session_id)]) + session_id

    # Cipher Suites

    cipher_bytes = b"".join(struct.pack(">H", c) for c in cipher_list)

    cipher_field = struct.pack(">H", len(cipher_bytes)) + cipher_bytes

    # Compression (null only)

    compression = b"\x01\x00"

    # Extensions

    ext_data = b""

    ext_data += _sni_extension(hostname)

    ext_data += _supported_groups_extension(group_list)

    ext_data += _ec_point_formats_extension()

    ext_data += _signature_algorithms_extension(sig_alg_list)

    ext_data += _supported_versions_extension(
        [tls_version] if tls_version == 0x0303 else [tls_version, 0x0303]
    )

    x25519_key = secrets.token_bytes(32)

    ext_data += _key_share_extension([(NAMED_GROUP_X25519, x25519_key)])

    ext_data += _alpn_extension(alpn_list)

    ext_field = struct.pack(">H", len(ext_data)) + ext_data

    # Handshake body

    handshake_body = (
        client_version
        + client_random
        + session_id_field
        + cipher_field
        + compression
        + ext_field
    )

    # Handshake header (type=0x01, 3-byte length)

    handshake_header = b"\x01" + len(handshake_body).to_bytes(3, "big")

    # Record header (type=0x16, version=0x0301, 2-byte length)

    record_data = handshake_header + handshake_body

    record_header = struct.pack(">BHH", 0x16, 0x0301, len(record_data))

    # Metadata for JA3/JA4

    metadata = {
        "legacy_version": 771,  # 0x0303
        "ciphers": cipher_list,
        "extensions": extensions
        or [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27],
        "groups": group_list,
        "point_formats": [0],
        "sig_algorithms": sig_alg_list,
        "alpn": alpn_list,
        "tls_version": tls_version,
        "sni": hostname,
    }

    return record_header + record_data, metadata


def _build_client_hello_from_profile(
    hostname: str,
    profile: BrowserProfile,
) -> tuple[bytes, dict[str, Any]]:
    """Constrói ClientHello a partir de um BrowserProfile."""

    return _build_client_hello(
        hostname=hostname,
        ciphers=profile.ciphers,
        extensions=profile.extensions,
        groups=profile.groups,
        sig_algorithms=profile.sig_algorithms,
        alpn=profile.alpn,
    )


# ─── ServerHello Parser ─────────────────────────────────────────────────────


def _parse_server_hello(data: bytes) -> dict[str, Any]:
    """Parse ServerHello raw. Retorna dict com version, cipher_suite, extensions."""

    result: dict[str, Any] = {
        "version": 0,
        "cipher_suite": 0,
        "cipher_name": "UNKNOWN",
        "extensions": {},
        "alpn": None,
        "error": None,
    }

    try:
        if len(data) < 9:
            result["error"] = "response too short"

            return result

        # Skip record header (5 bytes)

        offset = 5

        # Handshake type + length (4 bytes)

        hs_type = data[offset]

        offset += 1

        if hs_type != 0x02:
            result["error"] = f"not ServerHello (type=0x{hs_type:02X})"

            return result

        _hs_len = int.from_bytes(data[offset : offset + 3], "big")

        offset += 3

        # Server Version

        result["version"] = struct.unpack(">H", data[offset : offset + 2])[0]

        offset += 2

        # Server Random (32 bytes)

        offset += 32

        # Session ID

        sid_len = data[offset]

        offset += 1 + sid_len

        # Cipher Suite

        result["cipher_suite"] = struct.unpack(">H", data[offset : offset + 2])[0]

        result["cipher_name"] = _CIPHER_INFO.get(
            result["cipher_suite"],
            (f"UNKNOWN_0x{result['cipher_suite']:04X}", 0, False, "?"),
        )[0]

        offset += 2

        # Compression

        offset += 1

        # Extensions

        if offset + 2 <= len(data):
            ext_len = struct.unpack(">H", data[offset : offset + 2])[0]

            offset += 2

            ext_end = offset + ext_len

            while offset + 4 <= ext_end:
                ext_type = struct.unpack(">H", data[offset : offset + 2])[0]

                ext_len_val = struct.unpack(">H", data[offset + 2 : offset + 4])[0]

                offset += 4

                ext_data = data[offset : offset + ext_len_val]

                result["extensions"][ext_type] = ext_data

                offset += ext_len_val

            # Extract ALPN

            if 0x0010 in result["extensions"]:
                alpn_data = result["extensions"][0x0010]

                if len(alpn_data) >= 2:
                    list_len = struct.unpack(">H", alpn_data[:2])[0]

                    if len(alpn_data) >= 2 + list_len and list_len > 0:
                        proto_len = alpn_data[2]

                        if len(alpn_data) >= 3 + proto_len:
                            result["alpn"] = alpn_data[3 : 3 + proto_len].decode(
                                "ascii", errors="replace"
                            )

    except (struct.error, IndexError) as exc:
        result["error"] = str(exc)[:100]

    return result


# ─── JA3/JA4 Computation ────────────────────────────────────────────────────


def _compute_ja3(metadata: dict[str, Any]) -> str:
    """Calcula JA3 hash (MD5) a partir dos dados do ClientHello."""

    version = metadata.get("legacy_version", 771)

    ciphers = [c for c in metadata.get("ciphers", []) if c not in _GREASE_VALUES]

    extensions = [e for e in metadata.get("extensions", []) if e not in _GREASE_VALUES]

    groups = [g for g in metadata.get("groups", []) if g not in _GREASE_VALUES]

    point_formats = metadata.get("point_formats", [])

    cipher_str = "-".join(str(c) for c in ciphers)

    ext_str = "-".join(str(e) for e in extensions)

    group_str = "-".join(str(g) for g in groups)

    format_str = "-".join(str(f) for f in point_formats)

    ja3_string = f"{version},{cipher_str},{ext_str},{group_str},{format_str}"

    return hashlib.md5(ja3_string.encode()).hexdigest()


def _compute_ja4(metadata: dict[str, Any]) -> str:
    """Calcula JA4 fingerprint (mais granular que JA3)."""

    tls_ver = "13" if metadata.get("tls_version", 0x0304) == 0x0304 else "12"

    sni = "d" if metadata.get("sni") else "i"

    ciphers = sorted(
        [c for c in metadata.get("ciphers", []) if c not in _GREASE_VALUES]
    )

    extensions = sorted(
        [e for e in metadata.get("extensions", []) if e not in _GREASE_VALUES]
    )

    num_ciphers = f"{len(ciphers):02d}"

    num_exts = f"{len(extensions):02d}"

    alpn_list = metadata.get("alpn", [])

    _ALPN_TO_JA4 = {
        "http/1.1": "h1",
        "http/1.0": "h1",
        "h2": "h2",
        "http/2": "h2",
        "h2c": "h2",
        "h3": "h3",
        "http/3": "h3",
        "spdy/3.1": "h3",
    }

    _mapped = _ALPN_TO_JA4.get(alpn_list[0], "00") if alpn_list else "00"

    alpn_proto = _mapped[:2].ljust(2, "0")

    part_a = f"t{tls_ver}{sni}{num_ciphers}{num_exts}{alpn_proto}"

    cipher_str = ",".join(f"{c:04d}" for c in ciphers)

    part_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

    ext_str = ",".join(f"{e:04d}" for e in extensions)

    sig_algs = metadata.get("sig_algorithms", [])

    if sig_algs:
        sig_str = ",".join(f"{s:04d}" for s in sig_algs)

        ext_str += "|" + sig_str

    part_c = hashlib.sha256(ext_str.encode()).hexdigest()[:12]

    return f"{part_a}_{part_b}_{part_c}"


# ─── Connection Helpers ──────────────────────────────────────────────────────


def _parse_url(url: str) -> tuple[str, str, int, bool]:
    """Extrai host, path, port, tls de uma URL."""

    parsed = urlparse(url)

    host = parsed.hostname or ""

    path = parsed.path or "/"

    if parsed.query:
        path += f"?{parsed.query}"

    scheme = parsed.scheme.lower()

    tls = scheme in ("https", "wss")

    port = parsed.port or (443 if tls else 80)

    return host, path, port, tls


def _send_raw_tls(
    host: str,
    port: int,
    timeout: float,
    client_hello: bytes,
) -> tuple[bytes, float]:
    """Envia ClientHello raw e retorna (response_bytes, rtt_ms)."""

    sock = socket.create_connection((host, port), timeout=timeout)

    try:
        start = time.time()

        sock.sendall(client_hello)

        sock.settimeout(timeout)

        response = b""

        while True:
            try:
                chunk = sock.recv(4096)

                if not chunk:
                    break

                response += chunk

                if len(response) >= 5:
                    rec_len = struct.unpack(">H", response[3:5])[0]

                    if len(response) >= 5 + rec_len:
                        break

            except TimeoutError, OSError:
                break

        rtt = (time.time() - start) * 1000

        return response, rtt

    finally:
        sock.close()


def _create_tls_socket(
    host: str,
    port: int,
    timeout: float,
    ciphers: str | None = None,
    alpn: list[str] | None = None,
) -> ssl.SSLSocket:
    """Cria socket TLS usando ssl module (para enumeracao de ciphers)."""

    sock = socket.create_connection((host, port), timeout=timeout)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    ctx.check_hostname = False

    ctx.verify_mode = ssl.CERT_NONE

    if ciphers:
        ctx.set_ciphers(ciphers)

    if alpn:
        ctx.set_alpn_protocols(alpn)

    return ctx.wrap_socket(sock, server_hostname=host)


def _probe_cipher(
    host: str,
    port: int,
    timeout: float,
    cipher_name: str,
) -> tuple[bool, str]:
    """Testa se servidor aceita um cipher específico. Retorna (accepted, info)."""

    try:
        sock = _create_tls_socket(host, port, timeout, ciphers=cipher_name)

        try:
            negotiated = sock.cipher()

            version = sock.version()

            return True, f"{version}/{negotiated[0] if negotiated else '?'}"

        finally:
            sock.close()

    except ssl.SSLError as exc:
        return False, str(exc)[:80]

    except Exception as exc:
        return False, str(exc)[:80]


def _get_cert_info(
    host: str,
    port: int,
    timeout: float,
) -> dict[str, Any]:
    """Obtém informações do certificado TLS do servidor."""

    try:
        sock = _create_tls_socket(host, port, timeout)

        try:
            cert = sock.getpeercert()

            cipher = sock.cipher()

            version = sock.version()

            alpn = sock.selected_alpn_protocol()

            shared = sock.shared_ciphers()

            subject: dict[str, str] = {}

            issuer: dict[str, str] = {}

            not_after = ""

            if cert:
                for tup in cert.get("subject", ()):
                    if tup:
                        subject[tup[0][0]] = tup[0][1]

                for tup in cert.get("issuer", ()):
                    if tup:
                        issuer[tup[0][0]] = tup[0][1]

                not_after = cert.get("notAfter", "") or ""

            return {
                "subject": subject,
                "issuer": issuer,
                "not_after": not_after,
                "cipher": cipher[0] if cipher else "unknown",
                "cipher_bits": cipher[2] if cipher else 0,
                "version": version or "unknown",
                "alpn": alpn,
                "shared_ciphers_count": len(shared) if shared else 0,
            }

        finally:
            sock.close()

    except Exception as exc:
        return {"error": str(exc)[:100]}


# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TLSFingerprintAttempt:
    """Tentativa individual de TLS fingerprinting."""

    technique: str

    category: str

    description: str

    ja3: str

    ja4: str

    cipher_suite: str

    tls_version: str

    alpn: str

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class TLSFingerprintResult:
    """Resultado consolidado do scan."""

    target: str

    host: str

    port: int

    tls: bool

    server_cipher: str

    server_version: str

    ja3_hash: str

    ja4_hash: str

    attempts: list[TLSFingerprintAttempt]

    vulnerable_techniques: list[str]

    issues: list[str]

    overall_status: str


# ─── Category 148: tls_fingerprint ──────────────────────────────────────────


async def _test_tls_fingerprint(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[TLSFingerprintAttempt]:
    """Testa fingerprint TLS: JA3/JA4, cipher order, extensions, ALPN."""

    results: list[TLSFingerprintAttempt] = []

    techniques = [
        ("ja3_hash", "JA3 fingerprint hash (server-side)"),
        ("ja4_draft", "JA4 fingerprint (granular)"),
        ("cipher_order", "Cipher order respect"),
        ("extensions_list", "Extensions enumeration"),
        ("alpn_fingerprint", "ALPN fingerprint"),
    ]

    # Build default ClientHello

    client_hello, metadata = _build_client_hello(host)

    try:
        response, rtt = _send_raw_tls(host, port, timeout, client_hello)

        server_hello = _parse_server_hello(response)

    except Exception as exc:
        for tech, desc in techniques:
            results.append(
                TLSFingerprintAttempt(
                    technique=tech,
                    category="tls_fingerprint",
                    description=desc,
                    ja3="",
                    ja4="",
                    cipher_suite="",
                    tls_version="",
                    alpn="",
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                )
            )

        return results

    ja3 = _compute_ja3(metadata)

    ja4 = _compute_ja4(metadata)

    cipher_name = server_hello.get("cipher_name", "UNKNOWN")

    version = f"0x{server_hello.get('version', 0):04X}"

    alpn = server_hello.get("alpn") or "none"

    ext_count = len(server_hello.get("extensions", {}))

    for tech, desc in techniques:
        if tech == "ja3_hash":
            details = f"JA3: {ja3} (RTT: {rtt:.1f}ms)"

        elif tech == "ja4_draft":
            details = f"JA4: {ja4}"

        elif tech == "cipher_order":
            details = f"Server chose: {cipher_name}"

        elif tech == "extensions_list":
            details = f"{ext_count} extensions: {list(server_hello.get('extensions', {}).keys())}"

        elif tech == "alpn_fingerprint":
            details = f"ALPN: {alpn}"

        else:  # pragma: no cover
            details = ""

        results.append(
            TLSFingerprintAttempt(
                technique=tech,
                category="tls_fingerprint",
                description=desc,
                ja3=ja3,
                ja4=ja4,
                cipher_suite=cipher_name,
                tls_version=version,
                alpn=alpn,
                vulnerable=False,
                details=details,
                error="",
            )
        )

    return results


# ─── Category 149: tls_replay ──────────────────────────────────────────────


async def _test_tls_replay(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[TLSFingerprintAttempt]:
    """Testa replay de TLS fingerprint de browsers conhecidos."""

    results: list[TLSFingerprintAttempt] = []

    profiles = [
        ("chrome_profile", "Chrome 120+ fingerprint", CHROME_PROFILE),
        ("firefox_profile", "Firefox 121+ fingerprint", FIREFOX_PROFILE),
        ("safari_profile", "Safari 17+ fingerprint", SAFARI_PROFILE),
        ("edge_profile", "Edge 120+ fingerprint", EDGE_PROFILE),
        ("curl_default", "curl/OpenSSL fingerprint", CURL_PROFILE),
    ]

    for tech, desc, profile in profiles:
        try:
            client_hello, metadata = _build_client_hello_from_profile(host, profile)

            response, rtt = _send_raw_tls(host, port, timeout, client_hello)

            server_hello = _parse_server_hello(response)

            ja3 = _compute_ja3(metadata)

            ja4 = _compute_ja4(metadata)

            cipher_name = server_hello.get("cipher_name", "UNKNOWN")

            version = f"0x{server_hello.get('version', 0):04X}"

            alpn = server_hello.get("alpn") or "none"

            accepted = not server_hello.get("error")

            details = f"Accepted: {accepted}, cipher: {cipher_name}, RTT: {rtt:.1f}ms"

            results.append(
                TLSFingerprintAttempt(
                    technique=tech,
                    category="tls_replay",
                    description=desc,
                    ja3=ja3,
                    ja4=ja4,
                    cipher_suite=cipher_name,
                    tls_version=version,
                    alpn=alpn,
                    vulnerable=False,
                    details=details,
                    error=server_hello.get("error") or "",
                )
            )

        except Exception as exc:
            results.append(
                TLSFingerprintAttempt(
                    technique=tech,
                    category="tls_replay",
                    description=desc,
                    ja3="",
                    ja4="",
                    cipher_suite="",
                    tls_version="",
                    alpn="",
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                )
            )

    return results


# ─── Category 150: key_exchange ─────────────────────────────────────────────


async def _test_key_exchange(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[TLSFingerprintAttempt]:
    """Testa key exchange: RSA, DHE, ECDHE, DH fraco, X25519."""

    results: list[TLSFingerprintAttempt] = []

    techniques = [
        ("rsa_keyexchange", "RSA key exchange (no Forward Secrecy)", "RSA"),
        ("dhe_keyexchange", "DHE key exchange", "DHE"),
        ("ecdhe_keyexchange", "ECDHE key exchange", "ECDHE"),
        ("weak_dh_group", "Weak DH group (<2048 bits)", "DHE"),
        ("x25519_support", "X25519 support", "ECDHE"),
    ]

    cert_info = _get_cert_info(host, port, timeout)

    for tech, desc, _ke_type in techniques:
        try:
            if tech == "rsa_keyexchange":
                accepted, info = _probe_cipher(
                    host,
                    port,
                    timeout,
                    "RSA_AES_128_GCM_SHA256",
                )

                vulnerable = accepted

                details = f"RSA key exchange: {'accepted' if accepted else 'rejected'} — {info}"

            elif tech == "dhe_keyexchange":
                accepted, info = _probe_cipher(
                    host,
                    port,
                    timeout,
                    "DHE_RSA_AES_128_GCM_SHA256",
                )

                vulnerable = False

                details = f"DHE available: {accepted} — {info} (forward secrecy supported, informational)"

            elif tech == "ecdhe_keyexchange":
                cipher = cert_info.get("cipher", "")

                vulnerable = False

                details = f"Current cipher: {cipher}, ECDHE/DHE (forward secrecy) supported — informational"

            elif tech == "weak_dh_group":
                vulnerable = False

                details = "DH group analysis requires raw DHE handshake (not available via ssl module)"

            elif tech == "x25519_support":
                accepted, info = _probe_cipher(
                    host,
                    port,
                    timeout,
                    "ECDHE_RSA_AES_128_GCM_SHA256",
                )

                vulnerable = False

                details = f"ECDHE available: {accepted} — {info} (modern cipher accepted, informational)"

            else:  # pragma: no cover
                vulnerable = False

                details = ""

            results.append(
                TLSFingerprintAttempt(
                    technique=tech,
                    category="key_exchange",
                    description=desc,
                    ja3="",
                    ja4="",
                    cipher_suite=cert_info.get("cipher", "unknown"),
                    tls_version=cert_info.get("version", "unknown"),
                    alpn=str(cert_info.get("alpn") or "none"),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    exploit="ja3_hash_replay" if vulnerable else "",
                    tool="ja3",
                )
            )

        except Exception as exc:
            results.append(
                TLSFingerprintAttempt(
                    technique=tech,
                    category="key_exchange",
                    description=desc,
                    ja3="",
                    ja4="",
                    cipher_suite="",
                    tls_version="",
                    alpn="",
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                )
            )

    return results


# ─── Category 151: cipher_audit ─────────────────────────────────────────────


async def _test_cipher_audit(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[TLSFingerprintAttempt]:
    """Audita cipher suites: deprecated, export, null, weak MAC, key size."""

    results: list[TLSFingerprintAttempt] = []

    cert_info = _get_cert_info(host, port, timeout)

    current_cipher = cert_info.get("cipher", "unknown")

    current_bits = cert_info.get("cipher_bits", 0)

    # Test weak ciphers

    weak_found: list[str] = []

    for cipher_id in _WEAK_CIPHERS:
        info = _CIPHER_INFO.get(cipher_id, ("UNKNOWN", 0, False, "?"))

        accepted, _ = _probe_cipher(host, port, timeout, info[0])

        if accepted:
            weak_found.append(info[0])

    # Test export ciphers

    export_found: list[str] = []

    for cipher_id in _EXPORT_CIPHERS:
        info = _CIPHER_INFO.get(cipher_id, ("UNKNOWN", 0, False, "?"))

        accepted, _ = _probe_cipher(host, port, timeout, info[0])

        if accepted:
            export_found.append(info[0])

    # Test null ciphers

    null_found: list[str] = []

    for cipher_id in _NULL_CIPHERS:
        info = _CIPHER_INFO.get(cipher_id, ("UNKNOWN", 0, False, "?"))

        accepted, _ = _probe_cipher(host, port, timeout, info[0])

        if accepted:
            null_found.append(info[0])

    # Audit current cipher

    cipher_meta = _CIPHER_INFO.get(0, ("UNKNOWN", 0, False, "?"))

    for meta in _CIPHER_INFO.values():
        if meta[0] == current_cipher:
            cipher_meta = meta

            break

    weak_mac = cipher_meta[3] in ("MD5", "SHA1")

    small_key = current_bits < 128

    techniques = [
        ("deprecated_ciphers", "Deprecated cipher suites (RC4, 3DES)"),
        ("export_ciphers", "Export-grade cipher suites"),
        ("null_ciphers", "NULL cipher suites (no encryption)"),
        ("weak_mac", "Weak MAC (MD5/SHA1)"),
        ("large_key_check", "Key size >= 128 bits"),
    ]

    for tech, desc in techniques:
        if tech == "deprecated_ciphers":
            vulnerable = len(weak_found) > 0

            details = f"Found: {weak_found}" if weak_found else "None found"

        elif tech == "export_ciphers":
            vulnerable = len(export_found) > 0

            details = f"Found: {export_found}" if export_found else "None found"

        elif tech == "null_ciphers":
            vulnerable = len(null_found) > 0

            details = f"Found: {null_found}" if null_found else "None found"

        elif tech == "weak_mac":
            vulnerable = weak_mac

            details = f"Current MAC: {cipher_meta[3]}, Weak: {weak_mac}"

        elif tech == "large_key_check":
            vulnerable = small_key

            details = f"Current key: {current_bits} bits, Weak: {small_key}"

        else:  # pragma: no cover
            vulnerable = False

            details = ""

        results.append(
            TLSFingerprintAttempt(
                technique=tech,
                category="cipher_audit",
                description=desc,
                ja3="",
                ja4="",
                cipher_suite=current_cipher,
                tls_version=cert_info.get("version", "unknown"),
                alpn=str(cert_info.get("alpn") or "none"),
                vulnerable=vulnerable,
                details=details,
                error="",
                exploit="ja3_hash_replay" if vulnerable else "",
                tool="ja3",
            )
        )

    return results


# ─── Dispatch ────────────────────────────────────────────────────────────────


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[TLSFingerprintAttempt]]]
] = {
    "tls_fingerprint": _test_tls_fingerprint,
    "tls_replay": _test_tls_replay,
    "key_exchange": _test_key_exchange,
    "cipher_audit": _test_cipher_audit,
}


# ─── Print Results ───────────────────────────────────────────────────────────


def print_results(result: TLSFingerprintResult) -> None:
    """Imprime resultados formatados no terminal."""

    print()

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "TLS Fingerprinting Test")

    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")

    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )

    print(
        color("[*]", Cyber.CYAN),
        f"Server: {result.server_cipher} ({result.server_version})",
    )

    print(color("[*]", Cyber.CYAN), f"JA3: {result.ja3_hash}")

    print(color("[*]", Cyber.CYAN), f"JA4: {result.ja4_hash}")

    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")

        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)

        print()

    categories: dict[str, list[TLSFingerprintAttempt]] = {}

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
            color("[!]", Cyber.RED, Cyber.BOLD), "VULNERABLE — TLS weaknesses detected!"
        )

    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — TLS configuration looks good",
        )

    print()


# ─── Main Scan ───────────────────────────────────────────────────────────────


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> TLSFingerprintResult:
    """Executa scan de TLS Fingerprinting."""

    host, path, port, tls = _parse_url(target)

    # Get server info

    cert_info = _get_cert_info(host, port, timeout)

    server_cipher = cert_info.get("cipher", "unknown")

    server_version = cert_info.get("version", "unknown")

    # Compute JA3/JA4 from default ClientHello

    _, default_meta = _build_client_hello(host)

    ja3_hash = _compute_ja3(default_meta)

    ja4_hash = _compute_ja4(default_meta)

    all_attempts: list[TLSFingerprintAttempt] = []

    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)

        if tester is None:
            continue

        try:
            raw = await tester(host, port, path, timeout, tls, 0, 0)

            all_attempts.extend(raw)

        except Exception as e:
            all_attempts.append(
                TLSFingerprintAttempt(
                    technique=f"{cat}_error",
                    category=cat,
                    description="",
                    ja3="",
                    ja4="",
                    cipher_suite="",
                    tls_version="",
                    alpn="",
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]

    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]

    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []

    overall = "vulnerable" if vuln_techs else "secure"

    result = TLSFingerprintResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        server_cipher=server_cipher,
        server_version=server_version,
        ja3_hash=ja3_hash,
        ja4_hash=ja4_hash,
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
        prog="mytools-tlsfp",
        description="TLS Fingerprinting — JA3/JA4, Replay, Key Exchange, Cipher Audit",
    )

    parser.add_argument("url", help="URL alvo (https://)")

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

    init_scanner(args)

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
        banner_fn=create_banner(_BANNER_LINES, "TLS Fingerprinting"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="tlsfp> ",
        description="Teste de TLS Fingerprinting (JA3/JA4, Replay, Key Exchange, Cipher Audit).",
        example="https://target.com -c tls_fingerprint cipher_audit",
        contextual_help=(
            "Categorias disponiveis:\n"
            "  tls_fingerprint  — JA3/JA4, cipher order, extensions, ALPN\n"
            "  tls_replay       — ClientHello de browsers (Chrome, Firefox, Safari, Edge)\n"
            "  key_exchange     — RSA, DHE, ECDHE, DH fraco, X25519\n"
            "  cipher_audit     — deprecated, export, null, MAC fraco, key size"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
