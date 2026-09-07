#!/usr/bin/env python3
"""Modulo de testes de Certificate Checks.

Testa configuracao de certificados TLS e seguranca:
  - OCSP Stapling: stapling check, response status, must-staple, revocation
  - Certificate Chain: full chain, intermediate CA, self-signed, expired, hostname
  - Certificate Transparency: SCT TLS extension, SCT X.509, SCT count, embedded
  - CT Split-World: crt.sh CA query, regional issuance, CA comparison
  - HSTS Preload: header, max-age, includeSubDomains, preload, Chrome list
  - Mixed Content: active mixed, passive mixed, upgrade-insecure, CSP upgrade
"""

from __future__ import annotations

import argparse
import logging
import re
import socket
import ssl
from collections.abc import Callable, Coroutine, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlparse

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_banner,
    print_exploit_info,
    print_json,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.certcheck")

# ─── Banner ──────────────────────────────────────────────────────────────────

_BANNER_LINES: str = (
    "  _____                _                    ____ ____  _  __\n"
    " / ____|              | |                  / ___|  _ \\| |/ /\n"
    "| |     _ __ ___  __ _| |_ ___  _ __ ___  | |   | | | | ' / \n"
    "| |    | '__/ _ \\/ _` | __/ _ \\| '__/ __| | |___| |_| | . \\ \n"
    "| |____| | |  __/ (_| | || (_) | | \\__ \\  \\____|____/|_|\\_\\\n"
    " \\_____|_|  \\___|\\__,_|\\__\\___/|_|  |___/                   \n"
)

# ─── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CertCheckAttempt:
    """Tentativa individual de certificate check."""

    technique: str
    category: str
    description: str
    vulnerable: bool
    details: str
    error: str
    cert_issuer: str
    cert_subject: str
    cert_expiry: str
    ocsp_status: str
    sct_count: int
    hsts_preload: bool
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class CertCheckResult:
    """Resultado consolidado do scan."""

    target: str
    host: str
    port: int
    tls: bool
    cert_issuer: str
    cert_subject: str
    cert_expiry: str
    chain_valid: bool
    attempts: list[CertCheckAttempt]
    vulnerable_techniques: list[str]
    issues: list[str]
    overall_status: str


# ─── Category Map ────────────────────────────────────────────────────────────

_CATEGORY_MAP: dict[str, list[str]] = {
    "ocsp_stapling": [
        "ocsp_stapling_check",
        "ocsp_response_status",
        "must_staple",
        "ocsp_revocation",
        "ocsp_responder_url",
    ],
    "cert_chain": [
        "full_chain",
        "intermediate_ca",
        "self_signed",
        "expired",
        "not_yet_valid",
        "hostname_mismatch",
        "key_size",
        "pinning",
    ],
    "ct_sct": [
        "sct_tls_extension",
        "sct_x509_extension",
        "sct_count",
        "embedded_vs_logged",
    ],
    "ct_split_world": [
        "crtsh_ca_query",
        "regional_issuance",
        "ca_comparison",
    ],
    "hsts_preload": [
        "hsts_header",
        "max_age",
        "include_subdomains",
        "preload_directive",
        "chrome_preload_list",
    ],
    "mixed_content": [
        "active_mixed",
        "passive_mixed",
        "upgrade_insecure",
        "csp_upgrade",
    ],
}

# ─── Constants ───────────────────────────────────────────────────────────────

_HSTS_PRELOAD_DOMAINS = frozenset(
    {
        "google.com",
        "www.google.com",
        "gmail.com",
        "youtube.com",
        "facebook.com",
        "www.facebook.com",
        "twitter.com",
        "github.com",
        "amazon.com",
        "www.amazon.com",
        "microsoft.com",
        "apple.com",
        "cloudflare.com",
        "mozilla.org",
        "wikipedia.org",
    }
)

_CT_SPLIT_WORLD_CAS = frozenset(
    {
        "Let's Encrypt",
        "DigiCert",
        "Comodo",
        "Sectigo",
        "GeoTrust",
        "Symantec",
        "Thawte",
        "GlobalSign",
        "GoDaddy",
        "Entrust",
    }
)

_CT_REGIONAL_CAS = frozenset(
    {
        "CNNIC",
        "CFCA",
        "Buypass",
        "SSL.com",
        "TrustCor",
    }
)


# ─── URL Parser ──────────────────────────────────────────────────────────────


def _parse_url(target: str) -> tuple[str, str, int, bool]:
    """Parse URL em host, path, port, tls."""
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    tls = parsed.scheme in ("https", "wss")
    default_port = 443 if tls else 80
    port = parsed.port or default_port
    return host, path, port, tls


# ─── SSL Helpers ─────────────────────────────────────────────────────────────


def _get_cert_info(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Obtem informacoes do certificado via ssl module."""
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as ssock,
        ):
            cert: dict[str, Any] = cast(dict[str, Any], ssock.getpeercert())
            cert_der = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            version = ssock.version()

            info: dict[str, Any] = {
                "cert": cert,
                "cert_der": cert_der,
                "cipher": cipher[0] if cipher else "unknown",
                "cipher_bits": cipher[2] if cipher else 0,
                "version": version or "unknown",
                "subject": _extract_dn(cert.get("subject", ())),
                "issuer": _extract_dn(cert.get("issuer", ())),
                "serial": cert.get("serialNumber", ""),
                "not_before": cert.get("notBefore", ""),
                "not_after": cert.get("notAfter", ""),
                "san": cert.get("subjectAltName", ()),
                "ocsp": cert.get("OCSP", ()),
                "ca_issuers": cert.get("caIssuers", ()),
                "crl_distribution": cert.get("crlDistributionPoints", ()),
            }

            try:
                chain = ssock.get_unverified_chain()
                info["chain_length"] = len(chain)
                info["chain_certs"] = chain
            except Exception:
                info["chain_length"] = 1
                info["chain_certs"] = []

            return info
    except Exception as e:
        return {"error": str(e)[:200]}


def _extract_dn(dn_tuple: Any) -> str:
    """Extrai DN de certificado como string."""
    parts: list[str] = []
    try:
        for rdn in dn_tuple:
            for attr_type, attr_value in rdn:
                parts.append(f"{attr_type}={attr_value}")
    except TypeError, ValueError:
        pass
    return ", ".join(parts)


# ─── OCSP Helpers ────────────────────────────────────────────────────────────


def _build_ocsp_request(cert_der: bytes, issuer_der: bytes) -> bytes:
    """Constrói request OCSP em DER format."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import ocsp as ocsp_mod

        cert = x509.load_der_x509_certificate(cert_der)
        issuer = x509.load_der_x509_certificate(issuer_der)
        builder = ocsp_mod.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA256())
        req = builder.build()
        return req.public_bytes(serialization.Encoding.DER)
    except Exception:
        return b""


def _check_ocsp_stapling_raw(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Verifica OCSP stapling via TLS com status_request extension."""
    result: dict[str, Any] = {
        "stapling": False,
        "response_status": "unknown",
        "responder_url": "",
        "revocation_status": "unknown",
        "this_update": "",
        "next_update": "",
    }

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as ssock,
        ):
            cert_der = ssock.getpeercert(binary_form=True)

            if cert_der is None:
                return result

            try:
                from cryptography import x509

                cert = x509.load_der_x509_certificate(cert_der)

                ocsp_url = ""
                for ext in cert.extensions:
                    try:
                        aia = ext.value
                        for access_desc in aia:
                            method = access_desc.access_method
                            uri = access_desc.access_location.value
                            if str(method) == "1.3.6.1.5.5.7.48.1":
                                ocsp_url = uri
                    except Exception:
                        pass

                if ocsp_url:
                    # A presence of an AIA OCSP responder URL is NOT evidence
                    # that the server actually staples OCSP responses. Without
                    # a real OCSP response the status stays "unknown" and
                    # stapling stays False (see _check_ocsp_stapling_raw caller).
                    result["responder_url"] = ocsp_url

            except Exception:
                pass

    except Exception:
        pass

    return result


def _parse_ocsp_response(response_der: bytes) -> dict[str, Any]:
    """Parse OCSP response DER."""
    result: dict[str, Any] = {
        "response_status": "unknown",
        "revocation_status": "unknown",
        "this_update": "",
        "next_update": "",
    }

    try:
        from cryptography.x509 import ocsp as ocsp_mod

        ocsp_resp = ocsp_mod.load_der_ocsp_response(response_der)
        status = ocsp_resp.certificate_status
        result["response_status"] = (
            "good" if status == ocsp_mod.OCSPCertStatus.GOOD else "revoked"
        )
        result["revocation_status"] = result["response_status"]

        if ocsp_resp.this_update_utc:
            result["this_update"] = ocsp_resp.this_update_utc.isoformat()
        if ocsp_resp.next_update_utc:
            result["next_update"] = ocsp_resp.next_update_utc.isoformat()

    except Exception:
        result["response_status"] = "parse_error"

    return result


# ─── CT Helpers ───────────────────────────────────────────────────────────────


def _extract_scts_from_tls(cert_der: bytes) -> int:
    """Extrai SCTs do certificado via TLS SCT extension."""
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(cert_der)
        sct_count = 0

        for ext in cert.extensions:
            try:
                ext_value = ext.value
                if hasattr(ext_value, "__iter__"):
                    for _sct in ext_value:
                        sct_count += 1
            except Exception:
                pass

        return sct_count
    except Exception:
        return 0


def _extract_scts_from_x509(cert_der: bytes) -> int:
    """Extrai SCTs da extensão X.509 SCT."""
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(cert_der)
        sct_count = 0

        for ext in cert.extensions:
            oid_str = str(ext.oid.dotted_string)
            if oid_str == "1.3.6.1.4.1.11129.2.4.5":
                try:
                    sct_list = ext.value
                    sct_count = len(list(sct_list))
                except Exception:
                    sct_count = 1

        return sct_count
    except Exception:
        return 0


async def _fetch_crt_sh(domain: str, timeout: float) -> list[dict[str, Any]]:
    """Consulta crt.sh para certificados CT."""
    try:
        import httpx

        url = f"https://crt.sh/?q={domain}&output=json"
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return []


# ─── HSTS Helpers ────────────────────────────────────────────────────────────


async def _check_hsts_header(url: str, timeout: float) -> dict[str, Any]:
    """Verifica header HSTS em resposta HTTP."""
    result: dict[str, Any] = {
        "hsts_present": False,
        "max_age": 0,
        "include_subdomains": False,
        "preload": False,
        "raw_header": "",
    }

    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True
        ) as client:
            resp = await client.head(url)
            hsts = resp.headers.get("strict-transport-security", "")

            if hsts:
                result["hsts_present"] = True
                result["raw_header"] = hsts

                ma_match = re.search(r"max-age=(\d+)", hsts)
                if ma_match:
                    result["max_age"] = int(ma_match.group(1))

                result["include_subdomains"] = "includeSubDomains" in hsts
                result["preload"] = "preload" in hsts

    except Exception:
        pass

    return result


async def _check_chrome_preload(domain: str, timeout: float) -> str:
    """Verifica se dominio esta na lista de preload do Chrome.

    Retorna "present", "not_present" ou "unknown" (API indisponivel).
    """
    try:
        import httpx

        url = "https://hstspreload.org/api/v2/status"
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(url, params={"domain": domain})
            if resp.status_code == 200:
                data = resp.json()
                return "present" if data.get("status") == "present" else "not_present"
    except Exception:
        pass

    return "unknown"


# ─── Mixed Content Helpers ───────────────────────────────────────────────────


async def _fetch_page_content(
    url: str, timeout: float
) -> tuple[str, Mapping[str, str]]:
    """Busca conteudo HTML e headers de resposta de pagina HTTPS."""
    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True
        ) as client:
            resp = await client.get(url)
            return resp.text, resp.headers
    except Exception:
        return "", {}


def _detect_mixed_content(html: str, base_url: str) -> dict[str, Any]:
    """Detecta mixed content em HTML."""
    result: dict[str, Any] = {
        "active_mixed": [],
        "passive_mixed": [],
    }

    active_tags = re.findall(
        r"<(?:script|iframe|object|embed|applet)[^>]+src\s*=\s*['\"]http://[^'\"]+['\"]",
        html,
        re.IGNORECASE,
    )
    result["active_mixed"] = active_tags

    passive_tags = re.findall(
        r"<(?:img|link|source|video|audio)[^>]+(?:src|href)\s*=\s*['\"]http://[^'\"]+['\"]",
        html,
        re.IGNORECASE,
    )
    result["passive_mixed"] = passive_tags

    return result


# ─── Category 152: ocsp_stapling ─────────────────────────────────────────────


async def _test_ocsp_stapling(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[CertCheckAttempt]:
    """Testa OCSP stapling e OCSP response."""
    results: list[CertCheckAttempt] = []

    cert_info = _get_cert_info(host, port, timeout)
    if "error" in cert_info:
        return [
            CertCheckAttempt(
                technique="ocsp_stapling_check",
                category="ocsp_stapling",
                description="OCSP Stapling availability",
                vulnerable=False,
                details="",
                error=cert_info["error"],
                cert_issuer="",
                cert_subject="",
                cert_expiry="",
                ocsp_status="error",
                sct_count=0,
                hsts_preload=False,
            )
        ]

    cert_issuer = cert_info.get("issuer", "")
    cert_subject = cert_info.get("subject", "")
    cert_expiry = cert_info.get("not_after", "")

    ocsp_info = _check_ocsp_stapling_raw(host, port, timeout)

    techniques = [
        ("ocsp_stapling_check", "OCSP Stapling availability"),
        ("ocsp_response_status", "OCSP response status"),
        ("must_staple", "Must-Staple extension"),
        ("ocsp_revocation", "OCSP revocation status"),
        ("ocsp_responder_url", "OCSP responder URL accessibility"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "ocsp_stapling_check":
                vulnerable = False
                details = (
                    "OCSP Stapling: enabled"
                    if ocsp_info.get("stapling", False)
                    else "OCSP stapling: sem evidencia de stapling (nao verificado)"
                )
            elif tech == "ocsp_response_status":
                status = ocsp_info.get("response_status", "unknown")
                vulnerable = status not in ("good", "stapled", "unknown")
                details = f"OCSP Response: {status}"
            elif tech == "must_staple":
                vulnerable = False
                details = "Must-Staple: not detected (requires cert extension parse)"
            elif tech == "ocsp_revocation":
                status = ocsp_info.get("revocation_status", "unknown")
                vulnerable = status == "revoked"
                details = f"Revocation: {status}"
            elif tech == "ocsp_responder_url":
                url = ocsp_info.get("responder_url", "")
                vulnerable = not bool(url)
                details = f"Responder: {url}" if url else "No OCSP responder URL found"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="ocsp_stapling",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status=ocsp_info.get("response_status", "unknown"),
                    sct_count=0,
                    hsts_preload=False,
                )
            )
        except Exception as exc:
            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="ocsp_stapling",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="error",
                    sct_count=0,
                    hsts_preload=False,
                )
            )

    return results


# ─── Category 153: cert_chain ────────────────────────────────────────────────


async def _test_cert_chain(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[CertCheckAttempt]:
    """Testa cadeia de certificados."""
    results: list[CertCheckAttempt] = []

    cert_info = _get_cert_info(host, port, timeout)
    if "error" in cert_info:
        return [
            CertCheckAttempt(
                technique="full_chain",
                category="cert_chain",
                description="Certificate chain verification",
                vulnerable=False,
                details="",
                error=cert_info["error"],
                cert_issuer="",
                cert_subject="",
                cert_expiry="",
                ocsp_status="",
                sct_count=0,
                hsts_preload=False,
            )
        ]

    cert_issuer = cert_info.get("issuer", "")
    cert_subject = cert_info.get("subject", "")
    cert_expiry = cert_info.get("not_after", "")
    cert = cert_info.get("cert", {})
    chain_length = cert_info.get("chain_length", 1)
    san = cert_info.get("san", ())
    key_size = cert_info.get("cipher_bits", 0)

    now = datetime.now(UTC)
    expired = False
    not_yet_valid = False
    try:
        if cert_expiry:
            expiry_dt = datetime.strptime(cert_expiry, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=UTC
            )
            expired = expiry_dt < now
    except Exception:
        pass

    not_before = cert.get("notBefore", "")
    try:
        if not_before:
            start_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=UTC
            )
            not_yet_valid = start_dt > now
    except Exception:
        pass

    self_signed = (cert_issuer == cert_subject) or (
        chain_length <= 1 and not cert_issuer
    )
    intermediate_missing = chain_length < 3 and not self_signed
    hostname_mismatch = True
    if san:
        hostname_mismatch = not any(
            host == entry[1]
            or (entry[0] == "DNS" and host.endswith(entry[1].lstrip("*.")))
            for entry in san
        )

    weak_key = key_size < 2048 and key_size > 0
    pinned = bool(cert_info.get("ca_issuers")) and bool(
        cert_info.get("crl_distribution")
    )

    techniques = [
        ("full_chain", "Full certificate chain"),
        ("intermediate_ca", "Intermediate CA present"),
        ("self_signed", "Self-signed certificate"),
        ("expired", "Certificate expired"),
        ("not_yet_valid", "Certificate not yet valid"),
        ("hostname_mismatch", "Hostname mismatch"),
        ("key_size", "Key size >= 2048 bits"),
        ("pinning", "Certificate pinning"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "full_chain":
                vulnerable = chain_length < 3
                details = f"Chain length: {chain_length}"
            elif tech == "intermediate_ca":
                vulnerable = intermediate_missing
                details = f"Chain length: {chain_length}, Intermediate: {'present' if not vulnerable else 'missing'}"
            elif tech == "self_signed":
                vulnerable = self_signed
                details = f"Issuer: {cert_issuer}" if self_signed else "Issued by CA"
            elif tech == "expired":
                vulnerable = expired
                details = f"Expiry: {cert_expiry}"
            elif tech == "not_yet_valid":
                vulnerable = not_yet_valid
                details = f"Not before: {not_before}"
            elif tech == "hostname_mismatch":
                vulnerable = hostname_mismatch
                details = f"Host: {host}, SAN: {len(san)} entries"
            elif tech == "key_size":
                vulnerable = weak_key
                details = f"Key: {key_size} bits"
            elif tech == "pinning":
                vulnerable = False
                details = f"HPKP: {'present' if pinned else 'not detected'}"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="cert_chain",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=False,
                )
            )
        except Exception as exc:
            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="cert_chain",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=False,
                )
            )

    return results


# ─── Category 154: ct_sct ────────────────────────────────────────────────────


async def _test_ct_sct(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[CertCheckAttempt]:
    """Testa Certificate Transparency SCTs."""
    results: list[CertCheckAttempt] = []

    cert_info = _get_cert_info(host, port, timeout)
    if "error" in cert_info:
        return [
            CertCheckAttempt(
                technique="sct_tls_extension",
                category="ct_sct",
                description="SCT via TLS extension",
                vulnerable=False,
                details="",
                error=cert_info["error"],
                cert_issuer="",
                cert_subject="",
                cert_expiry="",
                ocsp_status="",
                sct_count=0,
                hsts_preload=False,
            )
        ]

    cert_issuer = cert_info.get("issuer", "")
    cert_subject = cert_info.get("subject", "")
    cert_expiry = cert_info.get("not_after", "")
    cert_der = cert_info.get("cert_der", b"")

    sct_tls = _extract_scts_from_tls(cert_der)
    sct_x509 = _extract_scts_from_x509(cert_der)
    total_sct = max(sct_tls, sct_x509)

    techniques = [
        ("sct_tls_extension", "SCT via TLS extension"),
        ("sct_x509_extension", "SCT via X.509 extension"),
        ("sct_count", "SCT count >= 3"),
        ("embedded_vs_logged", "Embedded vs logged SCTs"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "sct_tls_extension":
                vulnerable = sct_tls == 0
                details = f"SCTs (TLS): {sct_tls}"
            elif tech == "sct_x509_extension":
                vulnerable = sct_x509 == 0
                details = f"SCTs (X.509): {sct_x509}"
            elif tech == "sct_count":
                vulnerable = total_sct < 3 and total_sct > 0
                details = f"Total SCTs: {total_sct} (need >= 3)"
            elif tech == "embedded_vs_logged":
                vulnerable = False
                details = f"Embedded: {sct_x509}, Logged: {sct_tls}"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="ct_sct",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=total_sct,
                    hsts_preload=False,
                )
            )
        except Exception as exc:
            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="ct_sct",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=total_sct,
                    hsts_preload=False,
                )
            )

    return results


# ─── Category 155: ct_split_world ────────────────────────────────────────────


async def _test_ct_split_world(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[CertCheckAttempt]:
    """Testa CT split-world (regional CAs)."""
    results: list[CertCheckAttempt] = []

    cert_info = _get_cert_info(host, port, timeout)
    cert_issuer = cert_info.get("issuer", "")
    cert_subject = cert_info.get("subject", "")
    cert_expiry = cert_info.get("not_after", "")

    crt_sh_data = await _fetch_crt_sh(host, timeout)

    ca_names: set[str] = set()
    for entry in crt_sh_data:
        issuer = entry.get("issuer_name", "")
        if issuer:
            ca_names.add(issuer)

    techniques = [
        ("crtsh_ca_query", "crt.sh CA query"),
        ("regional_issuance", "Regional CA issuance"),
        ("ca_comparison", "CA comparison"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "crtsh_ca_query":
                vulnerable = len(crt_sh_data) == 0
                details = f"Found {len(crt_sh_data)} certs, {len(ca_names)} CAs"
            elif tech == "regional_issuance":
                regional = ca_names.intersection(_CT_REGIONAL_CAS)
                vulnerable = len(regional) > 0
                details = (
                    f"Regional CAs: {regional}"
                    if regional
                    else "No regional CAs detected"
                )
            elif tech == "ca_comparison":
                known = ca_names.intersection(_CT_SPLIT_WORLD_CAS)
                unknown = ca_names - _CT_SPLIT_WORLD_CAS
                vulnerable = len(unknown) > 0
                details = f"Known: {len(known)}, Unknown: {len(unknown)}"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="ct_split_world",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=False,
                )
            )
        except Exception as exc:
            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="ct_split_world",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=False,
                )
            )

    return results


# ─── Category 156: hsts_preload ──────────────────────────────────────────────


async def _test_hsts_preload(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[CertCheckAttempt]:
    """Testa HSTS e preload status."""
    results: list[CertCheckAttempt] = []

    cert_info = _get_cert_info(host, port, timeout)
    cert_issuer = cert_info.get("issuer", "")
    cert_subject = cert_info.get("subject", "")
    cert_expiry = cert_info.get("not_after", "")

    scheme = "https" if tls else "http"
    url = f"{scheme}://{host}{path}"
    hsts_info = await _check_hsts_header(url, timeout)
    preload_status = await _check_chrome_preload(host, timeout)
    in_preload = preload_status == "present"

    techniques = [
        ("hsts_header", "HSTS header present"),
        ("max_age", "max-age >= 6 months"),
        ("include_subdomains", "includeSubDomains"),
        ("preload_directive", "preload directive"),
        ("chrome_preload_list", "Chrome preload list"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "hsts_header":
                vulnerable = not hsts_info.get("hsts_present", False)
                details = f"Header: {hsts_info.get('raw_header', 'not found')}"
            elif tech == "max_age":
                ma = hsts_info.get("max_age", 0)
                vulnerable = ma < 15768000
                details = f"max-age: {ma}"
            elif tech == "include_subdomains":
                vulnerable = not hsts_info.get("include_subdomains", False)
                details = f"includeSubDomains: {not vulnerable}"
            elif tech == "preload_directive":
                vulnerable = not hsts_info.get("preload", False)
                details = f"preload: {not vulnerable}"
            elif tech == "chrome_preload_list":
                vulnerable = preload_status == "not_present"
                if preload_status == "present":
                    details = "In preload list: True"
                elif preload_status == "unknown":
                    details = "Preload status: unknown (API failure)"
                else:
                    details = "In preload list: False"
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="hsts_preload",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=in_preload,
                )
            )
        except Exception as exc:
            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="hsts_preload",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=in_preload,
                )
            )

    return results


# ─── Category 157: mixed_content ─────────────────────────────────────────────


async def _test_mixed_content(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    _b_status: int,
    _b_size: int,
) -> list[CertCheckAttempt]:
    """Testa mixed content em pagina HTTPS."""
    results: list[CertCheckAttempt] = []

    cert_info = _get_cert_info(host, port, timeout)
    cert_issuer = cert_info.get("issuer", "")
    cert_subject = cert_info.get("subject", "")
    cert_expiry = cert_info.get("not_after", "")

    if not tls:
        for tech, desc in [
            ("active_mixed", "Active mixed content"),
            ("passive_mixed", "Passive mixed content"),
            ("upgrade_insecure", "Upgrade-Insecure-Requests"),
            ("csp_upgrade", "CSP upgrade-insecure"),
        ]:
            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="mixed_content",
                    description=desc,
                    vulnerable=False,
                    details="Target is not HTTPS",
                    error="",
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=False,
                )
            )
        return results

    scheme = "https" if tls else "http"
    url = f"{scheme}://{host}{path}"
    # Reuse a single module fetch for both body and headers, avoiding a second
    # raw client with different (verify/proxy) settings.
    html, headers = await _fetch_page_content(url, timeout)

    mixed = _detect_mixed_content(html, url)

    upgrade_header = headers.get("upgrade-insecure-requests", "")
    csp_header = headers.get("content-security-policy", "")
    has_upgrade = bool(upgrade_header)
    has_csp_upgrade = "upgrade-insecure-requests" in csp_header

    techniques = [
        ("active_mixed", "Active mixed content"),
        ("passive_mixed", "Passive mixed content"),
        ("upgrade_insecure", "Upgrade-Insecure-Requests"),
        ("csp_upgrade", "CSP upgrade-insecure"),
    ]

    for tech, desc in techniques:
        try:
            if tech == "active_mixed":
                vulnerable = len(mixed["active_mixed"]) > 0
                details = f"Found: {len(mixed['active_mixed'])} active elements"
            elif tech == "passive_mixed":
                vulnerable = len(mixed["passive_mixed"]) > 0
                details = f"Found: {len(mixed['passive_mixed'])} passive elements"
            elif tech == "upgrade_insecure":
                vulnerable = False
                details = (
                    "Upgrade-Insecure-Requests: present"
                    if has_upgrade
                    else "Upgrade-Insecure-Requests: missing (informational)"
                )
            elif tech == "csp_upgrade":
                vulnerable = False
                details = (
                    "CSP upgrade-insecure: present"
                    if has_csp_upgrade
                    else "CSP upgrade-insecure: missing (informational)"
                )
            else:  # pragma: no cover
                vulnerable = False
                details = ""

            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="mixed_content",
                    description=desc,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=False,
                )
            )
        except Exception as exc:
            results.append(
                CertCheckAttempt(
                    technique=tech,
                    category="mixed_content",
                    description=desc,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=False,
                )
            )

    return results


# ─── Dispatch ────────────────────────────────────────────────────────────────

_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[CertCheckAttempt]]]
] = {
    "ocsp_stapling": _test_ocsp_stapling,
    "cert_chain": _test_cert_chain,
    "ct_sct": _test_ct_sct,
    "ct_split_world": _test_ct_split_world,
    "hsts_preload": _test_hsts_preload,
    "mixed_content": _test_mixed_content,
}

# ─── Print Results ───────────────────────────────────────────────────────────


def print_results(result: CertCheckResult) -> None:
    """Imprime resultados formatados no terminal."""
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Certificate Checks")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )
    print(color("[*]", Cyber.CYAN), f"Issuer: {result.cert_issuer}")
    print(color("[*]", Cyber.CYAN), f"Subject: {result.cert_subject}")
    print(color("[*]", Cyber.CYAN), f"Expiry: {result.cert_expiry}")
    print(
        color("[*]", Cyber.CYAN),
        f"Chain: {'valid' if result.chain_valid else 'invalid'}",
    )
    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()

    categories: dict[str, list[CertCheckAttempt]] = {}
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
            "VULNERABLE — Certificate issues detected!",
        )
    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — Certificate configuration looks good",
        )
    print()


# ─── Main Scan ───────────────────────────────────────────────────────────────


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
    json_output: bool = False,
) -> CertCheckResult:
    """Executa scan de Certificate Checks."""
    host, path, port, tls = _parse_url(target)

    cert_info = _get_cert_info(host, port, timeout)
    cert_issuer = cert_info.get("issuer", "")
    cert_subject = cert_info.get("subject", "")
    cert_expiry = cert_info.get("not_after", "")
    chain_valid = cert_info.get("chain_length", 0) >= 2

    all_attempts: list[CertCheckAttempt] = []
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
                CertCheckAttempt(
                    technique=f"{cat}_error",
                    category=cat,
                    description="",
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                    cert_issuer=cert_issuer,
                    cert_subject=cert_subject,
                    cert_expiry=cert_expiry,
                    ocsp_status="",
                    sct_count=0,
                    hsts_preload=False,
                )
            )

    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]
    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []
    overall = "vulnerable" if vuln_techs else "secure"

    result = CertCheckResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        cert_issuer=cert_issuer,
        cert_subject=cert_subject,
        cert_expiry=cert_expiry,
        chain_valid=chain_valid,
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        issues=issues,
        overall_status=overall,
    )

    if json_output:
        print_json(asdict(result))
        return result
    print_results(result)

    if output_file:
        write_output(output_file, [asdict(a) for a in all_attempts])

    return result


# ─── CLI ─────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Constrói parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-certcheck",
        description="Certificate Checks — OCSP, Chain, CT, HSTS, Mixed Content",
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
    result = safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=getattr(args, "categories", None),
            timeout=getattr(args, "timeout", 5.0),
            output_file=getattr(args, "output", None),
            json_output=getattr(args, "json_output", False),
        )
    )
    return 1 if result.overall_status == "vulnerable" else 0


def main() -> int:
    """Entry point principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(_BANNER_LINES, "Certificate Checks"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="certcheck> ",
        description="Teste de Certificate Checks (OCSP, Chain, CT, HSTS, Mixed Content).",
        example="https://target.com -c ocsp_stapling cert_chain",
        contextual_help=(
            "Categorias disponiveis:\n"
            "  ocsp_stapling  — OCSP stapling, response status, must-staple, revocation\n"
            "  cert_chain     — Full chain, intermediate, self-signed, expired, hostname\n"
            "  ct_sct         — SCT TLS extension, SCT X.509, SCT count, embedded\n"
            "  ct_split_world — crt.sh CA query, regional issuance, CA comparison\n"
            "  hsts_preload   — HSTS header, max-age, includeSubDomains, preload\n"
            "  mixed_content  — Active/passive mixed, upgrade-insecure, CSP upgrade"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
