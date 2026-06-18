#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import secrets
import socket
import ssl
import sys
import warnings
import time
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from utils import (
    Cyber,
    RateLimiter,
    add_common_args,
    apply_session_auth,
    color,
    create_async_client,
    ensure_output_dir,
    extract_hostname,
    fetch,
    header_get,
    normalize_url,
    resolve_target_urls,
    run_interactive_shell,
    set_color,
    setup_logging,
    show_banner,
    status_color,
    write_output,
    __version__,
)

import logging

logger = logging.getLogger("mytools.attackaudit")

"""Ferramenta de auditoria web para alvos autorizados, combinando red team e hardening defensivo."""

SECURITY_HEADERS_RECS = {
    "strict-transport-security": "Ative HSTS com max-age alto e includeSubDomains quando fizer sentido.",
    "content-security-policy": "Defina CSP para reduzir XSS e carregamento de recursos nao confiaveis.",
    "x-frame-options": "Use DENY/SAMEORIGIN ou frame-ancestors via CSP contra clickjacking.",
    "x-content-type-options": "Use nosniff para impedir MIME sniffing.",
    "referrer-policy": "Use politica restritiva, como strict-origin-when-cross-origin.",
    "permissions-policy": "Desabilite APIs do browser que a aplicacao nao usa.",
}

INTERESTING_PATHS = [
    ".env", ".git/HEAD", "backup.zip", "backup.tar.gz", "dump.sql", "db.sql",
    "config.php", "phpinfo.php", "server-status", "actuator", "actuator/env",
    "swagger.json", "swagger-ui/", "api-docs", "openapi.json", "robots.txt",
    "sitemap.xml", "admin", "login", "wp-admin", "phpmyadmin",
]

METHODS_TO_TEST = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "HEAD"]

RISK_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}

_SEVERITY_COLORS = {
    "critical": Cyber.RED,
    "high": Cyber.RED,
    "medium": Cyber.YELLOW,
    "low": Cyber.BLUE,
    "info": Cyber.GRAY,
}

SQL_ERROR_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "mysql": [
        re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
        re.compile(r"Warning.*mysql_", re.IGNORECASE),
        re.compile(r"MySqlException", re.IGNORECASE),
        re.compile(r"valid MySQL result", re.IGNORECASE),
        re.compile(r"check the manual that corresponds to your MySQL", re.IGNORECASE),
        re.compile(r"MySqlClient\.", re.IGNORECASE),
        re.compile(r"com\.mysql\.jdbc", re.IGNORECASE),
    ],
    "postgresql": [
        re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
        re.compile(r"Warning.*\Wpg_", re.IGNORECASE),
        re.compile(r"valid PostgreSQL result", re.IGNORECASE),
        re.compile(r"Npgsql\.", re.IGNORECASE),
        re.compile(r"PG::SyntaxError", re.IGNORECASE),
        re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE),
        re.compile(r"ERROR:\s+syntax error at or near", re.IGNORECASE),
    ],
    "mssql": [
        re.compile(r"Driver.* SQL[\-\_\ ]*Server", re.IGNORECASE),
        re.compile(r"OLE DB.* SQL Server", re.IGNORECASE),
        re.compile(r"(\W|\A)SQL Server[^a-zA-Z0-9]", re.IGNORECASE),
        re.compile(r"ODBC SQL Server Driver", re.IGNORECASE),
        re.compile(r"SQLJDBC", re.IGNORECASE),
        re.compile(r"com\.microsoft\.sqlserver\.jdbc", re.IGNORECASE),
        re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
    ],
    "oracle": [
        re.compile(r"(\W|\A)ORA-[0-9][0-9][0-9][0-9]", re.IGNORECASE),
        re.compile(r"Oracle error", re.IGNORECASE),
        re.compile(r"Oracle.*Driver", re.IGNORECASE),
        re.compile(r"Warning.*\Woci_", re.IGNORECASE),
        re.compile(r"Warning.*\Wora_", re.IGNORECASE),
    ],
    "sqlite": [
        re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
        re.compile(r"SQLite\.Exception", re.IGNORECASE),
        re.compile(r"System\.Data\.SQLite\.SQLiteException", re.IGNORECASE),
        re.compile(r"Warning.*sqlite_", re.IGNORECASE),
        re.compile(r"Warning.*SQLite3::", re.IGNORECASE),
        re.compile(r"(\W|\A)SQLITE_ERROR", re.IGNORECASE),
        re.compile(r"SQLite error", re.IGNORECASE),
    ],
}

SQLI_PAYLOADS = ["'", "\"", "`", "' OR '1'='1", "\" OR \"1\"=\"1"]

CSRF_FIELD_NAMES_LOWER = frozenset({
    "csrf_token", "_csrf", "csrf", "csrftoken", "_token",
    "authenticity_token", "xsrf-token", "_xsrf", "xsrf-token",
    "_csrf_token", "csrfmiddlewaretoken", "__requestverificationtoken",
})


class PageParser(HTMLParser):
    """Analisa HTML para extrair forms, scripts externos, comentarios e titulo."""

    def __init__(self) -> None:
        super().__init__()
        self.forms = 0
        self.password_inputs = 0
        self.external_scripts: set[str] = set()
        self.comments: list[str] = []
        self._title = False
        self.title_parts: list[str] = []
        self.form_has_csrf: list[bool] = []
        self._current_form_has_csrf = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self._title = True
        if tag.lower() == "form":
            self.forms += 1
            self._current_form_has_csrf = False
        if tag.lower() == "input":
            input_type = attrs_dict.get("type", "").lower()
            input_name = attrs_dict.get("name", "").lower()
            if input_type == "password":
                self.password_inputs += 1
            if input_type == "hidden" and input_name in CSRF_FIELD_NAMES_LOWER:
                self._current_form_has_csrf = True
        if tag.lower() == "script" and attrs_dict.get("src"):
            self.external_scripts.add(attrs_dict["src"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._title = False
        if tag.lower() == "form":
            self.form_has_csrf.append(self._current_form_has_csrf)

    def handle_data(self, data: str) -> None:
        if self._title:
            self.title_parts.append(data.strip())

    def handle_comment(self, data: str) -> None:
        text = " ".join(data.split())
        if text:
            self.comments.append(text[:120])

    @property
    def title(self) -> str:
        return " ".join(part for part in self.title_parts if part)[:100]

    @property
    def forms_missing_csrf(self) -> int:
        """Retorna numero de formulários POST sem token CSRF."""
        if not self.form_has_csrf:
            return 0
        return sum(1 for has_csrf in self.form_has_csrf if not has_csrf)


@dataclass(frozen=True)
class Probe:
    """Resultado de probing de um path na aplicacao."""

    url: str
    status: int
    size: int
    location: str


@dataclass(frozen=True)
class Finding:
    """Finding de seguranca identificado durante a auditoria."""

    severity: str
    category: str
    item: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class TLSVersionResult:
    """Resultado de teste de versao TLS."""

    protocol: str
    supported: bool
    reason: str = ""


@dataclass(frozen=True)
class MethodResult:
    """Resultado de teste de metodo HTTP em um endpoint."""

    url: str
    method: str
    status: int
    size: int


@dataclass(frozen=True)
class AuditResult:
    """Resultado completo de uma auditoria web."""

    target: str
    final_url: str
    status: int
    title: str
    ip: str
    tls_subject: str
    tls_issuer: str
    tls_not_after: str
    allowed_methods: list[str]
    forms: int
    password_inputs: int
    probes: list[Probe]
    findings: list[Finding]
    risk_score: int
    elapsed: float
    tls_versions: list[TLSVersionResult] = field(default_factory=list)
    xss_reflected: bool = False
    sqli_errors: list[str] = field(default_factory=list)
    csrf_missing: int = 0
    method_results: list[MethodResult] = field(default_factory=list)


def banner() -> None:
    """Exibe banner ASCII art do AttackAudit."""
    art = r"""
    ___   __  __             __      ___             ___ __
   /   | / /_/ /_____ ______/ /__   /   | __  ______/ (_) /_
  / /| |/ __/ __/ __ `/ ___/ //_/  / /| |/ / / / __  / / __/
 / ___ / /_/ /_/ /_/ / /__/ ,<    / ___ / /_/ / /_/ / / /_
/_/  |_\__/\__/\__,_/\___/_/|_|  /_/  |_\__,_/\__,_/_/\__/
"""
    show_banner(art, "   red/blue web audit | ofensivo autorizado + hardening defensivo")


def load_paths_from_file(paths_file: str) -> list[str]:
    """Carrega paths customizados de arquivo (um por linha)."""
    try:
        with open(paths_file, "r", encoding="utf-8", errors="replace") as fh:
            paths = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        raise ValueError(f"arquivo de paths nao encontrado: {paths_file}")
    if not paths:
        raise ValueError(f"nenhum path valido em {paths_file}")
    return sorted(set(paths))


def _resolve_ip_sync(hostname: str) -> str:
    """Resolve hostname para endereco IP (sincrono, para usar com asyncio.to_thread)."""
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return ""


async def resolve_ip(hostname: str) -> str:
    """Resolve hostname para endereco IP de forma assincrona."""
    return await asyncio.to_thread(_resolve_ip_sync, hostname)


def _tls_info_sync(url: str, timeout: float) -> tuple[str, str, str]:
    """Coleta subject, issuer e data de expiracao do certificado TLS (sincrono)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "", "", ""
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((parsed.hostname or "", port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError, TimeoutError):
        return "", "", ""

    def flatten_name(rows: tuple[tuple[tuple[str, str], ...], ...]) -> str:
        parts = []
        for row in rows:
            for key, value in row:
                if key in {"commonName", "organizationName"}:
                    parts.append(value)
        return ", ".join(parts)

    return (
        flatten_name(cert.get("subject", ())),
        flatten_name(cert.get("issuer", ())),
        cert.get("notAfter", ""),
    )


async def tls_info(url: str, timeout: float) -> tuple[str, str, str]:
    """Coleta subject, issuer e data de expiracao do certificado TLS (assincrono)."""
    return await asyncio.to_thread(_tls_info_sync, url, timeout)


def _check_tls_versions_sync(url: str, timeout: float) -> list[TLSVersionResult]:
    """Testa suporte a versoes TLS/SSL (sincrono, para usar com asyncio.to_thread)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return []
    hostname = parsed.hostname or ""
    port = parsed.port or 443
    results: list[TLSVersionResult] = []

    version_configs = [
        ("SSLv3", ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, 'SSLv3') else None),
        ("TLS 1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
    ]

    for protocol_name, tls_version in version_configs:
        if tls_version is None:
            results.append(TLSVersionResult(protocol=protocol_name, supported=False, reason="nao disponivel no Python"))
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                ctx.minimum_version = tls_version
                ctx.maximum_version = tls_version
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                        _ = tls_sock.version()
            results.append(TLSVersionResult(protocol=protocol_name, supported=True))
        except (ssl.SSLError, OSError, TimeoutError) as e:
            results.append(TLSVersionResult(protocol=protocol_name, supported=False, reason=str(e)[:80]))

    return results


async def check_tls_versions(url: str, timeout: float) -> list[TLSVersionResult]:
    """Testa suporte a versoes TLS/SSL de forma assincrona."""
    return await asyncio.to_thread(_check_tls_versions_sync, url, timeout)


async def check_xss_reflection(client, base_url: str, timeout: float) -> tuple[bool, str]:
    """Testa se a URL reflete entrada sem sanitizacao basica de XSS."""
    marker = "xss" + secrets.token_hex(4)
    separator = "&" if "?" in base_url else "?"
    test_url = base_url + separator + "q=" + marker

    try:
        _, headers, body, _ = await fetch(client, test_url, timeout=timeout)
    except ValueError:
        return False, ""

    text = body.decode("utf-8", errors="replace")
    if marker in text:
        lower_text = text.lower()
        marker_lower = marker.lower()
        context = "html_body"
        idx = lower_text.find(marker_lower)
        snippet = text[max(0, idx - 30):idx + len(marker) + 30]
        return True, f"refletido em {context}: ...{snippet}..."
    return False, ""


async def check_sqli_errors(client, base_url: str, timeout: float) -> list[str]:
    """Testa se a aplicacao retorna erros SQL em payloads de injecao."""
    detected_databases: list[str] = []
    parsed = urlparse(base_url)

    for payload in SQLI_PAYLOADS[:2]:
        if parsed.query:
            test_url = re.sub(r'=[^&]*', '=' + payload, base_url, count=1)
        else:
            test_url = base_url + "?id=" + payload

        try:
            _, _, body, _ = await fetch(client, test_url, timeout=timeout)
        except ValueError:
            continue

        text = body.decode("utf-8", errors="replace")
        for db_name, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(text):
                    if db_name not in detected_databases:
                        detected_databases.append(db_name)
                    break

    return detected_databases


async def parse_allowed_methods(client, url: str, timeout: float) -> list[str]:
    """Obtem metodos HTTP permitidos via requisicao OPTIONS."""
    try:
        _, headers, _, _ = await fetch(client, url, timeout=timeout, method="OPTIONS")
    except ValueError:
        return []
    allow = header_get(headers, "allow") or header_get(headers, "access-control-allow-methods")
    return sorted({item.strip().upper() for item in allow.split(",") if item.strip()})


async def probe_path(client, rate_limiter: RateLimiter, base_url: str, path: str, timeout: float) -> Probe | None:
    """Faz probing de um path especifico, retornando Probe se acessivel."""
    url = urljoin(base_url.rstrip("/") + "/", path)
    await rate_limiter.wait()
    try:
        status, headers, body, _ = await fetch(client, url, timeout=timeout)
    except ValueError:
        return None
    if status in {200, 204, 301, 302, 307, 308, 401, 403}:
        return Probe(url, status, len(body), header_get(headers, "location"))
    return None


async def scan_paths(
    client,
    rate_limiter: RateLimiter,
    base_url: str,
    timeout: float,
    concurrency: int,
    paths: list[str] | None = None,
) -> list[Probe]:
    """Escaneia paths interessantes em paralelo usando asyncio.gather."""
    target_paths = paths if paths is not None else INTERESTING_PATHS
    sem = asyncio.Semaphore(concurrency)

    async def _limited_probe(path: str) -> Probe | None:
        async with sem:
            return await probe_path(client, rate_limiter, base_url, path, timeout)

    tasks = [_limited_probe(path) for path in target_paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    probes: list[Probe] = []
    for result in results:
        if isinstance(result, Exception):
            continue
        if result:
            probes.append(result)
            print(
                f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                f"{color(str(result.status).ljust(3), status_color(result.status), Cyber.BOLD)} "
                f"{color(str(result.size).rjust(7), Cyber.YELLOW)}B "
                f"{color(result.url, Cyber.CYAN)}"
            )
    return sorted(probes, key=lambda item: (item.status, item.url))


async def test_http_methods(
    client,
    probes: list[Probe],
    timeout: float,
    rate_limiter: RateLimiter,
    methods: list[str] | None = None,
) -> list[MethodResult]:
    """Testa metodos HTTP perigosos nos endpoints descobertos."""
    to_test = methods or METHODS_TO_TEST
    results: list[MethodResult] = []
    seen: set[tuple[str, str]] = set()

    for probe in probes:
        if probe.status not in {200, 401, 403}:
            continue
        for method in to_test:
            key = (probe.url, method)
            if key in seen:
                continue
            seen.add(key)
            await rate_limiter.wait()
            try:
                status, _, body, _ = await fetch(client, probe.url, timeout=timeout, method=method)
            except ValueError:
                continue
            if status not in {0, 404, 405} and method in {"PUT", "DELETE", "PATCH", "TRACE"}:
                results.append(MethodResult(probe.url, method, status, len(body)))
                if status in {200, 201, 204}:
                    print(
                        f"  {color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                        f"{color(method.ljust(7), Cyber.YELLOW, Cyber.BOLD)} "
                        f"{color(str(status).ljust(3), status_color(status), Cyber.BOLD)} "
                        f"{color(probe.url, Cyber.CYAN)}"
                    )
    return results


def build_findings(
    url: str,
    status: int,
    headers: dict[str, str],
    parser: PageParser,
    methods: list[str],
    probes: list[Probe],
    tls_subject: str,
    tls_versions: list[TLSVersionResult] | None = None,
    xss_reflected: bool = False,
    xss_evidence: str = "",
    sqli_databases: list[str] | None = None,
    raw_headers: dict[str, list[str]] | None = None,
    method_results: list[MethodResult] | None = None,
) -> list[Finding]:
    """Gera lista de findings de seguranca baseado nos dados coletados."""
    findings: list[Finding] = []
    parsed = urlparse(url)
    lower_headers = {key.lower(): value for key, value in headers.items()}

    if parsed.scheme == "http":
        findings.append(Finding(
            "high", "transport", "HTTP sem TLS",
            "A pagina principal respondeu sem HTTPS.",
            "Force HTTPS, redirecione HTTP para HTTPS e use HSTS.",
        ))
    elif not tls_subject:
        findings.append(Finding(
            "medium", "transport", "TLS nao validado pela ferramenta",
            "Nao foi possivel coletar certificado TLS.",
            "Verifique validade, cadeia, hostname e protocolos aceitos.",
        ))

    if tls_versions:
        weak_versions = [tv for tv in tls_versions if tv.supported and tv.protocol in ("SSLv3", "TLS 1.0", "TLS 1.1")]
        for tv in weak_versions:
            findings.append(Finding(
                "high", "transport", f"Versao TLS obsoleta: {tv.protocol}",
                f"{tv.protocol} esta habilitado no servidor.",
                f"Desabilite {tv.protocol} e use no minimo TLS 1.2.",
            ))

    for header, recommendation in SECURITY_HEADERS_RECS.items():
        if header not in lower_headers:
            findings.append(Finding(
                "medium", "headers", f"Header ausente: {header}",
                "Header nao apareceu na resposta principal.",
                recommendation,
            ))

    server = header_get(headers, "server")
    powered_by = header_get(headers, "x-powered-by")
    if server:
        findings.append(Finding("low", "fingerprint", "Server exposto", server, "Reduza versao/banner quando possivel."))
    if powered_by:
        findings.append(Finding("low", "fingerprint", "X-Powered-By exposto", powered_by, "Remova o header para reduzir fingerprinting."))

    cors = header_get(headers, "access-control-allow-origin")
    if cors == "*":
        findings.append(Finding(
            "medium", "cors", "CORS permissivo",
            "Access-Control-Allow-Origin: *",
            "Restrinja origens permitidas e revise credenciais CORS.",
        ))

    cookies = (raw_headers or {}).get("set-cookie", [])
    for cookie in cookies:
        lowered = cookie.lower()
        missing = [flag for flag in ("httponly", "secure", "samesite") if flag not in lowered]
        if missing:
            findings.append(Finding(
                "medium", "cookies", "Cookie sem flags fortes",
                f"faltando: {', '.join(missing)}",
                "Use Secure, HttpOnly e SameSite em cookies sensiveis.",
            ))

    dangerous_methods = [method for method in methods if method in {"PUT", "DELETE", "TRACE", "CONNECT"}]
    if dangerous_methods:
        findings.append(Finding(
            "high", "methods", "Metodos HTTP perigosos habilitados",
            ", ".join(dangerous_methods),
            "Desabilite metodos nao usados no servidor, proxy e aplicacao.",
        ))

    if parser.password_inputs and parsed.scheme == "http":
        findings.append(Finding(
            "critical", "auth", "Senha em pagina sem HTTPS",
            f"{parser.password_inputs} campo(s) password detectado(s).",
            "Nunca sirva formularios de autenticacao via HTTP.",
        ))
    elif parser.password_inputs:
        findings.append(Finding(
            "info", "auth", "Formulario de login detectado",
            f"{parser.password_inputs} campo(s) password detectado(s).",
            "Revise MFA, rate limit, lockout e protecao contra credential stuffing.",
        ))

    if parser.comments:
        findings.append(Finding(
            "low", "content", "Comentarios HTML presentes",
            parser.comments[0],
            "Remova comentarios com detalhes internos, rotas, tokens ou tecnologia.",
        ))

    sensitive_hits = [
        probe for probe in probes
        if probe.status in {200, 401, 403} and any(token in probe.url for token in (".env", ".git", "dump", "backup", "config", "phpinfo", "actuator"))
    ]
    for probe in sensitive_hits:
        severity = "high" if probe.status == 200 else "medium"
        findings.append(Finding(
            severity, "exposure", "Endpoint/arquivo sensivel exposto",
            f"{probe.status} {probe.url}",
            "Remova arquivos sensiveis do webroot e restrinja endpoints administrativos.",
        ))

    if 500 <= status < 600:
        findings.append(Finding(
            "medium", "stability", "Erro 5xx na pagina principal",
            f"HTTP {status}",
            "Investigue logs e tratamento de erro para evitar vazamento e indisponibilidade.",
        ))

    if xss_reflected:
        findings.append(Finding(
            "high", "xss", "Entrada refletida sem sanitizacao",
            xss_evidence,
            "Use encoding de saida (HTML entities) e CSP para mitigar XSS refletido.",
        ))

    if sqli_databases:
        findings.append(Finding(
            "critical", "sqli", "Possivel injecao SQL (error-based)",
            f"Banco detectado: {', '.join(sqli_databases)}",
            "Use queries parametrizadas/prepared statements e validacao de entrada.",
        ))

    missing_csrf = parser.forms_missing_csrf
    if missing_csrf > 0:
        findings.append(Finding(
            "medium", "csrf", "Formulario sem token CSRF",
            f"{missing_csrf} formulario(s) POST sem campo CSRF hidden.",
            "Adicione tokens CSRF em todos os formularios que modificam estado.",
        ))

    if method_results:
        high_methods = [mr for mr in method_results if mr.status in {200, 201, 204} and mr.method in {"PUT", "DELETE", "TRACE"}]
        for mr in high_methods:
            severity = "high" if mr.method in {"PUT", "DELETE"} else "medium"
            recommendation = (
                "Restrinja metodos HTTP nao utilizados via servidor/proxy/WAF."
                if mr.method == "TRACE"
                else "Verifique autenticacao/autorizacao e restrinja metodos nao utilizados."
            )
            findings.append(Finding(
                severity, "methods", f"Metodo {mr.method} aceito",
                f"{mr.status} {mr.url}",
                recommendation,
            ))

        medium_methods = [mr for mr in method_results if mr.status in {200, 201, 204} and mr.method == "PATCH"]
        for mr in medium_methods:
            findings.append(Finding(
                "medium", "methods", "Metodo PATCH aceito",
                f"{mr.status} {mr.url}",
                "Verifique autenticacao/autorizacao e restrinja metodos nao utilizados.",
            ))

    return findings


def risk_score(findings: list[Finding]) -> int:
    """Calcula score de risco somando pesos das severidades."""
    return sum(RISK_WEIGHTS.get(finding.severity, 0) for finding in findings)


def severity_color(severity: str) -> str:
    """Retorna cor ANSI correspondente a severidade do finding."""
    return _SEVERITY_COLORS.get(severity, Cyber.WHITE)


async def run_audit(
    url: str,
    timeout: float,
    user_agent: str,
    threads: int,
    deep: bool,
    proxy: str | None = None,
    requests_per_second: float = 0.0,
    test_vulns: bool = False,
    test_methods: bool = False,
    auth: dict[str, str] | None = None,
    bearer_token: str | None = None,
    cookie: str | None = None,
    extra_headers: list[str] | None = None,
    paths: list[str] | None = None,
) -> AuditResult:
    """Executa auditoria completa em uma URL alvo."""
    started = time.monotonic()
    target = normalize_url(url)
    parsed = urlparse(target)
    ip = await resolve_ip(parsed.hostname or "")
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy)
    apply_session_auth(client, auth=auth, bearer_token=bearer_token, cookie=cookie, extra_headers=extra_headers)

    logger.info("audit iniciado: %s", target)
    logger.debug("threads=%d, deep=%s, test_vulns=%s, test_methods=%s", threads, deep, test_vulns, test_methods)

    try:
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(target, Cyber.WHITE, Cyber.BOLD)}")
        if ip:
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"IP: {color(ip, Cyber.YELLOW)}")

        status, headers, body, raw_headers = await fetch(client, target, timeout=timeout)
        content_type = header_get(headers, "content-type")
        text = body.decode("utf-8", errors="replace") if "text/html" in content_type.lower() else ""
        parser = PageParser()
        if text:
            parser.feed(text)

        tls_subject, tls_issuer, tls_not_after = await tls_info(target, timeout)
        tls_versions = await check_tls_versions(target, timeout) if parsed.scheme == "https" else []
        methods = await parse_allowed_methods(client, target, timeout)
        probes = await scan_paths(client, rate_limiter, target, timeout, threads, paths=paths) if deep else []

        spa_shell_size: int | None = None
        if len(probes) > 10:
            size_counts: dict[int, int] = {}
            for p in probes:
                size_counts[p.size] = size_counts.get(p.size, 0) + 1
            dominant_size, dominant_count = max(size_counts.items(), key=lambda kv: kv[1])
            if dominant_count > len(probes) * 0.8:
                spa_shell_size = dominant_size
                logger.debug("SPA detectado: %d/%d probes com size=%d",
                             dominant_count, len(probes), dominant_size)

        xss_reflected, xss_evidence = False, ""
        sqli_databases: list[str] | None = None
        if test_vulns:
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Testando XSS reflection...")
            xss_reflected, xss_evidence = await check_xss_reflection(client, target, timeout)
            if xss_reflected:
                print(color("[!]", Cyber.RED, Cyber.BOLD), "XSS refletido detectado!")

            print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Testando SQLi error-based...")
            sqli_databases = await check_sqli_errors(client, target, timeout)
            if sqli_databases:
                print(color("[!]", Cyber.RED, Cyber.BOLD), f"Erros SQL detectados: {', '.join(sqli_databases)}")

        method_results: list[MethodResult] | None = None
        if test_methods and probes:
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Testando metodos HTTP...")
            method_results = await test_http_methods(client, probes, timeout, rate_limiter)
            if not method_results:
                print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Nenhum metodo perigoso aceito.")
    finally:
        await client.aclose()

    if spa_shell_size is not None:
        probes = [p for p in probes if p.size != spa_shell_size]
        if method_results:
            method_results = [m for m in method_results if m.size != spa_shell_size]

    findings = build_findings(
        target, status, headers, parser, methods, probes, tls_subject,
        tls_versions=tls_versions, xss_reflected=xss_reflected,
        xss_evidence=xss_evidence, sqli_databases=sqli_databases,
        raw_headers=raw_headers, method_results=method_results,
    )

    return AuditResult(
        target=url,
        final_url=target,
        status=status,
        title=parser.title,
        ip=ip,
        tls_subject=tls_subject,
        tls_issuer=tls_issuer,
        tls_not_after=tls_not_after,
        allowed_methods=methods,
        forms=parser.forms,
        password_inputs=parser.password_inputs,
        probes=probes,
        findings=findings,
        risk_score=risk_score(findings),
        elapsed=time.monotonic() - started,
        tls_versions=tls_versions,
        xss_reflected=xss_reflected,
        sqli_errors=sqli_databases,
        csrf_missing=parser.forms_missing_csrf,
        method_results=method_results,
    )


def print_result(result: AuditResult) -> None:
    """Exibe resultado da auditoria formatado no terminal."""
    print()
    print(color("Resumo", Cyber.CYAN, Cyber.BOLD))
    print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} URL: {color(result.final_url, Cyber.WHITE, Cyber.BOLD)}")
    print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} Status: {color(str(result.status), status_color(result.status), Cyber.BOLD)} | Score: {color(str(result.risk_score), Cyber.YELLOW, Cyber.BOLD)} | Tempo: {color(f'{result.elapsed:.2f}s', Cyber.YELLOW)}")
    if result.title:
        print(f"{color('[T]', Cyber.MAGENTA, Cyber.BOLD)} Title: {color(result.title, Cyber.WHITE)}")
    if result.tls_subject:
        print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} TLS: {color(result.tls_subject, Cyber.GREEN)} | expira: {color(result.tls_not_after, Cyber.YELLOW)}")
    if result.tls_versions:
        weak = [tv for tv in result.tls_versions if tv.supported and tv.protocol in ("SSLv3", "TLS 1.0", "TLS 1.1")]
        strong = [tv for tv in result.tls_versions if tv.supported and tv.protocol in ("TLS 1.2", "TLS 1.3")]
        tls_status = color(", ".join(tv.protocol for tv in strong), Cyber.GREEN)
        if weak:
            tls_status += " | " + color(", ".join(tv.protocol for tv in weak), Cyber.RED, Cyber.BOLD)
        print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} TLS versions: {tls_status}")
    if result.allowed_methods:
        print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} Metodos: {color(', '.join(result.allowed_methods), Cyber.WHITE)}")
    print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} Forms: {color(str(result.forms), Cyber.WHITE)} | Password inputs: {color(str(result.password_inputs), Cyber.WHITE)}")
    if result.xss_reflected:
        print(f"{color('[!]', Cyber.RED, Cyber.BOLD)} XSS refletido: {color('SIM', Cyber.RED, Cyber.BOLD)}")
    if result.sqli_errors:
        print(f"{color('[!]', Cyber.RED, Cyber.BOLD)} SQLi erros: {color(', '.join(result.sqli_errors), Cyber.RED, Cyber.BOLD)}")
    if result.csrf_missing:
        print(f"{color('[!]', Cyber.YELLOW, Cyber.BOLD)} CSRF ausente: {color(str(result.csrf_missing), Cyber.YELLOW)} formulario(s)")
    if result.method_results:
        print(color("\nHTTP Methods scan", Cyber.CYAN, Cyber.BOLD))
        for mr in result.method_results:
            marker = color("[+]", Cyber.GREEN, Cyber.BOLD) if mr.status in {200, 201, 204} else color("[-]", Cyber.YELLOW)
            print(
                f"  {marker} "
                f"{color(mr.method.ljust(7), Cyber.YELLOW, Cyber.BOLD)} "
                f"{color(str(mr.status).ljust(3), status_color(mr.status), Cyber.BOLD)} "
                f"{color(mr.url, Cyber.CYAN)}"
            )

    print(color("\nFindings red/blue", Cyber.CYAN, Cyber.BOLD))
    if not result.findings:
        print(color("Nenhum finding relevante com os checks atuais.", Cyber.GREEN))
        return

    for finding in sorted(result.findings, key=lambda item: -RISK_WEIGHTS.get(item.severity, 0)):
        sev = color(finding.severity.upper().ljust(8), severity_color(finding.severity), Cyber.BOLD)
        print(f"{sev} {color(finding.category.ljust(11), Cyber.GRAY)} {color(finding.item, Cyber.WHITE, Cyber.BOLD)}")
        print(f"         evidencia: {color(finding.evidence, Cyber.YELLOW)}")
        print(f"         defesa:    {color(finding.recommendation, Cyber.GREEN)}")


def _save_audit_output(path: str, result: AuditResult, quiet: bool = False) -> None:
    """Salva resultado da auditoria em arquivo JSON ou CSV."""
    data = asdict(result)
    write_output(
        path,
        data,
        fieldnames=["severity", "category", "item", "evidence", "recommendation"],
        csv_rows=data["findings"],
        quiet=quiet,
    )


def build_parser() -> argparse.ArgumentParser:
    """Constroi parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Auditoria web red/blue para laboratorios e alvos autorizados."
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: https://example.com")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com URLs alvo (uma por linha).")
    parser.add_argument("--output-dir", dest="output_dir", help="Diretorio para salvos individuais (hostname.json).")
    parser.add_argument("--threads", type=int, default=20, help="Threads para probes de paths. Padrao: 20")
    parser.add_argument("--paths-file", dest="paths_file", help="Arquivo com paths customizados (um por linha). Ativa --deep automaticamente.")
    parser.add_argument("--deep", action="store_true", help="Ativa probes de arquivos/endpoints comuns.")
    parser.add_argument(
        "--test-vulns",
        action="store_true",
        help="Ativa testes de vulnerabilidade (XSS reflection, SQLi error-based).",
    )
    parser.add_argument(
        "--test-methods",
        action="store_true",
        help="Testa metodos HTTP perigosos (PUT, DELETE, PATCH, TRACE) nos endpoints.",
    )
    parser.set_defaults(user_agent=f"Mozilla/5.0 (X11; Linux x86_64) AttackAudit/{__version__}")
    return parser


async def _run_single(url: str, args: argparse.Namespace, quiet: bool = False) -> AuditResult:
    """Executa auditoria em uma unica URL."""
    custom_paths = None
    if getattr(args, "paths_file", None):
        custom_paths = load_paths_from_file(args.paths_file)
    result = await run_audit(
        url, args.timeout, args.user_agent, args.threads, args.deep,
        proxy=args.proxy, requests_per_second=args.delay,
        test_vulns=args.test_vulns,
        test_methods=getattr(args, "test_methods", False),
        auth=getattr(args, "auth", None),
        bearer_token=getattr(args, "bearer_token", None),
        cookie=getattr(args, "cookie", None),
        extra_headers=getattr(args, "header", None),
        paths=custom_paths,
    )
    if not quiet:
        print_result(result)
    return result


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa uma unica auditoria (async)."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    quiet = getattr(args, "quiet", False)
    if getattr(args, "color", None) is not None:
        set_color(args.color)
    if getattr(args, "paths_file", None):
        args.deep = True
    if args.threads < 1:
        raise ValueError("threads precisa ser maior que zero")

    urls = resolve_target_urls(args)
    output_dir = getattr(args, "output_dir", None)
    ensure_output_dir(output_dir)

    all_results: list[AuditResult] = []
    for url in urls:
        result = await _run_single(url, args, quiet=quiet)
        all_results.append(result)
        if output_dir:
            hostname = extract_hostname(url)
            out_path = os.path.join(output_dir, f"{hostname}.json")
            _save_audit_output(out_path, result, quiet=quiet)

    if args.output:
        if len(all_results) == 1:
            _save_audit_output(args.output, all_results[0], quiet=quiet)
        else:
            consolidated = [asdict(r) for r in all_results]
            _path = args.output
            with open(_path, "w", encoding="utf-8") as fh:
                json.dump(consolidated, fh, indent=2)
                fh.write("\n")
            if not quiet:
                print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Resultado consolidado salvo em {color(_path, Cyber.GREEN)}")
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa uma unica auditoria com os argumentos fornecidos."""
    return asyncio.run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do AttackAudit."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.url and not getattr(args, "target_list", None):
        return run_interactive_shell(
            parser, "audit> ", run_once,
            description="AttackAudit interativo.",
            example="https://example.com --deep --test-vulns -o audit.json",
            banner_fn=banner,
        )

    quiet = getattr(args, "quiet", False)
    if quiet and not args.output:
        print(color("Erro: modo quiet requer -o/--output", Cyber.RED), file=sys.stderr)
        return 1

    try:
        if not quiet:
            banner()
        return run_once(args)
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
