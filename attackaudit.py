#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import secrets
import shlex
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from utils import (
    Cyber,
    RateLimiter,
    clear_console,
    color,
    create_session,
    fetch,
    header_get,
    setup_logging,
    status_color,
)

import logging

logger = logging.getLogger("mytools.attackaudit")

"""Ferramenta de auditoria web para alvos autorizados, combinando red team e hardening defensivo."""

SECURITY_HEADERS = {
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

RISK_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}

SQL_ERROR_PATTERNS: dict[str, list[str]] = {
    "mysql": [
        r"You have an error in your SQL syntax",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "mssql": [
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server[^a-zA-Z0-9]",
        r"ODBC SQL Server Driver",
        r"SQLJDBC",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"Unclosed quotation mark after the character string",
    ],
    "oracle": [
        r"(\W|\A)ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"(\W|\A)SQLITE_ERROR",
        r"SQLite error",
    ],
}

SQLI_PAYLOADS = ["'", "\"", "`", "' OR '1'='1", "\" OR \"1\"=\"1"]

CSRF_FIELD_NAMES = {
    "csrf_token", "_csrf", "csrf", "csrftoken", "_token",
    "authenticity_token", "xsrf-token", "_xsrf", "XSRF-TOKEN",
    "_csrf_token", "csrfmiddlewaretoken", "__RequestVerificationToken",
}


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
        self._in_form = False
        self.form_has_csrf: list[bool] = []
        self._current_form_has_csrf = False
        self._hidden_inputs: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self._title = True
        if tag.lower() == "form":
            self.forms += 1
            self._in_form = True
            self._current_form_has_csrf = False
        if tag.lower() == "input":
            input_type = attrs_dict.get("type", "").lower()
            input_name = attrs_dict.get("name", "").lower()
            if input_type == "password":
                self.password_inputs += 1
            if input_type == "hidden" and input_name in {f.lower() for f in CSRF_FIELD_NAMES}:
                self._current_form_has_csrf = True
            if input_type == "hidden" and input_name:
                self._hidden_inputs.append((input_name, attrs_dict.get("value", "")))
        if tag.lower() == "script" and attrs_dict.get("src"):
            self.external_scripts.add(attrs_dict["src"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._title = False
        if tag.lower() == "form":
            self._in_form = False
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
    tls_versions: list[TLSVersionResult] | None = None
    xss_reflected: bool = False
    sqli_errors: list[str] | None = None
    csrf_missing: int = 0


def banner() -> None:
    """Exibe banner ASCII art do AttackAudit."""
    art = r"""
    ___   __  __             __      ___             ___ __ 
   /   | / /_/ /_____ ______/ /__   /   | __  ______/ (_) /_
  / /| |/ __/ __/ __ `/ ___/ //_/  / /| |/ / / / __  / / __/
 / ___ / /_/ /_/ /_/ / /__/ ,<    / ___ / /_/ / /_/ / / /_  
/_/  |_\__/\__/\__,_/\___/_/|_|  /_/  |_\__,_/\__,_/_/\__/  
"""
    print(color(art.rstrip(), Cyber.CYAN, Cyber.BOLD))
    print(color("   red/blue web audit | ofensivo autorizado + hardening defensivo\n", Cyber.MAGENTA))


def normalize_url(url: str) -> str:
    """Normaliza e valida a URL alvo, adicionando https:// se necessario."""
    url = url.strip()
    if not url:
        raise ValueError("informe uma URL alvo")
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"URL invalida: {url}")
    return url.rstrip("/")


def resolve_ip(hostname: str) -> str:
    """Resolve hostname para endereco IP, retornando string vazia em caso de erro."""
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return ""


def tls_info(url: str, timeout: float) -> tuple[str, str, str]:
    """Coleta subject, issuer e data de expiracao do certificado TLS."""
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


def check_tls_versions(url: str, timeout: float) -> list[TLSVersionResult]:
    """Testa suporte a versoes TLS/SSL, identificando versoes obsoletas."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return []
    hostname = parsed.hostname or ""
    port = parsed.port or 443
    results: list[TLSVersionResult] = []

    version_configs = [
        ("SSLv3", ssl.PROTOCOL_TLS, ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, 'SSLv3') else None),
        ("TLS 1.0", ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None),
        ("TLS 1.1", ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None),
        ("TLS 1.2", ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1_3),
    ]

    for protocol_name, _, tls_version in version_configs:
        if tls_version is None:
            results.append(TLSVersionResult(protocol=protocol_name, supported=False, reason="nao disponivel no Python"))
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    _ = tls_sock.version()
            results.append(TLSVersionResult(protocol=protocol_name, supported=True))
        except (ssl.SSLError, OSError, TimeoutError) as e:
            results.append(TLSVersionResult(protocol=protocol_name, supported=False, reason=str(e)[:80]))

    return results


def check_xss_reflection(session, base_url: str, timeout: float) -> tuple[bool, str]:
    """Testa se a URL reflete entrada sem sanitizacao basica de XSS."""
    marker = "xss" + secrets.token_hex(4)
    test_url = base_url
    parsed = urlparse(base_url)

    if parsed.query:
        test_url = base_url + marker
    else:
        separator = "&" if "?" in base_url else "?"
        test_url = base_url + separator + "q=" + marker

    try:
        _, headers, body = fetch(session, test_url, timeout=timeout)
    except ValueError:
        return False, ""

    text = body.decode("utf-8", errors="replace")
    if marker in text:
        lower_text = text.lower()
        marker_lower = marker.lower()
        if marker_lower in lower_text:
            context = "html_body"
            idx = lower_text.find(marker_lower)
            snippet = text[max(0, idx - 30):idx + len(marker) + 30]
            return True, f"refletido em {context}: ...{snippet}..."
    return False, ""


def check_sqli_errors(session, base_url: str, timeout: float) -> list[str]:
    """Testa se a aplicacao retorna erros SQL em payloads de injecao."""
    detected_databases: list[str] = []
    parsed = urlparse(base_url)

    for payload in SQLI_PAYLOADS[:2]:
        if parsed.query:
            test_url = re.sub(r'=[^&]*', '=' + payload, base_url, count=1)
        else:
            test_url = base_url + "?id=" + payload

        try:
            _, _, body = fetch(session, test_url, timeout=timeout)
        except ValueError:
            continue

        text = body.decode("utf-8", errors="replace")
        for db_name, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    if db_name not in detected_databases:
                        detected_databases.append(db_name)
                    break

    return detected_databases


def parse_allowed_methods(session, url: str, timeout: float) -> list[str]:
    """Obtem metodos HTTP permitidos via requisicao OPTIONS."""
    try:
        _, headers, _ = fetch(session, url, timeout=timeout, method="OPTIONS")
    except ValueError:
        return []
    allow = header_get(headers, "allow") or header_get(headers, "access-control-allow-methods")
    return sorted({item.strip().upper() for item in allow.split(",") if item.strip()})


def probe_path(session, rate_limiter: RateLimiter, base_url: str, path: str, timeout: float) -> Probe | None:
    """Faz probing de um path especifico, retornando Probe se acessivel."""
    url = urljoin(base_url.rstrip("/") + "/", path)
    rate_limiter.wait()
    try:
        status, headers, body = fetch(session, url, timeout=timeout)
    except ValueError:
        return None
    if status in {200, 204, 301, 302, 307, 308, 401, 403}:
        return Probe(url, status, len(body), header_get(headers, "location"))
    return None


def scan_paths(
    session,
    rate_limiter: RateLimiter,
    base_url: str,
    timeout: float,
    threads: int,
) -> list[Probe]:
    """Escaneia paths interessantes em paralelo usando ThreadPoolExecutor."""
    probes: list[Probe] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(probe_path, session, rate_limiter, base_url, path, timeout)
            for path in INTERESTING_PATHS
        ]
        for future in as_completed(futures):
            try:
                probe = future.result()
            except Exception:
                continue
            if probe:
                probes.append(probe)
                print(
                    f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                    f"{color(str(probe.status).ljust(3), status_color(probe.status), Cyber.BOLD)} "
                    f"{color(str(probe.size).rjust(7), Cyber.YELLOW)}B "
                    f"{color(probe.url, Cyber.CYAN)}"
                )
    return sorted(probes, key=lambda item: (item.status, item.url))


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

    for header, recommendation in SECURITY_HEADERS.items():
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

    cookies = [value for key, value in headers.items() if key.lower() == "set-cookie"]
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

    return findings


def risk_score(findings: list[Finding]) -> int:
    """Calcula score de risco somando pesos das severidades."""
    return sum(RISK_WEIGHTS.get(finding.severity, 0) for finding in findings)


def severity_color(severity: str) -> str:
    """Retorna cor ANSI correspondente a severidade do finding."""
    return {
        "critical": Cyber.RED,
        "high": Cyber.RED,
        "medium": Cyber.YELLOW,
        "low": Cyber.BLUE,
        "info": Cyber.GRAY,
    }.get(severity, Cyber.WHITE)


def run_audit(
    url: str,
    timeout: float,
    user_agent: str,
    threads: int,
    deep: bool,
    proxy: str | None = None,
    requests_per_second: float = 0.0,
    test_vulns: bool = False,
) -> AuditResult:
    """Executa auditoria completa em uma URL alvo."""
    started = time.monotonic()
    target = normalize_url(url)
    parsed = urlparse(target)
    ip = resolve_ip(parsed.hostname or "")
    rate_limiter = RateLimiter(requests_per_second)
    session = create_session(user_agent=user_agent, proxy=proxy)

    logger.info("audit iniciado: %s", target)
    logger.debug("threads=%d, deep=%s, test_vulns=%s", threads, deep, test_vulns)

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(target, Cyber.WHITE, Cyber.BOLD)}")
    if ip:
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"IP: {color(ip, Cyber.YELLOW)}")

    status, headers, body = fetch(session, target, timeout=timeout)
    content_type = header_get(headers, "content-type")
    text = body.decode("utf-8", errors="replace") if "text/html" in content_type.lower() else ""
    parser = PageParser()
    if text:
        parser.feed(text)

    tls_subject, tls_issuer, tls_not_after = tls_info(target, timeout)
    tls_versions = check_tls_versions(target, timeout) if parsed.scheme == "https" else None
    methods = parse_allowed_methods(session, target, timeout)
    probes = scan_paths(session, rate_limiter, target, timeout, threads) if deep else []

    xss_reflected, xss_evidence = False, ""
    sqli_databases: list[str] | None = None
    if test_vulns:
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Testando XSS reflection...")
        xss_reflected, xss_evidence = check_xss_reflection(session, target, timeout)
        if xss_reflected:
            print(color("[!]", Cyber.RED, Cyber.BOLD), "XSS refletido detectado!")

        print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Testando SQLi error-based...")
        sqli_databases = check_sqli_errors(session, target, timeout)
        if sqli_databases:
            print(color("[!]", Cyber.RED, Cyber.BOLD), f"Erros SQL detectados: {', '.join(sqli_databases)}")

    findings = build_findings(
        target, status, headers, parser, methods, probes, tls_subject,
        tls_versions=tls_versions, xss_reflected=xss_reflected,
        xss_evidence=xss_evidence, sqli_databases=sqli_databases,
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

    print(color("\nFindings red/blue", Cyber.CYAN, Cyber.BOLD))
    if not result.findings:
        print(color("Nenhum finding relevante com os checks atuais.", Cyber.GREEN))
        return

    for finding in sorted(result.findings, key=lambda item: -RISK_WEIGHTS.get(item.severity, 0)):
        sev = color(finding.severity.upper().ljust(8), severity_color(finding.severity), Cyber.BOLD)
        print(f"{sev} {color(finding.category.ljust(11), Cyber.GRAY)} {color(finding.item, Cyber.WHITE, Cyber.BOLD)}")
        print(f"         evidencia: {color(finding.evidence, Cyber.YELLOW)}")
        print(f"         defesa:    {color(finding.recommendation, Cyber.GREEN)}")


def write_output(path: str, result: AuditResult) -> None:
    """Salva resultado da auditoria em arquivo JSON ou CSV."""
    extension = os.path.splitext(path)[1].lower()
    data = asdict(result)
    with open(path, "w", encoding="utf-8", newline="") as file_handle:
        if extension == ".csv":
            writer = csv.DictWriter(
                file_handle,
                fieldnames=["severity", "category", "item", "evidence", "recommendation"],
            )
            writer.writeheader()
            for finding in data["findings"]:
                writer.writerow(finding)
        else:
            json.dump(data, file_handle, indent=2)
            file_handle.write("\n")
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Resultado salvo em {color(path, Cyber.GREEN)}")


def build_parser() -> argparse.ArgumentParser:
    """Constroi parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Auditoria web red/blue para laboratorios e alvos autorizados."
    )
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: https://example.com")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Timeout em segundos. Padrao: 5")
    parser.add_argument("--threads", type=int, default=20, help="Threads para probes de paths. Padrao: 20")
    parser.add_argument("--deep", action="store_true", help="Ativa probes de arquivos/endpoints comuns.")
    parser.add_argument(
        "--test-vulns",
        action="store_true",
        help="Ativa testes de vulnerabilidade (XSS reflection, SQLi error-based).",
    )
    parser.add_argument(
        "-A",
        "--user-agent",
        default="Mozilla/5.0 (X11; Linux x86_64) AttackAudit/1.0",
        help="User-Agent usado nas requests.",
    )
    parser.add_argument(
        "--proxy",
        help="Proxy para as requests. Ex: http://proxy:8080",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay entre requests (requests por segundo). 0 = sem limite. Padrao: 0",
    )
    parser.add_argument("-o", "--output", help="Salva resultado em .json ou .csv.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostra mensagens de debug no terminal.")
    parser.add_argument("--log-file", help="Salva logs em arquivo.")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa uma unica auditoria com os argumentos fornecidos."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    if not args.url:
        raise ValueError("informe uma URL alvo")
    if args.timeout <= 0:
        raise ValueError("timeout precisa ser maior que zero")
    if args.threads < 1:
        raise ValueError("threads precisa ser maior que zero")

    result = run_audit(
        args.url, args.timeout, args.user_agent, args.threads, args.deep,
        proxy=args.proxy, requests_per_second=args.delay,
        test_vulns=args.test_vulns,
    )
    print_result(result)
    if args.output:
        write_output(args.output, result)
    return 0


def interactive_shell(parser: argparse.ArgumentParser) -> int:
    """Inicia shell interativo para execucao de auditorias."""
    banner()
    print(color("AttackAudit interativo.", Cyber.WHITE, Cyber.BOLD), "Digite 'help', 'clear' ou 'exit'.")
    print(color("Ex:", Cyber.CYAN), "https://example.com --deep --test-vulns -o audit.json")

    while True:
        try:
            raw = input(color("audit> ", Cyber.GREEN, Cyber.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not raw:
            continue
        if raw in {"exit", "quit"}:
            return 0
        if raw == "clear":
            clear_console()
            continue
        if raw == "help":
            parser.print_help()
            continue

        try:
            args = parser.parse_args(shlex.split(raw))
            run_once(args)
        except SystemExit:
            continue
        except Exception as error:
            print(color(f"Erro: {error}", Cyber.RED))


def main() -> int:
    """Ponto de entrada principal do AttackAudit."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.url:
        return interactive_shell(parser)

    try:
        banner()
        return run_once(args)
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
