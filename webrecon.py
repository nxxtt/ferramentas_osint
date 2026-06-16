#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import httpx
import ipaddress
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils import (
    Cyber,
    SECURITY_HEADERS,
    add_common_args,
    apply_session_auth,
    color,
    create_async_client,
    extract_hostname,
    extract_title,
    fetch,
    header_get,
    normalize_url,
    query_nvd,
    run_interactive_shell,
    set_color,
    setup_logging,
    show_banner,
    status_color,
    write_output,
    __version__,
)

import logging

import whois

logger = logging.getLogger("mytools.webrecon")

"""Ferramenta de reconhecimento HTTP para laboratórios e hosts autorizados."""

# ---------------------------------------------------------------------------
# Fingerprinting signatures
# ---------------------------------------------------------------------------


def _lower_signatures(sigs: dict[str, dict[str, list[str]]]) -> dict[str, dict[str, list[str]]]:
    """Pré-computa valores lowercase de todas as assinaturas."""
    return {
        name: {k: [v.lower() for v in vals] for k, vals in sigs_dict.items()}
        for name, sigs_dict in sigs.items()
    }

CMS_SIGNATURES = _lower_signatures({
    "WordPress": {
        "headers": ["x-pingback"],
        "body": ["wp-content", "wp-includes", "wp-json", "wp-api", "wordpress"],
        "cookies": ["wordpress_", "wp-settings-"],
        "urls": ["/wp-admin", "/wp-login.php", "/xmlrpc.php"],
    },
    "Joomla": {
        "headers": ["x-content-encoded-by"],
        "body": ["/media/jui/", "Joomla!", "com_content", "joomla"],
        "cookies": ["joomla_"],
        "urls": ["/administrator/"],
    },
    "Drupal": {
        "headers": ["x-generator: Drupal", "x-drupal-cache"],
        "body": ["drupal.js", "Drupal.settings", "/sites/default/files/"],
        "cookies": ["SESS", "Drupal.toolbar"],
        "urls": ["/node/", "/user/login"],
    },
    "Shopify": {
        "headers": ["x-shopify-stage"],
        "body": ["Shopify.theme", "cdn.shopify.com"],
        "cookies": ["_shopify_"],
        "urls": [],
    },
    "Magento": {
        "headers": [],
        "body": ["Mage.Cookies", "magento", "skin/frontend/"],
        "cookies": ["frontend", "guest_view"],
        "urls": ["/admin/"],
    },
})

FRAMEWORK_SIGNATURES = _lower_signatures({
    "Laravel": {
        "headers": [],
        "body": ["csrf-token", "laravel"],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "urls": [],
    },
    "Django": {
        "headers": [],
        "body": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "cookies": ["csrftoken", "sessionid"],
        "urls": ["/admin/"],
    },
    "Express": {
        "headers": ["x-powered-by: Express"],
        "body": [],
        "cookies": ["connect.sid"],
        "urls": [],
    },
    "Flask": {
        "headers": ["x-powered-by: Flask"],
        "body": [],
        "cookies": ["session=ey"],
        "urls": [],
    },
    "ASP.NET": {
        "headers": ["x-aspnet-version", "x-powered-by: ASP.NET"],
        "body": ["__VIEWSTATE", "__VIEWSTATEENCRYPTED"],
        "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
        "urls": [],
    },
    "Spring": {
        "headers": [],
        "body": [],
        "cookies": ["JSESSIONID"],
        "urls": [],
    },
})

LIBRARY_SIGNATURES = _lower_signatures({
    "jQuery": {
        "body": ["jquery", "jQuery("],
    },
    "Bootstrap": {
        "body": ["bootstrap.min.css", "bootstrap.min.js", "bootstrap/"],
    },
    "React": {
        "body": ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "react.production", "react-dom"],
    },
    "Vue.js": {
        "body": ["Vue.__vue__", "vue.min.js", "__vue__"],
    },
    "Angular": {
        "body": ["ng-version", "angular.min.js", "ng-app"],
    },
})

SERVER_PATTERNS: dict[str, re.Pattern[str]] = {
    "Apache": re.compile(r"Apache", re.IGNORECASE),
    "Nginx": re.compile(r"nginx", re.IGNORECASE),
    "IIS": re.compile(r"Microsoft-IIS", re.IGNORECASE),
    "LiteSpeed": re.compile(r"LiteSpeed", re.IGNORECASE),
    "Caddy": re.compile(r"Caddy", re.IGNORECASE),
    "PHP": re.compile(r"PHP/[\d.]+", re.IGNORECASE),
    "Python": re.compile(r"Python|WSGI|Gunicorn|uWSGI", re.IGNORECASE),
    "Node.js": re.compile(r"Express|Node\.js", re.IGNORECASE),
}

# ---------------------------------------------------------------------------
# WAF detection signatures
# ---------------------------------------------------------------------------

WAF_SIGNATURES: dict[str, dict[str, list[str]]] = _lower_signatures({
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "body": ["_cf_chl_opt", "cf_chl_opt"],
        "cookies": ["__cfduid", "cf_clearance"],
        "urls": [],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "server: akamai"],
        "body": ["akamai"],
        "cookies": ["akamai_"],
        "urls": [],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body": [],
        "cookies": ["sucuri_"],
        "urls": [],
    },
    "Imperva": {
        "headers": ["x-iinfo", "server: incapsula"],
        "body": ["_incap_"],
        "cookies": ["incap_ses", "visid_incap_"],
        "urls": [],
    },
    "F5 BIG-IP": {
        "headers": ["server: bigip", "x-cnection"],
        "body": [],
        "cookies": ["bigipserver"],
        "urls": [],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "server: awselb"],
        "body": [],
        "cookies": ["aws-waf-token"],
        "urls": [],
    },
    "ModSecurity": {
        "headers": ["server: mod_security", "server: mod_security_v2"],
        "body": ["mod_security"],
        "cookies": [],
        "urls": [],
    },
    "Fortinet": {
        "headers": ["server: fortigate", "x-fortinet"],
        "body": [],
        "cookies": ["svpncookie"],
        "urls": [],
    },
    "Barracuda": {
        "headers": ["server: barracuda"],
        "body": [],
        "cookies": ["barra_counter_session_"],
        "urls": [],
    },
    "Radware": {
        "headers": ["server: radware"],
        "body": [],
        "cookies": ["rdwr_"],
        "urls": [],
    },
    "Varnish": {
        "headers": ["server: varnish", "x-varnish"],
        "body": [],
        "cookies": [],
        "urls": [],
    },
    "NAXSI": {
        "headers": [],
        "body": ["naxsi_"],
        "cookies": [],
        "urls": [],
    },
})

# ---------------------------------------------------------------------------
# Version extraction patterns (headers + body)
# ---------------------------------------------------------------------------

VERSION_PATTERNS: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "Apache": [(re.compile(r"Apache/([\d.]+)", re.IGNORECASE), "header")],
    "Nginx": [(re.compile(r"nginx/([\d.]+)", re.IGNORECASE), "header")],
    "PHP": [(re.compile(r"PHP/([\d.]+)", re.IGNORECASE), "header")],
    "IIS": [(re.compile(r"Microsoft-IIS/([\d.]+)", re.IGNORECASE), "header")],
    "LiteSpeed": [(re.compile(r"LiteSpeed/([\d.]+)", re.IGNORECASE), "header")],
    "Caddy": [(re.compile(r"Caddy", re.IGNORECASE), "header")],
    "ASP.NET": [
        (re.compile(r"X-AspNet-Version:\s*([\d.]+)", re.IGNORECASE), "header"),
        (re.compile(r"X-AspNetMvc-Version:\s*([\d.]+)", re.IGNORECASE), "header"),
    ],
    "WordPress": [(re.compile(r'content="WordPress\s+([\d.]+)"', re.IGNORECASE), "body")],
    "Joomla": [(re.compile(r'content="Joomla!\s*([\d.]+)"', re.IGNORECASE), "body")],
    "Drupal": [(re.compile(r'content="Drupal\s+([\d.]+)"', re.IGNORECASE), "body")],
    "Angular": [(re.compile(r'ng-version="([\d.]+)"', re.IGNORECASE), "body")],
    "jQuery": [
        (re.compile(r"jquery[.-]([\d]+(?:\.[\d]+)*)", re.IGNORECASE), "body"),
        (re.compile(r"jquery\.min\.js\?v=([\d]+(?:\.[\d]+)*)", re.IGNORECASE), "body"),
    ],
    "Bootstrap": [
        (re.compile(r"bootstrap[.-]([\d]+(?:\.[\d]+)*)", re.IGNORECASE), "body"),
        (re.compile(r"bootstrap\.min\.css\?v=([\d]+(?:\.[\d]+)*)", re.IGNORECASE), "body"),
    ],
}

# ---------------------------------------------------------------------------
# Email harvesting patterns
# ---------------------------------------------------------------------------

EMAIL_PATTERN: re.Pattern[str] = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
)

# Maps detected technology name to NVD keyword search term
CPE_MAP: dict[str, str] = {
    "Apache": "Apache HTTP Server",
    "Nginx": "Nginx",
    "PHP": "PHP",
    "IIS": "Microsoft IIS",
    "LiteSpeed": "LiteSpeed",
    "Caddy": "Caddy",
    "WordPress": "WordPress",
    "Joomla": "Joomla",
    "Drupal": "Drupal",
    "jQuery": "jQuery",
    "Bootstrap": "Bootstrap",
    "Angular": "Angular",
    "ASP.NET": "ASP.NET",
}


def _match_signature(
    sigs: dict,
    header_blob: str,
    body_lower: str,
    cookie_blob: str,
    url_lower: str,
) -> bool:
    """Verifica se uma assinatura corresponde aos dados coletados."""
    for h in sigs.get("headers", []):
        if h in header_blob:
            return True
    for b in sigs.get("body", []):
        if b in body_lower:
            return True
    for c in sigs.get("cookies", []):
        if c in cookie_blob:
            return True
    for u in sigs.get("urls", []):
        if u in url_lower:
            return True
    return False


def detect_technologies(
    headers: dict[str, str],
    body: str,
    url: str,
    cookies: list[str] | None = None,
    lower_headers: dict[str, str] | None = None,
    header_blob: str | None = None,
    body_lower: str | None = None,
    cookie_blob: str | None = None,
    url_lower: str | None = None,
) -> dict[str, list[str]]:
    """Detecta tecnologias (CMS, frameworks, libs) a partir de headers, body e cookies."""
    result: dict[str, list[str]] = {"cms": [], "frameworks": [], "libraries": [], "server": []}
    if lower_headers is None:
        lower_headers = {k.lower(): v for k, v in headers.items()}
    if header_blob is None:
        header_blob = " ".join(f"{k}: {v}".lower() for k, v in lower_headers.items())
    if body_lower is None:
        body_lower = body.lower()
    if cookie_blob is None:
        cookie_blob = " ".join((cookies or [])).lower()
    if url_lower is None:
        url_lower = url.lower()

    for name, sigs in CMS_SIGNATURES.items():
        if _match_signature(sigs, header_blob, body_lower, cookie_blob, url_lower):
            result["cms"].append(name)

    for name, sigs in FRAMEWORK_SIGNATURES.items():
        if _match_signature(sigs, header_blob, body_lower, cookie_blob, url_lower):
            result["frameworks"].append(name)

    for name, sigs in LIBRARY_SIGNATURES.items():
        for b in sigs.get("body", []):
            if b in body_lower:
                result["libraries"].append(name)
                break

    server_header = lower_headers.get("server", "")
    if server_header:
        for name, pattern in SERVER_PATTERNS.items():
            if pattern.search(server_header):
                result["server"].append(name)

    return result


def detect_waf(
    headers: dict[str, str],
    body: str,
    url: str,
    cookies: list[str] | None = None,
    lower_headers: dict[str, str] | None = None,
    header_blob: str | None = None,
    body_lower: str | None = None,
    cookie_blob: str | None = None,
    url_lower: str | None = None,
) -> list[str]:
    """Detecta WAF/CDN a partir de headers, body e cookies."""
    if lower_headers is None:
        lower_headers = {k.lower(): v for k, v in headers.items()}
    if header_blob is None:
        header_blob = " ".join(f"{k}: {v}".lower() for k, v in lower_headers.items())
    if body_lower is None:
        body_lower = body.lower()
    if cookie_blob is None:
        cookie_blob = " ".join((cookies or [])).lower()
    if url_lower is None:
        url_lower = url.lower()

    detected: list[str] = []
    for name, sigs in WAF_SIGNATURES.items():
        if _match_signature(sigs, header_blob, body_lower, cookie_blob, url_lower):
            detected.append(name)
    return detected


def extract_versions(
    headers: dict[str, str],
    body: str,
    lower_headers: dict[str, str] | None = None,
    header_blob: str | None = None,
    body_lower: str | None = None,
) -> list[tuple[str, str]]:
    """Extrai nomes e versoes de tecnologias a partir de headers e body.

    Returns:
        Lista de tuplas (nome, versao) ordenada por relevancia.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    if lower_headers is None:
        lower_headers = {k.lower(): v for k, v in headers.items()}
    if header_blob is None:
        header_blob = " ".join(f"{k}: {v}".lower() for k, v in lower_headers.items())
    if body_lower is None:
        body_lower = body.lower()

    for tech_name, patterns in VERSION_PATTERNS.items():
        if tech_name in seen:
            continue
        for pattern, source in patterns:
            blob = header_blob if source == "header" else body_lower
            match = pattern.search(blob)
            if match:
                version = match.group(1) if match.lastindex else ""
                if version:
                    found.append((tech_name, version))
                    seen.add(tech_name)
                break

    return found


def harvest_emails(text: str) -> list[str]:
    """Extrai enderecos de email de um texto via regex."""
    return sorted(set(EMAIL_PATTERN.findall(text)))


async def _fetch_file(client, url: str, timeout: float) -> str:
    """Busca o conteudo de um arquivo (robots.txt, sitemap.xml) como string."""
    try:
        _, _, body, _ = await fetch(client, url, timeout=timeout)
        return body.decode("utf-8", errors="replace")
    except ValueError:
        return ""


async def crawl_internal_links(
    client,
    url: str,
    body_text: str,
    timeout: float,
    max_links: int = 10,
) -> list[str]:
    """Crawl links internos para coletar emails adicionais."""
    parsed_base = urlparse(url)
    base_netloc = parsed_base.netloc.lower()

    soup = BeautifulSoup(body_text, "html.parser")
    seen_urls: set[str] = set()
    internal_urls: list[str] = []

    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        if href.startswith("/"):
            href = f"{parsed_base.scheme}://{base_netloc}{href}"
        parsed = urlparse(href)
        if parsed.netloc.lower() != base_netloc:
            continue
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if clean in seen_urls:
            continue
        seen_urls.add(clean)
        internal_urls.append(clean)
        if len(internal_urls) >= max_links:
            break

    emails: list[str] = []
    for link in internal_urls:
        try:
            _, _, link_body, _ = await fetch(client, link, timeout=timeout)
            link_text = link_body.decode("utf-8", errors="replace")
            emails.extend(harvest_emails(link_text))
        except ValueError:
            continue

    return emails


@dataclass(frozen=True)
class CVEFinding:
    """Uma vulnerabilidade CVE encontrada para uma tecnologia."""

    cve_id: str
    description: str
    score: float
    severity: str
    technology: str
    version: str


def _severity_color(severity: str) -> str:
    """Retorna a cor ANSI correspondente a severidade CVSS."""
    severity_upper = severity.upper()
    if severity_upper == "CRITICAL":
        return Cyber.RED
    if severity_upper == "HIGH":
        return Cyber.MAGENTA
    if severity_upper == "MEDIUM":
        return Cyber.YELLOW
    if severity_upper == "LOW":
        return Cyber.GREEN
    return Cyber.GRAY


async def lookup_cves(
    versions: list[tuple[str, str]],
    api_key: str | None = None,
    limit_per_tech: int = 5,
    client: httpx.AsyncClient | None = None,
) -> list[CVEFinding]:
    """Consulta CVEs para cada tecnologia detectada na NVD.

    Args:
        versions: Lista de (nome_tecnologia, versao) de extract_versions().
        api_key: Chave opcional da API NVD.
        limit_per_tech: Maximo de CVEs por tecnologia.
        client: Cliente HTTP opcional para reutilizar.

    Returns:
        Lista de CVEFinding ordenada por score decrescente.
    """
    findings: list[CVEFinding] = []
    seen_cves: set[str] = set()

    for tech_name, version in versions:
        search_term = CPE_MAP.get(tech_name, tech_name)
        keyword = f"{search_term} {version}"
        logger.info("NVD lookup: %s", keyword)

        try:
            results = await query_nvd(keyword, api_key=api_key, limit=limit_per_tech, client=client)
        except Exception as error:
            logger.debug("NVD lookup failed for %s: %s", keyword, error)
            continue

        for result in results:
            cve_id = result["id"]
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            findings.append(CVEFinding(
                cve_id=cve_id,
                description=result["description"][:200],
                score=result["score"],
                severity=result["severity"],
                technology=tech_name,
                version=version,
            ))

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


@dataclass(frozen=True)
class WhoisResult:
    """Resultado de uma consulta WHOIS de dominio."""

    domain: str
    registrar: str | None = None
    registrant_name: str | None = None
    registrant_organization: str | None = None
    registrant_country: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    updated_date: str | None = None
    name_servers: list[str] | None = None
    emails: list[str] | None = None
    status: list[str] | None = None


def _format_date(value) -> str | None:
    """Converte valor de data WHOIS para string ISO."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _ensure_list(value) -> list[str] | None:
    """Normaliza valor para lista de strings."""
    if value is None:
        return None
    if isinstance(value, str):
        return [value] if value.strip() else None
    if isinstance(value, list):
        result = [str(v) for v in value if v]
        return result if result else None
    return None


def _run_whois_sync(domain: str) -> WhoisResult | None:
    """Executa consulta WHOIS (sincrona, para usar com asyncio.to_thread).

    Returns:
        WhoisResult ou None se a consulta falhar ou dominio for IP.
    """
    parsed = urlparse(domain)
    hostname = parsed.netloc or parsed.path
    hostname = hostname.split(":")[0].strip()

    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    try:
        w = whois.whois(hostname)
    except Exception as error:
        logger.debug("WHOIS lookup failed for %s: %s", hostname, error)
        return None

    if w is None:
        return None

    name_servers = _ensure_list(getattr(w, "name_servers", None))
    whois_emails = _ensure_list(getattr(w, "emails", None))
    status = _ensure_list(getattr(w, "status", None))

    return WhoisResult(
        domain=hostname,
        registrar=getattr(w, "registrar", None),
        registrant_name=getattr(w, "name", None),
        registrant_organization=getattr(w, "org", None),
        registrant_country=getattr(w, "country", None),
        creation_date=_format_date(getattr(w, "creation_date", None)),
        expiration_date=_format_date(getattr(w, "expiration_date", None)),
        updated_date=_format_date(getattr(w, "updated_date", None)),
        name_servers=name_servers,
        emails=whois_emails,
        status=status,
    )


async def run_whois(domain: str) -> WhoisResult | None:
    """Executa consulta WHOIS de forma assincrona.

    Returns:
        WhoisResult ou None se a consulta falhar ou dominio for IP.
    """
    return await asyncio.to_thread(_run_whois_sync, domain)


@dataclass(frozen=True)
class ReconResult:
    """Resultado de uma operação de reconhecimento HTTP."""

    url: str
    status: int
    final_url: str
    title: str
    server: str
    powered_by: str
    content_type: str
    content_length: int
    redirect: str
    security_headers_present: list[str]
    security_headers_missing: list[str]
    robots_status: int | None
    sitemap_status: int | None
    elapsed: float
    technologies: dict[str, list[str]] | None = None
    cve_findings: list[CVEFinding] = field(default_factory=list)
    waf_detected: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    whois_data: WhoisResult | None = None


def banner() -> None:
    """Exibe o banner ASCII art da ferramenta."""
    art = r"""
 _       __     __    ____
| |     / /__  / /_  / __ \___  _________  ____
| | /| / / _ \/ __ \/ /_/ / _ \/ ___/ __ \/ __ \
| |/ |/ /  __/ /_/ / _, _/  __/ /__/ /_/ / / / /
|__/|__/\___/_.___/_/ |_|\___/\___/\____/_/ /_/
"""
    show_banner(art, "   HTTP recon | headers + robots + security checks")


def candidate_urls(url: str) -> list[str]:
    """Gera lista de URLs candidatas (https e http) para reconhecimento."""
    url = url.strip()
    if not url:
        raise ValueError("informe uma URL alvo")

    parsed = urlparse(url)
    if parsed.scheme in {"http", "https"}:
        return [normalize_url(url)]

    return [normalize_url("https://" + url), normalize_url("http://" + url)]


async def probe_status(client, url: str, timeout: float) -> int | None:
    """Verifica o status HTTP de uma URL, retornando None em caso de falha."""
    try:
        status, _, _, _ = await fetch(client, url, timeout=timeout)
        return status
    except ValueError:
        return None


async def run_recon(
    url: str,
    timeout: float,
    user_agent: str,
    proxy: str | None = None,
    auth: dict[str, str] | None = None,
    bearer_token: str | None = None,
    cookie: str | None = None,
    extra_headers: list[str] | None = None,
    cve: bool = False,
    nvd_api_key: str | None = None,
    deep: bool = False,
    crawl_limit: int = 10,
) -> ReconResult:
    """Executa reconhecimento completo da URL alvo e retorna o resultado."""
    started = time.monotonic()
    errors = []
    client = create_async_client(user_agent=user_agent, proxy=proxy)
    apply_session_auth(client, auth=auth, bearer_token=bearer_token, cookie=cookie, extra_headers=extra_headers)

    logger.info("recon iniciado: %s", url)

    try:
        for target in candidate_urls(url):
            try:
                status, headers, body, raw_headers = await fetch(client, target, timeout=timeout)
                break
            except ValueError as error:
                errors.append(str(error))
        else:
            if len(errors) > 1:
                raise ValueError("falha ao acessar alvo com https e http:\n  - " + "\n  - ".join(errors))
            raise ValueError(errors[0])

        content_type = header_get(headers, "content-type")
        text = body.decode("utf-8", errors="replace") if "text/html" in content_type.lower() else ""

        robots_url = urljoin(target.rstrip("/") + "/", "robots.txt")
        sitemap_url = urljoin(target.rstrip("/") + "/", "sitemap.xml")

        cookie_list = raw_headers.get("set-cookie", [])

        lower_headers = {key.lower(): value for key, value in headers.items()}
        header_blob = " ".join(f"{k}: {v}".lower() for k, v in lower_headers.items())
        body_lower = text.lower()
        cookie_blob = " ".join(cookie_list).lower()
        url_lower = target.lower()

        present = [header for header in SECURITY_HEADERS if header in lower_headers]
        missing = [header for header in SECURITY_HEADERS if header not in lower_headers]

        technologies = detect_technologies(
            headers=headers,
            body=text,
            url=target,
            cookies=cookie_list,
            lower_headers=lower_headers,
            header_blob=header_blob,
            body_lower=body_lower,
            cookie_blob=cookie_blob,
            url_lower=url_lower,
        )

        waf_detected = detect_waf(
            headers=headers,
            body=text,
            url=target,
            cookies=cookie_list,
            lower_headers=lower_headers,
            header_blob=header_blob,
            body_lower=body_lower,
            cookie_blob=cookie_blob,
            url_lower=url_lower,
        )

        cve_findings: list[CVEFinding] = []
        if cve:
            versions = extract_versions(headers=headers, body=text, lower_headers=lower_headers, header_blob=header_blob, body_lower=body_lower)
            if versions:
                cve_findings = await lookup_cves(versions, api_key=nvd_api_key, client=client)
            else:
                cve_findings = []

        emails = harvest_emails(text)
        robots_text = await _fetch_file(client, robots_url, timeout)
        emails.extend(harvest_emails(robots_text))
        sitemap_text = await _fetch_file(client, sitemap_url, timeout)
        emails.extend(harvest_emails(sitemap_text))
        if deep:
            emails.extend(await crawl_internal_links(client, target, text, timeout, max_links=crawl_limit))
        emails = sorted(set(emails))

        whois_data = await run_whois(target)

        robots_status = await probe_status(client, robots_url, timeout)
        sitemap_status = await probe_status(client, sitemap_url, timeout)
    finally:
        await client.aclose()

    return ReconResult(
        url=target,
        status=status,
        final_url=target,
        title=extract_title(text),
        server=header_get(headers, "server"),
        powered_by=header_get(headers, "x-powered-by"),
        content_type=content_type,
        content_length=len(body),
        redirect=header_get(headers, "location"),
        security_headers_present=present,
        security_headers_missing=missing,
        robots_status=robots_status,
        sitemap_status=sitemap_status,
        elapsed=time.monotonic() - started,
        technologies=technologies,
        cve_findings=cve_findings,
        waf_detected=waf_detected,
        emails=emails,
        whois_data=whois_data,
    )


def print_result(result: ReconResult) -> None:
    """Exibe o resultado do reconhecimento formatado no terminal."""
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"URL: {color(result.url, Cyber.WHITE, Cyber.BOLD)}")
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Status: {status_text(result.status)} | Tempo: {color(f'{result.elapsed:.2f}s', Cyber.YELLOW)}")

    if result.redirect:
        print(color("[>]", Cyber.YELLOW, Cyber.BOLD), f"Redirect: {color(result.redirect, Cyber.YELLOW)}")
    if result.title:
        print(color("[T]", Cyber.MAGENTA, Cyber.BOLD), f"Title: {color(result.title, Cyber.WHITE)}")

    print(color("\nHeaders interessantes", Cyber.CYAN, Cyber.BOLD))
    rows = {
        "server": result.server,
        "x-powered-by": result.powered_by,
        "content-type": result.content_type,
        "content-length": str(result.content_length),
    }
    for key, value in rows.items():
        marker = color("[+]", Cyber.GREEN, Cyber.BOLD) if value else color("[-]", Cyber.RED, Cyber.BOLD)
        print(f"{marker} {color(key.ljust(16), Cyber.GRAY)} {value or 'ausente'}")

    print(color("\nSecurity headers", Cyber.CYAN, Cyber.BOLD))
    for header in result.security_headers_present:
        print(f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} {color(header, Cyber.GREEN)}")
    for header in result.security_headers_missing:
        print(f"{color('[-]', Cyber.RED, Cyber.BOLD)} {color(header, Cyber.RED)}")

    if result.technologies:
        _print_technologies(result.technologies)

    if result.cve_findings:
        _print_cve_findings(result.cve_findings)

    if result.waf_detected:
        print(color("\nWAF detectado", Cyber.CYAN, Cyber.BOLD))
        print(f"  {color('[+]', Cyber.GREEN, Cyber.BOLD)} {', '.join(result.waf_detected)}")

    if result.emails:
        print(color(f"\nEmails encontrados ({len(result.emails)})", Cyber.CYAN, Cyber.BOLD))
        for email in result.emails[:30]:
            print(f"  {color('[+]', Cyber.GREEN, Cyber.BOLD)} {color(email, Cyber.GREEN)}")
        if len(result.emails) > 30:
            print(f"  {color(f'... e mais {len(result.emails) - 30} emails', Cyber.GRAY)}")

    if result.whois_data:
        _print_whois(result.whois_data)

    print(color("\nArquivos comuns", Cyber.CYAN, Cyber.BOLD))
    print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} robots.txt  {status_text(result.robots_status)}")
    print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} sitemap.xml  {status_text(result.sitemap_status)}")


def _print_technologies(tech: dict[str, list[str]]) -> None:
    """Exibe as tecnologias detectadas no terminal."""
    labels = {
        "cms": ("CMS", Cyber.MAGENTA),
        "frameworks": ("Framework", Cyber.CYAN),
        "libraries": ("Bibliotecas", Cyber.YELLOW),
        "server": ("Servidor", Cyber.GREEN),
    }
    has_any = any(tech.get(k) for k in labels)
    if not has_any:
        return

    print(color("\nTecnologias detectadas", Cyber.CYAN, Cyber.BOLD))
    for key, (label, style) in labels.items():
        items = tech.get(key, [])
        if items:
            print(f"  {color('[+]', style, Cyber.BOLD)} {label}: {', '.join(items)}")


def _print_cve_findings(findings: list[CVEFinding]) -> None:
    """Exibe os CVEs encontrados no terminal."""
    if not findings:
        print(color("\nCVEs", Cyber.CYAN, Cyber.BOLD))
        print(f"  {color('[-]', Cyber.GREEN, Cyber.BOLD)} Nenhuma vulnerabilidade encontrada")
        return

    print(color(f"\nCVEs ({len(findings)} encontrados)", Cyber.CYAN, Cyber.BOLD))
    for finding in findings[:20]:
        sev_color = _severity_color(finding.severity)
        print(
            f"  {color('[!]', sev_color, Cyber.BOLD)} "
            f"{color(finding.cve_id, sev_color, Cyber.BOLD)} "
            f"({finding.technology} {finding.version}) "
            f"Score: {color(f'{finding.score:.1f}', sev_color, Cyber.BOLD)} "
            f"[{finding.severity.upper()}]"
        )
        print(f"    {color(finding.description[:120], Cyber.GRAY)}")

    if len(findings) > 20:
        print(f"  {color(f'... e mais {len(findings) - 20} CVEs', Cyber.GRAY)}")


def _print_whois(w: WhoisResult) -> None:
    """Exibe os dados WHOIS encontrados no terminal."""
    print(color("\nWHOIS", Cyber.CYAN, Cyber.BOLD))
    rows = [
        ("Domain", w.domain),
        ("Registrar", w.registrar),
        ("Owner", w.registrant_name),
        ("Organization", w.registrant_organization),
        ("Country", w.registrant_country),
        ("Created", w.creation_date),
        ("Expires", w.expiration_date),
        ("Updated", w.updated_date),
    ]
    for label, value in rows:
        if value:
            marker = color("[+]", Cyber.GREEN, Cyber.BOLD)
            print(f"{marker} {color(label.ljust(16), Cyber.GRAY)} {value}")

    if w.name_servers:
        print(f"  {color('[+]', Cyber.GREEN, Cyber.BOLD)} {color('Nameservers'.ljust(16), Cyber.GRAY)} {', '.join(w.name_servers)}")
    if w.emails:
        print(f"  {color('[+]', Cyber.GREEN, Cyber.BOLD)} {color('Emails'.ljust(16), Cyber.GRAY)} {', '.join(w.emails)}")
    if w.status:
        print(f"  {color('[+]', Cyber.GREEN, Cyber.BOLD)} {color('Status'.ljust(16), Cyber.GRAY)} {', '.join(w.status[:5])}")


def status_text(status: int | None) -> str:
    """Retorna representação colorida do código de status HTTP."""
    if status is None:
        return color("sem resposta", Cyber.RED)
    return color(str(status), status_color(status), Cyber.BOLD)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="HTTP recon rapido para laboratorios e hosts autorizados."
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: https://example.com")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com URLs alvo (uma por linha).")
    parser.add_argument("--output-dir", dest="output_dir", help="Diretorio para salvos individuais (hostname.json).")
    parser.add_argument("--cve", action="store_true", help="Busca CVEs para versoes detectadas (via NIST NVD).")
    parser.add_argument("--nvd-api-key", dest="nvd_api_key", help="Chave da API NVD (aumenta rate limit de 5 para 50 req/30s).")
    parser.add_argument("--crawl-limit", dest="crawl_limit", type=int, default=10, help="Limite de links internos para crawl de emails. Padrao: 10. Requer --deep.")
    parser.add_argument("--deep", action="store_true", help="Ativa crawl de links internos para coleta de emails.")
    parser.set_defaults(user_agent=f"Mozilla/5.0 (X11; Linux x86_64) WebRecon/{__version__}")
    return parser


async def _run_single(url: str, args: argparse.Namespace, quiet: bool = False) -> ReconResult:
    """Executa recon em uma unica URL."""
    result = await run_recon(
        url, args.timeout, args.user_agent, proxy=args.proxy,
        auth=getattr(args, "auth", None),
        bearer_token=getattr(args, "bearer_token", None),
        cookie=getattr(args, "cookie", None),
        extra_headers=getattr(args, "header", None),
        cve=getattr(args, "cve", False),
        nvd_api_key=getattr(args, "nvd_api_key", None),
        deep=getattr(args, "deep", False),
        crawl_limit=getattr(args, "crawl_limit", 10),
    )
    if not quiet:
        print_result(result)
    return result


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa uma unica operacao de reconhecimento (async)."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    quiet = getattr(args, "quiet", False)
    if getattr(args, "color", None) is not None:
        set_color(args.color)

    urls: list[str] = []
    if getattr(args, "target_list", None):
        try:
            with open(args.target_list, "r", encoding="utf-8", errors="replace") as fh:
                urls = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            raise ValueError(f"arquivo nao encontrado: {args.target_list}")
    if args.url:
        urls.append(args.url)
    if not urls:
        raise ValueError("informe uma URL alvo ou use -l/--list")

    output_dir = getattr(args, "output_dir", None)
    if output_dir and not os.path.isdir(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    all_results: list[ReconResult] = []
    for url in urls:
        result = await _run_single(url, args, quiet=quiet)
        all_results.append(result)
        if output_dir:
            hostname = extract_hostname(url)
            out_path = os.path.join(output_dir, f"{hostname}.json")
            write_output(out_path, asdict(result), quiet=quiet)

    if args.output:
        if len(all_results) == 1:
            write_output(args.output, asdict(all_results[0]), quiet=quiet)
        else:
            write_output(args.output, [asdict(r) for r in all_results], quiet=quiet)
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa uma unica operacao de reconhecimento com os argumentos fornecidos."""
    return asyncio.run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal da ferramenta."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.url and not getattr(args, "target_list", None):
        return run_interactive_shell(
            parser, "webrecon> ", run_once,
            description="WebRecon interativo.",
            example="https://example.com -o recon.json",
            banner_fn=banner,
        )

    quiet = getattr(args, "quiet", False)
    if quiet and not args.output:
        print(color("Erro: modo quiet requer -o/--output", Cyber.RED), file=sys.stderr)
        return 1

    try:
        if not quiet:
            banner()
            sys.stdout.flush()
        return run_once(args)
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
