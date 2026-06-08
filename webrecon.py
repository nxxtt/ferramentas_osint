#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
from dataclasses import asdict, dataclass
from urllib.parse import urljoin, urlparse

from utils import (
    Cyber,
    RateLimiter,
    clear_console,
    color,
    create_session,
    extract_title,
    fetch,
    header_get,
    setup_logging,
    status_color,
)

import logging

logger = logging.getLogger("mytools.webrecon")

"""Ferramenta de reconhecimento HTTP para laboratórios e hosts autorizados."""

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

INTERESTING_HEADERS = [
    "server",
    "x-powered-by",
    "via",
    "set-cookie",
    "location",
    "content-type",
]

# ---------------------------------------------------------------------------
# Fingerprinting signatures
# ---------------------------------------------------------------------------

CMS_SIGNATURES: dict[str, dict[str, list[str]]] = {
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
}

FRAMEWORK_SIGNATURES: dict[str, dict[str, list[str]]] = {
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
}

LIBRARY_SIGNATURES: dict[str, dict[str, list[str]]] = {
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
}

SERVER_PATTERNS: dict[str, str] = {
    "Apache": r"Apache",
    "Nginx": r"nginx",
    "IIS": r"Microsoft-IIS",
    "LiteSpeed": r"LiteSpeed",
    "Caddy": r"Caddy",
    "PHP": r"PHP/[\d.]+",
    "Python": r"Python|WSGI|Gunicorn|uWSGI",
    "Node.js": r"Express|Node\.js",
}


def detect_technologies(
    headers: dict[str, str],
    body: str,
    url: str,
    cookies: list[str] | None = None,
) -> dict[str, list[str]]:
    """Detecta tecnologias (CMS, frameworks, libs) a partir de headers, body e cookies."""
    result: dict[str, list[str]] = {"cms": [], "frameworks": [], "libraries": [], "server": []}
    lower_headers = {k.lower(): v for k, v in headers.items()}
    header_blob = " ".join(f"{k}: {v}" for k, v in lower_headers.items())
    body_lower = body.lower()
    cookie_blob = " ".join(cookies or [])
    url_lower = url.lower()

    for name, sigs in CMS_SIGNATURES.items():
        match = False
        for h in sigs.get("headers", []):
            if h.lower() in header_blob.lower():
                match = True
                break
        if not match:
            for b in sigs.get("body", []):
                if b.lower() in body_lower:
                    match = True
                    break
        if not match:
            for c in sigs.get("cookies", []):
                if c.lower() in cookie_blob.lower():
                    match = True
                    break
        if not match:
            for u in sigs.get("urls", []):
                if u.lower() in url_lower:
                    match = True
                    break
        if match:
            result["cms"].append(name)

    for name, sigs in FRAMEWORK_SIGNATURES.items():
        match = False
        for h in sigs.get("headers", []):
            if h.lower() in header_blob.lower():
                match = True
                break
        if not match:
            for b in sigs.get("body", []):
                if b.lower() in body_lower:
                    match = True
                    break
        if not match:
            for c in sigs.get("cookies", []):
                if c.lower() in cookie_blob.lower():
                    match = True
                    break
        if not match:
            for u in sigs.get("urls", []):
                if u.lower() in url_lower:
                    match = True
                    break
        if match:
            result["frameworks"].append(name)

    for name, sigs in LIBRARY_SIGNATURES.items():
        for b in sigs.get("body", []):
            if b.lower() in body_lower:
                result["libraries"].append(name)
                break

    server_header = lower_headers.get("server", "")
    if server_header:
        import re
        for name, pattern in SERVER_PATTERNS.items():
            if re.search(pattern, server_header, re.IGNORECASE):
                result["server"].append(name)

    return result


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


def banner() -> None:
    """Exibe o banner ASCII art da ferramenta."""
    art = r"""
 _       __     __    ____                      
| |     / /__  / /_  / __ \___  _________  ____ 
| | /| / / _ \/ __ \/ /_/ / _ \/ ___/ __ \/ __ \
| |/ |/ /  __/ /_/ / _, _/  __/ /__/ /_/ / / / /
|__/|__/\___/_.___/_/ |_|\___/\___/\____/_/ /_/ 
"""
    print(color(art.rstrip(), Cyber.CYAN, Cyber.BOLD))
    print(color("   HTTP recon | headers + robots + security checks\n", Cyber.MAGENTA))


def normalize_url(url: str) -> str:
    """Valida e retorna a URL se for HTTP/HTTPS válida."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"URL invalida: {url}")
    return url


def candidate_urls(url: str) -> list[str]:
    """Gera lista de URLs candidatas (https e http) para reconhecimento."""
    url = url.strip()
    if not url:
        raise ValueError("informe uma URL alvo")

    parsed = urlparse(url)
    if parsed.scheme:
        return [normalize_url(url)]

    return [normalize_url("https://" + url), normalize_url("http://" + url)]


def probe_status(session, url: str, timeout: float) -> int | None:
    """Verifica o status HTTP de uma URL, retornando None em caso de falha."""
    try:
        status, _, _ = fetch(session, url, timeout=timeout)
        return status
    except ValueError:
        return None


def run_recon(
    url: str,
    timeout: float,
    user_agent: str,
    proxy: str | None = None,
) -> ReconResult:
    """Executa reconhecimento completo da URL alvo e retorna o resultado."""
    started = time.monotonic()
    errors = []
    session = create_session(user_agent=user_agent, proxy=proxy)

    logger.info("recon iniciado: %s", url)

    for target in candidate_urls(url):
        try:
            status, headers, body = fetch(session, target, timeout=timeout)
            break
        except ValueError as error:
            errors.append(str(error))
    else:
        if len(errors) > 1:
            raise ValueError("falha ao acessar alvo com https e http:\n  - " + "\n  - ".join(errors))
        raise ValueError(errors[0])

    content_type = header_get(headers, "content-type")
    text = body.decode("utf-8", errors="replace") if "text" in content_type.lower() else ""

    lower_headers = {key.lower(): value for key, value in headers.items()}
    present = [header for header in SECURITY_HEADERS if header in lower_headers]
    missing = [header for header in SECURITY_HEADERS if header not in lower_headers]

    robots_url = urljoin(target.rstrip("/") + "/", "robots.txt")
    sitemap_url = urljoin(target.rstrip("/") + "/", "sitemap.xml")

    cookie_header = header_get(headers, "set-cookie")
    cookie_list = [cookie_header] if cookie_header else []

    technologies = detect_technologies(
        headers=headers,
        body=text,
        url=target,
        cookies=cookie_list,
    )

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
        robots_status=probe_status(session, robots_url, timeout),
        sitemap_status=probe_status(session, sitemap_url, timeout),
        elapsed=time.monotonic() - started,
        technologies=technologies,
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


def status_text(status: int | None) -> str:
    """Retorna representação colorida do código de status HTTP."""
    if status is None:
        return color("sem resposta", Cyber.RED)
    if 200 <= status < 300:
        style = Cyber.GREEN
    elif 300 <= status < 400:
        style = Cyber.YELLOW
    elif status in {401, 403}:
        style = Cyber.MAGENTA
    elif 400 <= status < 500:
        style = Cyber.RED
    else:
        style = Cyber.GRAY
    return color(str(status), style, Cyber.BOLD)


def write_output(path: str, result: ReconResult) -> None:
    """Salva o resultado do reconhecimento em formato JSON."""
    with open(path, "w", encoding="utf-8") as file_handle:
        json.dump(asdict(result), file_handle, indent=2)
        file_handle.write("\n")
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Resultado salvo em {color(path, Cyber.GREEN)}")


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="HTTP recon rapido para laboratorios e hosts autorizados."
    )
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: https://example.com")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Timeout em segundos. Padrao: 5")
    parser.add_argument(
        "-A",
        "--user-agent",
        default="Mozilla/5.0 (X11; Linux x86_64) WebRecon/1.0",
        help="User-Agent usado nas requests.",
    )
    parser.add_argument(
        "--proxy",
        help="Proxy para as requests. Ex: http://proxy:8080",
    )
    parser.add_argument("-o", "--output", help="Salva resultado em JSON.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostra mensagens de debug no terminal.")
    parser.add_argument("--log-file", help="Salva logs em arquivo.")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa uma única operação de reconhecimento com os argumentos fornecidos."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    if not args.url:
        raise ValueError("informe uma URL alvo")
    if args.timeout <= 0:
        raise ValueError("timeout precisa ser maior que zero")

    result = run_recon(args.url, args.timeout, args.user_agent, proxy=args.proxy)
    print_result(result)
    if args.output:
        write_output(args.output, result)
    return 0


def interactive_shell(parser: argparse.ArgumentParser) -> int:
    """Inicia o shell interativo para múltiplas operações de reconhecimento."""
    banner()
    print(color("WebRecon interativo.", Cyber.WHITE, Cyber.BOLD), "Digite 'help', 'clear' ou 'exit'.")
    print(color("Ex:", Cyber.CYAN), "https://example.com -o recon.json")

    while True:
        try:
            raw = input(color("webrecon> ", Cyber.GREEN, Cyber.BOLD)).strip()
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
    """Ponto de entrada principal da ferramenta."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.url:
        return interactive_shell(parser)

    try:
        banner()
        sys.stdout.flush()
        return run_once(args)
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
