#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from urllib.parse import urljoin, urlparse

from utils import (
    Cyber,
    RateLimiter,
    SECURITY_HEADERS,
    add_common_args,
    apply_session_auth,
    color,
    create_session,
    extract_hostname,
    extract_title,
    fetch,
    header_get,
    run_interactive_shell,
    setup_logging,
    show_banner,
    status_color,
    write_output,
)

import logging

logger = logging.getLogger("mytools.webrecon")

"""Ferramenta de reconhecimento HTTP para laboratórios e hosts autorizados."""

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


def _match_signature(
    sigs: dict,
    header_blob: str,
    body_lower: str,
    cookie_blob: str,
    url_lower: str,
) -> bool:
    """Verifica se uma assinatura corresponde aos dados coletados."""
    for h in sigs.get("headers", []):
        if h.lower() in header_blob:
            return True
    for b in sigs.get("body", []):
        if b.lower() in body_lower:
            return True
    for c in sigs.get("cookies", []):
        if c.lower() in cookie_blob:
            return True
    for u in sigs.get("urls", []):
        if u.lower() in url_lower:
            return True
    return False


def detect_technologies(
    headers: dict[str, str],
    body: str,
    url: str,
    cookies: list[str] | None = None,
) -> dict[str, list[str]]:
    """Detecta tecnologias (CMS, frameworks, libs) a partir de headers, body e cookies."""
    result: dict[str, list[str]] = {"cms": [], "frameworks": [], "libraries": [], "server": []}
    lower_headers = {k.lower(): v for k, v in headers.items()}
    header_blob = " ".join(f"{k}: {v}".lower() for k, v in lower_headers.items())
    body_lower = body.lower()
    cookie_blob = " ".join((cookies or [])).lower()
    url_lower = url.lower()

    for name, sigs in CMS_SIGNATURES.items():
        if _match_signature(sigs, header_blob, body_lower, cookie_blob, url_lower):
            result["cms"].append(name)

    for name, sigs in FRAMEWORK_SIGNATURES.items():
        if _match_signature(sigs, header_blob, body_lower, cookie_blob, url_lower):
            result["frameworks"].append(name)

    for name, sigs in LIBRARY_SIGNATURES.items():
        for b in sigs.get("body", []):
            if b.lower() in body_lower:
                result["libraries"].append(name)
                break

    server_header = lower_headers.get("server", "")
    if server_header:
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
    show_banner(art, "   HTTP recon | headers + robots + security checks")


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
        status, _, _, _ = fetch(session, url, timeout=timeout)
        return status
    except ValueError:
        return None


def run_recon(
    url: str,
    timeout: float,
    user_agent: str,
    proxy: str | None = None,
    auth: dict[str, str] | None = None,
    bearer_token: str | None = None,
    cookie: str | None = None,
    extra_headers: list[str] | None = None,
) -> ReconResult:
    """Executa reconhecimento completo da URL alvo e retorna o resultado."""
    started = time.monotonic()
    errors = []
    session = create_session(user_agent=user_agent, proxy=proxy)
    apply_session_auth(session, auth=auth, bearer_token=bearer_token, cookie=cookie, extra_headers=extra_headers)

    logger.info("recon iniciado: %s", url)

    for target in candidate_urls(url):
        try:
            status, headers, body, raw_headers = fetch(session, target, timeout=timeout)
            break
        except ValueError as error:
            errors.append(str(error))
    else:
        if len(errors) > 1:
            raise ValueError("falha ao acessar alvo com https e http:\n  - " + "\n  - ".join(errors))
        raise ValueError(errors[0])

    content_type = header_get(headers, "content-type")
    text = body.decode("utf-8", errors="replace") if "text/html" in content_type.lower() else ""

    lower_headers = {key.lower(): value for key, value in headers.items()}
    present = [header for header in SECURITY_HEADERS if header in lower_headers]
    missing = [header for header in SECURITY_HEADERS if header not in lower_headers]

    robots_url = urljoin(target.rstrip("/") + "/", "robots.txt")
    sitemap_url = urljoin(target.rstrip("/") + "/", "sitemap.xml")

    cookie_list = raw_headers.get("set-cookie", [])

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
    parser.set_defaults(user_agent="Mozilla/5.0 (X11; Linux x86_64) WebRecon/3.0")
    return parser


def _run_single(url: str, args: argparse.Namespace, quiet: bool = False) -> ReconResult:
    """Executa recon em uma unica URL."""
    result = run_recon(
        url, args.timeout, args.user_agent, proxy=args.proxy,
        auth=getattr(args, "auth", None),
        bearer_token=getattr(args, "bearer_token", None),
        cookie=getattr(args, "cookie", None),
        extra_headers=getattr(args, "header", None),
    )
    if not quiet:
        print_result(result)
    return result


def run_once(args: argparse.Namespace) -> int:
    """Executa uma única operação de reconhecimento com os argumentos fornecidos."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    quiet = getattr(args, "quiet", False)

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
        result = _run_single(url, args, quiet=quiet)
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
