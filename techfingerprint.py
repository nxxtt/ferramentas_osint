#!/usr/bin/env python3
"""Fingerprint de tecnologias com versoes exatas via headers, meta tags, scripts.

Analisa HTTP response para detectar CMS, frameworks, libraries e servers
com versao precisa, usando 7 tipos de sinal:
  1. HTTP headers (X-Powered-By, X-Generator, Server, etc.)
  2. Meta tags (<meta name="generator">, etc.)
  3. Script src URLs (jquery-3.7.1.min.js, react@18.2.0/...)
  4. CSS link hrefs (bootstrap.5.3.0.css, font-awesome@6.4.0/...)
  5. Cookies (_rails_session, XSRF-TOKEN, etc.)
  6. HTML body (ng-version, data-reactroot, __vue__)
  7. Headers de seguranca (indican tecnologias)

Cada deteccao inclui nivel de confianca (high/medium/low) e evidencia.
"""
from __future__ import annotations

import argparse
import logging
import re
import time
from dataclasses import asdict, dataclass
from typing import Any

from utils import (
    Cyber,
    FetchError,
    add_base_args,
    add_http_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    init_scanner,
    print_table,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.techfingerprint")

BANNER_ART = r"""
  _____ _           _              _____               _
 |_   _| |__   __ _| | _____  __ |_   _|__ __ _ _ __ | |_
   | | | '_ \ / _` | |/ / _ \/ __| | |/ __/ _` | '_ \| __|
   | | | | | | (_| |   <  __/\__ \ | | (_| (_| | | | | |_
   |_| |_| |_|\__,_|_|\_\___||___/ |_|\___\__,_|_| |_|\__|
"""

DEFAULT_TIMEOUT = 10.0

# ---------------------------------------------------------------------------
# Version extraction patterns — headers, meta, script, css, body
# ---------------------------------------------------------------------------

HEADER_VERSION_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "Apache": [re.compile(r"Apache/([\d.]+)", re.IGNORECASE)],
    "Nginx": [re.compile(r"nginx/([\d.]+)", re.IGNORECASE)],
    "PHP": [re.compile(r"PHP/([\d.]+)", re.IGNORECASE)],
    "IIS": [re.compile(r"Microsoft-IIS/([\d.]+)", re.IGNORECASE)],
    "LiteSpeed": [re.compile(r"LiteSpeed/([\d.]+)", re.IGNORECASE)],
    "Caddy": [re.compile(r"Caddy", re.IGNORECASE)],
    "Express": [re.compile(r"Express/([\d.]+)", re.IGNORECASE)],
    "X-Powered-By": [
        re.compile(r"X-Powered-By:\s*(\S+)", re.IGNORECASE),
    ],
    "ASP.NET": [
        re.compile(r"X-AspNet-Version:\s*([\d.]+)", re.IGNORECASE),
        re.compile(r"X-AspNetMvc-Version:\s*([\d.]+)", re.IGNORECASE),
    ],
}

META_GENERATOR_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("WordPress", re.compile(r'content="WordPress\s+([\d.]+)"', re.IGNORECASE)),
    ("Joomla", re.compile(r'content="Joomla!\s*([\d.]*)"', re.IGNORECASE)),
    ("Drupal", re.compile(r'content="Drupal\s+([\d.]+)"', re.IGNORECASE)),
    ("Ghost", re.compile(r'content="Ghost\s+([\d.]+)"', re.IGNORECASE)),
    ("Hugo", re.compile(r'content="Hugo\s+([\d.]+)"', re.IGNORECASE)),
    ("Jekyll", re.compile(r'content="Jekyll\s+([\d.]+)"', re.IGNORECASE)),
    ("Hexo", re.compile(r'content="Hexo\s+([\d.]+)"', re.IGNORECASE)),
    ("Next.js", re.compile(r'content="Next\.js\s+([\d.]+)"', re.IGNORECASE)),
    ("Nuxt.js", re.compile(r'content="Nuxt\.js\s+([\d.]+)"', re.IGNORECASE)),
    ("Gatsby", re.compile(r'content="Gatsby\s+([\d.]+)"', re.IGNORECASE)),
    ("Squarespace", re.compile(r'content="Squarespace"', re.IGNORECASE)),
    ("Wix", re.compile(r'content="Wix\.com"', re.IGNORECASE)),
    ("TYPO3", re.compile(r'content="TYPO3\s+([\d.]+)"', re.IGNORECASE)),
    ("Craft CMS", re.compile(r'content="Craft CMS"', re.IGNORECASE)),
    ("Hugo", re.compile(r'name="generator"\s+content="Hugo\s+([\d.]+)"', re.IGNORECASE)),
]

SCRIPT_VERSION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("jQuery", re.compile(r'/jquery[@. -]([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("jQuery", re.compile(r'/jquery\.min\.js\?v=([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Bootstrap", re.compile(r'/bootstrap[@. -]([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Bootstrap", re.compile(r'/bootstrap\.min\.js\?v=([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("React", re.compile(r'/react@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("React", re.compile(r'/react\.production\.min\.js', re.IGNORECASE)),
    ("Vue.js", re.compile(r'/vue@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Vue.js", re.compile(r'/vue\.min\.js\?v=([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Angular", re.compile(r'/angular[@. -]([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Angular", re.compile(r'ng-version="([\d.]+)"', re.IGNORECASE)),
    ("Lodash", re.compile(r'/lodash@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Moment.js", re.compile(r'/moment@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Axios", re.compile(r'/axios@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Font Awesome", re.compile(r'/font-awesome[@/](\d+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Font Awesome", re.compile(r'/fontawesome[@/](\d+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Animate.css", re.compile(r'/animate\.css@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Tailwind CSS", re.compile(r'/tailwindcss@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
]

CSS_VERSION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Bootstrap", re.compile(r'/bootstrap[@. -]([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Font Awesome", re.compile(r'/font-awesome[@/](\d+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Font Awesome", re.compile(r'/fontawesome[@/](\d+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Tailwind CSS", re.compile(r'/tailwindcss@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Animate.css", re.compile(r'/animate\.css@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Bulma", re.compile(r'/bulma@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
    ("Materialize", re.compile(r'/materialize@([\d]+\.[\d]+\.[\d]+)', re.IGNORECASE)),
]

COOKIE_TECH_MAP: dict[str, str] = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "connect.sid": "Express/Node.js",
    "laravel_session": "Laravel",
    "_rails_session": "Ruby on Rails",
    "XSRF-TOKEN": "Laravel",
    "csrftoken": "Django",
    "sessionid": "Django",
    "wordpress_": "WordPress",
    "wp-settings-": "WordPress",
    "joomla_": "Joomla",
    "SESS": "Drupal",
    "Drupal.toolbar": "Drupal",
    "_cfuid": "Cloudflare",
    "__cf_bm": "Cloudflare",
    "AWSALBCORS": "AWS ALB",
    "AWSALB": "AWS ALB",
}

# Exact cookie name matches (full string equality)
_COOKIE_EXACT: dict[str, str] = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "connect.sid": "Express/Node.js",
    "laravel_session": "Laravel",
    "_rails_session": "Ruby on Rails",
    "XSRF-TOKEN": "Laravel",
    "csrftoken": "Django",
    "sessionid": "Django",
}

# Prefix cookie matches
_COOKIE_PREFIX: dict[str, str] = {
    "wordpress_": "WordPress",
    "wp-settings-": "WordPress",
    "joomla_": "Joomla",
    "SESS": "Drupal",
    "Drupal.toolbar": "Drupal",
    "_cfuid": "Cloudflare",
    "__cf_bm": "Cloudflare",
    "AWSALBCORS": "AWS ALB",
    "AWSALB": "AWS ALB",
}

BODY_TECH_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("Angular", "body", re.compile(r'ng-version="([\d.]+)"', re.IGNORECASE)),
    ("Angular", "body", re.compile(r'ng-app=', re.IGNORECASE)),
    ("React", "body", re.compile(r'data-reactroot', re.IGNORECASE)),
    ("React", "body", re.compile(r'_reactRootContainer', re.IGNORECASE)),
    ("Vue.js", "body", re.compile(r'data-v-', re.IGNORECASE)),
    ("Vue.js", "body", re.compile(r'__vue__', re.IGNORECASE)),
    ("WordPress", "body", re.compile(r'wp-content', re.IGNORECASE)),
    ("Joomla", "body", re.compile(r'/media/jui/', re.IGNORECASE)),
    ("Drupal", "body", re.compile(r'Drupal\.settings', re.IGNORECASE)),
    ("Django", "body", re.compile(r'csrfmiddlewaretoken', re.IGNORECASE)),
    ("Laravel", "body", re.compile(r'laravel_session', re.IGNORECASE)),
    ("Express", "body", re.compile(r'X-Powered-By.*Express', re.IGNORECASE)),
    ("Svelte", "body", re.compile(r'__svelte', re.IGNORECASE)),
    ("Next.js", "body", re.compile(r'__NEXT_DATA__', re.IGNORECASE)),
    ("Nuxt.js", "body", re.compile(r'__NUXT__', re.IGNORECASE)),
    ("Gatsby", "body", re.compile(r'___gatsby', re.IGNORECASE)),
    ("Shopify", "body", re.compile(r'cdn\.shopify\.com', re.IGNORECASE)),
    ("Magento", "body", re.compile(r'mage/', re.IGNORECASE)),
    ("PrestaShop", "body", re.compile(r'prestashop', re.IGNORECASE)),
    ("OpenCart", "body", re.compile(r'catalog/view/theme', re.IGNORECASE)),
]

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TechFingerprint:
    """Deteccao de uma tecnologia com versao e evidencia."""

    name: str
    version: str = ""
    source: str = ""
    confidence: str = "medium"
    evidence: str = ""
    category: str = ""


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def _detect_header_versions(
    header_blob: str,
    lower_headers: dict[str, str],
) -> list[TechFingerprint]:
    """Detecta versoes exatas a partir de HTTP headers."""
    results: list[TechFingerprint] = []
    seen: set[str] = set()

    for tech_name, patterns in HEADER_VERSION_PATTERNS.items():
        for pat in patterns:
            m = pat.search(header_blob)
            if m:
                version = m.group(1) if pat.groups else ""
                key = f"{tech_name}:{version}"
                if key in seen:
                    continue
                seen.add(key)
                category = "server" if tech_name in {"Apache", "Nginx", "IIS", "LiteSpeed", "Caddy"} else "language"
                results.append(TechFingerprint(
                    name=tech_name,
                    version=version,
                    source="header",
                    confidence="high",
                    evidence=m.group(0)[:80],
                    category=category,
                ))
                break

    return results


def _detect_meta_generators(body: str) -> list[TechFingerprint]:
    """Detecta CMS/frameworks via <meta name="generator"> tags."""
    results: list[TechFingerprint] = []
    seen: set[str] = set()

    for tech_name, pat in META_GENERATOR_PATTERNS:
        m = pat.search(body)
        if m:
            version = m.group(1) if pat.groups and m.lastindex else ""
            key = f"{tech_name}:{version}"
            if key in seen:
                continue
            seen.add(key)
            results.append(TechFingerprint(
                name=tech_name,
                version=version,
                source="meta",
                confidence="high",
                evidence=m.group(0)[:80],
                category="cms",
            ))

    return results


def _detect_script_versions(body: str) -> list[TechFingerprint]:
    """Detecta versoes a partir de <script src="..."> URLs."""
    results: list[TechFingerprint] = []
    seen: set[str] = set()

    for tech_name, pat in SCRIPT_VERSION_PATTERNS:
        for m in pat.finditer(body):
            version = m.group(1) if pat.groups and m.lastindex else ""
            key = f"{tech_name}:{version}"
            if key in seen:
                continue
            seen.add(key)
            category = "library" if tech_name in {
                "jQuery", "Lodash", "Moment.js", "Axios", "Font Awesome",
                "Animate.css", "Tailwind CSS",
            } else "framework"
            results.append(TechFingerprint(
                name=tech_name,
                version=version,
                source="script",
                confidence="high" if version else "medium",
                evidence=m.group(0)[:80],
                category=category,
            ))

    return results


def _detect_css_versions(body: str) -> list[TechFingerprint]:
    """Detecta versoes a partir de <link href="..."> CSS URLs."""
    results: list[TechFingerprint] = []
    seen: set[str] = set()

    for tech_name, pat in CSS_VERSION_PATTERNS:
        for m in pat.finditer(body):
            version = m.group(1) if pat.groups and m.lastindex else ""
            key = f"{tech_name}:{version}"
            if key in seen:
                continue
            seen.add(key)
            results.append(TechFingerprint(
                name=tech_name,
                version=version,
                source="css",
                confidence="high" if version else "medium",
                evidence=m.group(0)[:80],
                category="library",
            ))

    return results


def _detect_cookie_techs(cookies: list[str]) -> list[TechFingerprint]:
    """Detecta tecnologias a partir de nomes de cookies."""
    results: list[TechFingerprint] = []
    seen: set[str] = set()

    for cookie_str in cookies:
        cookie_name = cookie_str.split("=")[0].strip().split(";")[0].strip()

        # Check exact match first
        tech = _COOKIE_EXACT.get(cookie_name)
        if tech and tech not in seen:
            seen.add(tech)
            category = "language" if tech in {"PHP", "Java", "ASP.NET"} else "framework"
            results.append(TechFingerprint(
                name=tech,
                source="cookie",
                confidence="medium",
                evidence=cookie_str[:60],
                category=category,
            ))
            continue

        # Check prefix match
        for prefix, tech in _COOKIE_PREFIX.items():
            if cookie_name.startswith(prefix) and tech not in seen:
                seen.add(tech)
                category = "language" if tech in {"PHP", "Java", "ASP.NET"} else "framework"
                results.append(TechFingerprint(
                    name=tech,
                    source="cookie",
                    confidence="medium",
                    evidence=cookie_str[:60],
                    category=category,
                ))
                break

    return results


def _detect_body_techs(body: str) -> list[TechFingerprint]:
    """Detecta frameworks/CMS via padroes no HTML body."""
    results: list[TechFingerprint] = []
    seen: set[str] = set()

    for tech_name, _signal_type, pat in BODY_TECH_PATTERNS:
        m = pat.search(body)
        if m and tech_name not in seen:
            version = m.group(1) if pat.groups and m.lastindex else ""
            seen.add(tech_name)
            category = "cms" if tech_name in {
                "WordPress", "Joomla", "Drupal", "Shopify", "Magento",
                "PrestaShop", "OpenCart",
            } else "framework"
            results.append(TechFingerprint(
                name=tech_name,
                version=version,
                source="body",
                confidence="high" if version else "low",
                evidence=m.group(0)[:80] if m else "",
                category=category,
            ))

    return results


def fingerprint(
    url: str,
    headers: dict[str, str],
    body: str,
    cookies: list[str],
) -> list[TechFingerprint]:
    """Executa fingerprint completo de tecnologias.

    Combina os 7 sinais e retorna lista unificada deduplicada.
    """
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
    lower_headers = {k.lower(): v for k, v in headers.items()}

    all_results: list[TechFingerprint] = []
    all_results.extend(_detect_header_versions(header_blob, lower_headers))
    all_results.extend(_detect_meta_generators(body))
    all_results.extend(_detect_script_versions(body))
    all_results.extend(_detect_css_versions(body))
    all_results.extend(_detect_cookie_techs(cookies))
    all_results.extend(_detect_body_techs(body))

    # Deduplica por nome — prioriza maior confianca e versao mais detalhada
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    deduped: dict[str, TechFingerprint] = {}
    for fp in all_results:
        existing = deduped.get(fp.name)
        if not existing:
            deduped[fp.name] = fp
            continue
        fp_rank = confidence_order.get(fp.confidence, 3)
        ex_rank = confidence_order.get(existing.confidence, 3)
        if fp_rank < ex_rank or (fp_rank == ex_rank and fp.version and not existing.version):
            deduped[fp.name] = fp

    result = sorted(deduped.values(), key=lambda x: (x.category, x.name, x.version))
    logger.info("Fingerprint: %d tecnologias detectadas em %s", len(result), url)
    return result


# ---------------------------------------------------------------------------
# Async runner
# ---------------------------------------------------------------------------


async def _async_scan(url: str, timeout: float, user_agent: str | None = None) -> list[TechFingerprint]:
    """Executa scan assincrono de uma URL."""
    client = create_async_client(user_agent=user_agent, timeout=timeout) if user_agent is not None else create_async_client(timeout=timeout)
    async with client:
        _status, resp_headers, body_bytes, _raw_headers = await fetch(client, url, timeout)
        body = body_bytes.decode("latin-1", errors="replace")

        # Extrai cookies do header Set-Cookie
        cookies: list[str] = []
        for key, val in resp_headers.items():
            if key.lower() == "set-cookie":
                cookies.append(val)

        return fingerprint(url, dict(resp_headers), body, cookies)


def _scan_url(url: str, timeout: float, user_agent: str | None = None) -> list[TechFingerprint]:
    """Wrapper sync para scan de URL."""
    return safe_asyncio_run(_async_scan(url, timeout, user_agent))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-techfp",
        description="Fingerprint de tecnologias com versoes exatas via headers, meta tags, scripts.",
    )
    parser.add_argument("urls", nargs="*", help="URL(s) para analisar.")
    parser.add_argument("-l", "--list", dest="url_list", help="Arquivo com URLs (uma por linha).")
    add_base_args(parser, timeout_default=DEFAULT_TIMEOUT)
    add_http_args(parser)
    return parser


def _print_results(url: str, results: list[TechFingerprint]) -> None:
    """Imprime tabela de resultados."""
    print(color(f"\n  {url}", Cyber.CYAN, Cyber.BOLD))

    if not results:
        print(color("  [*] Nenhuma tecnologia detectada.", Cyber.GRAY))
        return

    print_table(
        headers=("Tecnologia", "Versao", "Categoria", "Fonte", "Confianca", "Evidencia"),
        rows=[(
            r.name,
            r.version or "-",
            r.category,
            r.source,
            r.confidence,
            r.evidence[:40] if r.evidence else "-",
        ) for r in results],
        column_styles=[
            (Cyber.WHITE, Cyber.BOLD),
            (Cyber.YELLOW,),
            (Cyber.CYAN,),
            (Cyber.GREEN,),
            (Cyber.MAGENTA,),
            (Cyber.GRAY,),
        ],
    )

    # Resumo por categoria
    categories: dict[str, list[str]] = {}
    for r in results:
        categories.setdefault(r.category, []).append(f"{r.name} {r.version}".strip())
    print()
    for cat, techs in sorted(categories.items()):
        print(color(f"  {cat.upper()}: ", Cyber.CYAN, Cyber.BOLD) + ", ".join(techs))


def run_once(args: argparse.Namespace) -> int:
    """Executa fingerprint contra URLs."""
    init_scanner(args)

    urls = list(args.urls) if args.urls else []
    if getattr(args, "url_list", None):
        try:
            with open(args.url_list) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
        except FileNotFoundError:
            print(color("[!]", Cyber.RED, Cyber.BOLD), f"Arquivo nao encontrado: {args.url_list}")
            return 1

    if not urls:
        print(color("[!]", Cyber.RED, Cyber.BOLD), "Nenhuma URL especificada. Use posicao ou --list.")
        return 1

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhum scan sera realizado.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"URLs: {color(str(len(urls)), Cyber.WHITE, Cyber.BOLD)}")
        return 0

    all_results: dict[str, list[dict[str, Any]]] = {}
    start = time.time()
    user_agent = getattr(args, "user_agent", None)

    for url in urls:
        try:
            results = _scan_url(url, args.timeout, user_agent)
            _print_results(url, results)
            all_results[url] = [asdict(r) for r in results]
        except FetchError as exc:
            print(color("[!]", Cyber.RED, Cyber.BOLD), f"Erro ao acessar {url}: {exc}")
            all_results[url] = [{"error": str(exc)}]
        except Exception as exc:
            print(color("[!]", Cyber.RED, Cyber.BOLD), f"Erro inesperado em {url}: {exc}")
            all_results[url] = [{"error": str(exc)}]

    elapsed = time.time() - start

    total_techs = sum(len(v) for v in all_results.values() if isinstance(v, list) and v and "error" not in v[0])
    print()
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"URLs: {color(str(len(urls)), Cyber.GREEN, Cyber.BOLD)} | "
        f"Tecnologias: {color(str(total_techs), Cyber.GREEN, Cyber.BOLD)} | "
        f"Tempo: {color(f'{elapsed:.1f}s', Cyber.WHITE)}"
    )

    if getattr(args, "output", None):
        write_output(args.output, all_results)

    return 0


def main() -> int:
    """Entry point CLI."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.urls and not getattr(args, "url_list", None):
        return run_main_loop(
            parser=parser,
            banner_fn=create_banner(BANNER_ART, "Technology Fingerprint"),
            run_fn=run_once,
            has_target=lambda a: bool(a.urls or getattr(a, "url_list", None)),
            prompt="techfp> ",
            description="Fingerprint de tecnologias — detecta versoes exatas via HTTP.",
            example="https://example.com -o tech.json",
            contextual_help=(
                "Uso: <url> [opcoes]\n"
                "Exemplos:\n"
                "  https://example.com\n"
                "  https://example.com -o tech.json\n"
                "  -l urls.txt -o results.json"
            ),
        )
    return run_once(args)


if __name__ == "__main__":
    raise SystemExit(main())
