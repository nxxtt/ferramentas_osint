#!/usr/bin/env python3
"""Modulo de Google Dorking e OSINT search.

Gera Google dorks para um alvo e pode buscar via DuckDuckGo.
Modo padrao: gera URLs clicaveis para o browser.
Modo --search: busca via DuckDuckGo HTML scraping.

Dorks disponiveis por categoria:
  filetype  - Busca por tipos de arquivo expostos
  directory - Directory listing aberto
  login     - Paginas de login/admin expostas
  error     - Mensagens de erro detalhadas
  sensitive - Arquivos sensiveis (.env, .sql, .bak, etc.)
  subdomain - Enumeracao de subdominios via dorks
"""
import argparse
import asyncio
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import quote_plus

import httpx
from bs4 import BeautifulSoup

from utils import (
    Cyber,
    FetchError,
    RateLimiter,
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

logger = logging.getLogger("mytools.googledorking")

STATUS_OK = frozenset({200})

# ── Dork constants ────────────────────────────────────────────────────────────

FILETYPE_DORKS: list[str] = [
    "filetype:pdf",
    "filetype:sql",
    "filetype:env",
    "filetype:log",
    "filetype:bak",
    "filetype:xml",
    "filetype:csv",
    "filetype:xlsx",
    "filetype:doc",
    "filetype:conf",
    "filetype:ini",
    "filetype:yml",
    "filetype:json",
]

DIRECTORY_DORKS: list[str] = [
    'intitle:"index of"',
    'intitle:"index of /"',
    '"parent directory"',
    'intitle:"index of" "wp-content"',
    'intitle:"index of" "backup"',
    'intitle:"index of" ".git"',
    'intitle:"index of" ".env"',
]

LOGIN_DORKS: list[str] = [
    "inurl:login",
    "inurl:admin",
    "inurl:signin",
    "inurl:wp-login",
    "inurl:cpanel",
    "inurl:phpmyadmin",
    "inurl:webmail",
    "inurl:portal",
    "inurl:user/login",
    "inurl:auth/login",
]

ERROR_DORKS: list[str] = [
    'intext:"error" "mysql"',
    'intext:"SQL syntax" "mysql"',
    'intext:"Warning:" "mysql_fetch"',
    'intext:"Fatal error"',
    'intext:"stack trace"',
    'intext:"Exception" "at line"',
    'intext:"Debug" "Traceback"',
    'intext:"Error in query"',
    'intext:"ORA-"',
    'intext:"Microsoft OLE DB Provider"',
]

SENSITIVE_DORKS: list[str] = [
    "inurl:.env",
    "inurl:wp-config",
    "inurl:config.php",
    "inurl:database",
    "inurl:dump",
    "inurl:phpinfo",
    "inurl:server-status",
    "inurl:server-info",
    "inurl:.htaccess",
    "inurl:.htpasswd",
    "inurl:shadow",
    "inurl:passwd",
    "inurl:web.config",
    "inurl:crossdomain.xml",
    "inurl:clientsaccesspolicy.xml",
]

SUBDOMAIN_DORKS: list[str] = [
    "site:*.{domain}",
    'intitle:"index of" site:*.{domain}',
    "inurl:admin site:*.{domain}",
]

ALL_CATEGORIES: dict[str, list[str]] = {
    "filetype": FILETYPE_DORKS,
    "directory": DIRECTORY_DORKS,
    "login": LOGIN_DORKS,
    "error": ERROR_DORKS,
    "sensitive": SENSITIVE_DORKS,
    "subdomain": SUBDOMAIN_DORKS,
}

CATEGORY_LABELS: dict[str, str] = {
    "filetype": "File Types",
    "directory": "Directory Listing",
    "login": "Login/Admin Pages",
    "error": "Error Messages",
    "sensitive": "Sensitive Files",
    "subdomain": "Subdomains",
}

CATEGORY_COLORS: dict[str, tuple[str, ...]] = {
    "filetype": (Cyber.GREEN, Cyber.BOLD),
    "directory": (Cyber.CYAN, Cyber.BOLD),
    "login": (Cyber.YELLOW, Cyber.BOLD),
    "error": (Cyber.RED, Cyber.BOLD),
    "sensitive": (Cyber.RED, Cyber.BOLD),
    "subdomain": (Cyber.MAGENTA, Cyber.BOLD),
}


banner = create_banner(
    r"""
     ____                               __  __   _____
    / ___/_  __________ _____  _____   / / / /  / ___/
   / / __ \ |/_/ ___/ __ `/ __ \ / _ \ / / / /   \__ \
  / / / / / / / /  / /_/ / /_/ /  __// /_/ /____ ___/ /
 /_/ /_/ /_/_/_/   \__,_/ .___/\___/ \____//____//____/
                       /_/
""",
    "Google Dorking & OSINT Search | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class DorkQuery:
    """Representa uma dork gerada para o alvo."""

    category: str
    dork: str
    full_query: str
    google_url: str
    ddg_url: str
    results: list[dict[str, str]] = field(default_factory=list)


def _build_full_query(dork: str, domain: str) -> str:
    """Monta query completa: dork + site:domain."""
    if "{domain}" in dork:
        return dork.format(domain=domain)
    return f"site:{domain} {dork}"


def _build_google_url(query: str) -> str:
    """Monta URL de busca do Google."""
    return f"https://www.google.com/search?q={quote_plus(query)}"


def _build_ddg_url(query: str) -> str:
    """Monta URL de busca do DuckDuckGo."""
    return f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"


def generate_dorks(domain: str, categories: list[str] | None = None) -> list[DorkQuery]:
    """Gera todas as dorks para o dominio alvo."""
    cats = categories or list(ALL_CATEGORIES.keys())
    queries: list[DorkQuery] = []

    for cat in cats:
        dorks = ALL_CATEGORIES.get(cat, [])
        for dork in dorks:
            full = _build_full_query(dork, domain)
            queries.append(DorkQuery(
                category=cat,
                dork=dork,
                full_query=full,
                google_url=_build_google_url(full),
                ddg_url=_build_ddg_url(full),
            ))

    return queries


def add_custom_dorks(domain: str, custom_dorks: list[str], queries: list[DorkQuery]) -> list[DorkQuery]:
    """Adiciona dorks customizadas a lista existente."""
    for dork in custom_dorks:
        full = _build_full_query(dork, domain)
        queries.append(DorkQuery(
            category="custom",
            dork=dork,
            full_query=full,
            google_url=_build_google_url(full),
            ddg_url=_build_ddg_url(full),
        ))
    return queries


def _parse_ddg_results(html: str) -> list[dict[str, str]]:
    """Parseia resultados do DuckDuckGo HTML."""
    soup = BeautifulSoup(html, "html.parser")
    results: list[dict[str, str]] = []

    for result_div in soup.find_all("div", class_="result"):
        title_tag = result_div.find("a", class_="result__a")
        snippet_tag = result_div.find("a", class_="result__snippet")
        url_tag = result_div.find("a", class_="result__url")

        title = title_tag.get_text(strip=True) if title_tag else ""
        snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
        url = url_tag.get_text(strip=True) if url_tag else ""

        if title or url:
            results.append({"title": title, "url": url, "snippet": snippet})

    return results


async def search_ddg(
    client: httpx.AsyncClient,
    query: str,
    timeout: float,
    rate_limiter: RateLimiter,
    max_results: int = 5,
) -> list[dict[str, str]]:
    """Busca via DuckDuckGo HTML scraping."""
    ddg_url = _build_ddg_url(query)
    await rate_limiter.wait()

    try:
        status, _headers, body, _ = await fetch(
            client, ddg_url, timeout=timeout, max_retries=1,
            rate_limiter=rate_limiter,
        )
    except FetchError:
        return []

    if status not in STATUS_OK:
        return []

    html = body.decode("utf-8", errors="replace")
    results = _parse_ddg_results(html)
    return results[:max_results]


async def scan_dorks(
    domain: str,
    categories: list[str] | None = None,
    custom_dorks: list[str] | None = None,
    do_search: bool = False,
    max_results: int = 5,
    user_agent: str = "MyTools/3.0",
    proxy: str | None = None,
    verify: bool = False,
    timeout: float = 10.0,
    requests_per_second: float = 1.0,
) -> list[DorkQuery]:
    """Gera dorks e opcionalmente busca via DuckDuckGo."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(domain, Cyber.WHITE, Cyber.BOLD)}")

    queries = generate_dorks(domain, categories)

    if custom_dorks:
        queries = add_custom_dorks(domain, custom_dorks, queries)

    total = len(queries)
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dorks geradas: {color(str(total), Cyber.WHITE, Cyber.BOLD)}")

    if do_search:
        client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)
        sem = asyncio.Semaphore(3)
        completed = 0
        completed_lock = asyncio.Lock()

        async def _search_one(q: DorkQuery) -> DorkQuery:
            nonlocal completed
            async with sem:
                results = await search_ddg(client, q.full_query, timeout, rate_limiter, max_results)
                new_q = DorkQuery(
                    category=q.category,
                    dork=q.dork,
                    full_query=q.full_query,
                    google_url=q.google_url,
                    ddg_url=q.ddg_url,
                    results=results,
                )
                async with completed_lock:
                    completed += 1
                    if completed % 10 == 0 or completed == total:
                        sys.stdout.write(f"\r  Progresso: {completed}/{total} dorks buscadas...")
                        sys.stdout.flush()
                return new_q

        try:
            async with asyncio.TaskGroup() as tg:
                futures = [tg.create_task(_search_one(q)) for q in queries]
            queries = [f.result() for f in futures]
            sys.stdout.write("\r" + " " * 50 + "\r")
            sys.stdout.flush()
        finally:
            await client.aclose()

    elapsed = time.monotonic() - started
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}")

    return queries


def print_results(queries: list[DorkQuery], quiet: bool = False) -> None:
    """Imprime dorks geradas, agrupadas por categoria."""
    if not queries:
        print(color("Nenhuma dork gerada.", Cyber.RED))
        return

    by_cat: dict[str, list[DorkQuery]] = {}
    for q in queries:
        by_cat.setdefault(q.category, []).append(q)

    for cat, cat_queries in by_cat.items():
        label = CATEGORY_LABELS.get(cat, cat.title())
        cat_color = CATEGORY_COLORS.get(cat, (Cyber.WHITE,))

        print(color(f"\n  [{label}]", *cat_color))

        hdrs = ("#", "DORK", "GOOGLE URL", "RESULTS")
        rows: list[tuple[str, ...]] = []
        for i, q in enumerate(cat_queries, 1):
            n_results = str(len(q.results)) if q.results else "-"
            rows.append((
                str(i),
                q.dork[:50],
                q.google_url[:70],
                n_results,
            ))

        def _styles(_row: tuple[str, ...]) -> list[tuple[str, ...]]:
            return [
                (Cyber.GRAY,),
                (Cyber.WHITE,),
                (Cyber.CYAN,),
                (Cyber.YELLOW,),
            ]

        print_table(
            headers=hdrs,
            rows=rows,
            empty_message=f"Nenhuma dork de {label}.",
            alignments=["right", "left", "left", "right"],
            row_styles_fn=_styles,
        )

        if any(q.results for q in cat_queries):
            print(color("  Resultados encontrados:", Cyber.GREEN, Cyber.BOLD))
            for q in cat_queries:
                if q.results:
                    print(color(f"    {q.dork[:40]}", *cat_color))
                    for r in q.results[:3]:
                        title = r.get("title", "")[:60]
                        url = r.get("url", "")[:70]
                        print(f"      {color('→', Cyber.GRAY)} {color(title, Cyber.WHITE)}")
                        print(f"        {color(url, Cyber.CYAN)}")


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Google Dorking e OSINT search — gera dorks e busca via DuckDuckGo.",
    )
    add_base_args(parser)
    add_http_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo. Ex: example.com")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com dominios (um por linha).")
    parser.add_argument(
        "-c", "--category",
        choices=[*list(ALL_CATEGORIES.keys()), "all", "custom"],
        default="all",
        dest="category",
        help="Categoria de dorks para gerar. Padrao: all",
    )
    parser.add_argument(
        "--custom-dork",
        action="append",
        default=[],
        dest="custom_dorks",
        help="Dork customizada (pode repetir). Ex: 'inurl:api v1'",
    )
    parser.add_argument(
        "--search",
        action="store_true",
        dest="do_search",
        help="Ativar busca via DuckDuckGo (padrao: so gera URLs).",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=5,
        dest="max_results",
        help="Max resultados por dork no DuckDuckGo. Padrao: 5",
    )
    return parser




async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma requisicao HTTP sera enviada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(args.domain, Cyber.WHITE, Cyber.BOLD)}")
        return 0

    categories = None if args.category in ("all", "custom") else [args.category]

    queries = await scan_dorks(
        domain=args.domain,
        categories=categories,
        custom_dorks=args.custom_dorks or None,
        do_search=getattr(args, "do_search", False),
        max_results=getattr(args, "max_results", 5),
        user_agent=args.user_agent,
        proxy=args.proxy,
        verify=getattr(args, "verify", False),
        timeout=args.timeout,
        requests_per_second=args.delay,
    )

    if not quiet:
        print_results(queries, quiet=quiet)

    if args.output:
        write_output(
            args.output,
            [asdict(q) for q in queries],
            ["category", "dork", "full_query", "google_url", "ddg_url", "results"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Google Dorking."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain or getattr(a, "target_list", None)),
        prompt="dork> ",
        description="Google Dorking interativo.",
        example="example.com --category sensitive",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --category filetype\n"
            "  example.com --category sensitive --search\n"
            "  example.com --custom-dork 'inurl:api v1'\n"
            "  -l domains.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
