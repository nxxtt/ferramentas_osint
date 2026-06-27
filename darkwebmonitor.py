#!/usr/bin/env python3
"""Modulo de monitoramento da Dark Web (Dark Web Monitoring).

Busca mencoes do dominio alvo em conteúdo da dark web usando APIs publicas
de enginas de busca que indexam sites .onion:
  - Ahmia — busca em sites .onion indexados (gratis, sem API key)
  - DarkSearch — API REST para busca em dark web (gratis, 30 req/min)
  - Intelligence X — busca em pastes, leaks, darknet (gratis, 50/day, API key)

Limitacao importante:
  Estas APIs buscam em sites .onion PUBLICOS indexados por crawlers.
  Forums privados, marketplaces fechados e canais Telegram NAO sao cobertos.
  Para monitoramento completo, use servicos pagos (DarkOwl, Recorded Future)
  ou acesse a dark web via Tor (socks5://127.0.0.1:9050).

Fluxo:
  1. Busca dominio em cada engine configurada
  2. Classifica mencoes por severidade
  3. Dedup por (fonte, url)
  4. Exibe resumo colorido
"""
import argparse
import json
import logging
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from urllib.parse import quote

import httpx

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
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.darkwebmonitor")

STATUS_OK = frozenset({200})

AHMIA_URL = "https://ahmia.fi/search/?q={domain}"
DARKSEARCH_URL = "https://darksearch.io/api/search?query={domain}"
INTELX_URL = "https://2.intelx.io/intelligent/search"

DEFAULT_SOURCES: list[str] = ["ahmia", "darksearch"]

_SEVERITY_KEYWORDS: dict[str, list[str]] = {
    "critical": ["password", "credential", "leak", "dump", "database", "breach", "exposed", "compromised"],
    "high": ["hack", "attack", "vulnerability", "exploit", "ransomware", "malware", "stealer"],
    "medium": ["discussion", "forum", "review", "tutorial", "guide", "method"],
    "low": ["mention", "reference", "link", "paste"],
}


@dataclass(frozen=True, slots=True)
class DarkWebMention:
    """Representa uma mencao do dominio encontrada na dark web."""

    source: str
    url: str
    title: str
    snippet: str
    date_seen: str
    domain: str
    severity: str


def _classify_severity(text: str) -> str:
    """Classifica a severidade baseado em palavras-chave no texto."""
    text_lower = text.lower()
    for severity in ("critical", "high", "medium", "low"):
        for keyword in _SEVERITY_KEYWORDS[severity]:
            if keyword in text_lower:
                return severity
    return "info"


def _dedup_mentions(mentions: list[DarkWebMention]) -> list[DarkWebMention]:
    """Remove duplicatas por (source, url)."""
    seen: set[tuple[str, str]] = set()
    result: list[DarkWebMention] = []
    for mention in mentions:
        key = (mention.source, mention.url)
        if key not in seen:
            seen.add(key)
            result.append(mention)
    return result


async def _query_ahmia(
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
    rate_limiter: RateLimiter,
    max_results: int = 30,
) -> list[DarkWebMention]:
    """Busca mencoes do dominio no Ahmia (dark web search engine)."""
    mentions: list[DarkWebMention] = []
    url = AHMIA_URL.format(domain=quote(domain))

    try:
        await rate_limiter.wait()
        status, _h, body, _ = await fetch(
            client, url, timeout=timeout, max_retries=2, rate_limiter=rate_limiter,
        )
    except FetchError as e:
        logger.debug("Ahmia fetch error: %s", e)
        return mentions

    if status not in STATUS_OK:
        logger.debug("Ahmia status %d", status)
        return mentions

    html = body.decode("utf-8", errors="replace")
    now = datetime.now(UTC).isoformat()

    results = re.findall(
        r'<h3[^>]*>.*?<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>.*?</h3>',
        html,
        re.DOTALL,
    )

    for href, title_html in results[:max_results]:
        title = re.sub(r"<[^>]+>", "", title_html).strip()
        if not title:
            continue

        result_url = href if href.startswith("http") else f"https://ahmia.fi{href}"
        snippet = title[:200]
        severity = _classify_severity(snippet)

        mentions.append(
            DarkWebMention(
                source="ahmia",
                url=result_url,
                title=title,
                snippet=snippet,
                date_seen=now,
                domain=domain,
                severity=severity,
            )
        )

    return mentions


async def _query_darksearch(
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
    rate_limiter: RateLimiter,
    max_results: int = 30,
) -> list[DarkWebMention]:
    """Busca mencoes do dominio no DarkSearch (dark web search API)."""
    mentions: list[DarkWebMention] = []
    url = DARKSEARCH_URL.format(domain=quote(domain))

    try:
        await rate_limiter.wait()
        status, _h, body, _ = await fetch(
            client, url, timeout=timeout, max_retries=2, rate_limiter=rate_limiter,
        )
    except FetchError as e:
        logger.debug("DarkSearch fetch error: %s", e)
        return mentions

    if status not in STATUS_OK:
        logger.debug("DarkSearch status %d", status)
        return mentions

    data = json.loads(body)
    now = datetime.now(UTC).isoformat()

    for item in data.get("data", [])[:max_results]:
        title = item.get("title", "").strip()
        snippet = item.get("description", "").strip()[:200]
        link = item.get("link", "")
        date_str = item.get("date", now)
        severity = _classify_severity(f"{title} {snippet}")

        if not link:
            continue

        mentions.append(
            DarkWebMention(
                source="darksearch",
                url=link,
                title=title or "(sem titulo)",
                snippet=snippet,
                date_seen=date_str,
                domain=domain,
                severity=severity,
            )
        )

    return mentions


async def _query_intelx(
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
    rate_limiter: RateLimiter,
    api_key: str,
    max_results: int = 30,
) -> list[DarkWebMention]:
    """Busca mencoes do dominio no Intelligence X (dark web + pastes)."""
    if not api_key:
        return []

    mentions: list[DarkWebMention] = []

    try:
        await rate_limiter.wait()
        status, _h, body, _ = await fetch(
            client,
            INTELX_URL,
            timeout=timeout,
            method="POST",
            max_retries=2,
            rate_limiter=rate_limiter,
        )
    except FetchError as e:
        logger.debug("IntelX fetch error: %s", e)
        return mentions

    if status not in {200, 201, 202}:
        logger.debug("IntelX search status %d", status)
        return mentions

    search_id = json.loads(body).get("id", "")
    if not search_id:
        return mentions

    await rate_limiter.wait()
    try:
        s2, _, body2, _ = await fetch(
            client,
            f"https://2.intelx.io/intelligent/search/result?id={search_id}&x=20",
            timeout=timeout,
            max_retries=2,
            rate_limiter=rate_limiter,
        )
    except FetchError:
        return mentions

    if s2 != 200:
        return mentions

    now = datetime.now(UTC).isoformat()
    records = json.loads(body2).get("records", [])

    for rec in records[:max_results]:
        title = rec.get("name", "(sem titulo)")
        selector = rec.get("selector_value", domain)
        bucket = rec.get("bucket", "")
        severity = _classify_severity(title)

        mentions.append(
            DarkWebMention(
                source="intelx",
                url=f"https://intelx.io/{selector}",
                title=title,
                snippet=f"Bucket: {bucket}" if bucket else title,
                date_seen=now,
                domain=domain,
                severity=severity,
            )
        )

    return mentions


async def scan_darkweb(
    domain: str,
    sources: list[str],
    api_keys: dict[str, str | None],
    timeout: float = 5.0,
    user_agent: str = "",
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 2.0,
    max_results: int = 30,
) -> list[DarkWebMention]:
    """Executa scan de dark web em todas as fontes configuradas."""
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(
        user_agent=user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MyTools",
        proxy=proxy,
        verify=verify,
    )

    all_mentions: list[DarkWebMention] = []

    try:
        for source in sources:
            if source == "ahmia":
                found = await _query_ahmia(client, domain, timeout, rate_limiter, max_results)
                all_mentions.extend(found)
                logger.info("[%s] %d mencoes encontradas", source, len(found))
            elif source == "darksearch":
                found = await _query_darksearch(client, domain, timeout, rate_limiter, max_results)
                all_mentions.extend(found)
                logger.info("[%s] %d mencoes encontradas", source, len(found))
            elif source == "intelx":
                key = api_keys.get("intelx_key") or ""
                found = await _query_intelx(client, domain, timeout, rate_limiter, key, max_results)
                all_mentions.extend(found)
                logger.info("[%s] %d mencoes encontradas", source, len(found))
    finally:
        await client.aclose()

    return _dedup_mentions(all_mentions)


def print_results(mentions: list[DarkWebMention]) -> None:
    """Exibe as mencoes encontradas de forma colorida."""
    if not mentions:
        print(color("[*] Nenhuma mencao encontrada na dark web.", Cyber.GREEN))
        return

    severity_colors: dict[str, str] = {
        "critical": Cyber.RED,
        "high": Cyber.ORANGE,
        "medium": Cyber.YELLOW,
        "low": Cyber.CYAN,
        "info": Cyber.GRAY,
    }

    by_source: dict[str, list[DarkWebMention]] = {}
    for mention in mentions:
        by_source.setdefault(mention.source, []).append(mention)

    total = len(mentions)
    sources_count = len(by_source)
    print(
        color(f"\n[+] {total} mencao(es) encontrada(s) em {sources_count} fonte(s):", Cyber.GREEN, Cyber.BOLD)
    )

    for source, source_mentions in by_source.items():
        print(color(f"\n  Fonte: {source}", Cyber.CYAN, Cyber.BOLD))
        for mention in source_mentions:
            sev_color = severity_colors.get(mention.severity, Cyber.GRAY)
            print(
                f"    {color(mention.severity.upper(), sev_color, Cyber.BOLD)}"
                f" | {color(mention.title[:60], Cyber.WHITE)}"
            )
            print(f"      {color(mention.url, Cyber.GRAY)}")


def banner() -> None:
    """Exibe o banner do Dark Web Monitoring."""
    art = r"""
    _____  ______  __               ______            __
   / __/ |/ / _/ |/ /__  ___  ___/ _/ _/ /__  ____  / /____
  / _//    / _/    / _ \/ _ \/ _  / / / / -_)/ __ \/ __/_  /
 /___/_/_/_/__/_/_/_//_/_//_/\__,_/_/_/ \__//_/ /_/\__/ /__/
"""
    create_banner(art, "   dark web monitoring: ahmia + darksearch + intelx")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Monitoramento da Dark Web — busca mencoes do dominio em fonts da dark web.",
    )
    add_base_args(parser)
    add_http_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo para monitorar (ex: example.com).")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com dominios (um por linha).")
    parser.add_argument(
        "--source",
        action="append",
        choices=["ahmia", "darksearch", "intelx"],
        dest="sources",
        help="Fonte para monitoramento (pode repetir). Padrao: ahmia,darksearch.",
    )
    parser.add_argument(
        "--intelx-key",
        dest="intelx_key",
        help="API key do Intelligence X (obrigatoria para --source intelx).",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=30,
        dest="max_results",
        help="Max resultados por fonte. Padrao: 30",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    domain = getattr(args, "domain", None)
    target_list = getattr(args, "target_list", None)

    if not domain and target_list:
        try:
            with open(target_list, encoding="utf-8") as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(color(f"[!] Arquivo nao encontrado: {target_list}", Cyber.RED))
            return 1
    elif domain:
        domains = [domain]
    else:
        print(color("[!] Informe um dominio ou use -l <arquivo>.", Cyber.RED))
        return 1

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma requisicao HTTP sera enviada.")
        for d in domains:
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(d, Cyber.WHITE, Cyber.BOLD)}")
        return 0

    sources = args.sources or list(DEFAULT_SOURCES)
    api_keys: dict[str, str | None] = {
        "intelx_key": getattr(args, "intelx_key", None),
    }

    for s in sources:
        if s == "intelx" and not api_keys.get("intelx_key"):
            print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "intelx requer API key (use --intelx-key)")

    all_mentions: list[DarkWebMention] = []
    for d in domains:
        mentions = await scan_darkweb(
            domain=d,
            sources=sources,
            api_keys=api_keys,
            timeout=args.timeout,
            user_agent=args.user_agent,
            proxy=args.proxy,
            verify=getattr(args, "verify", False),
            requests_per_second=args.delay,
            max_results=getattr(args, "max_results", 30),
        )
        all_mentions.extend(mentions)

    all_mentions = _dedup_mentions(all_mentions)

    if not quiet:
        print_results(all_mentions)

    if args.output:
        write_output(
            args.output,
            [asdict(m) for m in all_mentions],
            ["source", "url", "title", "snippet", "date_seen", "domain", "severity"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Dark Web Monitoring."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain or getattr(a, "target_list", None)),
        prompt="darkweb> ",
        description="Dark Web Monitoring interativo.",
        example="example.com --source ahmia",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --source ahmia --source darksearch\n"
            "  example.com --intelx-key KEY\n"
            "  -l domains.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
