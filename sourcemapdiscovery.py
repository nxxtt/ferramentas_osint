#!/usr/bin/env python3
"""Modulo de descoberta de source maps de JavaScript expostos em alvos HTTP.

Busca arquivos .map de JavaScript por duas abordagens:
  1. Script scanning: extrai <script src> da pagina e tenta encontrar .map correspondente
  2. Path probing: sonda paths comuns de .map files diretamente

Fluxo:
  1. Busca a pagina principal e extrai URLs de scripts JS
  2. Para cada JS, gera candidatos .map (append, substituicao)
  3. Sonda paths comuns de JS para buscar .map
  4. Parse do JSON do source map para extrair sources, names
  5. Exibe resumo colorido e salva output detalhado
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin

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
    extract_hostname,
    fetch,
    header_get,
    init_scanner,
    normalize_url,
    print_table,
    resolve_target_urls,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.sourcemapdiscovery")

DEFAULT_SCRIPT_PATHS: list[str] = [
    "static/js/app.js",
    "static/js/main.js",
    "static/js/bundle.js",
    "dist/js/app.js",
    "dist/js/main.js",
    "dist/bundle.js",
    "assets/js/app.js",
    "assets/js/main.js",
    "js/app.js",
    "js/main.js",
    "js/bundle.js",
    "build/bundle.js",
    "build/static/js/main.js",
    "public/static/js/app.js",
    "_next/static/chunks/pages/_app.js",
    "_nuxt/dist/app/client.js",
    "wp-content/themes/*/assets/js/app.js",
    "vendor.js",
    "app.min.js",
    "main.min.js",
    "bundle.min.js",
    "index.js",
    "app.js",
    "main.js",
    "bundle.js",
    "chunk.js",
    "runtime.js",
]

STATUS_OK = frozenset({200})

SCRIPT_PATTERN = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"'?#]+\.js(?:\?[^"'#]*)?)["']""",
    re.IGNORECASE,
)

banner = create_banner(
    r"""
  _____              _                  __  __  ___
 / ____|            | |                |  \/  |/ _ \
 \___ \  ___   ___  | |_ ___  _ __ ___| \  / | | | |
  ___) |/ _ \ / _ \ | __/ _ \| '__/ _ \ |\/| | | | |
 |____/| (_) | (_) || || (_) | | |  __/ |  | | |_| |
      |___/ \___/  \__\___/|_|  \___|_|  |_|\___/
""",
    "Source Map Discovery | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class SourceMapInfo:
    """Representa um source map descoberto."""

    url: str
    js_url: str = ""
    status: int = 0
    raw_size: int = 0
    sources: list[str] = field(default_factory=list)
    sources_count: int = 0
    names_count: int = 0


def extract_script_urls(html: str, base_url: str) -> list[str]:
    """Extrai URLs de scripts externos de um HTML."""
    urls: list[str] = []
    seen: set[str] = set()
    for match in SCRIPT_PATTERN.finditer(html):
        src = match.group(1)
        full = urljoin(base_url, src)
        if full not in seen:
            seen.add(full)
            urls.append(full)
    return urls


def build_map_urls(js_url: str) -> list[str]:
    """Gera URLs candidatas de .map para um JS."""
    candidates: list[str] = []
    if js_url.endswith(".js"):
        candidates.append(js_url + ".map")
        candidates.append(js_url[:-3] + ".js.map")
        candidates.append(js_url[:-3] + ".map")
    elif ".js?" in js_url:
        base = js_url.split("?")[0]
        if base.endswith(".js"):
            candidates.append(base + ".map")
            candidates.append(base[:-3] + ".js.map")
            candidates.append(base[:-3] + ".map")
    return candidates


def parse_source_map(content: bytes) -> SourceMapInfo | None:
    """Faz parse do JSON de um source map e retorna SourceMapInfo."""
    if not content.strip():
        return None

    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    if "sources" not in data and "mappings" not in data:
        return None

    sources: list[str] = []
    raw_sources = data.get("sources", [])
    if isinstance(raw_sources, list):
        for s in raw_sources:
            if isinstance(s, str):
                sources.append(s)

    names: list[str] = []
    raw_names = data.get("names", [])
    if isinstance(raw_names, list):
        for n in raw_names:
            if isinstance(n, str):
                names.append(n)

    return SourceMapInfo(
        url="",
        sources=sources,
        sources_count=len(sources),
        names_count=len(names),
        raw_size=len(content),
    )


async def _probe_map(
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    map_url: str,
    js_url: str,
    timeout: float,
    retries: int = 2,
) -> SourceMapInfo | None:
    """Sonda uma URL de .map e retorna SourceMapInfo se valido."""
    await rate_limiter.wait()

    try:
        status, _headers, content, _ = await fetch(
            client, map_url, timeout=timeout, method="GET",
            max_retries=retries, rate_limiter=rate_limiter,
        )
    except FetchError:
        return None

    if status not in STATUS_OK:
        return None

    parsed = parse_source_map(content)
    if parsed is None:
        return None

    return SourceMapInfo(
        url=map_url,
        js_url=js_url,
        status=status,
        raw_size=len(content),
        sources=parsed.sources,
        sources_count=parsed.sources_count,
        names_count=parsed.names_count,
    )


async def _fetch_page(
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    url: str,
    timeout: float,
    retries: int = 2,
) -> str:
    """Busca uma pagina e retorna o body como string."""
    await rate_limiter.wait()
    try:
        _status, _headers, content, _ = await fetch(
            client, url, timeout=timeout, method="GET",
            max_retries=retries, rate_limiter=rate_limiter,
        )
    except FetchError:
        return ""

    content_type = header_get(_headers, "content-type").lower()
    if "html" in content_type or "text" in content_type or content.strip().startswith(b"<"):
        return content.decode("utf-8", errors="replace")
    return ""


async def scan_sourcemaps(
    base_url: str,
    timeout: float,
    concurrency: int,
    user_agent: str,
    scan_scripts: bool = True,
    custom_paths: list[str] | None = None,
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 0.0,
    retries: int = 2,
) -> list[SourceMapInfo]:
    """Busca source maps no alvo por script scanning e path probing."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)

    logger.info("scan sourcemap iniciado: %s", base_url)

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(base_url, Cyber.WHITE, Cyber.BOLD)}")

    sem = asyncio.Semaphore(concurrency)
    all_map_urls: list[tuple[str, str]] = []  # (map_url, js_url)
    seen_maps: set[str] = set()

    # Script scanning
    if scan_scripts:
        html = await _fetch_page(client, rate_limiter, base_url, timeout, retries)
        if html:
            script_urls = extract_script_urls(html, base_url)
            print(
                color("[*]", Cyber.CYAN, Cyber.BOLD),
                f"Scripts encontrados: {color(str(len(script_urls)), Cyber.WHITE, Cyber.BOLD)}",
            )
            for js_url in script_urls:
                for map_url in build_map_urls(js_url):
                    if map_url not in seen_maps:
                        seen_maps.add(map_url)
                        all_map_urls.append((map_url, js_url))
        else:
            print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Nao foi possivel buscar a pagina principal")

    # Path probing
    paths = custom_paths if custom_paths else DEFAULT_SCRIPT_PATHS
    for path in paths:
        full_js_url = urljoin(base_url, path)
        for map_url in build_map_urls(full_js_url):
            if map_url not in seen_maps:
                seen_maps.add(map_url)
                all_map_urls.append((map_url, ""))

    total = len(all_map_urls)
    if total == 0:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Nenhum candidato para sondar")
        await client.aclose()
        return []

    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Candidatos: {color(str(total), Cyber.WHITE, Cyber.BOLD)} | "
        f"Concurrency: {color(str(concurrency), Cyber.YELLOW)}",
    )

    completed = 0
    completed_lock = asyncio.Lock()

    async def _limited_probe(map_url: str, js_url: str) -> SourceMapInfo | None:
        nonlocal completed
        async with sem:
            result = await _probe_map(client, rate_limiter, map_url, js_url, timeout, retries)
            async with completed_lock:
                completed += 1
                if completed % 20 == 0 or completed == total:
                    sys.stdout.write(f"\r  Progresso: {completed}/{total} candidatos testados...")
                    sys.stdout.flush()
            return result

    try:
        tasks = [_limited_probe(mu, ju) for mu, ju in all_map_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

        maps: list[SourceMapInfo] = []
        for r in results:
            if isinstance(r, SourceMapInfo):
                maps.append(r)
                logger.info("Source map encontrado: %s (sources=%d)", r.url, r.sources_count)
                print(
                    f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                    f"{color(f'{r.raw_size}B', Cyber.YELLOW)} "
                    f"{color(f'{r.sources_count} sources', Cyber.WHITE)} "
                    f"{color(r.url, Cyber.CYAN)}"
                )
    finally:
        await client.aclose()

    elapsed = time.monotonic() - started
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}. "
        f"Source maps encontrados: {color(str(len(maps)), Cyber.GREEN, Cyber.BOLD)}",
    )
    return maps


def print_results(maps: list[SourceMapInfo]) -> None:
    """Imprime tabela resumo dos source maps encontrados."""
    if not maps:
        print(color("Nenhum source map encontrado.", Cyber.RED))
        return

    print(color("\n  Source Maps Encontrados", Cyber.CYAN, Cyber.BOLD))

    hdrs = ("TAMANHO", "SOURCES", "NAMES", "JS ORIGINAL", "URL")
    rows = []
    for m in maps:
        rows.append((
            f"{m.raw_size}",
            str(m.sources_count),
            str(m.names_count),
            m.js_url or "-",
            m.url,
        ))

    def _row_styles(row: tuple[str, ...]) -> list[tuple[str, ...]]:
        return [
            (Cyber.YELLOW,),
            (Cyber.GREEN,),
            (Cyber.WHITE,),
            (Cyber.GRAY,),
            (Cyber.CYAN,),
        ]

    print_table(
        headers=hdrs,
        rows=rows,
        empty_message="Nenhum source map encontrado.",
        alignments=["right", "right", "right", "left", "left"],
        row_styles_fn=_row_styles,
    )


def print_sources_detail(maps: list[SourceMapInfo]) -> None:
    """Imprime detalhes dos sources de cada source map."""
    for m in maps:
        if not m.sources:
            continue
        print(color(f"\n  Sources: {m.url}", Cyber.CYAN, Cyber.BOLD))
        for s in m.sources[:30]:
            print(f"    {color('-', Cyber.GRAY)} {s}")
        if len(m.sources) > 30:
            print(f"    {color(f'... +{len(m.sources) - 30} mais', Cyber.GRAY)}")


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Descoberta de source maps de JavaScript expostos.",
    )
    add_base_args(parser)
    add_http_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: http://example.com")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com URLs alvo (uma por linha).")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=30,
        help="Concorrencia assincrona. Padrao: 30",
    )
    parser.add_argument(
        "--no-scan-scripts",
        action="store_true",
        dest="no_scan_scripts",
        help="Nao escanear <script src> da pagina (apenas path probing).",
    )
    parser.add_argument(
        "--sources",
        action="store_true",
        dest="show_sources",
        help="Mostrar detalhes dos sources de cada source map.",
    )
    parser.add_argument(
        "--paths",
        type=int,
        default=0,
        help="Numero maximo de paths para sondar (0=todos). Padrao: 0",
    )
    return parser


def _load_paths_from_args(args: argparse.Namespace) -> list[str]:
    """Retorna lista de paths customizados (ou vazio para default)."""
    max_paths = getattr(args, "paths", 0)
    if max_paths > 0:
        return DEFAULT_SCRIPT_PATHS[:max_paths]
    return []


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)
    urls = resolve_target_urls(args)

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma requisicao HTTP sera enviada.")
        for url in urls:
            base_url = normalize_url(url, default_scheme="https", ensure_trailing_slash=True)
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(base_url, Cyber.WHITE, Cyber.BOLD)}")
        return 0

    all_maps: list[SourceMapInfo] = []
    for url in urls:
        base_url = normalize_url(url, default_scheme="https", ensure_trailing_slash=True)
        custom_paths = _load_paths_from_args(args)

        maps = await scan_sourcemaps(
            base_url=base_url,
            timeout=args.timeout,
            concurrency=args.concurrency,
            user_agent=args.user_agent,
            scan_scripts=not args.no_scan_scripts,
            custom_paths=custom_paths or None,
            proxy=args.proxy,
            verify=getattr(args, "verify", False),
            requests_per_second=args.delay,
            retries=args.retries,
        )

        if not quiet:
            print_results(maps)
            if args.show_sources:
                print_sources_detail(maps)

        all_maps.extend(maps)

        if getattr(args, "output_dir", None):
            hostname = extract_hostname(url)
            out_path = f"{args.output_dir}/{hostname}.json"
            write_output(
                out_path,
                [asdict(m) for m in maps],
                ["url", "js_url", "status", "raw_size", "sources_count", "names_count", "sources"],
                quiet=quiet,
            )

    if args.output:
        write_output(
            args.output,
            [asdict(m) for m in all_maps],
            ["url", "js_url", "status", "raw_size", "sources_count", "names_count", "sources"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Source Map Discovery."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.url or getattr(a, "target_list", None)),
        prompt="sm> ",
        description="Source Map Discovery interativo.",
        example="http://target.com --sources",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --sources\n"
            "  http://target.com --no-scan-scripts\n"
            "  -l urls.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
