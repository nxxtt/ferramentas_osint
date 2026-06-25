#!/usr/bin/env python3
"""Modulo de descoberta de GraphQL Playgrounds expostos em alvos HTTP.

Sonda paths comuns de GraphQL IDEs e endpoints, detecta ferramentas
(GraphiQL, Playground, Altair, Voyager, Apollo Sandbox) e opcionalmente
executa introspection query para extrair schema.

Fluxo:
  1. Sonda ~15 paths comuns de GraphQL
  2. Para cada hit (200), analisa body para identificar ferramenta
  3. Opcionalmente envia introspection query para extrair schema
  4. Exibe resumo colorido e salva output detalhado
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
import time
from collections.abc import Mapping
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

logger = logging.getLogger("mytools.graphqlplayground")

DEFAULT_PATHS: list[str] = [
    "graphql",
    "graphiql",
    "playground",
    "altair",
    "voyager",
    "graphql/console",
    "_graphql",
    "api/graphql",
    "v1/graphql",
    "v2/graphql",
    "v3/graphql",
    "graph",
    "gql",
    "query",
    "graphql-api",
    "graphql-playground",
    "graphql-altair",
    "graphql-voyager",
]

STATUS_OK = frozenset({200})

INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }",
})

TOOL_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("graphiql", re.compile(r"<div\s+id=['\"]?graphiql['\"]?|graphiql\.react\.min\.js|GraphiQL\.create|new\s+GraphiQL", re.IGNORECASE)),
    ("playground", re.compile(r"graphql-playground|GraphQL Playground|playground\.render|createPlayground|[\"']playground[\"']|class=[\"'].*playground", re.IGNORECASE)),
    ("altair", re.compile(r"altair-graphql|AltairGraphQL|altair\.js|altair\.render|window\.altair", re.IGNORECASE)),
    ("voyager", re.compile(r"graphql-voyager|GraphQLVoyager|voyager\.render|voyager\.min\.js|[\"']voyager[\"']|class=[\"'].*voyager", re.IGNORECASE)),
    ("apollo-sandbox", re.compile(r"apollo-sandbox|Apollo Sandbox|ApolloSandbox|sandbox\.apollo\.dev", re.IGNORECASE)),
]

banner = create_banner(
    r"""
  ___           _        __ _
 | __|_ _  __ _| |_ ___ / _(_)__ _
 | _/ _` |/ _` |  _/ -_)  _| / _` |
 |_\__,_|\__,_|\__\___|_| |_\__,_|
""",
    "GraphQL Playground/IDE discovery | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class GraphqlEndpoint:
    """Representa um GraphQL endpoint ou playground descoberto."""

    url: str
    tool: str
    status: int
    supports_introspection: bool = False
    schema_types: list[str] = field(default_factory=list)
    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""
    raw_size: int = 0


def detect_tool(body: str, headers: Mapping[str, str]) -> str:
    """Identifica a ferramenta GraphQL pelo conteudo HTML e headers."""
    content_type = header_get(headers, "content-type").lower()

    if "graphql-response" in content_type:
        return "graphql"

    for tool_name, pattern in TOOL_SIGNATURES:
        if pattern.search(body):
            return tool_name

    return "unknown"


def parse_introspection(data: dict[str, object]) -> tuple[list[str], str, str, str]:
    """Extrai info do schema a partir de uma resposta de introspection."""
    data_obj = data.get("data", {})
    if not isinstance(data_obj, dict):
        return [], "", "", ""

    schema = data_obj.get("__schema", {})
    if not isinstance(schema, dict):
        return [], "", "", ""

    types_raw = schema.get("types", [])
    types: list[str] = []
    if isinstance(types_raw, list):
        for t in types_raw:
            if isinstance(t, dict):
                name = str(t.get("name", ""))
                kind = str(t.get("kind", ""))
                if name and not name.startswith("__"):
                    types.append(f"{name} ({kind})")

    query_type_obj = schema.get("queryType", {})
    query_type = str(query_type_obj.get("name", "")) if isinstance(query_type_obj, dict) else ""

    mutation_type_obj = schema.get("mutationType", {})
    mutation_type = str(mutation_type_obj.get("name", "")) if isinstance(mutation_type_obj, dict) else ""

    subscription_type_obj = schema.get("subscriptionType", {})
    subscription_type = str(subscription_type_obj.get("name", "")) if isinstance(subscription_type_obj, dict) else ""

    return types, query_type, mutation_type, subscription_type


async def run_introspection(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    rate_limiter: RateLimiter,
    retries: int = 2,
) -> tuple[list[str], str, str, str]:
    """Envia introspection query e retorna tipos do schema."""
    await rate_limiter.wait()
    try:
        status, _headers, content, _ = await fetch(
            client, url, timeout=timeout, method="POST",
            max_retries=retries, rate_limiter=rate_limiter,
        )
    except FetchError:
        return [], "", "", ""

    if status != 200:
        return [], "", "", ""

    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return [], "", "", ""

    if not isinstance(data, dict) or "errors" in data:
        return [], "", "", ""

    return parse_introspection(data)


async def probe_endpoint(
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    base_url: str,
    path: str,
    timeout: float,
    introspect: bool = False,
    retries: int = 2,
) -> GraphqlEndpoint | None:
    """Sonda um path GraphQL e retorna GraphqlEndpoint se encontrar algo relevante."""
    full_url = urljoin(base_url, path)
    await rate_limiter.wait()

    try:
        status, headers, content, _ = await fetch(
            client, full_url, timeout=timeout, method="GET",
            max_retries=retries, rate_limiter=rate_limiter,
        )
    except FetchError:
        return None

    if status not in STATUS_OK:
        return None

    content_type = header_get(headers, "content-type").lower()
    body = ""
    if "html" in content_type or "text" in content_type or content.strip().startswith(b"<"):
        body = content.decode("utf-8", errors="replace")
    elif "json" in content_type:
        try:
            data = json.loads(content)
            if isinstance(data, dict) and ("data" in data or "errors" in data):
                return GraphqlEndpoint(
                    url=full_url,
                    tool="graphql",
                    status=status,
                    raw_size=len(content),
                )
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    tool = detect_tool(body, headers)

    if tool == "unknown":
        if "graphql" not in full_url.lower() and "gql" not in full_url.lower():
            return None
        tool = "graphql"

    types: list[str] = []
    query_type = ""
    mutation_type = ""
    subscription_type = ""
    supports_introspection = False

    if introspect:
        types, query_type, mutation_type, subscription_type = await run_introspection(
            client, full_url, timeout, rate_limiter, retries,
        )
        supports_introspection = bool(types)

    return GraphqlEndpoint(
        url=full_url,
        tool=tool,
        status=status,
        supports_introspection=supports_introspection,
        schema_types=types,
        query_type=query_type,
        mutation_type=mutation_type,
        subscription_type=subscription_type,
        raw_size=len(content),
    )


async def scan_graphql(
    base_url: str,
    paths: list[str],
    timeout: float,
    concurrency: int,
    user_agent: str,
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 0.0,
    retries: int = 2,
    introspect: bool = False,
) -> list[GraphqlEndpoint]:
    """Sonda todos os paths GraphQL em paralelo."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)

    logger.info("scan GraphQL iniciado: %s (%d paths)", base_url, len(paths))

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(base_url, Cyber.WHITE, Cyber.BOLD)}")
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Paths: {color(str(len(paths)), Cyber.WHITE, Cyber.BOLD)} | "
        f"Concurrency: {color(str(concurrency), Cyber.YELLOW)}"
        + (f" | Introspection: {color('sim', Cyber.GREEN)}" if introspect else ""),
    )

    sem = asyncio.Semaphore(concurrency)
    total = len(paths)
    completed = 0

    async def _limited_probe(path: str) -> GraphqlEndpoint | None:
        nonlocal completed
        async with sem:
            result = await probe_endpoint(client, rate_limiter, base_url, path, timeout, introspect, retries)
            completed += 1
            if completed % 10 == 0 or completed == total:
                sys.stdout.write(f"\r  Progresso: {completed}/{total} paths testados...")
                sys.stdout.flush()
            return result

    try:
        tasks = [_limited_probe(p) for p in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

        endpoints: list[GraphqlEndpoint] = []
        for r in results:
            if isinstance(r, GraphqlEndpoint):
                endpoints.append(r)
                logger.info("GraphQL encontrado: %s (tool=%s)", r.url, r.tool)
                intros_info = ""
                if r.supports_introspection:
                    intros_info = f" | introspection: {color(str(len(r.schema_types)), Cyber.GREEN)} tipos"
                print(
                    f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                    f"{color(r.tool.upper(), Cyber.YELLOW, Cyber.BOLD)} "
                    f"{color(r.url, Cyber.CYAN)}"
                    f"{color(intros_info, Cyber.GRAY)}"
                )
    finally:
        await client.aclose()

    elapsed = time.monotonic() - started
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}. "
        f"Endpoints encontrados: {color(str(len(endpoints)), Cyber.GREEN, Cyber.BOLD)}",
    )
    return endpoints


def print_results(endpoints: list[GraphqlEndpoint]) -> None:
    """Imprime tabela resumo dos endpoints GraphQL encontrados."""
    if not endpoints:
        print(color("Nenhum GraphQL endpoint/playground encontrado.", Cyber.RED))
        return

    print(color("\n  GraphQL Endpoints Encontrados", Cyber.CYAN, Cyber.BOLD))

    headers = ("FERRAMENTA", "STATUS", "INTROSPECTION", "TIPOS", "URL")
    rows = []
    for ep in endpoints:
        intros = "sim" if ep.supports_introspection else "nao"
        types_count = str(len(ep.schema_types)) if ep.schema_types else "-"
        rows.append((
            ep.tool.upper(),
            str(ep.status),
            intros,
            types_count,
            ep.url,
        ))

    tool_colors = {
        "GRAPHIQL": (Cyber.GREEN, Cyber.BOLD),
        "PLAYGROUND": (Cyber.YELLOW, Cyber.BOLD),
        "ALTAIR": (Cyber.CYAN, Cyber.BOLD),
        "VOYAGER": (Cyber.MAGENTA, Cyber.BOLD),
        "APOLLO-SANDBOX": (Cyber.BLUE, Cyber.BOLD),
        "GRAPHQL": (Cyber.WHITE,),
        "UNKNOWN": (Cyber.GRAY,),
    }

    def _row_styles(row: tuple[str, ...]) -> list[tuple[str, ...]]:
        return [
            tool_colors.get(row[0].upper(), (Cyber.WHITE,)),
            (Cyber.WHITE,),
            (Cyber.GREEN,) if row[2] == "sim" else (Cyber.RED,),
            (Cyber.YELLOW,),
            (Cyber.CYAN,),
        ]

    print_table(
        headers=headers,
        rows=rows,
        empty_message="Nenhum GraphQL endpoint/playground encontrado.",
        alignments=["left", "right", "left", "right", "left"],
        row_styles_fn=_row_styles,
    )


def print_schema_details(ep: GraphqlEndpoint) -> None:
    """Imprime detalhes do schema de um endpoint com introspection."""
    if not ep.supports_introspection or not ep.schema_types:
        return

    print(color(f"\n  Schema: {ep.url}", Cyber.CYAN, Cyber.BOLD))

    if ep.query_type:
        print(f"  {color('Query:', Cyber.YELLOW)} {ep.query_type}")
    if ep.mutation_type:
        print(f"  {color('Mutation:', Cyber.YELLOW)} {ep.mutation_type}")
    if ep.subscription_type:
        print(f"  {color('Subscription:', Cyber.YELLOW)} {ep.subscription_type}")

    print(color(f"\n  Tipos ({len(ep.schema_types)}):", Cyber.YELLOW))
    for t in ep.schema_types[:30]:
        print(f"    {color('-', Cyber.GRAY)} {t}")
    if len(ep.schema_types) > 30:
        print(f"    {color(f'... +{len(ep.schema_types) - 30} mais', Cyber.GRAY)}")


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Descoberta de GraphQL Playgrounds e endpoints expostos.",
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
        "--introspect",
        action="store_true",
        help="Executa introspection query para extrair schema (pode revelar tipos expostos).",
    )
    parser.add_argument(
        "--schema",
        action="store_true",
        dest="show_schema",
        help="Mostrar detalhes do schema para endpoints com introspection.",
    )
    parser.add_argument(
        "--paths",
        type=int,
        default=0,
        help="Numero maximo de paths para sondar (0=todos). Padrao: 0",
    )
    return parser


def _load_paths_from_args(args: argparse.Namespace) -> list[str]:
    """Retorna lista de paths a sondar."""
    paths = list(DEFAULT_PATHS)
    max_paths = getattr(args, "paths", 0)
    if max_paths > 0:
        paths = paths[:max_paths]
    return paths


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)
    urls = resolve_target_urls(args)

    if getattr(args, "dry_run", False):
        paths = _load_paths_from_args(args)
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma requisicao HTTP sera enviada.")
        for url in urls:
            base_url = normalize_url(url, default_scheme="https", ensure_trailing_slash=True)
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(base_url, Cyber.WHITE, Cyber.BOLD)}")
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Paths: {color(str(len(paths)), Cyber.WHITE, Cyber.BOLD)} | Concurrency: {color(str(args.concurrency), Cyber.YELLOW)}")
        return 0

    all_endpoints: list[GraphqlEndpoint] = []
    for url in urls:
        base_url = normalize_url(url, default_scheme="https", ensure_trailing_slash=True)
        paths = _load_paths_from_args(args)

        endpoints = await scan_graphql(
            base_url=base_url,
            paths=paths,
            timeout=args.timeout,
            concurrency=args.concurrency,
            user_agent=args.user_agent,
            proxy=args.proxy,
            verify=getattr(args, "verify", False),
            requests_per_second=args.delay,
            retries=args.retries,
            introspect=args.introspect,
        )

        if not quiet:
            print_results(endpoints)
            if args.show_schema:
                for ep in endpoints:
                    print_schema_details(ep)

        all_endpoints.extend(endpoints)

        if getattr(args, "output_dir", None):
            hostname = extract_hostname(url)
            out_path = f"{args.output_dir}/{hostname}.json"
            write_output(
                out_path,
                [asdict(e) for e in endpoints],
                ["url", "tool", "status", "supports_introspection", "query_type", "mutation_type", "subscription_type", "schema_types", "raw_size"],
                quiet=quiet,
            )

    if args.output:
        write_output(
            args.output,
            [asdict(e) for e in all_endpoints],
            ["url", "tool", "status", "supports_introspection", "query_type", "mutation_type", "subscription_type", "schema_types", "raw_size"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do GraphQL Playground Discovery."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.url or getattr(a, "target_list", None)),
        prompt="gql> ",
        description="GraphQL Playground Discovery interativo.",
        example="http://target.com --introspect",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --introspect\n"
            "  http://target.com --introspect --schema\n"
            "  -l urls.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
