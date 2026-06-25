#!/usr/bin/env python3
"""Modulo de descoberta de specs OpenAPI/Swagger expostas em alvos HTTP.

Sonda paths comuns de specs (JSON e YAML), faz parse do conteudo e extrai:
  - Titulo, versao e descricao da API
  - Servidores documentados
  - Endpoints (metodo, path, parametros, tags)
  - Schemas/componentes disponiveis

Fluxo:
  1. Sonda ~20 paths comuns de OpenAPI/Swagger
  2. Para cada hit (200), tenta parsear como JSON ou YAML
  3. Extrai metadados da API e lista de endpoints
  4. Exibe resumo colorido e salva output detalhado
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
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

logger = logging.getLogger("mytools.openapidiscovery")

DEFAULT_PATHS: list[str] = [
    "swagger.json",
    "swagger/v1/swagger.json",
    "swagger/v2/swagger.json",
    "v1/swagger.json",
    "v2/swagger.json",
    "api/swagger.json",
    "api/v1/swagger.json",
    "api/v2/swagger.json",
    "openapi.json",
    "openapi.yaml",
    "openapi/v1.json",
    "openapi/v1.yaml",
    "api-docs",
    "api-docs/",
    "api/docs",
    "swagger-ui.html",
    "swagger-ui/",
    "redoc/",
    "docs/",
    "apidoc/",
    "api/swagger-ui.html",
    "swagger-resources",
    "swagger-resources/configuration/ui",
    "swagger-resources/configuration/security",
]

STATUS_OK = frozenset({200, 301, 302, 307, 308})

banner = create_banner(
    r"""
   ___                    ____  __
  / _ \ _ __   ___ _ __ |  _ \/_/___  _ __   __ _
 / /_)/| '__| / _ \ '_ \| | | | / _ \| '_ \ / _` |
/ ___/ | |   |  __/ | | | |/ />  (_) | | | | (_| |
\/     |_|    \___|_| |_|_/ /_/\___/|_| |_|\__,_|
""",
    "OpenAPI/Swagger discovery | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class EndpointInfo:
    """Informacao de um endpoint extraido da spec."""

    method: str
    path: str
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ApiSpecInfo:
    """Metadados de uma spec OpenAPI/Swagger descoberta."""

    url: str
    format: str
    title: str = ""
    version: str = ""
    description: str = ""
    servers: list[str] = field(default_factory=list)
    endpoints: list[EndpointInfo] = field(default_factory=list)
    schemas: list[str] = field(default_factory=list)
    raw_size: int = 0
    status: int = 0


def _parse_openapi_v3(spec: dict[str, object]) -> tuple[str, str, str, list[str], list[EndpointInfo], list[str]]:
    """Extrai metadados de uma spec OpenAPI 3.x."""
    info = spec.get("info", {})
    title = str(info.get("title", "")) if isinstance(info, dict) else ""
    version = str(info.get("version", "")) if isinstance(info, dict) else ""
    description = str(info.get("description", "")) if isinstance(info, dict) else ""

    servers_raw = spec.get("servers", [])
    servers = [str(s.get("url", "")) for s in servers_raw if isinstance(s, dict)] if isinstance(servers_raw, list) else []

    endpoints: list[EndpointInfo] = []
    paths = spec.get("paths", {})
    if isinstance(paths, dict):
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method in ("get", "post", "put", "delete", "patch", "head", "options"):
                operation = methods.get(method)
                if not isinstance(operation, dict):
                    continue
                summary = str(operation.get("summary", "")) if operation.get("summary") else ""
                tags = [str(t) for t in operation.get("tags", []) if isinstance(t, str)] if isinstance(operation.get("tags"), list) else []
                params = []
                op_params = operation.get("parameters", [])
                if isinstance(op_params, list):
                    for p in op_params:
                        if isinstance(p, dict):
                            name = str(p.get("name", ""))
                            loc = str(p.get("in", ""))
                            if name:
                                params.append(f"{name} ({loc})")
                endpoints.append(EndpointInfo(
                    method=method.upper(),
                    path=path,
                    summary=summary,
                    tags=tags,
                    parameters=params,
                ))

    schemas: list[str] = []
    components = spec.get("components", {})
    if isinstance(components, dict):
        schemas_obj = components.get("schemas", {})
        if isinstance(schemas_obj, dict):
            schemas = list(schemas_obj.keys())

    return title, version, description, servers, endpoints, schemas


def _parse_openapi_v2(spec: dict[str, object]) -> tuple[str, str, str, list[str], list[EndpointInfo], list[str]]:
    """Extrai metadados de uma spec Swagger 2.0."""
    info = spec.get("info", {})
    title = str(info.get("title", "")) if isinstance(info, dict) else ""
    version = str(info.get("version", "")) if isinstance(info, dict) else ""
    description = str(info.get("description", "")) if isinstance(info, dict) else ""

    host = str(spec.get("host", "")) if isinstance(spec.get("host"), str) else ""
    base_path = str(spec.get("basePath", "")) if isinstance(spec.get("basePath"), str) else ""
    schemes = spec.get("schemes", ["https"])
    servers: list[str] = []
    if host:
        scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
        servers = [f"{scheme}://{host}{base_path}"]

    endpoints: list[EndpointInfo] = []
    paths = spec.get("paths", {})
    if isinstance(paths, dict):
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method in ("get", "post", "put", "delete", "patch", "head", "options"):
                operation = methods.get(method)
                if not isinstance(operation, dict):
                    continue
                summary = str(operation.get("summary", "")) if operation.get("summary") else ""
                tags = [str(t) for t in operation.get("tags", []) if isinstance(t, str)] if isinstance(operation.get("tags"), list) else []
                params = []
                op_params = operation.get("parameters", [])
                if isinstance(op_params, list):
                    for p in op_params:
                        if isinstance(p, dict):
                            name = str(p.get("name", ""))
                            loc = str(p.get("in", ""))
                            if name:
                                params.append(f"{name} ({loc})")
                endpoints.append(EndpointInfo(
                    method=method.upper(),
                    path=path,
                    summary=summary,
                    tags=tags,
                    parameters=params,
                ))

    schemas: list[str] = []
    definitions = spec.get("definitions", {})
    if isinstance(definitions, dict):
        schemas = list(definitions.keys())

    return title, version, description, servers, endpoints, schemas


def parse_spec(content: bytes, content_type: str) -> ApiSpecInfo | None:
    """Tenta parsear conteudo como OpenAPI/Swagger JSON ou YAML."""
    if not content:
        return None

    spec: dict[str, object] | None = None
    fmt = ""

    content_lower = content_type.lower()

    if "json" in content_lower or content.strip().startswith(b"{"):
        try:
            spec = json.loads(content)
            fmt = "json"
        except (json.JSONDecodeError, ValueError):
            pass

    if spec is None:
        try:
            import yaml
            text = content.decode("utf-8", errors="replace")
            loaded = yaml.safe_load(text)
            if isinstance(loaded, dict):
                spec = loaded
                fmt = "yaml"
        except Exception:
            pass

    if spec is None or not isinstance(spec, dict):
        return None

    openapi = str(spec.get("openapi", ""))
    swagger = str(spec.get("swagger", ""))

    if not openapi and not swagger:
        return None

    if openapi.startswith("3."):
        title, version, description, servers, endpoints, schemas = _parse_openapi_v3(spec)
    elif swagger.startswith("2."):
        title, version, description, servers, endpoints, schemas = _parse_openapi_v2(spec)
    else:
        return None

    return ApiSpecInfo(
        url="",
        format=fmt,
        title=title,
        version=version,
        description=description[:200] if description else "",
        servers=servers,
        endpoints=endpoints,
        schemas=schemas,
        raw_size=len(content),
    )


async def probe_spec(
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    base_url: str,
    path: str,
    timeout: float,
    retries: int = 2,
) -> ApiSpecInfo | None:
    """Sonda um path de spec e retorna ApiSpecInfo se encontrar OpenAPI/Swagger valido."""
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

    content_type = header_get(headers, "content-type")
    spec = parse_spec(content, content_type)

    if spec is None:
        return None

    spec = ApiSpecInfo(
        url=full_url,
        format=spec.format,
        title=spec.title,
        version=spec.version,
        description=spec.description,
        servers=spec.servers,
        endpoints=spec.endpoints,
        schemas=spec.schemas,
        raw_size=spec.raw_size,
        status=status,
    )
    return spec


async def scan_specs(
    base_url: str,
    paths: list[str],
    timeout: float,
    concurrency: int,
    user_agent: str,
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 0.0,
    retries: int = 2,
) -> list[ApiSpecInfo]:
    """Sonda todos os paths de spec em paralelo."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)

    logger.info("scan OpenAPI iniciado: %s (%d paths)", base_url, len(paths))

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(base_url, Cyber.WHITE, Cyber.BOLD)}")
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Paths: {color(str(len(paths)), Cyber.WHITE, Cyber.BOLD)} | "
        f"Concurrency: {color(str(concurrency), Cyber.YELLOW)}",
    )

    sem = asyncio.Semaphore(concurrency)
    total = len(paths)
    completed = 0
    found_event = asyncio.Event()

    async def _limited_probe(path: str) -> ApiSpecInfo | None:
        nonlocal completed
        if found_event.is_set():
            return None
        async with sem:
            if found_event.is_set():
                return None
            result = await probe_spec(client, rate_limiter, base_url, path, timeout, retries)
            completed += 1
            if result is not None:
                found_event.set()
            if completed % 10 == 0 or completed == total:
                sys.stdout.write(f"\r  Progresso: {completed}/{total} paths testados...")
                sys.stdout.flush()
            return result

    try:
        tasks = [_limited_probe(p) for p in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

        specs: list[ApiSpecInfo] = []
        for r in results:
            if isinstance(r, ApiSpecInfo):
                specs.append(r)
                logger.info("spec encontrada: %s (%s, %d endpoints)", r.url, r.format, len(r.endpoints))
                print(
                    f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                    f"{color(r.format.upper(), Cyber.YELLOW, Cyber.BOLD)} "
                    f"{color(str(len(r.endpoints)).rjust(4), Cyber.WHITE)} endpoints "
                    f"{color(r.url, Cyber.CYAN)}"
                    f"{color(f' | {r.title} v{r.version}' if r.title else '', Cyber.GRAY)}"
                )
    finally:
        await client.aclose()

    elapsed = time.monotonic() - started
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}. "
        f"Specs encontradas: {color(str(len(specs)), Cyber.GREEN, Cyber.BOLD)}",
    )
    return specs


def print_api_summary(specs: list[ApiSpecInfo]) -> None:
    """Imprime tabela resumo das specs encontradas."""
    if not specs:
        print(color("Nenhuma spec OpenAPI/Swagger encontrada.", Cyber.RED))
        return

    print(color("\n  Specs Encontradas", Cyber.CYAN, Cyber.BOLD))

    headers = ("FORMATO", "ENDPOINTS", "SCHEMAS", "VERSAO", "TITULO", "URL")
    rows = []
    for spec in specs:
        rows.append((
            spec.format.upper(),
            str(len(spec.endpoints)),
            str(len(spec.schemas)),
            spec.version or "-",
            (spec.title[:40] + "...") if len(spec.title) > 40 else (spec.title or "-"),
            spec.url,
        ))

    def _row_styles(row: tuple[str, ...]) -> list[tuple[str, ...]]:
        return [
            (Cyber.YELLOW, Cyber.BOLD),
            (Cyber.WHITE,),
            (Cyber.WHITE,),
            (Cyber.GREEN,),
            (Cyber.CYAN,),
            (Cyber.GRAY,),
        ]

    print_table(
        headers=headers,
        rows=rows,
        empty_message="Nenhuma spec OpenAPI/Swagger encontrada.",
        alignments=["left", "right", "right", "left", "left", "left"],
        row_styles_fn=_row_styles,
    )


def print_api_endpoints(spec: ApiSpecInfo) -> None:
    """Imprime lista detalhada de endpoints de uma spec."""
    label = f"{spec.title} v{spec.version}" if spec.title else spec.url
    print(color(f"\n  Endpoints: {label}", Cyber.CYAN, Cyber.BOLD))

    if spec.servers:
        print(color("  Servidores:", Cyber.YELLOW))
        for s in spec.servers:
            print(f"    {color('-', Cyber.GRAY)} {s}")

    if not spec.endpoints:
        print(color("  Nenhum endpoint extraido.", Cyber.GRAY))
        return

    headers = ("METHOD", "PATH", "TAGS", "SUMMARY")
    rows = []
    for ep in spec.endpoints:
        rows.append((
            ep.method,
            ep.path,
            ", ".join(ep.tags[:3]) if ep.tags else "-",
            (ep.summary[:50] + "...") if len(ep.summary) > 50 else (ep.summary or "-"),
        ))

    method_colors = {
        "GET": (Cyber.GREEN,),
        "POST": (Cyber.YELLOW,),
        "PUT": (Cyber.CYAN,),
        "DELETE": (Cyber.RED, Cyber.BOLD),
        "PATCH": (Cyber.MAGENTA,),
        "HEAD": (Cyber.GRAY,),
        "OPTIONS": (Cyber.GRAY,),
    }

    def _row_styles(row: tuple[str, ...]) -> list[tuple[str, ...]]:
        return [
            method_colors.get(row[0].upper(), (Cyber.WHITE,)),
            (Cyber.WHITE,),
            (Cyber.MAGENTA,),
            (Cyber.GRAY,),
        ]

    print_table(
        headers=headers,
        rows=rows,
        empty_message="Nenhum endpoint encontrado.",
        alignments=["left", "left", "left", "left"],
        row_styles_fn=_row_styles,
    )

    if spec.schemas:
        print(color(f"\n  Schemas: {len(spec.schemas)}", Cyber.YELLOW))
        for s in spec.schemas[:20]:
            print(f"    {color('-', Cyber.GRAY)} {s}")
        if len(spec.schemas) > 20:
            print(f"    {color(f'... +{len(spec.schemas) - 20} mais', Cyber.GRAY)}")


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Descoberta de specs OpenAPI/Swagger expostas em alvos HTTP.",
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
        "--endpoints",
        action="store_true",
        dest="show_endpoints",
        help="Mostrar endpoints detalhados de cada spec encontrada.",
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

    all_specs: list[ApiSpecInfo] = []
    for url in urls:
        base_url = normalize_url(url, default_scheme="https", ensure_trailing_slash=True)
        paths = _load_paths_from_args(args)

        specs = await scan_specs(
            base_url=base_url,
            paths=paths,
            timeout=args.timeout,
            concurrency=args.concurrency,
            user_agent=args.user_agent,
            proxy=args.proxy,
            verify=getattr(args, "verify", False),
            requests_per_second=args.delay,
            retries=args.retries,
        )

        if not quiet:
            print_api_summary(specs)
            if args.show_endpoints:
                for spec in specs:
                    print_api_endpoints(spec)

        all_specs.extend(specs)

        if getattr(args, "output_dir", None):
            hostname = extract_hostname(url)
            out_path = f"{args.output_dir}/{hostname}.json"
            write_output(
                out_path,
                [asdict(s) for s in specs],
                ["url", "format", "title", "version", "description", "servers", "schemas", "raw_size", "status", "endpoints"],
                quiet=quiet,
            )

    if args.output:
        write_output(
            args.output,
            [asdict(s) for s in all_specs],
            ["url", "format", "title", "version", "description", "servers", "schemas", "raw_size", "status", "endpoints"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do OpenAPI/Swagger Discovery."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.url or getattr(a, "target_list", None)),
        prompt="oas> ",
        description="OpenAPI/Swagger Discovery interativo.",
        example="http://target.com --endpoints",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --endpoints\n"
            "  http://target.com --concurrency 50\n"
            "  -l urls.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
