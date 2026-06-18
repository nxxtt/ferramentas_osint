#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from dataclasses import asdict, dataclass
from urllib.parse import urljoin

from utils import (
    Cyber,
    RateLimiter,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    ensure_output_dir,
    extract_hostname,
    extract_title,
    fetch,
    normalize_url,
    parse_extra_headers,
    parse_int_range,
    print_table,
    resolve_target_urls,
    run_interactive_shell,
    set_color,
    setup_logging,
    status_color,
    write_output,
    __version__,
)

import logging

logger = logging.getLogger("mytools.dirscanner")


DEFAULT_PATHS = [
    "admin", "login", "dashboard", "wp-admin", "administrator", "backup",
    "backups", "config", "config.php", ".env", "phpinfo.php", "images",
    "uploads", "files", "assets", "static", "robots.txt", "sitemap.xml",
    ".git", ".htaccess", "server-status", "api", "api/v1", "v1", "admin.php",
    "panel", "phpmyadmin", "dev", "test", "staging", "old", "tmp", "private",
    "db", "database", "dump.sql", "backup.zip",
]

DEFAULT_STATUSES = frozenset({200, 204, 301, 302, 307, 308, 401, 403})

"""Scanner HTTP de diretórios e arquivos para alvos autorizados."""


@dataclass(frozen=True)
class Finding:
    """Representa um caminho encontrado durante o scan."""

    url: str
    path: str
    status: int
    size: int
    words: int
    title: str
    location: str = ""
    method: str = "GET"


banner = create_banner(r"""
    ____  _      _____
   / __ \(_)____/ ___/_________ _____  ____  ___  _____
  / / / / / ___/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /_/ / / /  ___/ / /__/ /_/ / / / / / / /  __/ /
/_/  /_/_/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/
""", "   HTTP directory scanner | use apenas em alvos autorizados")


def parse_statuses(value: str) -> set[int]:
    """Converte string de status HTTP para conjunto de inteiros."""
    aliases = {
        "default": sorted(DEFAULT_STATUSES),
        "all": list(range(100, 600)),
    }
    return set(parse_int_range(value, 100, 599, "status", aliases))


def parse_extensions(value: str) -> list[str]:
    """Converte lista de extensões separadas por vírgula."""
    if not value:
        return []
    extensions = []
    for extension in value.split(","):
        extension = extension.strip().lstrip(".")
        if extension:
            extensions.append(extension)
    return extensions


def parse_range(value: str) -> tuple[int, int] | None:
    """Converte string de range 'min-max' em tupla (min, max). None se vazio."""
    if not value:
        return None
    parts = value.split("-")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"formato invalido: {value!r} (use min-max)")
    try:
        min_val, max_val = int(parts[0]), int(parts[1])
    except ValueError:
        raise argparse.ArgumentTypeError(f"valores nao numericos: {value!r}")
    if min_val > max_val:
        min_val, max_val = max_val, min_val
    return (min_val, max_val)


def load_paths(wordlist: str | None, extensions: list[str]) -> list[str]:
    """Carrega caminhos da wordlist ou lista padrão e aplica extensões."""
    if wordlist:
        try:
            with open(wordlist, "r", encoding="utf-8", errors="replace") as file_handle:
                raw_paths = [
                    line.strip()
                    for line in file_handle
                    if line.strip() and not line.lstrip().startswith("#")
                ]
        except FileNotFoundError:
            raise ValueError(f"wordlist nao encontrada: {wordlist}")
    else:
        raw_paths = list(DEFAULT_PATHS)

    paths: set[str] = set()
    for raw_path in raw_paths:
        path = raw_path.strip().lstrip("/")
        if not path:
            continue
        paths.add(path)
        if extensions and "." not in os.path.basename(path):
            for extension in extensions:
                paths.add(f"{path}.{extension}")

    if not paths:
        raise ValueError("nenhum path valido para testar")
    return sorted(paths)


def matches_filter(
    finding: Finding,
    size_range: tuple[int, int] | None,
    words_range: tuple[int, int] | None,
) -> bool:
    """Verifica se o finding atende aos filtros de tamanho e palavras."""
    if size_range:
        if not (size_range[0] <= finding.size <= size_range[1]):
            return False
    if words_range:
        if not (words_range[0] <= finding.words <= words_range[1]):
            return False
    return True


async def scan_path(
    client,
    rate_limiter: RateLimiter,
    base_url: str,
    path: str,
    timeout: float,
    statuses: set[int],
    method: str = "GET",
) -> Finding | None:
    """Realiza request HTTP para um caminho especifico e retorna Finding."""
    full_url = urljoin(base_url, path)
    await rate_limiter.wait()

    try:
        status, headers, content, _ = await fetch(client, full_url, timeout=timeout, method=method, rate_limiter=rate_limiter)
    except ValueError:
        return None

    if status not in statuses:
        return None

    content_type = headers.get("content-type", "")
    text = content.decode("utf-8", errors="replace") if "text/html" in content_type.lower() else ""
    return Finding(
        url=full_url,
        path="/" + path,
        status=status,
        size=len(content),
        words=len(text.split()),
        title=extract_title(text),
        location=headers.get("location", ""),
        method=method,
    )


async def scan_target(
    base_url: str,
    paths: list[str],
    timeout: float,
    concurrency: int,
    statuses: set[int],
    user_agent: str,
    proxy: str | None = None,
    requests_per_second: float = 0.0,
    method: str = "GET",
    auth_headers: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
    size_range: tuple[int, int] | None = None,
    words_range: tuple[int, int] | None = None,
) -> list[Finding]:
    """Executa scan paralelo de todos os caminhos contra o alvo."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy)

    logger.info("scan iniciado: %s (%d paths)", base_url, len(paths))
    logger.debug("method=%s, concurrency=%d, statuses=%s", method, concurrency, statuses)

    if auth_headers:
        client.headers.update(auth_headers)
    if extra_headers:
        client.headers.update(extra_headers)

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(base_url, Cyber.WHITE, Cyber.BOLD)}")
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Paths: {color(str(len(paths)), Cyber.WHITE, Cyber.BOLD)} | "
        f"Status: {color(','.join(map(str, sorted(statuses))), Cyber.YELLOW)} | "
        f"Method: {color(method, Cyber.WHITE, Cyber.BOLD)} | "
        f"Concurrency: {color(str(concurrency), Cyber.YELLOW)}",
    )

    sem = asyncio.Semaphore(concurrency)
    total_paths = len(paths)
    completed = 0

    async def _limited_scan(path: str) -> Finding | None:
        nonlocal completed
        async with sem:
            result = await scan_path(client, rate_limiter, base_url, path, timeout, statuses, method)
            completed += 1
            if completed % 20 == 0 or completed == total_paths:
                sys.stdout.write(f"\r  Progresso: {completed}/{total_paths} paths testados...")
                sys.stdout.flush()
            return result

    try:
        tasks = [_limited_scan(path) for path in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

        non_null = [r for r in results if isinstance(r, Finding)]
        spa_skip: set[str] = set()
        if len(non_null) > 10:
            groups: dict[tuple[int, int], list[Finding]] = {}
            for r in non_null:
                groups.setdefault((r.size, r.words), []).append(r)
            dominant_size, dominant_group = max(groups.items(), key=lambda kv: len(kv[1]))
            if len(dominant_group) > len(non_null) * 0.8:
                spa_skip = {r.url for r in dominant_group}
                logger.debug("SPA detectado: %d/%d findings ignorados (size=%d, words=%d)",
                             len(spa_skip), len(non_null), dominant_size[0], dominant_size[1])

        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, Finding):
                continue
            if result.url in spa_skip:
                continue
            if not matches_filter(result, size_range, words_range):
                continue
            findings.append(result)
            details = []
            if result.location:
                details.append(f"-> {result.location}")
            if result.title:
                details.append(f"title={result.title}")
            suffix = f" | {' | '.join(details)}" if details else ""
            print(
                f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                f"{color(str(result.status).ljust(3), status_color(result.status), Cyber.BOLD)} "
                f"{color(str(result.size).rjust(7), Cyber.YELLOW)}B "
                f"{color(result.url, Cyber.CYAN)}"
                f"{color(suffix, Cyber.GRAY)}"
            )
    finally:
        await client.aclose()

    elapsed = time.monotonic() - started
    findings.sort(key=lambda item: (item.status, item.url))
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}. "
        f"Achados: {color(str(len(findings)), Cyber.GREEN, Cyber.BOLD)}",
    )
    return findings


def print_dir_table(findings: list[Finding]) -> None:
    """Imprime tabela formatada dos achados do scan."""
    if not findings:
        print(color("Nenhum diretorio/arquivo encontrado com os filtros atuais.", Cyber.RED))
        return

    headers = ("STATUS", "SIZE", "WORDS", "METHOD", "PATH", "TITLE/LOCATION")
    rows = []
    for item in findings:
        extra = item.location or item.title
        rows.append((str(item.status), str(item.size), str(item.words), item.method, item.path, extra))

    def _row_styles(row: tuple[str, ...]) -> list[tuple[str, ...]]:
        return [
            (status_color(int(row[0])), Cyber.BOLD),
            (Cyber.YELLOW,),
            (Cyber.WHITE,),
            (Cyber.MAGENTA,),
            (Cyber.CYAN,),
            (Cyber.GRAY,),
        ]

    print_table(
        headers=headers,
        rows=rows,
        empty_message="Nenhum diretorio/arquivo encontrado com os filtros atuais.",
        alignments=["left", "right", "right", "left", "left", "left"],
        row_styles_fn=_row_styles,
    )



def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Directory/file scanner HTTP rapido para laboratorios e hosts autorizados."
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: http://example.com")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com URLs alvo (uma por linha).")
    parser.add_argument("--output-dir", dest="output_dir", help="Diretorio para salvos individuais (hostname.json).")
    parser.add_argument("-w", "--wordlist", help="Wordlist customizada, um path por linha.")
    parser.add_argument(
        "-x",
        "--extensions",
        type=parse_extensions,
        default=[],
        help="Extensoes para testar em paths sem extensao. Ex: php,txt,bak",
    )
    parser.add_argument(
        "-s",
        "--status",
        type=parse_statuses,
        default=DEFAULT_STATUSES,
        help="Status aceitos: default, all, 200,403 ou 200-399. Padrao: default",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=40,
        help="Concorrencia assincrona (requests simultaneos). Padrao: 40",
    )
    parser.add_argument(
        "-M",
        "--method",
        default="GET",
        choices=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        help="Metodo HTTP para as requests. Padrao: GET",
    )
    parser.add_argument(
        "--filter-size",
        type=parse_range,
        help="Filtrar por tamanho em bytes. Ex: 100-5000",
    )
    parser.add_argument(
        "--filter-words",
        type=parse_range,
        help="Filtrar por numero de palavras. Ex: 10-100",
    )
    parser.set_defaults(user_agent=f"Mozilla/5.0 (X11; Linux x86_64) DirScanner/{__version__}")
    return parser


async def _run_single(url: str, args: argparse.Namespace, quiet: bool = False) -> list[Finding]:
    """Executa scan em uma unica URL."""
    extra_headers = parse_extra_headers(args.header) if args.header else {}
    cookie_headers = {"Cookie": args.cookie} if args.cookie else {}
    base_url = normalize_url(url, default_scheme="http", ensure_trailing_slash=True)
    paths = load_paths(args.wordlist, args.extensions)
    findings = await scan_target(
        base_url=base_url,
        paths=paths,
        timeout=args.timeout,
        concurrency=args.concurrency,
        statuses=args.status,
        user_agent=args.user_agent,
        proxy=args.proxy,
        requests_per_second=args.delay,
        method=args.method,
        auth_headers=args.auth,
        extra_headers={**extra_headers, **cookie_headers} if cookie_headers or extra_headers else None,
        size_range=args.filter_size,
        words_range=args.filter_words,
    )
    if not quiet:
        print_dir_table(findings)
    return findings


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    quiet = getattr(args, "quiet", False)
    if getattr(args, "color", None) is not None:
        set_color(args.color)
    if args.concurrency < 1:
        raise ValueError("concorrencia precisa ser maior que zero")

    urls = resolve_target_urls(args)
    output_dir = getattr(args, "output_dir", None)
    ensure_output_dir(output_dir)

    all_findings: list[Finding] = []
    for url in urls:
        findings = await _run_single(url, args, quiet=quiet)
        all_findings.extend(findings)
        if output_dir:
            hostname = extract_hostname(url)
            out_path = os.path.join(output_dir, f"{hostname}.json")
            write_output(
                out_path,
                [asdict(f) for f in findings],
                ["url", "path", "status", "size", "words", "title", "location", "method"],
                quiet=quiet,
            )

    if args.output:
        write_output(
            args.output,
            [asdict(f) for f in all_findings],
            ["url", "path", "status", "size", "words", "title", "location", "method"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return asyncio.run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do DirScanner."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.url and not getattr(args, "target_list", None):
        return run_interactive_shell(
            parser, "dirscan> ", run_once,
            description="DirScanner interativo.",
            example="http://localhost:8000 -x php,txt,bak -s 200,301,403",
            banner_fn=banner,
        )

    quiet = getattr(args, "quiet", False)
    if quiet and not args.output:
        print(color("Erro: modo quiet requer -o/--output", Cyber.RED), file=sys.stderr)
        return 1

    try:
        if not quiet:
            banner()
        return run_once(args)
    except KeyboardInterrupt:
        print(color("\n[*] Interrompido pelo usuario.", Cyber.YELLOW), file=sys.stderr)
        return 130
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
