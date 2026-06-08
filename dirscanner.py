#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import shlex
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    setup_logging,
    status_color,
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

DEFAULT_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}

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


def banner() -> None:
    """Exibe o banner ASCII do DirScanner."""
    art = r"""
    ____  _      _____
   / __ \(_)____/ ___/_________ _____  ____  ___  _____
  / / / / / ___/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /_/ / / /  ___/ / /__/ /_/ / / / / / / /  __/ /
/_____/_/_/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/
"""
    print(color(art.rstrip(), Cyber.CYAN, Cyber.BOLD))
    print(color("   HTTP directory scanner | use apenas em alvos autorizados\n", Cyber.MAGENTA))


def normalize_base_url(url: str) -> str:
    """Normaliza a URL alvo garantindo esquema e barra final."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"URL invalida: {url}")
    return url.rstrip("/") + "/"


def parse_statuses(value: str) -> set[int]:
    """Converte string de status HTTP para conjunto de inteiros."""
    if value == "default":
        return set(DEFAULT_STATUSES)
    if value == "all":
        return set(range(100, 600))

    statuses: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start_raw, end_raw = part.split("-", 1)
                start, end = int(start_raw), int(end_raw)
                if start > end:
                    start, end = end, start
                statuses.update(range(start, end + 1))
            else:
                statuses.add(int(part))
        except ValueError:
            raise argparse.ArgumentTypeError(f"status invalido: {part!r}")

    invalid = [status for status in statuses if status < 100 or status > 599]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"status invalidos: {', '.join(map(str, sorted(invalid)))}"
        )
    if not statuses:
        raise argparse.ArgumentTypeError("informe pelo menos um status")
    return statuses


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


def parse_auth(value: str) -> dict[str, str]:
    """Converte string 'user:pass' em headers de autenticacao Basic."""
    if ":" not in value:
        raise argparse.ArgumentTypeError(f"formato invalido: {value!r} (use user:pass)")
    user, password = value.split(":", 1)
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


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


def scan_path(
    session,
    rate_limiter: RateLimiter,
    base_url: str,
    path: str,
    timeout: float,
    statuses: set[int],
    method: str = "GET",
) -> Finding | None:
    """Realiza request HTTP para um caminho específico e retorna Finding."""
    full_url = urljoin(base_url, path)
    rate_limiter.wait()

    try:
        status, headers, content = fetch(session, full_url, timeout=timeout, method=method)
    except ValueError:
        return None

    if status not in statuses:
        return None

    content_type = headers.get("content-type", "")
    text = content.decode("utf-8", errors="replace") if "text/" in content_type.lower() else ""
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


def scan_target(
    base_url: str,
    paths: list[str],
    timeout: float,
    workers: int,
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
    findings: list[Finding] = []
    rate_limiter = RateLimiter(requests_per_second)
    session = create_session(user_agent=user_agent, proxy=proxy)

    logger.info("scan iniciado: %s (%d paths)", base_url, len(paths))
    logger.debug("method=%s, threads=%d, statuses=%s", method, workers, statuses)

    if auth_headers:
        session.headers.update(auth_headers)
    if extra_headers:
        session.headers.update(extra_headers)

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(base_url, Cyber.WHITE, Cyber.BOLD)}")
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Paths: {color(str(len(paths)), Cyber.WHITE, Cyber.BOLD)} | "
        f"Status: {color(','.join(map(str, sorted(statuses))), Cyber.YELLOW)} | "
        f"Method: {color(method, Cyber.WHITE, Cyber.BOLD)} | "
        f"Threads: {color(str(workers), Cyber.YELLOW)}",
    )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_path, session, rate_limiter, base_url, path, timeout, statuses, method)
            for path in paths
        ]

        for future in as_completed(futures):
            try:
                finding = future.result()
            except Exception:
                continue
            if not finding:
                continue
            if not matches_filter(finding, size_range, words_range):
                continue

            findings.append(finding)
            details = []
            if finding.location:
                details.append(f"-> {finding.location}")
            if finding.title:
                details.append(f"title={finding.title}")
            suffix = f" | {' | '.join(details)}" if details else ""

            print(
                f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                f"{color(str(finding.status).ljust(3), status_color(finding.status), Cyber.BOLD)} "
                f"{color(str(finding.size).rjust(7), Cyber.YELLOW)}B "
                f"{color(finding.url, Cyber.CYAN)}"
                f"{color(suffix, Cyber.GRAY)}"
            )

    elapsed = time.monotonic() - started
    findings.sort(key=lambda item: (item.status, item.url))
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}. "
        f"Achados: {color(str(len(findings)), Cyber.GREEN, Cyber.BOLD)}",
    )
    return findings


def print_table(findings: list[Finding]) -> None:
    """Imprime tabela formatada dos achados do scan."""
    if not findings:
        print(color("Nenhum diretorio/arquivo encontrado com os filtros atuais.", Cyber.RED))
        return

    headers = ("STATUS", "SIZE", "WORDS", "METHOD", "PATH", "TITLE/LOCATION")
    rows = []
    for item in findings:
        extra = item.location or item.title
        rows.append((str(item.status), str(item.size), str(item.words), item.method, item.path, extra))

    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]

    print()
    print(color("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)), Cyber.CYAN, Cyber.BOLD))
    print(color("  ".join("-" * width for width in widths), Cyber.BLUE))
    for row in rows:
        status, size, words, method, path, extra = row
        print(
            "  ".join(
                (
                    color(status.ljust(widths[0]), status_color(int(status)), Cyber.BOLD),
                    color(size.rjust(widths[1]), Cyber.YELLOW),
                    color(words.rjust(widths[2]), Cyber.WHITE),
                    color(method.ljust(widths[3]), Cyber.MAGENTA),
                    color(path.ljust(widths[4]), Cyber.CYAN),
                    color(extra.ljust(widths[5]), Cyber.GRAY),
                )
            )
        )


def write_output(path: str, findings: list[Finding]) -> None:
    """Salva os achados em formato JSON ou CSV."""
    extension = os.path.splitext(path)[1].lower()
    with open(path, "w", encoding="utf-8", newline="") as file_handle:
        if extension == ".json":
            json.dump([asdict(item) for item in findings], file_handle, indent=2)
            file_handle.write("\n")
        else:
            writer = csv.DictWriter(
                file_handle,
                fieldnames=["url", "path", "status", "size", "words", "title", "location", "method"],
            )
            writer.writeheader()
            for item in findings:
                writer.writerow(asdict(item))
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Resultado salvo em {color(path, Cyber.GREEN)}")


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Directory/file scanner HTTP rapido para laboratorios e hosts autorizados."
    )
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: http://example.com")
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
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout por request em segundos. Padrao: 5",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=40,
        help="Numero de threads. Padrao: 40",
    )
    parser.add_argument(
        "-A",
        "--user-agent",
        default="Mozilla/5.0 (X11; Linux x86_64) DirScanner/2.0",
        help="User-Agent usado nas requests.",
    )
    parser.add_argument(
        "--proxy",
        help="Proxy para as requests. Ex: http://proxy:8080",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay entre requests (requests por segundo). 0 = sem limite. Padrao: 0",
    )
    parser.add_argument(
        "-M",
        "--method",
        default="GET",
        choices=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        help="Metodo HTTP para as requests. Padrao: GET",
    )
    parser.add_argument(
        "--auth",
        type=parse_auth,
        help="Autenticacao Basic (user:pass). Envia header Authorization.",
    )
    parser.add_argument(
        "--cookie",
        help="Cookie para as requests. Ex: 'session=abc123; token=xyz'",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Header customizado (pode usar mais de um). Ex: 'X-Token: abc'",
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
    parser.add_argument("-o", "--output", help="Salva resultado em .json ou .csv.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostra mensagens de debug no terminal.")
    parser.add_argument("--log-file", help="Salva logs em arquivo.")
    return parser


def parse_extra_headers(raw_headers: list[str]) -> dict[str, str]:
    """Converte lista de strings 'Name: Value' em dict de headers."""
    headers: dict[str, str] = {}
    for raw in raw_headers:
        if ":" not in raw:
            raise ValueError(f"header invalido: {raw!r} (use 'Name: Value')")
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def run_once(args: argparse.Namespace) -> int:
    """Executa um único scan com os argumentos fornecidos."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    if not args.url:
        raise ValueError("informe uma URL alvo")
    if args.timeout <= 0:
        raise ValueError("timeout precisa ser maior que zero")
    if args.threads < 1:
        raise ValueError("threads precisa ser maior que zero")

    extra_headers = parse_extra_headers(args.header) if args.header else None
    cookie_headers = {"Cookie": args.cookie} if args.cookie else None

    base_url = normalize_base_url(args.url)
    paths = load_paths(args.wordlist, args.extensions)
    findings = scan_target(
        base_url=base_url,
        paths=paths,
        timeout=args.timeout,
        workers=args.threads,
        statuses=args.status,
        user_agent=args.user_agent,
        proxy=args.proxy,
        requests_per_second=args.delay,
        method=args.method,
        auth_headers=args.auth,
        extra_headers={**cookie_headers, **extra_headers} if cookie_headers or extra_headers else None,
        size_range=args.filter_size,
        words_range=args.filter_words,
    )
    print_table(findings)
    if args.output:
        write_output(args.output, findings)
    return 0


def interactive_shell(parser: argparse.ArgumentParser) -> int:
    """Modo interativo com loop de comandos até exit."""
    banner()
    print(color("DirScanner interativo.", Cyber.WHITE, Cyber.BOLD), "Digite 'help', 'clear' ou 'exit'.")
    print(color("Ex:", Cyber.CYAN), "http://localhost:8000 -x php,txt,bak -s 200,301,403")

    while True:
        try:
            raw = input(color("dirscan> ", Cyber.GREEN, Cyber.BOLD)).strip()
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
    """Ponto de entrada principal do DirScanner."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.url:
        return interactive_shell(parser)

    try:
        banner()
        return run_once(args)
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
