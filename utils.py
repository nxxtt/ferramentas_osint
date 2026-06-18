#!/usr/bin/env python3
"""Utilitários gerais para formatação, cores e manipulação de dados."""
from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import json
import logging
import os
import shlex
import sys
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("mytools")

__version__ = "3.2.0"

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    """Configura logging para o MyTools.

    Args:
        verbose: Se True, mostra mensagens DEBUG no terminal.
        log_file: Se fornecido, salva logs neste arquivo (sempre em modo verbose).
    """
    level = logging.DEBUG if verbose else logging.WARNING
    if log_file and not verbose:
        level = logging.INFO

    log = logging.getLogger("mytools")
    log.setLevel(level)
    log.handlers.clear()

    terminal = logging.StreamHandler(sys.stderr)
    terminal.setLevel(level)
    terminal.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"))
    log.addHandler(terminal)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        log.addHandler(file_handler)


_USE_COLOR: bool = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def set_color(enabled: bool) -> None:
    """Habilita ou desabilita cores ANSI no terminal."""
    global _USE_COLOR
    _USE_COLOR = enabled


class Cyber:
    """Constantes de cores ANSI para formatação de terminal."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[38;5;203m"
    GREEN = "\033[38;5;46m"
    CYAN = "\033[38;5;51m"
    BLUE = "\033[38;5;39m"
    MAGENTA = "\033[38;5;201m"
    YELLOW = "\033[38;5;226m"
    WHITE = "\033[38;5;255m"
    GRAY = "\033[38;5;244m"


def color(text: str, *styles: str) -> str:
    """Aplica estilos de cor ANSI ao texto."""
    if not _USE_COLOR:
        return text
    return "".join(styles) + text + Cyber.RESET


def clear_console() -> None:
    """Limpa a tela do console."""
    os.system("cls" if os.name == "nt" else "clear")


class RateLimiter:
    """Rate limiter async usando intervalo minimo entre requests com backoff adaptativo."""

    def __init__(self, requests_per_second: float = 0.0) -> None:
        self._base_rps = requests_per_second
        self._min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0.0
        self._last_request_time = 0.0
        self._backoff_multiplier: float = 1.0

    async def wait(self) -> None:
        """Bloqueia ate que o intervalo minimo entre requests tenha passado."""
        effective_interval = self._min_interval * self._backoff_multiplier
        if effective_interval <= 0:
            self._last_request_time = time.monotonic()
            return
        now = time.monotonic()
        next_slot = self._last_request_time + effective_interval
        if now >= next_slot:
            self._last_request_time = now
            return
        sleep_time = next_slot - now
        self._last_request_time = next_slot
        await asyncio.sleep(sleep_time)

    def notify_429(self) -> None:
        """Notifica que um 429 foi recebido, aumentando o delay."""
        self._backoff_multiplier = min(self._backoff_multiplier * 2.0, 16.0)

    def reset_backoff(self) -> None:
        """Reseta o multiplicador de backoff para 1.0."""
        self._backoff_multiplier = 1.0


def create_async_client(
    user_agent: str = f"MyTools/{__version__}",
    proxy: str | None = None,
    timeout: float = 5.0,
) -> httpx.AsyncClient:
    """Cria um cliente HTTP async com headers padrao."""
    headers = {"User-Agent": user_agent}
    return httpx.AsyncClient(
        headers=headers,
        proxy=proxy,
        timeout=timeout,
        follow_redirects=False,
        verify=False,
    )


def _extract_raw_headers(response: httpx.Response) -> dict[str, list[str]]:
    """Extrai todos os valores de headers (incluindo duplicados como Set-Cookie)."""
    raw: dict[str, list[str]] = {}
    for name, value in response.headers.multi_items():
        raw.setdefault(name.lower(), []).append(value)
    return raw


async def fetch(
    client: httpx.AsyncClient,
    url: str,
    timeout: float = 5.0,
    method: str = "GET",
    allow_redirects: bool = False,
    max_retries: int = 3,
    rate_limiter: RateLimiter | None = None,
) -> tuple[int, Mapping[str, str], bytes, dict[str, list[str]]]:
    """Realiza uma requisicao HTTP async e retorna status, headers, corpo e raw_headers.

    raw_headers e um dict mapeando nomes de headers (lowercase) para listas de
    todos os valores, preservando headers duplicados como Set-Cookie.
    """
    last_error: Exception | None = None
    for attempt in range(max_retries):
        logger.debug("request %s %s (timeout=%.1f, attempt=%d)", method, url, timeout, attempt + 1)
        try:
            response = await client.request(
                method=method,
                url=url,
                timeout=timeout,
                follow_redirects=allow_redirects,
            )
            if response.status_code == 429 and rate_limiter is not None:
                rate_limiter.notify_429()
                retry_after = float(response.headers.get("Retry-After", "5"))
                await asyncio.sleep(min(retry_after, 30))
                continue
            logger.debug("response %d %s (%d bytes)", response.status_code, url, len(response.content))
            return response.status_code, response.headers, response.content, _extract_raw_headers(response)
        except httpx.RequestError as error:
            logger.debug("error %s: %s", url, error)
            last_error = error
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
    raise ValueError(f"falha ao acessar {url}: {last_error}")


def status_color(status: int) -> str:
    """Retorna a cor ANSI correspondente ao código de status HTTP."""
    if 200 <= status < 300:
        return Cyber.GREEN
    if 300 <= status < 400:
        return Cyber.YELLOW
    if status in {401, 403}:
        return Cyber.MAGENTA
    if 400 <= status < 500:
        return Cyber.RED
    return Cyber.GRAY


def header_get(headers: Mapping[str, str], name: str) -> str:
    """Obtém o valor de um header HTTP, ignorando maiúsculas/minúsculas."""
    return headers.get(name, "")


def parse_int_range(
    value: str,
    min_val: int,
    max_val: int,
    error_label: str,
    aliases: dict[str, list[int]] | None = None,
) -> list[int]:
    """Converte string de inteiros/ranges em lista ordenada. Ex: '80,443,8000-9000'."""
    if aliases and value in aliases:
        return aliases[value]

    result: set[int] = set()
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
                result.update(range(start, end + 1))
            else:
                result.add(int(part))
        except ValueError:
            raise argparse.ArgumentTypeError(f"{error_label} invalido: {part!r}")

    invalid = [v for v in result if v < min_val or v > max_val]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"{error_label}s invalidos: {', '.join(map(str, sorted(invalid)))}"
        )
    if not result:
        raise argparse.ArgumentTypeError(f"informe pelo menos um {error_label}")
    return sorted(result)


def extract_title(text: str) -> str:
    """Extrai o conteúdo da tag <title> de um HTML."""
    lower = text.lower()
    start = lower.find("<title>")
    end = lower.find("</title>", start + 7)
    if start == -1 or end == -1:
        return ""
    return " ".join(text[start + 7:end].strip().split())[:100]


def show_banner(art: str, subtitle: str) -> None:
    """Exibe banner ASCII art colorido com subtitle."""
    print(color(art.rstrip(), Cyber.CYAN, Cyber.BOLD))
    print(color(subtitle, Cyber.MAGENTA))


def create_banner(art: str, subtitle: str, extra: Callable[[], None] | None = None) -> Callable[[], None]:
    """Cria uma funcao de banner reutilizavel a partir de art e subtitle."""
    def _banner() -> None:
        show_banner(art, subtitle)
        if extra:
            extra()
    return _banner


def print_table(
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
    column_styles: list[tuple[str, ...]] | None = None,
    empty_message: str = "Nenhum resultado encontrado.",
    alignments: list[str] | None = None,
    row_styles_fn: Callable[[tuple[str, ...]], list[tuple[str, ...]]] | None = None,
) -> None:
    """Exibe tabela formatada no terminal com cores por coluna.

    Args:
        headers: Titulos das colunas.
        rows: Lista de tuplas com valores de cada linha.
        column_styles: Estilos estaticos por coluna (ignorado quando row_styles_fn).
        empty_message: Mensagem exibida quando nao ha linhas.
        alignments: Alinhamento por coluna ('left' ou 'right').
        row_styles_fn: Funcao que recebe uma row e retorna estilos por coluna.
    """
    if not rows:
        print(color(empty_message, Cyber.RED))
        return

    if alignments is None:
        alignments = ["left"] * len(headers)

    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows))
        for i in range(len(headers))
    ]

    print()
    print(color("  ".join(header.ljust(widths[i]) for i, header in enumerate(headers)), Cyber.CYAN, Cyber.BOLD))
    print(color("  ".join("-" * width for width in widths), Cyber.BLUE))
    for row in rows:
        cells = []
        styles = row_styles_fn(row) if row_styles_fn else column_styles
        assert styles is not None
        for i, value in enumerate(row):
            aligned = value.ljust(widths[i]) if alignments[i] == "left" else value.rjust(widths[i])
            cells.append(color(aligned, *styles[i]))
        print("  ".join(cells))


def write_output(
    path: str,
    data: Any,
    fieldnames: list[str] | None = None,
    csv_rows: list[dict] | None = None,
    quiet: bool = False,
) -> None:
    """Salva dados em arquivo JSON ou CSV."""
    extension = os.path.splitext(path)[1].lower()
    if extension not in (".json", ".csv"):
        raise ValueError(f"extensao nao suportada: {extension!r} (use .json ou .csv)")
    with open(path, "w", encoding="utf-8", newline="") as file_handle:
        if extension == ".json":
            json.dump(data, file_handle, indent=2)
            file_handle.write("\n")
        else:
            rows = csv_rows if csv_rows is not None else data
            if fieldnames is None:
                fieldnames = list(rows[0].keys()) if rows else []
            writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
            writer.writeheader()
            for item in rows:
                writer.writerow(item)
    if not quiet:
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Resultado salvo em {color(path, Cyber.GREEN)}")


def parse_auth(value: str) -> dict[str, str]:
    """Converte string 'user:pass' em headers de autenticacao Basic."""
    if ":" not in value:
        raise argparse.ArgumentTypeError(f"formato invalido: {value!r} (use user:pass)")
    user, password = value.split(":", 1)
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def parse_extra_headers(raw_headers: list[str]) -> dict[str, str]:
    """Converte lista de strings 'Name: Value' em dict de headers."""
    headers: dict[str, str] = {}
    for raw in raw_headers:
        if ":" not in raw:
            raise ValueError(f"header invalido: {raw!r} (use 'Name: Value')")
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def normalize_url(url: str, default_scheme: str = "https", ensure_trailing_slash: bool = False) -> str:
    """Normaliza e valida uma URL, adicionando scheme padrao se necessario."""
    url = url.strip()
    if not url:
        raise ValueError("informe uma URL alvo")
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"{default_scheme}://" + url
        parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"URL invalida: {url}")
    url = url.rstrip("/")
    if ensure_trailing_slash:
        url += "/"
    return url


def add_base_args(parser: argparse.ArgumentParser, timeout_default: float = 5.0) -> None:
    """Adiciona argumentos base compartilhados (timeout, output, verbose, etc)."""
    parser.add_argument("-t", "--timeout", type=float, default=timeout_default, help="Timeout em segundos. Padrao: 5")
    parser.add_argument("-o", "--output", help="Salva resultado em .json ou .csv.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostra mensagens de debug no terminal.")
    parser.add_argument("--log-file", help="Salva logs em arquivo.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso: sem banner/progresso. Requer -o.")
    parser.add_argument("--color", action="store_true", default=None, dest="color", help="Forca cores no terminal.")
    parser.add_argument("--no-color", action="store_false", dest="color", help="Desabilita cores no terminal.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")


def add_http_args(parser: argparse.ArgumentParser) -> None:
    """Adiciona argumentos HTTP especificos (user-agent, proxy, auth, etc)."""
    parser.add_argument("-A", "--user-agent", help="User-Agent usado nas requests.")
    parser.add_argument("--proxy", help="Proxy para as requests. Ex: http://proxy:8080")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay entre requests (req/s). 0 = sem limite.")
    parser.add_argument(
        "--auth",
        type=parse_auth,
        help="Autenticacao Basic (user:pass). Envia header Authorization.",
    )
    parser.add_argument("--bearer-token", dest="bearer_token", help="Token Bearer para autenticacao.")
    parser.add_argument("--cookie", help="Cookie para as requests. Ex: 'session=abc123; token=xyz'")
    parser.add_argument("--header", action="append", default=[], help="Header customizado (pode usar mais de um). Ex: 'X-Token: abc'")


def add_common_args(parser: argparse.ArgumentParser) -> None:
    """Adiciona argumentos compartilhados (base + HTTP) a um parser."""
    add_base_args(parser)
    add_http_args(parser)


def apply_session_auth(
    client: httpx.AsyncClient,
    auth: dict[str, str] | None = None,
    bearer_token: str | None = None,
    cookie: str | None = None,
    extra_headers: list[str] | None = None,
) -> None:
    """Aplica headers de autenticacao e personalizados a um cliente async."""
    if auth:
        client.headers.update(auth)
    if bearer_token:
        client.headers["Authorization"] = f"Bearer {bearer_token}"
    if extra_headers:
        client.headers.update(parse_extra_headers(extra_headers))
    if cookie:
        client.headers["Cookie"] = cookie


def extract_hostname(url: str) -> str:
    """Extrai hostname de uma URL para uso em nomes de arquivo."""
    parsed = urlparse(url)
    host = parsed.hostname or url
    return host.replace("/", "_").replace(":", "_")


def resolve_target_urls(args: argparse.Namespace) -> list[str]:
    """Le -l/--list e args.url, retorna lista deduplicada de URLs."""
    urls: list[str] = []
    target_list = getattr(args, "target_list", None)
    if target_list:
        try:
            with open(target_list, "r", encoding="utf-8", errors="replace") as fh:
                urls = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            raise ValueError(f"arquivo nao encontrado: {target_list}")
    url = getattr(args, "url", None)
    if url:
        urls.append(url)
    if not urls:
        raise ValueError("informe uma URL alvo ou use -l/--list")
    return urls


def ensure_output_dir(output_dir: str | None) -> None:
    """Cria o diretorio de saida se nao existir."""
    if output_dir and not os.path.isdir(output_dir):
        os.makedirs(output_dir, exist_ok=True)


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def query_nvd(
    keyword: str,
    api_key: str | None = None,
    limit: int = 10,
    client: httpx.AsyncClient | None = None,
) -> list[dict]:
    """Consulta a API NIST NVD v2.0 e retorna lista de vulnerabilidades.

    Args:
        keyword: Termo de busca (ex: "Apache 2.4.41").
        api_key: Chave da API NVD (opcional, aumenta rate limit de 5 para 50 req/30s).
        limit: Numero maximo de resultados por query.
        client: Cliente HTTP opcional para reutilizar.

    Returns:
        Lista de dicts com chaves: id, description, score, severity.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {"keywordSearch": keyword, "resultsPerPage": limit}

    try:
        if client is not None:
            response = await client.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        else:
            async with httpx.AsyncClient() as tmp:
                response = await tmp.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        if response.status_code == 403:
            logger.debug("NVD rate limited for keyword: %s", keyword)
            return []
        if response.status_code != 200:
            logger.debug("NVD returned %d for keyword: %s", response.status_code, keyword)
            return []
    except httpx.RequestError as error:
        logger.debug("NVD request failed: %s", error)
        return []

    data = response.json()
    results: list[dict] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        score = 0.0
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if version_key in metrics:
                cvss_data = metrics[version_key][0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        results.append({"id": cve_id, "description": description, "score": score, "severity": severity})

    return results


def run_interactive_shell(
    parser: argparse.ArgumentParser,
    prompt: str,
    run_fn: Callable,
    description: str = "",
    example: str = "",
    validate_fn: Callable | None = None,
    banner_fn: Callable | None = None,
) -> int:
    """Inicia shell interativo generico com loop de comandos."""
    if banner_fn:
        banner_fn()
    print(color(description, Cyber.WHITE, Cyber.BOLD), "Digite 'help', 'clear' ou 'exit'.")
    if example:
        print(color("Ex:", Cyber.CYAN), example)

    while True:
        try:
            raw = input(color(prompt, Cyber.GREEN, Cyber.BOLD)).strip()
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
            if validate_fn:
                validate_fn(args)
            run_fn(args)
        except ValueError as error:
            print(color(f"Erro: {error}", Cyber.RED))
        except SystemExit:
            continue
        except Exception as error:
            print(color(f"Erro: {error}", Cyber.RED))
