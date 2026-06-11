#!/usr/bin/env python3
"""Utilitários gerais para formatação, cores e manipulação de dados."""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import shlex
import sys
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("mytools")

__version__ = "3.0.0"

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


USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


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
    if not USE_COLOR:
        return text
    return "".join(styles) + text + Cyber.RESET


def clear_console() -> None:
    """Limpa a tela do console."""
    os.system("cls" if os.name == "nt" else "clear")


class RateLimiter:
    """Rate limiter thread-safe usando lock e intervalo minimo entre requests."""

    def __init__(self, requests_per_second: float = 0.0) -> None:
        self._min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._last_request_time = 0.0

    def wait(self) -> None:
        """Bloqueia ate que o intervalo minimo entre requests tenha passado."""
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            next_slot = self._last_request_time + self._min_interval
            if now >= next_slot:
                self._last_request_time = now
                return
            sleep_time = next_slot - now
            self._last_request_time = next_slot
        time.sleep(sleep_time)


def create_session(
    user_agent: str = "MyTools/3.0",
    proxy: str | None = None,
    max_retries: int = 3,
    backoff_factor: float = 0.5,
) -> requests.Session:
    """Cria uma sessao HTTP compartilhada com retry, proxy e headers padrao."""
    session = requests.Session()

    retry = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update({"User-Agent": user_agent})

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    return session


def _extract_raw_headers(response: requests.Response) -> dict[str, list[str]]:
    """Extrai todos os valores de headers (incluindo duplicados como Set-Cookie)."""
    raw: dict[str, list[str]] = {}
    try:
        msg = response.raw._original_response.msg  # type: ignore[union-attr]
        for key in dict.fromkeys(msg.keys()):
            raw[key.lower()] = msg.get_all(key)  # type: ignore[union-attr]
    except (AttributeError, TypeError):
        pass
    return raw


def fetch(
    session: requests.Session,
    url: str,
    timeout: float = 5.0,
    method: str = "GET",
    allow_redirects: bool = False,
) -> tuple[int, Mapping[str, str], bytes, dict[str, list[str]]]:
    """Realiza uma requisicao HTTP e retorna status, headers, corpo e raw_headers.

    raw_headers e um dict mapeando nomes de headers (lowercase) para listas de
    todos os valores, preservando headers duplicados como Set-Cookie.
    """
    logger.debug("request %s %s (timeout=%.1f)", method, url, timeout)
    try:
        response = session.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )
        logger.debug("response %d %s (%d bytes)", response.status_code, url, len(response.content))
        return response.status_code, response.headers, response.content, _extract_raw_headers(response)
    except requests.exceptions.RequestException as error:
        logger.debug("error %s: %s", url, error)
        raise ValueError(f"falha ao acessar {url}: {error}") from error


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
    value = headers.get(name)
    if value is not None:
        return value
    lower_name = name.lower()
    for key, value in headers.items():
        if key.lower() == lower_name:
            return value
    return ""


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


def write_output(
    path: str,
    data: Any,
    fieldnames: list[str] | None = None,
    csv_rows: list[dict] | None = None,
    quiet: bool = False,
) -> None:
    """Salva dados em arquivo JSON ou CSV."""
    extension = os.path.splitext(path)[1].lower()
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
    import base64
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


def add_common_args(parser: argparse.ArgumentParser) -> None:
    """Adiciona argumentos compartilhados a um parser."""
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Timeout em segundos. Padrao: 5")
    parser.add_argument("-o", "--output", help="Salva resultado em .json ou .csv.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostra mensagens de debug no terminal.")
    parser.add_argument("--log-file", help="Salva logs em arquivo.")
    parser.add_argument("-A", "--user-agent", help="User-Agent usado nas requests.")
    parser.add_argument("--proxy", help="Proxy para as requests. Ex: http://proxy:8080")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay entre requests (req/s). 0 = sem limite.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso: sem banner/progresso. Requer -o.")
    parser.add_argument(
        "--auth",
        type=parse_auth,
        help="Autenticacao Basic (user:pass). Envia header Authorization.",
    )
    parser.add_argument("--bearer-token", dest="bearer_token", help="Token Bearer para autenticacao.")
    parser.add_argument("--cookie", help="Cookie para as requests. Ex: 'session=abc123; token=xyz'")
    parser.add_argument("--header", action="append", default=[], help="Header customizado (pode usar mais de um). Ex: 'X-Token: abc'")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")


def apply_session_auth(
    session: requests.Session,
    auth: dict[str, str] | None = None,
    bearer_token: str | None = None,
    cookie: str | None = None,
    extra_headers: list[str] | None = None,
) -> None:
    """Aplica headers de autenticacao e personalizados a uma sessao."""
    if auth:
        session.headers.update(auth)
    if bearer_token:
        session.headers["Authorization"] = f"Bearer {bearer_token}"
    if cookie:
        session.headers["Cookie"] = cookie
    if extra_headers:
        session.headers.update(parse_extra_headers(extra_headers))


def extract_hostname(url: str) -> str:
    """Extrai hostname de uma URL para uso em nomes de arquivo."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or url
    return host.replace("/", "_").replace(":", "_")


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd(
    keyword: str,
    api_key: str | None = None,
    limit: int = 10,
) -> list[dict]:
    """Consulta a API NIST NVD v2.0 e retorna lista de vulnerabilidades.

    Args:
        keyword: Termo de busca (ex: "Apache 2.4.41").
        api_key: Chave da API NVD (opcional, aumenta rate limit de 5 para 50 req/30s).
        limit: Numero maximo de resultados por query.

    Returns:
        Lista de dicts com chaves: id, description, score, severity.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {"keywordSearch": keyword, "resultsPerPage": limit}

    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        if response.status_code == 403:
            logger.debug("NVD rate limited for keyword: %s", keyword)
            return []
        if response.status_code != 200:
            logger.debug("NVD returned %d for keyword: %s", response.status_code, keyword)
            return []
    except requests.exceptions.RequestException as error:
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
