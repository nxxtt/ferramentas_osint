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
    user_agent: str = "MyTools/2.0",
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
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Resultado salvo em {color(path, Cyber.GREEN)}")


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
