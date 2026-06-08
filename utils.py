#!/usr/bin/env python3
"""Utilitários gerais para formatação, cores e manipulação de dados."""
from __future__ import annotations

import os
import sys
import threading
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


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
            elapsed = now - self._last_request_time
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_request_time = time.monotonic()


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


def fetch(
    session: requests.Session,
    url: str,
    timeout: float = 5.0,
    method: str = "GET",
    allow_redirects: bool = False,
) -> tuple[int, dict[str, str], bytes]:
    """Realiza uma requisicao HTTP e retorna status, headers e corpo."""
    try:
        response = session.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )
        return response.status_code, dict(response.headers), response.content
    except requests.exceptions.RequestException as error:
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


def header_get(headers: dict[str, str], name: str) -> str:
    """Obtém o valor de um header HTTP, ignorando maiúsculas/minúsculas."""
    for key, value in headers.items():
        if key.lower() == name.lower():
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
