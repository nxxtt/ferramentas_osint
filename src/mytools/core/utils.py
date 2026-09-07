#!/usr/bin/env python3
"""Utilitários gerais para formatação, cores e manipulação de dados.

Modulo compartilhado por todos os scanners do MyTools. Fornece:

- Cores ANSI: classe Cyber + funcao color()
- HTTP async: create_async_client(), fetch() com retry + rate limit
- Rate limiter: classe RateLimiter com backoff adaptativo em 429
- Parse de entrada: parse_int_range(), normalize_url(), parse_auth()
- Saida: write_output() para JSON/CSV, print_table() para terminal
- NVD API: query_nvd() para busca de CVEs no NIST NVD v2.0
- Logging: setup_logging() com suporte a arquivo e verbose
- Shell interativo: run_interactive_shell() reutilizavel por todos modulos

Padroes de design:
  - Todas as funcoes HTTP sao async (httpx.AsyncClient)
  - fetch() retenta automaticamente em erros de rede (max 3 tentativas)
  - RateLimiter notificado em 429 aumenta delay com backoff exponencial
  - safe_asyncio_run() funciona mesmo com event loop ativo (Jupyter/REPL)
"""

import argparse
import asyncio
import base64
import contextlib
import csv
import json
import logging
import os
import random
import re
import shlex
import sys
import threading
import time
import tomllib
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple
from urllib.parse import urlparse

import httpx

if TYPE_CHECKING:
    from curl_cffi.requests import BrowserTypeLiteral

logger = logging.getLogger("mytools")

_SECRET_PATTERNS = re.compile(r"(ghp_|sk-|gho_|glpat-|xox[bsrp]-|AKIA|^[^:]+:\S+$)")

_STDOUT_CONFIGURED = False


def _ensure_utf8_stdout() -> None:
    """Configura stdout para UTF-8 uma unica vez por processo."""
    global _STDOUT_CONFIGURED
    if _STDOUT_CONFIGURED:
        return
    stdout: Any = sys.stdout
    with contextlib.suppress(AttributeError, ValueError):
        stdout.reconfigure(encoding="utf-8")
    _STDOUT_CONFIGURED = True


__all__ = [
    "NVD_API_URL",
    "SECURITY_HEADERS",
    "THEMES",
    "FetchError",
    "FetchResult",
    "RateLimiter",
    "StealthContext",
    "add_base_args",
    "add_common_args",
    "add_http_args",
    "add_stealth_args",
    "apply_session_auth",
    "apply_session_auth_async",
    "apply_theme",
    "clear_console",
    "color",
    "create_async_client",
    "create_banner",
    "detect_spa_fallback",
    "ensure_output_dir",
    "extract_hostname",
    "extract_title",
    "fetch",
    "get_stealth_ctx",
    "header_get",
    "init_scanner",
    "normalize_url",
    "override_severity",
    "parse_auth",
    "parse_extra_headers",
    "parse_int_range",
    "print_exploit_info",
    "print_json",
    "print_table",
    "query_nvd",
    "resolve_cred",
    "resolve_cred_async",
    "resolve_target_urls",
    "run_concurrent",
    "run_interactive_shell",
    "run_main_loop",
    "safe_asyncio_run",
    "set_color",
    "set_fetch_cache_ttl",
    "setup_logging",
    "severity_color",
    "show_banner",
    "status_color",
    "validate_stealth_args",
    "workspace_path",
    "workspace_timestamp",
    "write_output",
]


def _read_version() -> str:
    """Le a versao de pyproject.toml (single source of truth)."""
    try:
        pyproject = Path(__file__).parent.parent.parent.parent / "pyproject.toml"
        with pyproject.open("rb") as fh:
            data = tomllib.load(fh)
        return data["project"]["version"]
    except FileNotFoundError, KeyError, ValueError:
        pass
    return "0.0.0"


__version__ = _read_version()


def _load_security_headers() -> list[str]:
    """Carrega SECURITY_HEADERS de YAML com fallback."""
    from mytools.data import load_payloads

    default = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    data = load_payloads("core", "security_headers", default={"headers": default})
    return data.get("headers", default)


SECURITY_HEADERS = _load_security_headers()


_logging_lock = threading.Lock()
_logging_config: tuple[bool, str | None] | None = None


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    """Configura logging para o MyTools.

    Args:
        verbose: Se True, mostra mensagens DEBUG no terminal.
        log_file: Se fornecido, salva logs neste arquivo (sempre em modo verbose).

    Thread-safe: reconfigura os handlers apenas quando a configuracao muda,
    evitando handlers duplicados quando varios scanners rodam em paralelo.
    """
    global _logging_config
    level = logging.DEBUG if verbose else logging.WARNING
    if log_file and not verbose:
        level = logging.INFO

    config = (verbose, log_file)
    with _logging_lock:
        log = logging.getLogger("mytools")
        if _logging_config != config:
            log.setLevel(level)
            log.handlers.clear()

            terminal = logging.StreamHandler(sys.stderr)
            terminal.setLevel(level)
            terminal.setFormatter(
                logging.Formatter(
                    "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                    datefmt="%H:%M:%S",
                )
            )
            log.addHandler(terminal)

            if log_file:
                file_handler = logging.FileHandler(log_file, encoding="utf-8")
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(
                    logging.Formatter(
                        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S",
                    )
                )
                log.addHandler(file_handler)
            _logging_config = config


_USE_COLOR: bool = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def set_color(enabled: bool) -> None:
    """Habilita ou desabilita cores ANSI no terminal."""
    global _USE_COLOR
    _USE_COLOR = enabled


def init_scanner(args: argparse.Namespace) -> bool:
    """Inicializa logging, quiet mode, color, tema e stealth para um scanner.

    Retorna True se o modo quiet esta ativo.
    """
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    quiet = getattr(args, "quiet", False)
    if getattr(args, "color", None) is not None:
        set_color(args.color)
    theme = getattr(args, "theme", None)
    if theme and theme != "cyber":
        apply_theme(theme)
    severity_raw = getattr(args, "severity_override", None)
    if severity_raw:
        for pair in severity_raw.split(","):
            if "=" in pair:
                sev, cname = pair.split("=", 1)
                override_severity(sev.strip(), cname.strip())
    _stealth_local.ctx = StealthContext.from_args(args)
    return quiet


def run_main_loop(
    parser: argparse.ArgumentParser,
    banner_fn: Callable[[], None],
    run_fn: Callable[[argparse.Namespace], int],
    has_target: Callable[[argparse.Namespace], bool],
    prompt: str,
    description: str,
    example: str,
    contextual_help: str,
    validate_fn: Callable[[argparse.Namespace], None] | None = None,
) -> int:
    """Loop principal compartilhado por todos os scanners.

    Trata parse_args, shell interativo, quiet check e try/except.
    """
    args = parser.parse_args()
    if getattr(args, "dump_payloads", False):
        import json

        from mytools.data import load_payloads
        from mytools.data.loader import _DATA_DIR, dump_registry

        for sub in sorted(
            p.name
            for p in _DATA_DIR.iterdir()
            if p.is_dir() and not p.name.startswith("_")
        ):
            for ext in ("*.yaml", "*.yml", "*.json"):
                for yaml_file in sorted((_DATA_DIR / sub).glob(ext)):
                    load_payloads(sub, yaml_file.stem)
        print(json.dumps(dump_registry(), indent=2, ensure_ascii=False, default=str))
        return 0
    if not has_target(args):
        return run_interactive_shell(
            parser,
            prompt,
            run_fn,
            description=description,
            example=example,
            validate_fn=validate_fn,
            banner_fn=banner_fn,
            contextual_help=contextual_help,
        )

    quiet = getattr(args, "quiet", False)
    output_dir = getattr(args, "output_dir", None)
    if output_dir and not args.output:
        target = getattr(args, "url", None) or getattr(args, "target", None)
        if target:
            args.output = str(workspace_path(output_dir, target))
            ensure_output_dir(str(Path(args.output).parent))
    if quiet and not args.output and not getattr(args, "json_output", False):
        print(color("Erro: modo quiet requer -o/--output", Cyber.RED), file=sys.stderr)
        return 1

    try:
        validate_stealth_args(args)
        if not quiet and not getattr(args, "json_output", False):
            banner_fn()
        return run_fn(args)
    except KeyboardInterrupt:
        print(color("\n[*] Interrompido pelo usuario.", Cyber.YELLOW), file=sys.stderr)
        return 130
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


class FetchError(Exception):
    """Erro de requisicao HTTP com contexto completo.

    Attributes:
        url: URL que falhou.
        attempts: Quantidade de tentativas realizadas.
        last_error: Excecao original do httpx.
    """

    def __init__(self, url: str, attempts: int, last_error: Exception) -> None:
        self.url = url
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(
            f"falha ao acessar {url} apos {attempts} tentativa(s): {last_error}"
        )


class FetchResult(NamedTuple):
    """Retorno tipado de fetch(). Subclasse de tuple — desempacotamento posicional preservado."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    raw_headers: dict[str, list[str]]


class Cyber:
    """Constantes de cores ANSI para formatação de terminal.

    Cores sao atualizadas por apply_theme(). RESET/BOLD/DIM sao fixos.
    """

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[38;5;203m"
    GREEN = "\033[38;5;46m"
    CYAN = "\033[38;5;51m"
    BLUE = "\033[38;5;39m"
    MAGENTA = "\033[38;5;201m"
    YELLOW = "\033[38;5;226m"
    ORANGE = "\033[38;5;208m"
    WHITE = "\033[38;5;255m"
    GRAY = "\033[38;5;244m"


THEMES: dict[str, dict[str, str]] = {
    "cyber": {
        "RED": "\033[38;5;203m",
        "GREEN": "\033[38;5;46m",
        "CYAN": "\033[38;5;51m",
        "BLUE": "\033[38;5;39m",
        "MAGENTA": "\033[38;5;201m",
        "YELLOW": "\033[38;5;226m",
        "ORANGE": "\033[38;5;208m",
        "WHITE": "\033[38;5;255m",
        "GRAY": "\033[38;5;244m",
    },
    "dracula": {
        "RED": "\033[38;5;203m",
        "GREEN": "\033[38;5;84m",
        "CYAN": "\033[38;5;117m",
        "BLUE": "\033[38;5;99m",
        "MAGENTA": "\033[38;5;212m",
        "YELLOW": "\033[38;5;228m",
        "ORANGE": "\033[38;5;215m",
        "WHITE": "\033[38;5;231m",
        "GRAY": "\033[38;5;248m",
    },
    "solarized": {
        "RED": "\033[38;5;167m",
        "GREEN": "\033[38;5;142m",
        "CYAN": "\033[38;5;108m",
        "BLUE": "\033[38;5;33m",
        "MAGENTA": "\033[38;5;168m",
        "YELLOW": "\033[38;5;178m",
        "ORANGE": "\033[38;5;166m",
        "WHITE": "\033[38;5;252m",
        "GRAY": "\033[38;5;246m",
    },
    "high-contrast": {
        "RED": "\033[38;5;196m",
        "GREEN": "\033[38;5;46m",
        "CYAN": "\033[38;5;51m",
        "BLUE": "\033[38;5;21m",
        "MAGENTA": "\033[38;5;201m",
        "YELLOW": "\033[38;5;226m",
        "ORANGE": "\033[38;5;208m",
        "WHITE": "\033[38;5;255m",
        "GRAY": "\033[38;5;240m",
    },
}

_SEVERITY_COLOR_NAMES: dict[str, str] = {
    "critical": "RED",
    "high": "ORANGE",
    "medium": "YELLOW",
    "low": "BLUE",
    "info": "GRAY",
}


def apply_theme(name: str) -> None:
    """Aplica um tema de cores atualizando os atributos da classe Cyber."""
    theme = THEMES[name]
    for attr, code in theme.items():
        setattr(Cyber, attr, code)


def override_severity(severity: str, color_name: str) -> None:
    """Sobrescreve a cor de um nivel de severidade especifico."""
    _SEVERITY_COLOR_NAMES[severity.lower()] = color_name.upper()


def color(text: str, *styles: str) -> str:
    """Aplica estilos de cor ANSI ao texto."""
    if not _USE_COLOR:
        return text
    return "".join(styles) + text + Cyber.RESET


def clear_console() -> None:
    """Limpa a tela do console."""
    os.system("cls" if os.name == "nt" else "clear")


def _parse_retry_after(value: str | None) -> float:
    """Parse Retry-After header: aceita segundos (int/float) ou HTTP-date."""
    if not value:
        return 5.0
    try:
        return float(value)
    except ValueError:
        pass
    try:
        from datetime import UTC, datetime
        from email.utils import parsedate_to_datetime

        dt = parsedate_to_datetime(value)
        delta = (dt - datetime.now(UTC)).total_seconds()
        return max(delta, 0.0)
    except Exception:
        return 5.0


class RateLimiter:
    """Rate limiter async usando intervalo minimo entre requests com backoff adaptativo.

    Mecanismo:
    - _min_interval: tempo minimo entre requests (1/rps)
    - _backoff_multiplier: multiplica o intervalo quando recebe 429
    - Em 429, dobramos o multiplicador (max 16x) para respeitar rate limit
    - wait() calcula o proximo slot valido e dorme se necessario
    - Jitter opcional para variar delays entre requests
    - Auto-recovery: backoff diminui gradualmente em responses 2xx
    - Not thread-safe (projetado para uso dentro de um event loop asyncio)
    """

    def __init__(self, requests_per_second: float = 0.0, jitter: float = 0.0) -> None:
        self._base_rps = max(requests_per_second, 0.0)
        self._min_interval = 1.0 / self._base_rps if self._base_rps > 0 else 0.0
        self._last_request_time = 0.0
        self._backoff_multiplier: float = 1.0
        self._jitter = max(jitter, 0.0)

    async def wait(self) -> None:
        """Bloqueia ate que o intervalo minimo entre requests tenha passado."""
        effective_interval = self._min_interval * self._backoff_multiplier
        if self._jitter > 0 and effective_interval > 0:
            effective_interval *= 1.0 + random.uniform(-self._jitter, self._jitter)
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

    def notify_429(self, retry_after: float = 0.0) -> None:
        """Notifica que um 429 foi recebido, ajustando backoff.

        Se retry_after > 0, calcula o multiplier exato baseado no valor do server.
        Caso contrario, usa backoff exponencial (dobra o multiplicador).
        """
        if retry_after > 0 and self._min_interval > 0:
            needed = retry_after / self._min_interval
            self._backoff_multiplier = min(max(needed, self._backoff_multiplier), 16.0)
        else:
            self._backoff_multiplier = min(self._backoff_multiplier * 2.0, 16.0)

    def notify_ok(self) -> None:
        """Notifica que um 2xx foi recebido, reduzindo backoff gradualmente."""
        if self._backoff_multiplier > 1.0:
            self._backoff_multiplier = max(self._backoff_multiplier * 0.8, 1.0)

    def reset_backoff(self) -> None:
        """Reseta o multiplicador de backoff para 1.0."""
        self._backoff_multiplier = 1.0

    def get_effective_rps(self) -> float:
        """Retorna RPS efetivo atual (considerando backoff e jitter)."""
        if self._min_interval <= 0:
            return 0.0
        effective = self._min_interval * self._backoff_multiplier
        if effective <= 0:
            return 0.0
        return 1.0 / effective


@dataclass(frozen=True, slots=True)
class StealthContext:
    """Contexto de stealth global, construido uma vez em init_scanner().

    Somente-leitura apos criacao. Consumido por create_async_client() e fetch().
    Default None = comportamento byte-compativel (sem flags stealth).
    """

    random_delay: bool = False
    jitter: float = 0.0
    user_agent_rotate: bool = False
    impersonate: str | None = None
    tor: bool = False
    waf_evasion: bool = False
    pad_headers: int = 0

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> StealthContext | None:
        """Constrói StealthContext a partir de args do CLI.

        Retorna None se nenhuma flag stealth estiver ativa.
        """
        fields = {
            "random_delay": getattr(args, "random_delay", False),
            "jitter": getattr(args, "jitter", 0.0),
            "user_agent_rotate": getattr(args, "user_agent_rotate", False),
            "impersonate": getattr(args, "impersonate", None),
            "tor": getattr(args, "tor", False),
            "waf_evasion": getattr(args, "waf_evasion", False),
            "pad_headers": getattr(args, "pad_headers", 0),
        }
        if not any(v and v != 0.0 and v != 0 for v in fields.values()):
            return None
        return cls(**fields)


#: Estado stealth por thread — cada worker do batch (-p) tem o proprio.
_stealth_local = threading.local()


def get_stealth_ctx() -> StealthContext | None:
    """Retorna o StealthContext da thread atual (para testes)."""
    return getattr(_stealth_local, "ctx", None)


def reset_stealth_ctx() -> None:
    """Zera o contexto stealth da thread atual (para testes/isolamento)."""
    _stealth_local.ctx = None


class _CurlCffiResponse:
    """Wrapper httpx-compativel sobre uma resposta curl-cffi.

    curl-cffi devolve headers como CaseInsensitiveDict (sem `multi_items()`),
    que quebra _extract_raw_headers() e header_get(). Este wrapper normaliza
    `.headers` para httpx.Headers e delega o restante para a resposta original.
    """

    __slots__ = ("_resp",)

    def __init__(self, resp: Any) -> None:
        object.__setattr__(self, "_resp", resp)

    @property
    def headers(self) -> httpx.Headers:
        raw = self._resp.headers
        return httpx.Headers(dict(raw.items()) if raw is not None else {})

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resp, name)


class _CurlCffiClient:
    """Adapter httpx-compativel sobre curl_cffi.AsyncSession.

    O curl-cffi usa `allow_redirects` (nao `follow_redirects`) e `close()`
    (nao `aclose()`). Como o resto do codigo usa a API do httpx, este adapter
    traduz os nomes e normaliza as respostas. Mantem `headers` espelhado na
    sessao subjacente.
    """

    def __init__(self, session: Any) -> None:
        self._session = session

    @property
    def headers(self) -> Any:
        return self._session.headers

    async def request(self, method: str, url: str, **kwargs: Any) -> _CurlCffiResponse:
        allow = kwargs.pop("follow_redirects", False)
        kwargs.setdefault("allow_redirects", allow)
        resp = await self._session.request(method, url, **kwargs)
        return _CurlCffiResponse(resp)

    async def get(self, url: str, **kwargs: Any) -> _CurlCffiResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> _CurlCffiResponse:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> _CurlCffiResponse:
        return await self.request("PUT", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> _CurlCffiResponse:
        return await self.request("OPTIONS", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> _CurlCffiResponse:
        return await self.request("HEAD", url, **kwargs)

    async def aclose(self) -> None:
        await self._session.close()


def create_async_client(
    user_agent: str | None = f"MyTools/{__version__}",
    proxy: str | None = None,
    timeout: float = 5.0,
    verify: bool = False,
    impersonate: BrowserTypeLiteral | None = None,
) -> Any:
    """Cria um cliente HTTP async com headers padrao.

    Suporta TLS fingerprint impersonation via curl-cffi quando disponivel.
    Injeta stealth automaticamente via StealthContext global (init_scanner).
    """
    ctx = get_stealth_ctx()

    effective_impersonate = impersonate
    effective_proxy = proxy
    effective_ua = user_agent or f"MyTools/{__version__}"

    if ctx is not None:
        from mytools.core.stealth import TorManager, random_user_agent

        if ctx.impersonate:
            effective_impersonate = ctx.impersonate
        if ctx.user_agent_rotate:
            effective_ua = random_user_agent()
        if ctx.tor:
            tor = TorManager()
            effective_proxy = tor.proxy_url
            logger.debug("stealth: tor proxy=%s", effective_proxy)

    headers = {"User-Agent": effective_ua}

    if effective_impersonate:
        try:
            from curl_cffi.requests import AsyncSession

            session = AsyncSession(
                impersonate=effective_impersonate,  # type: ignore[reportArgumentType]
                verify=verify,
                timeout=timeout,
                proxy=effective_proxy,
            )
            client = _CurlCffiClient(session)
            client.headers.update(headers)
            return client
        except ImportError:
            logger.debug("curl-cffi nao instalado, usando httpx padrao")
        except Exception as error:
            logger.debug("falha ao criar cliente curl-cffi: %s", error)

    return httpx.AsyncClient(
        headers=headers,
        proxy=effective_proxy,
        timeout=timeout,
        follow_redirects=False,
        verify=verify,
    )


def _extract_raw_headers(response: httpx.Response) -> dict[str, list[str]]:
    """Extrai todos os valores de headers (incluindo duplicados como Set-Cookie)."""
    raw: dict[str, list[str]] = {}
    for name, value in response.headers.multi_items():
        raw.setdefault(name.lower(), []).append(value)
    return raw


_fetch_cache: OrderedDict[
    tuple[Any, ...],
    tuple[float, tuple[int, Mapping[str, str], bytes, dict[str, list[str]]]],
] = OrderedDict()
_FETCH_CACHE_TTL = 60.0
#: Limite de entradas do cache — evita crescimento sem limite em scans longos.
_FETCH_CACHE_MAX = 5000


def set_fetch_cache_ttl(seconds: float) -> None:
    """Define o TTL global do cache de fetch() em segundos."""
    global _FETCH_CACHE_TTL
    _FETCH_CACHE_TTL = seconds


async def fetch(
    client: httpx.AsyncClient,
    url: str,
    timeout: float = 5.0,
    method: str = "GET",
    allow_redirects: bool = False,
    max_retries: int = 3,
    rate_limiter: RateLimiter | None = None,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
    cache_ttl: float | None = None,
) -> tuple[int, Mapping[str, str], bytes, dict[str, list[str]]]:
    """Realiza uma requisicao HTTP async e retorna status, headers, corpo e raw_headers.

    Logica de retry:
    - Retenta em erros de rede (ConnectionError, Timeout, etc.)
    - Em 429, notifica o rate_limiter e espera Retry-After (max 30s)
    - Backoff linear entre tentativas: 0.5s, 1.0s, 1.5s
    - After max_retries, levanta FetchError com contexto completo

    raw_headers e um dict mapeando nomes de headers (lowercase) para listas de
    todos os valores, preservando headers duplicados como Set-Cookie.
    """
    ctx = get_stealth_ctx()
    # A chave inclui id(client) e o contexto stealth: impede que uma resposta
    # obtida via Tor/proxy/impersonate seja servida a um cliente direto e
    # vice-versa (evita vazamento de IP).
    cache_key = (
        method,
        url,
        frozenset((headers or {}).items()),
        content,
        id(client),
        ctx,
    )
    now = time.monotonic()
    cached = _fetch_cache.get(cache_key)
    effective_ttl = cache_ttl if cache_ttl is not None else _FETCH_CACHE_TTL
    if cached is not None and now - cached[0] < effective_ttl:
        _fetch_cache.move_to_end(cache_key)
        logger.debug("cache hit %s %s", method, url)
        return cached[1]
    last_error: httpx.RequestError = httpx.RequestError("unknown error")
    for attempt in range(max_retries):
        effective_url = url
        effective_headers = dict(headers) if headers else None
        effective_content = content

        if ctx is not None:
            from mytools.core.stealth import (
                apply_jitter,
                waf_encode_headers,
                waf_encode_url,
            )

            if ctx.random_delay or ctx.jitter > 0:
                import random as _random

                base_delay = _random.uniform(0, 2) if ctx.random_delay else 0.0
                await asyncio.sleep(apply_jitter(base_delay, ctx.jitter))
            if ctx.waf_evasion:
                effective_url = waf_encode_url(url)
                if effective_headers:
                    effective_headers = waf_encode_headers(effective_headers)
            if ctx.user_agent_rotate:
                from mytools.core.stealth import random_user_agent

                ua = random_user_agent()
                if effective_headers is None:
                    effective_headers = {}
                effective_headers["User-Agent"] = ua

        logger.debug(
            "request %s %s (timeout=%.1f, attempt=%d)",
            method,
            url,
            timeout,
            attempt + 1,
        )
        try:
            response = await client.request(
                method=method,
                url=effective_url,
                timeout=timeout,
                follow_redirects=allow_redirects,
                headers=effective_headers,
                content=effective_content,
            )
            if response.status_code == 429 and rate_limiter is not None:
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                rate_limiter.notify_429(retry_after)
                await asyncio.sleep(min(retry_after, 30))
                continue
            logger.debug(
                "response %d %s (%d bytes)",
                response.status_code,
                url,
                len(response.content),
            )
            result = (
                response.status_code,
                response.headers,
                response.content,
                _extract_raw_headers(response),
            )
            _fetch_cache[cache_key] = (time.monotonic(), result)
            while len(_fetch_cache) > _FETCH_CACHE_MAX:
                _fetch_cache.popitem(last=False)
            return result
        except httpx.RequestError as error:
            logger.debug("error %s: %s", url, error)
            last_error = error
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
    raise FetchError(url=url, attempts=max_retries, last_error=last_error)


async def run_concurrent(
    coros: Iterable[Awaitable[object]],
    concurrency: int = 5,
) -> list[object]:
    """Executa coroutines concorrentemente com limite de paralelismo.

    Deduplica o boilerplate semáforo + wrapper + gather repetido em ~22 módulos
    web. Cada coroutine é executada sob um semaphore compartilhado.

    Args:
        coros: Iterável de coroutines (não chamadas — passar a chamada, não o
               resultado da chamada).
        concurrency: Número máximo de requisições simultâneas.

    Returns:
        Lista com o resultado de cada coroutine na ordem original.
        Exceções são capturadas e aparecem como BaseException na lista
        (comportamento padrão de asyncio.gather com return_exceptions=True).
    """
    sem = asyncio.Semaphore(concurrency)

    async def _limited(coro: Awaitable[object]) -> object:
        async with sem:
            return await coro

    return list(
        await asyncio.gather(*[_limited(c) for c in coros], return_exceptions=True)
    )


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


def severity_color(severity: str) -> str:
    """Retorna a cor ANSI correspondente a severidade CVSS.

    Usa _SEVERITY_COLOR_NAMES para mapear severidade → nome do atributo Cyber.
    Dinâmico: reflete tema atual e overrides individuais.
    """
    color_name = _SEVERITY_COLOR_NAMES.get(severity.lower(), "GRAY")
    return getattr(Cyber, color_name)


def print_exploit_info(exploit: str, tool: str) -> None:
    """Imprime exploit e ferramenta recomendada se disponíveis."""
    if exploit:
        print(color(f"      Exploit: {exploit}", Cyber.YELLOW))
    if tool:
        print(color(f"      Ferramenta: {tool}", Cyber.CYAN))


def header_get(headers: Mapping[str, str], name: str) -> str:
    """Obtém o valor de um header HTTP, ignorando maiúsculas/minúsculas."""
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower:
            return value
    return ""


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
                if end - start + 1 > _MAX_RANGE_ITEMS:
                    raise argparse.ArgumentTypeError(
                        f"{error_label} range grande demais: {part!r}"
                    )
                result.update(range(start, end + 1))
            else:
                result.add(int(part))
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"{error_label} invalido: {part!r}"
            ) from None

    if len(result) > _MAX_RANGE_ITEMS:
        raise argparse.ArgumentTypeError(
            f"{error_label}s em excesso (max {_MAX_RANGE_ITEMS})"
        )

    invalid = [v for v in result if v < min_val or v > max_val]
    if invalid:
        raise argparse.ArgumentTypeError(
            f"{error_label}s invalidos: {', '.join(map(str, sorted(invalid)))}"
        )
    if not result:
        raise argparse.ArgumentTypeError(f"informe pelo menos um {error_label}")
    return sorted(result)


#: Limite de itens expandidos por parse_int_range (evita estouro de memoria).
_MAX_RANGE_ITEMS = 65536


def extract_title(text: str) -> str:
    """Extrai o conteúdo da tag <title> de um HTML."""
    lower = text.lower()
    start = lower.find("<title>")
    end = lower.find("</title>", start + 7)
    if start == -1 or end == -1:
        return ""
    return " ".join(text[start + 7 : end].strip().split())[:100]


def show_banner(art: str, subtitle: str) -> None:
    """Exibe banner ASCII art colorido com subtitle."""
    print(color(art.rstrip(), Cyber.CYAN, Cyber.BOLD))
    print(color(subtitle, Cyber.MAGENTA))


def create_banner(
    art: str, subtitle: str, extra: Callable[[], None] | None = None
) -> Callable[[], None]:
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
    _ensure_utf8_stdout()
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
    print(
        color(
            "  ".join(header.ljust(widths[i]) for i, header in enumerate(headers)),
            Cyber.CYAN,
            Cyber.BOLD,
        )
    )
    print(color("  ".join("-" * width for width in widths), Cyber.BLUE))
    for row in rows:
        cells = []
        styles = row_styles_fn(row) if row_styles_fn else column_styles
        if styles is None:
            styles = [(Cyber.WHITE, Cyber.RESET)] * len(headers)
        for i, value in enumerate(row):
            aligned = (
                value.ljust(widths[i])
                if alignments[i] == "left"
                else value.rjust(widths[i])
            )
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
    extension = Path(path).suffix.lower()
    if extension not in (".json", ".csv"):
        raise ValueError(f"extensao nao suportada: {extension!r} (use .json ou .csv)")
    with Path(path).open("w", encoding="utf-8", newline="") as file_handle:
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
        print(
            color("[*]", Cyber.CYAN, Cyber.BOLD),
            f"Resultado salvo em {color(path, Cyber.GREEN)}",
        )


def print_json(data: Any) -> None:
    """Imprime dados como JSON formatado no stdout (para piping com jq/grep)."""
    _ensure_utf8_stdout()
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False, default=str)
    sys.stdout.write("\n")


def resolve_cred(value: str) -> str:
    """Resolve valor de credencial do keyring.

    Se o valor comeca com '@', busca a credencial homonima no keyring do SO.
    Caso contrario, retorna o valor como esta (compatibilidade total).

    Raises:
        ValueError: se comeca com '@' mas keyring nao esta disponivel.
        ValueError: se a credencial nao foi encontrada no keyring.
    """
    if not value.startswith("@"):
        if _SECRET_PATTERNS.search(value):
            logger.warning(
                "Segredo em texto puro detectado. Use keyring: mytools-cred set <nome> e depois @<nome>"
            )
        return value
    name = value[1:]
    if not name:
        raise ValueError("nome de credencial vazio (use @nome)")
    from mytools.core.cred import get_credential

    result = get_credential(name)
    if result is None:
        raise ValueError(
            f"credencial '{name}' nao encontrada. Use: mytools-cred set {name}"
        )
    return result


def parse_auth(value: str) -> dict[str, str]:
    """Converte string 'user:pass' em headers de autenticacao Basic.

    Suporta prefixo '@' para resolver credenciais do keyring.
    """
    value = resolve_cred(value)
    if ":" not in value:
        raise argparse.ArgumentTypeError(f"formato invalido: {value!r} (use user:pass)")
    user, password = value.split(":", 1)
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


async def resolve_cred_async(value: str) -> str:
    """Resolve valor de credencial do keyring de forma async (nao bloqueia o event loop)."""
    if not value.startswith("@"):
        return value
    return await asyncio.to_thread(resolve_cred, value)


def parse_extra_headers(raw_headers: list[str]) -> dict[str, str]:
    """Converte lista de strings 'Name: Value' em dict de headers."""
    headers: dict[str, str] = {}
    for raw in raw_headers:
        if ":" not in raw:
            raise ValueError(f"header invalido: {raw!r} (use 'Name: Value')")
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def normalize_url(
    url: str, default_scheme: str = "https", ensure_trailing_slash: bool = False
) -> str:
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


def add_base_args(
    parser: argparse.ArgumentParser, timeout_default: float = 5.0
) -> None:
    """Adiciona argumentos base compartilhados (timeout, output, verbose, etc)."""
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=timeout_default,
        help="Timeout em segundos. Padrao: 5",
    )
    parser.add_argument("-o", "--output", help="Salva resultado em .json ou .csv.")
    if "--output-dir" not in parser._option_string_actions:
        parser.add_argument(
            "--output-dir",
            dest="output_dir",
            default=None,
            help="Workspace de scan: salva outputs/<host>/<timestamp>.json. "
            "Coexiste com -o (Group B salva os dois; Group A: -o vence).",
        )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Mostra mensagens de debug no terminal.",
    )
    parser.add_argument("--log-file", help="Salva logs em arquivo.")
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Modo silencioso: sem banner/progresso. Requer -o.",
    )
    parser.add_argument(
        "--color",
        action="store_true",
        default=None,
        dest="color",
        help="Forca cores no terminal.",
    )
    parser.add_argument(
        "--no-color",
        action="store_false",
        dest="color",
        help="Desabilita cores no terminal.",
    )
    parser.add_argument(
        "--theme",
        choices=sorted(THEMES),
        default="cyber",
        help="Tema de cores. Padrao: cyber",
    )
    parser.add_argument(
        "--severity-override",
        help="Sobrescreve cores de severidade. Ex: critical=RED,high=ORANGE",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Numero de tentativas em caso de falha HTTP. Padrao: 3",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Mostra o que faria sem executar nada."
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        default=False,
        help="Verifica certificados SSL/TLS. Padrao: desabilitado.",
    )
    parser.add_argument(
        "--no-verify",
        action="store_false",
        dest="verify",
        help="Desabilita verificacao de certificados SSL/TLS (padrao).",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--dump-payloads",
        action="store_true",
        dest="dump_payloads",
        help="Exporta todos os payloads YAML carregados em JSON e sai.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Saida JSON para stdout (para piping com jq/grep). Recomenda-se usar com -q.",
    )


def add_http_args(parser: argparse.ArgumentParser) -> None:
    """Adiciona argumentos HTTP especificos (user-agent, proxy, auth, etc)."""
    parser.add_argument("-A", "--user-agent", help="User-Agent usado nas requests.")
    parser.add_argument("--proxy", help="Proxy para as requests. Ex: http://proxy:8080")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay em segundos entre requests. 0 = sem limite.",
    )
    parser.add_argument(
        "--auth",
        type=parse_auth,
        help="Autenticacao Basic (user:pass). Envia header Authorization.",
    )
    parser.add_argument(
        "--bearer-token", dest="bearer_token", help="Token Bearer para autenticacao."
    )
    parser.add_argument(
        "--cookie", help="Cookie para as requests. Ex: 'session=abc123; token=xyz'"
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Header customizado (pode usar mais de um). Ex: 'X-Token: abc'",
    )


# Compatibilidade de flags stealth por tipo de modulo
_STEALTH_COMPAT: dict[str, set[str]] = {
    "web": {
        "proxy",
        "delay",
        "random-delay",
        "jitter",
        "user-agent-rotate",
        "impersonate",
        "fragment",
        "tor",
        "waf-evasion",
        "pad-headers",
        "rate-limit",
    },
    "dns": {"proxy", "delay", "random-delay", "jitter", "tor", "rate-limit"},
    "email": {
        "proxy",
        "delay",
        "random-delay",
        "jitter",
        "fragment",
        "tor",
        "waf-evasion",
        "pad-headers",
        "rate-limit",
    },
    "osint": {
        "proxy",
        "delay",
        "random-delay",
        "jitter",
        "user-agent-rotate",
        "tor",
        "rate-limit",
    },
    "network": {
        "proxy",
        "delay",
        "random-delay",
        "jitter",
        "fragment-tcp",
        "tor",
        "src-port-random",
        "rate-limit",
    },
    "vcs": {"proxy", "delay", "random-delay", "jitter", "tor", "rate-limit"},
    "config": {"proxy", "delay", "random-delay", "jitter", "tor", "rate-limit"},
    "core": {"proxy", "delay", "random-delay", "jitter", "tor", "rate-limit"},
}


def add_stealth_args(
    parser: argparse.ArgumentParser, module_type: str = "core"
) -> None:
    """Adiciona argumentos stealth anti-detection ao parser.

    Apenas flags compativel com o tipo de modulo sao adicionadas.
    Flags incompatíveis NAO aparecem no -h.
    """
    compat = _STEALTH_COMPAT.get(module_type, _STEALTH_COMPAT["core"])

    if "random-delay" in compat:
        parser.add_argument(
            "--random-delay",
            action="store_true",
            help="Delay aleatorio entre requests (0-2s).",
        )
    if "jitter" in compat:
        parser.add_argument(
            "--jitter",
            type=float,
            default=0.0,
            help="Variacao aleatoria no delay (0.0-1.0). Ex: 0.2 = ±20%%.",
        )
    if "user-agent-rotate" in compat:
        parser.add_argument(
            "--user-agent-rotate",
            action="store_true",
            help="Rotaciona User-Agent a cada request.",
        )
    if "impersonate" in compat:
        parser.add_argument(
            "--impersonate",
            choices=["chrome", "firefox", "safari", "edge", "mobile"],
            help="TLS fingerprint de browser real (requer curl-cffi).",
        )
    if "fragment" in compat:
        parser.add_argument(
            "--fragment",
            type=int,
            default=0,
            help="Fragmenta headers HTTP em chunks (evasao L7, raw socket; nao integrado). Valor: tamanho do chunk.",
        )
    if "fragment-tcp" in compat:
        parser.add_argument(
            "--fragment-tcp",
            type=int,
            default=0,
            help="Fragmenta payload TCP em chunks (evasao L4, raw socket; nao integrado). Valor: tamanho do chunk.",
        )
    if "tor" in compat:
        parser.add_argument(
            "--tor", action="store_true", help="Redireciona requests via Tor (SOCKS5)."
        )
    if "waf-evasion" in compat:
        parser.add_argument(
            "--waf-evasion",
            action="store_true",
            help="Aplica encoding anti-WAF em URLs e headers.",
        )
    if "pad-headers" in compat:
        parser.add_argument(
            "--pad-headers",
            type=int,
            default=0,
            help="Adiciona headers padding (minimo total; nao integrado). Valor: count minimo.",
        )
    if "src-port-random" in compat:
        parser.add_argument(
            "--src-port-random",
            action="store_true",
            help="Randomiza porta de origem TCP (raw socket; nao integrado).",
        )
    if "rate-limit" in compat:
        parser.add_argument(
            "--rate-limit",
            type=float,
            default=0.0,
            help="Rate limit global (requests/segundo). 0 = sem limite.",
        )


def validate_stealth_args(
    args: argparse.Namespace, module_type: str | None = None
) -> None:
    """Valida flags stealth, abortando se incompativel com o tipo de modulo.

    Raises:
        SystemExit: se flag incompativel for usada (erro de usage, code 2).
    """
    resolved: str = (
        module_type
        if module_type is not None
        else getattr(args, "_module_type", "core")
    )
    compat = _STEALTH_COMPAT.get(resolved, _STEALTH_COMPAT["core"])

    stealth_flags = [
        "random_delay",
        "jitter",
        "user_agent_rotate",
        "impersonate",
        "fragment",
        "fragment_tcp",
        "tor",
        "waf_evasion",
        "pad_headers",
        "src_port_random",
        "rate_limit",
    ]
    flag_to_compat = {
        "random_delay": "random-delay",
        "jitter": "jitter",
        "user_agent_rotate": "user-agent-rotate",
        "impersonate": "impersonate",
        "fragment": "fragment",
        "fragment_tcp": "fragment-tcp",
        "tor": "tor",
        "waf_evasion": "waf-evasion",
        "pad_headers": "pad-headers",
        "src_port_random": "src-port-random",
        "rate_limit": "rate-limit",
    }

    for flag in stealth_flags:
        value = getattr(args, flag, None)
        if value is None or value is False or value == 0 or value == 0.0:
            continue
        compat_name = flag_to_compat.get(flag, flag)
        if compat_name not in compat:
            print(
                color(
                    f"Erro: --{compat_name.replace('_', '-')} nao e compativel com modulo {resolved}",
                    Cyber.RED,
                ),
                file=sys.stderr,
            )
            raise SystemExit(2)


def add_common_args(parser: argparse.ArgumentParser, module_type: str = "core") -> None:
    """Adiciona argumentos compartilhados (base + HTTP + stealth) a um parser."""
    add_base_args(parser)
    add_http_args(parser)
    add_stealth_args(parser, module_type)
    parser.set_defaults(_module_type=module_type)


def apply_session_auth(
    client: httpx.AsyncClient,
    auth: dict[str, str] | None = None,
    bearer_token: str | None = None,
    cookie: str | None = None,
    extra_headers: list[str] | None = None,
) -> None:
    """Aplica headers de autenticacao e personalizados a um cliente async.

    Suporta prefixo '@' em bearer_token e cookie para resolver do keyring.
    """
    if auth:
        client.headers.update(auth)
    if bearer_token:
        client.headers["Authorization"] = f"Bearer {resolve_cred(bearer_token)}"
    if extra_headers:
        resolved = [resolve_cred(h) for h in extra_headers]
        client.headers.update(parse_extra_headers(resolved))
    if cookie:
        client.headers["Cookie"] = resolve_cred(cookie)


async def apply_session_auth_async(
    client: httpx.AsyncClient,
    auth: dict[str, str] | None = None,
    bearer_token: str | None = None,
    cookie: str | None = None,
    extra_headers: list[str] | None = None,
) -> None:
    """Aplica headers de autenticacao de forma async (nao bloqueia o event loop).

    Suporta prefixo '@' em bearer_token e cookie para resolver do keyring.
    """
    if auth:
        client.headers.update(auth)
    if bearer_token:
        client.headers["Authorization"] = (
            f"Bearer {await resolve_cred_async(bearer_token)}"
        )
    if extra_headers:
        resolved = [await resolve_cred_async(h) for h in extra_headers]
        client.headers.update(parse_extra_headers(resolved))
    if cookie:
        client.headers["Cookie"] = await resolve_cred_async(cookie)


def extract_hostname(url: str) -> str:
    """Extrai hostname de uma URL para uso em nomes de arquivo."""
    parsed = urlparse(url)
    host = parsed.hostname or url
    return host.replace("/", "_").replace(":", "_")


def read_target_lines(
    filepath: str, *, lowercase: bool = False, sort_dedup: bool = False
) -> list[str]:
    """Le linhas de um arquivo, removendo blanks e comentarios #.

    Args:
        filepath: Caminho do arquivo.
        lowercase: Se True, converte linhas para minusculo.
        sort_dedup: Se True, ordena e remove duplicatas.
    """
    try:
        with Path(filepath).open(encoding="utf-8", errors="replace") as fh:
            lines = [
                line.strip() for line in fh if line.strip() and not line.startswith("#")
            ]
    except FileNotFoundError:
        raise ValueError(f"arquivo nao encontrado: {filepath}") from None
    if lowercase:
        lines = [line.lower() for line in lines]
    if sort_dedup:
        lines = sorted(set(lines))
    return lines


def detect_spa_fallback(
    items: list,
    key_fn: Callable[[Any], tuple],
    min_count: int = 10,
    threshold: float = 0.8,
) -> set[int]:
    """Detecta SPA retornando o mesmo shell para todos os paths.

    Retorna set de indices a ignorar (dominant group) se >threshold dos items
    tem mesma chave. Lista vazia se len(items) <= min_count.
    """
    if len(items) <= min_count:
        return set()
    groups: dict[tuple, list] = {}
    for idx, item in enumerate(items):
        groups.setdefault(key_fn(item), []).append((idx, item))
    _, dominant_group = max(groups.items(), key=lambda kv: len(kv[1]))
    if len(dominant_group) > len(items) * threshold:
        return {idx for idx, _ in dominant_group}
    return set()


def resolve_target_urls(args: argparse.Namespace) -> list[str]:
    """Le -l/--list e args.url, retorna lista deduplicada de URLs."""
    urls: list[str] = []
    target_list = getattr(args, "target_list", None)
    if target_list:
        urls.extend(read_target_lines(target_list))
    url = getattr(args, "url", None)
    if url:
        urls.append(url)
    if not urls:
        raise ValueError("informe uma URL alvo ou use -l/--list")
    return list(dict.fromkeys(urls))


def workspace_timestamp() -> str:
    """Timestamp ISO local legivel e Windows-safe para nomes de arquivo."""
    return datetime.now().strftime("%Y-%m-%dT%H-%M-%S")


def workspace_path(output_dir: str, hostname: str) -> Path:
    """Monta caminho output_dir/<host>[_port]/<timestamp>.json."""
    parsed = urlparse(hostname)
    host = parsed.hostname or hostname
    if parsed.port:
        host = f"{host}_{parsed.port}"
    host = host.replace("/", "_").replace(":", "_")
    return Path(output_dir) / host / f"{workspace_timestamp()}.json"


def ensure_output_dir(output_dir: str | None) -> None:
    """Cria o diretorio de saida se nao existir."""
    if output_dir and not Path(output_dir).is_dir():
        Path(output_dir).mkdir(parents=True, exist_ok=True)


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_NVD_CACHE_TTL = 300
_nvd_cache: dict[str, tuple[float, list[dict]]] = {}


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
    cache_key = f"{keyword}|{limit}"
    now = time.monotonic()
    if cache_key in _nvd_cache:
        cached_time, cached_results = _nvd_cache[cache_key]
        if now - cached_time < _NVD_CACHE_TTL:
            return cached_results
        del _nvd_cache[cache_key]

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {"keywordSearch": keyword, "resultsPerPage": limit}

    try:
        if client is not None:
            response = await client.get(
                NVD_API_URL, params=params, headers=headers, timeout=15
            )
        else:
            async with httpx.AsyncClient() as tmp:
                response = await tmp.get(
                    NVD_API_URL, params=params, headers=headers, timeout=15
                )
        if response.status_code == 403:
            logger.debug("NVD rate limited for keyword: %s", keyword)
            return []
        if response.status_code != 200:
            logger.debug(
                "NVD returned %d for keyword: %s", response.status_code, keyword
            )
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

        results.append(
            {
                "id": cve_id,
                "description": description,
                "score": score,
                "severity": severity,
            }
        )

    _nvd_cache[cache_key] = (time.monotonic(), results)
    return results


def safe_asyncio_run(coro: Any) -> Any:
    """Executa uma coroutine async de forma segura, mesmo com event loop ativo.

    Se ja existe um event loop rodando (ex: Jupyter, REPL interativo),
    executa a coroutine em uma thread separada com seu proprio loop.
    Caso contrario, usa asyncio.run() normalmente.
    """
    try:
        running_loop = asyncio.get_running_loop()
    except RuntimeError:
        running_loop = None

    if running_loop is None:
        return asyncio.run(coro)

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(asyncio.run, coro)
        try:
            return future.result(timeout=300)
        except concurrent.futures.TimeoutError:
            raise RuntimeError(
                "Timeout ao executar coroutine em thread separada (300s). Se estiver usando Jupyter, considere nest_asyncio."
            ) from None


_BUILTIN_COMMANDS = ("clear", "exit", "help", "quit")


def _setup_readline(
    parser: argparse.ArgumentParser,
    skip_values: list[str] | None = None,
) -> None:
    """Configura tab completion no shell interativo.

    Tenta usar readline (stdlib) ou pyreadline3 (Windows).
    Se nenhum disponivel, retorna silenciosamente.
    """
    _readline: Any = None
    try:
        import readline

        _readline = readline
    except ModuleNotFoundError:
        try:
            import pyreadline3

            _readline = pyreadline3
        except ModuleNotFoundError:
            return

    flag_names: list[str] = []
    for action in parser._actions:
        if action.option_strings:
            flag_names.extend(action.option_strings)

    all_values = list(_BUILTIN_COMMANDS) + flag_names
    if skip_values:
        all_values += [f"--skip={v}" for v in skip_values]

    def completer(text: str, state: int) -> str | None:
        if state == 0:
            completer.matches = [v for v in all_values if v.startswith(text)]  # type: ignore[attr-defined]
        matches = getattr(completer, "matches", [])
        return matches[state] if state < len(matches) else None

    _readline.set_completer(completer)
    _readline.set_completer_delims(" \t")
    with contextlib.suppress(Exception):
        _readline.parse_and_bind("tab: complete")


def run_interactive_shell(
    parser: argparse.ArgumentParser,
    prompt: str,
    run_fn: Callable[[argparse.Namespace], int],
    description: str = "",
    example: str = "",
    validate_fn: Callable[[argparse.Namespace], None] | None = None,
    banner_fn: Callable[[], None] | None = None,
    contextual_help: str | None = None,
) -> int:
    """Inicia shell interativo generico com loop de comandos."""
    _setup_readline(parser)
    if banner_fn:
        banner_fn()
    print(
        color(description, Cyber.WHITE, Cyber.BOLD), "Digite 'help', 'clear' ou 'exit'."
    )
    if example:
        print(color("Ex:", Cyber.CYAN), example)

    while True:
        try:
            raw = input(color(prompt, Cyber.GREEN, Cyber.BOLD)).strip()
        except EOFError, KeyboardInterrupt:
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
            if contextual_help:
                print(color(contextual_help, Cyber.WHITE, Cyber.BOLD))
            else:
                parser.print_help()
            continue

        try:
            args = parser.parse_args(shlex.split(raw))
            if validate_fn:
                validate_fn(args)
            validate_stealth_args(args)
            run_fn(args)
        except FetchError as error:
            print(color(f"Erro: {error}", Cyber.RED))
        except ValueError as error:
            print(color(f"Erro: {error}", Cyber.RED))
        except SystemExit:
            continue
        except Exception as error:
            logger.debug("excecao inesperada no shell interativo", exc_info=True)
            print(color(f"Erro: {error}", Cyber.RED))
