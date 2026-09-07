#!/usr/bin/env python3
"""Modulo de teste de seguranca em endpoints de autenticacao.

Testa a seguranca de endpoints de login:

  rate_limit:
    - Envia N requests rapidas ao endpoint de login
    - Verifica se o servidor retorna 429, 403 ou mensagem de throttle
    - Detecta ausencia de rate limiting

  lockout:
    - Envia senhas incorretas repetidamente
    - Verifica se a conta e bloqueada apos N tentativas
    - Detecta ausencia de account lockout

  credential:
    - Testa pares comuns de username/password
    - Wordlist limitada para testes seguros
    - Detecta credenciais fracas/expostas (heuristica, propensa a falso positivo)

  spray:
    - Testa poucas senhas comuns contra multiplos usernames
    - Detecta contas com senhas padrao

NOTA: O modulo de deteccao de login success e HEURISTICO e propenso a
falsos positivos. Indicadores como 'dashboard', 'logout', 'profile' podem
aparecer em paginas de erro. Recomenda-se validacao manual.
"""

import argparse
import asyncio
import logging
import sys
import time
from collections.abc import Awaitable
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    init_scanner,
    print_json,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.loginbruteforce")

# ---------------------------------------------------------------------------
# Payload loading
# ---------------------------------------------------------------------------

_USERNAMES_DEFAULT: list[str] = [
    "admin",
    "administrator",
    "root",
    "user",
    "test",
    "guest",
    "info",
    "support",
    "webmaster",
    "administrator@example",
]

_PASSWORDS_DEFAULT: list[str] = [
    "password",
    "123456",
    "admin",
    "root",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "qwerty",
]

_LOCKOUT_INDICATORS_DEFAULT: list[str] = [
    "account locked",
    "too many attempts",
    "try again later",
    "temporarily locked",
    "maximum login attempts",
    "brute force",
    "rate limit",
    "slow down",
    "too many failed",
    "security lockout",
    "locked out",
    "account has been locked",
    "login attempts exceeded",
    "security block",
]

_RATE_LIMIT_INDICATORS_DEFAULT: list[str] = [
    "rate limit",
    "too many requests",
    "slow down",
    "throttle",
    "try again",
    "429",
    "retry-after",
    "please wait",
    "request throttled",
    "temporarily unavailable",
]

_SUCCESS_INDICATORS_DEFAULT: list[str] = [
    "dashboard",
    "welcome back",
    "my account",
    "logout",
    "sign out",
    "profile",
    "settings",
    "account overview",
]


def _load_payloads() -> dict[str, object]:
    from mytools.data import load_payloads

    return load_payloads(
        "web",
        "login_bruteforce",
        default={
            "usernames": _USERNAMES_DEFAULT,
            "passwords": _PASSWORDS_DEFAULT,
            "lockout_indicators": _LOCKOUT_INDICATORS_DEFAULT,
            "rate_limit_indicators": _RATE_LIMIT_INDICATORS_DEFAULT,
            "success_indicators": _SUCCESS_INDICATORS_DEFAULT,
        },
    )


def _get_usernames() -> list[str]:
    data = _load_payloads()
    raw = data.get("usernames", _USERNAMES_DEFAULT)
    return list(raw) if isinstance(raw, list) else _USERNAMES_DEFAULT


def _get_passwords() -> list[str]:
    data = _load_payloads()
    raw = data.get("passwords", _PASSWORDS_DEFAULT)
    return list(raw) if isinstance(raw, list) else _PASSWORDS_DEFAULT


def _get_lockout_indicators() -> list[str]:
    data = _load_payloads()
    raw = data.get("lockout_indicators", _LOCKOUT_INDICATORS_DEFAULT)
    return list(raw) if isinstance(raw, list) else _LOCKOUT_INDICATORS_DEFAULT


def _get_rate_limit_indicators() -> list[str]:
    data = _load_payloads()
    raw = data.get("rate_limit_indicators", _RATE_LIMIT_INDICATORS_DEFAULT)
    return list(raw) if isinstance(raw, list) else _RATE_LIMIT_INDICATORS_DEFAULT


def _get_success_indicators() -> list[str]:
    data = _load_payloads()
    raw = data.get("success_indicators", _SUCCESS_INDICATORS_DEFAULT)
    return list(raw) if isinstance(raw, list) else _SUCCESS_INDICATORS_DEFAULT


# ---------------------------------------------------------------------------
# Form detection
# ---------------------------------------------------------------------------


class _LoginFormParser(HTMLParser):
    """Detecta forms de login em HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self._current_form: dict[str, object] | None = None
        self._fields: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict: dict[str, str] = {k: v for k, v in attrs if v is not None}
        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": (attr_dict.get("method") or "GET").upper(),
                "enctype": attr_dict.get("enctype", ""),
            }
            self._fields = []
        elif tag == "input" and self._current_form is not None:
            input_type = (attr_dict.get("type") or "text").lower()
            name = attr_dict.get("name", "")
            if name and input_type not in ("submit", "button", "hidden"):
                self._fields.append(
                    {
                        "type": input_type,
                        "name": name,
                        "value": attr_dict.get("value", ""),
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self._current_form["fields"] = list(self._fields)
            self.forms.append(self._current_form)
            self._current_form = None
            self._fields = []


def _detect_form(html: str, base_url: str) -> tuple[str, str, dict[str, str]] | None:
    """Detecta formulario de login no HTML.

    Retorna (action_url, method, {field_type: field_name}) ou None.
    field_type e 'username', 'password' ou 'other'.
    """
    parser = _LoginFormParser()
    try:
        parser.feed(html)
    except Exception:
        return None

    for form in parser.forms:
        fields = form.get("fields", [])
        if not isinstance(fields, list):
            continue

        username_field: str | None = None
        password_field: str | None = None

        for field in fields:
            if not isinstance(field, dict):
                continue
            ftype = field.get("type", "")
            fname = field.get("name", "")
            if ftype == "password" and fname:
                password_field = fname
            elif ftype in ("text", "email") and fname and not username_field:
                username_field = fname

        if password_field:
            action = form.get("action", "")
            method = form.get("method", "GET")
            if isinstance(action, str) and isinstance(method, str):
                action_url = urljoin(base_url, action) if action else base_url
                field_map: dict[str, str] = {"password": password_field}
                if username_field:
                    field_map["username"] = username_field
                return action_url, method, field_map

    return None


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _check_lockout(body: str, indicators: list[str]) -> tuple[bool, str]:
    """Verifica se lockout foi detectado no response body."""
    body_lower = body.lower()
    for indicator in indicators:
        if indicator.lower() in body_lower:
            return True, indicator
    return False, ""


def _check_rate_limit(
    status: int,
    body: str,
    indicators: list[str],
) -> tuple[bool, str]:
    """Verifica se rate limit foi detectado."""
    if status == 429:
        return True, "HTTP 429 Too Many Requests"

    body_lower = body.lower()
    for indicator in indicators:
        if indicator.lower() in body_lower:
            return True, indicator

    if status == 403 and any(
        ind.lower() in body_lower for ind in ("rate limit", "throttle", "slow down")
    ):
        return True, "HTTP 403 com indicador de rate limit"

    return False, ""


def _check_login_success(
    status: int,
    body: str,
    indicators: list[str],
    location: str,
) -> tuple[bool, str]:
    """Verifica se login foi bem-sucedido (heuristico).

    NOTA: Esta deteccao e propensa a falsos positivos.
    Indicadores como 'dashboard', 'logout', 'profile' podem aparecer
    em paginas de erro. Recomenda-se validacao manual.
    """
    if status in (301, 302, 303, 307, 308) and location:
        loc_lower = location.lower()
        if any(
            ind in loc_lower
            for ind in ("dashboard", "account", "home", "welcome", "admin")
        ):
            return True, f"Redirect para {location}"

    if status == 200:
        body_lower = body.lower()
        for indicator in indicators:
            if indicator.lower() in body_lower:
                return True, f"Indicador '{indicator}' encontrado no body"

    return False, ""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BruteForceAttempt:
    """Tentativa individual de brute force."""

    technique: str
    category: str
    url: str
    username: str
    payload: str
    status_code: int
    response_size: int
    response_time: float
    lockout_detected: bool
    rate_limit_detected: bool
    login_success: bool
    vulnerable: bool
    details: str
    error: str = ""


@dataclass(frozen=True, slots=True)
class BruteForceResult:
    """Resultado consolidado do scan de brute force."""

    target: str
    login_url: str
    attempts: list[BruteForceAttempt]
    rate_limit_found: bool
    lockout_found: bool
    weak_credentials: list[str]
    issues: list[str]
    overall_status: str


# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------


async def _test_rate_limit(
    client: httpx.AsyncClient,
    login_url: str,
    username: str,
    password: str,
    field_map: dict[str, str],
    count: int = 15,
    delay: float = 0.1,
) -> list[BruteForceAttempt]:
    """Testa se o servidor aplica rate limiting."""
    attempts: list[BruteForceAttempt] = []
    indicators = _get_rate_limit_indicators()
    user_field = field_map.get("username", "username")
    pass_field = field_map.get("password", "password")

    rate_limited = False
    for i in range(count):
        payload = f"{password}_{i}"
        data = {user_field: username, pass_field: payload}
        start = time.monotonic()
        try:
            resp = await client.post(login_url, data=data, follow_redirects=False)
            elapsed = time.monotonic() - start
            body = resp.text[:5000]

            detected, detail = _check_rate_limit(resp.status_code, body, indicators)
            if detected:
                rate_limited = True

            attempts.append(
                BruteForceAttempt(
                    technique="rate_limit",
                    category="rate_limit",
                    url=login_url,
                    username=username,
                    payload=payload,
                    status_code=resp.status_code,
                    response_size=len(resp.content),
                    response_time=round(elapsed, 3),
                    lockout_detected=False,
                    rate_limit_detected=detected,
                    login_success=False,
                    vulnerable=not detected,
                    details=detail
                    if detected
                    else f"Request {i + 1}/{count} sem rate limit",
                )
            )

            if rate_limited:
                break

        except httpx.RequestError as exc:
            elapsed = time.monotonic() - start
            attempts.append(
                BruteForceAttempt(
                    technique="rate_limit",
                    category="rate_limit",
                    url=login_url,
                    username=username,
                    payload=payload,
                    status_code=0,
                    response_size=0,
                    response_time=round(elapsed, 3),
                    lockout_detected=False,
                    rate_limit_detected=False,
                    login_success=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

        if delay > 0:
            await asyncio.sleep(delay)

    if not rate_limited and not any(a.error for a in attempts):
        attempts = [
            BruteForceAttempt(
                technique=a.technique,
                category=a.category,
                url=a.url,
                username=a.username,
                payload=a.payload,
                status_code=a.status_code,
                response_size=a.response_size,
                response_time=a.response_time,
                lockout_detected=a.lockout_detected,
                rate_limit_detected=a.rate_limit_detected,
                login_success=a.login_success,
                vulnerable=True,
                details=a.details,
                error=a.error,
            )
            if not a.rate_limit_detected
            else a
            for a in attempts
        ]

    return attempts


async def _test_lockout(
    client: httpx.AsyncClient,
    login_url: str,
    username: str,
    wrong_password: str,
    field_map: dict[str, str],
    count: int = 8,
    delay: float = 0.3,
) -> list[BruteForceAttempt]:
    """Testa se o servidor bloqueia apos tentativas incorretas."""
    attempts: list[BruteForceAttempt] = []
    indicators = _get_lockout_indicators()
    user_field = field_map.get("username", "username")
    pass_field = field_map.get("password", "password")

    lockout_found = False
    for i in range(count):
        data = {user_field: username, pass_field: f"{wrong_password}_{i}"}
        start = time.monotonic()
        try:
            resp = await client.post(login_url, data=data, follow_redirects=False)
            elapsed = time.monotonic() - start
            body = resp.text[:5000]

            detected, detail = _check_lockout(body, indicators)
            if detected:
                lockout_found = True

            attempts.append(
                BruteForceAttempt(
                    technique="lockout",
                    category="lockout",
                    url=login_url,
                    username=username,
                    payload=f"{wrong_password}_{i}",
                    status_code=resp.status_code,
                    response_size=len(resp.content),
                    response_time=round(elapsed, 3),
                    lockout_detected=detected,
                    rate_limit_detected=False,
                    login_success=False,
                    vulnerable=not detected,
                    details=detail
                    if detected
                    else f"Request {i + 1}/{count} sem lockout",
                )
            )

            if lockout_found:
                break

        except httpx.RequestError as exc:
            elapsed = time.monotonic() - start
            attempts.append(
                BruteForceAttempt(
                    technique="lockout",
                    category="lockout",
                    url=login_url,
                    username=username,
                    payload=f"{wrong_password}_{i}",
                    status_code=0,
                    response_size=0,
                    response_time=round(elapsed, 3),
                    lockout_detected=False,
                    rate_limit_detected=False,
                    login_success=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

        if delay > 0:
            await asyncio.sleep(delay)

    if not lockout_found and not any(a.error for a in attempts):
        attempts = [
            BruteForceAttempt(
                technique=a.technique,
                category=a.category,
                url=a.url,
                username=a.username,
                payload=a.payload,
                status_code=a.status_code,
                response_size=a.response_size,
                response_time=a.response_time,
                lockout_detected=a.lockout_detected,
                rate_limit_detected=a.rate_limit_detected,
                login_success=a.login_success,
                vulnerable=True,
                details=a.details,
                error=a.error,
            )
            if not a.lockout_detected
            else a
            for a in attempts
        ]

    return attempts


async def _test_credentials(
    client: httpx.AsyncClient,
    login_url: str,
    usernames: list[str],
    passwords: list[str],
    field_map: dict[str, str],
    delay: float = 0.2,
) -> list[BruteForceAttempt]:
    """Testa credenciais comuns (credential stuffing)."""
    attempts: list[BruteForceAttempt] = []
    success_indicators = _get_success_indicators()
    user_field = field_map.get("username", "username")
    pass_field = field_map.get("password", "password")

    for username in usernames:
        for password in passwords:
            data = {user_field: username, pass_field: password}
            start = time.monotonic()
            try:
                resp = await client.post(login_url, data=data, follow_redirects=False)
                elapsed = time.monotonic() - start
                body = resp.text[:5000]
                location = resp.headers.get("location", "")

                login_ok, detail = _check_login_success(
                    resp.status_code,
                    body,
                    success_indicators,
                    location,
                )

                attempts.append(
                    BruteForceAttempt(
                        technique="credential",
                        category="credential",
                        url=login_url,
                        username=username,
                        payload=password,
                        status_code=resp.status_code,
                        response_size=len(resp.content),
                        response_time=round(elapsed, 3),
                        lockout_detected=False,
                        rate_limit_detected=False,
                        login_success=login_ok,
                        vulnerable=login_ok,
                        details=detail
                        if login_ok
                        else f"{username}:{password} - sem indicacao de sucesso",
                    )
                )

            except httpx.RequestError as exc:
                elapsed = time.monotonic() - start
                attempts.append(
                    BruteForceAttempt(
                        technique="credential",
                        category="credential",
                        url=login_url,
                        username=username,
                        payload=password,
                        status_code=0,
                        response_size=0,
                        response_time=round(elapsed, 3),
                        lockout_detected=False,
                        rate_limit_detected=False,
                        login_success=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

            if delay > 0:
                await asyncio.sleep(delay)

    return attempts


async def _test_password_spray(
    client: httpx.AsyncClient,
    login_url: str,
    usernames: list[str],
    password: str,
    field_map: dict[str, str],
    delay: float = 0.2,
) -> list[BruteForceAttempt]:
    """Testa uma senha comum contra multiplos usernames."""
    attempts: list[BruteForceAttempt] = []
    success_indicators = _get_success_indicators()
    user_field = field_map.get("username", "username")
    pass_field = field_map.get("password", "password")

    for username in usernames:
        data = {user_field: username, pass_field: password}
        start = time.monotonic()
        try:
            resp = await client.post(login_url, data=data, follow_redirects=False)
            elapsed = time.monotonic() - start
            body = resp.text[:5000]
            location = resp.headers.get("location", "")

            login_ok, detail = _check_login_success(
                resp.status_code,
                body,
                success_indicators,
                location,
            )

            attempts.append(
                BruteForceAttempt(
                    technique="spray",
                    category="spray",
                    url=login_url,
                    username=username,
                    payload=password,
                    status_code=resp.status_code,
                    response_size=len(resp.content),
                    response_time=round(elapsed, 3),
                    lockout_detected=False,
                    rate_limit_detected=False,
                    login_success=login_ok,
                    vulnerable=login_ok,
                    details=detail
                    if login_ok
                    else f"{username}:{password} - sem indicacao de sucesso",
                )
            )

        except httpx.RequestError as exc:
            elapsed = time.monotonic() - start
            attempts.append(
                BruteForceAttempt(
                    technique="spray",
                    category="spray",
                    url=login_url,
                    username=username,
                    payload=password,
                    status_code=0,
                    response_size=0,
                    response_time=round(elapsed, 3),
                    lockout_detected=False,
                    rate_limit_detected=False,
                    login_success=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

        if delay > 0:
            await asyncio.sleep(delay)

    return attempts


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------


async def run_scan(
    url: str,
    category: str = "all",
    timeout: float = 10.0,
    concurrency: int = 5,
    output_file: str | None = None,
    json_output: bool = False,
    username: str = "admin",
    password: str = "password",
    delay: float = 0.0,
) -> BruteForceResult:
    """Executa o scan de Login Brute Force contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    async with create_async_client(
        user_agent="MyTools/loginbruteforce",
        timeout=timeout,
    ) as client:
        try:
            resp = await client.get(url, follow_redirects=True)
            body = resp.text[:10000]
        except httpx.RequestError as exc:
            return BruteForceResult(
                target=url,
                login_url=url,
                attempts=[],
                rate_limit_found=False,
                lockout_found=False,
                weak_credentials=[],
                issues=[f"Falha ao conectar: {exc}"],
                overall_status="error",
            )

        form = _detect_form(body, url)
        if form is None:
            return BruteForceResult(
                target=url,
                login_url=url,
                attempts=[],
                rate_limit_found=False,
                lockout_found=False,
                weak_credentials=[],
                issues=[
                    "Nenhum formulario de login detectado na URL.",
                    "Forneça a URL exata do endpoint de login.",
                ],
                overall_status="error",
            )

        login_url, method, field_map = form
        logger.info("Login form detectado: %s %s", method, login_url)
        logger.info("Campos: %s", field_map)

        valid_categories = {"rate_limit", "lockout", "credential", "spray", "all"}
        if category not in valid_categories:
            return BruteForceResult(
                target=url,
                login_url=login_url,
                attempts=[],
                rate_limit_found=False,
                lockout_found=False,
                weak_credentials=[],
                issues=[f"Categoria desconhecida: {category}"],
                overall_status="error",
            )

        all_attempts: list[BruteForceAttempt] = []
        issues: list[str] = []
        rate_limit_found = False
        lockout_found = False
        weak_credentials: list[str] = []

        sem = asyncio.Semaphore(max(1, concurrency))

        async def _limited(
            coro: Awaitable[list[BruteForceAttempt]], into: list[BruteForceAttempt]
        ) -> None:
            async with sem:
                into.extend(await coro)

        rl_attempts: list[BruteForceAttempt] = []
        lo_attempts: list[BruteForceAttempt] = []
        cr_attempts: list[BruteForceAttempt] = []
        sp_attempts: list[BruteForceAttempt] = []
        tasks: list[Awaitable[None]] = []

        if category in ("all", "rate_limit"):
            logger.info("Testando rate limiting...")
            tasks.append(
                _limited(
                    _test_rate_limit(
                        client,
                        login_url,
                        username,
                        password,
                        field_map,
                        count=15,
                        delay=delay,
                    ),
                    rl_attempts,
                )
            )

        if category in ("all", "lockout"):
            logger.info("Testando account lockout...")
            tasks.append(
                _limited(
                    _test_lockout(
                        client,
                        login_url,
                        username,
                        "wrongpassword",
                        field_map,
                        count=8,
                        delay=delay,
                    ),
                    lo_attempts,
                )
            )

        if category == "credential":
            print(
                color(
                    "ATENCAO: Executando credential stuffing. Use apenas com autorizacao.",
                    Cyber.YELLOW,
                ),
                file=sys.stderr,
            )
            logger.info("Testando credenciais comuns...")
            usernames = _get_usernames()[:5]
            passwords = _get_passwords()[:5]
            tasks.append(
                _limited(
                    _test_credentials(
                        client,
                        login_url,
                        usernames,
                        passwords,
                        field_map,
                        delay=delay,
                    ),
                    cr_attempts,
                )
            )

        if category == "spray":
            print(
                color(
                    "ATENCAO: Executando password spray. Use apenas com autorizacao.",
                    Cyber.YELLOW,
                ),
                file=sys.stderr,
            )
            logger.info("Testando password spray...")
            usernames = _get_usernames()[:10]
            spray_password = password if password != "password" else "password"
            tasks.append(
                _limited(
                    _test_password_spray(
                        client,
                        login_url,
                        usernames,
                        spray_password,
                        field_map,
                        delay=delay,
                    ),
                    sp_attempts,
                )
            )

        await asyncio.gather(*tasks)

        all_attempts.extend(rl_attempts)
        all_attempts.extend(lo_attempts)
        all_attempts.extend(cr_attempts)
        all_attempts.extend(sp_attempts)
        weak_credentials = [
            f"{a.username}:{a.payload}" for a in all_attempts if a.login_success
        ]

        if category in ("all", "rate_limit"):
            if any(a.rate_limit_detected for a in rl_attempts):
                rate_limit_found = True
                issues.append("Rate limiting detectado (bom)")
            else:
                issues.append("Rate limiting NAO detectado (ruim)")

        if category in ("all", "lockout"):
            if any(a.lockout_detected for a in lo_attempts):
                lockout_found = True
                issues.append("Account lockout detectado (bom)")
            else:
                issues.append("Account lockout NAO detectado (ruim)")

        has_vulnerable = any(a.vulnerable for a in all_attempts)
        overall = "vulnerable" if has_vulnerable else "secure"

        return BruteForceResult(
            target=url,
            login_url=login_url,
            attempts=all_attempts,
            rate_limit_found=rate_limit_found,
            lockout_found=lockout_found,
            weak_credentials=weak_credentials,
            issues=issues,
            overall_status=overall,
        )


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


def print_results(result: BruteForceResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  LOGIN BRUTE FORCE / CREDENTIAL TESTING", Cyber.CYAN))
    print(color("=" * 60, Cyber.CYAN))
    print(color(f"  Target: {result.target}", Cyber.WHITE))
    print(color(f"  Login URL: {result.login_url}", Cyber.WHITE))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN
    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    print(
        color(
            f"\n  Rate Limit: {'Detectado' if result.rate_limit_found else 'NAO detectado'}",
            Cyber.GREEN if result.rate_limit_found else Cyber.RED,
        )
    )
    print(
        color(
            f"  Lockout: {'Detectado' if result.lockout_found else 'NAO detectado'}",
            Cyber.GREEN if result.lockout_found else Cyber.RED,
        )
    )

    if result.weak_credentials:
        print(color("\n  [CREDENCIAIS FRACAS]", Cyber.RED))
        for cred in result.weak_credentials:
            print(color(f"    - {cred}", Cyber.RED))

    vuln_attempts = [
        a
        for a in result.attempts
        if a.vulnerable and a.technique in ("rate_limit", "lockout")
    ]
    if vuln_attempts:
        print(color("\n  [VULNERAVEL]", Cyber.RED))
        seen: set[str] = set()
        for a in vuln_attempts:
            key = f"{a.technique}"
            if key in seen:
                continue
            seen.add(key)
            print(color(f"    - {a.technique}: {a.details}", Cyber.RED))

    if result.issues:
        print(color("\n  Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))

    print(color("=" * 60, Cyber.CYAN))


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

banner_art = create_banner(
    r"""
    ____  __  ___   __      ______            __
   / __ \/ / / / | / /____/ ____/___  ____  / /____
  / /_/ / / / /  |/ / ___/ /   / __ \/ __ \/ / ___/
 / ____/ /_/ / /|  / /__/ /___/ /_/ / /_/ / (__  )
/_/    \____/_/ |_/\\___/\____/\____/\____/_/____/
    """,
    "Login Brute Force / Credential Testing — rate limit, lockout, credential stuffing, spray",
)


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta parser CLI para mytools-bruteforce."""
    parser = argparse.ArgumentParser(
        prog="mytools-bruteforce",
        description="Login Brute Force / Credential Testing — testa seguranca de endpoints de auth.",
    )
    parser.add_argument("url", nargs="?", help="URL do endpoint de login")
    parser.add_argument(
        "-c",
        "--category",
        choices=["rate_limit", "lockout", "credential", "spray", "all"],
        default="all",
        help="Categoria de testes (default: all = rate_limit + lockout)",
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Username para testes (default: admin)",
    )
    parser.add_argument(
        "--password",
        default="password",
        help="Senha para testes de lockout/rate_limit (default: password)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Requisicoes simultaneas (default: 5)",
    )
    add_common_args(parser, "web")
    return parser


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Brute Force a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("Login Brute Force scan iniciado para %s", args.url)

    result = safe_asyncio_run(
        run_scan(
            url=args.url,
            category=getattr(args, "category", "all"),
            timeout=getattr(args, "timeout", 10.0),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
            json_output=getattr(args, "json_output", False),
            username=getattr(args, "username", "admin"),
            password=getattr(args, "password", "password"),
            delay=getattr(args, "delay", 0.0),
        ),
    )

    if getattr(args, "json_output", False):
        print_json(asdict(result))
    else:
        print_results(result)

    if getattr(args, "output", None):
        write_output(args.output, asdict(result))

    return 1 if result.overall_status != "secure" else 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="brute> ",
        description="Login Brute Force / Credential Testing interativo.",
        example="https://target.com/login",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com/login\n"
            "  https://target.com/login -c rate_limit\n"
            "  https://target.com/login -c credential --username admin\n"
            "  https://target.com/login -c spray --password 123456\n"
            "  https://target.com/login --delay 1.0\n"
            "  https://target.com/login --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
