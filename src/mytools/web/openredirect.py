#!/usr/bin/env python3

"""Modulo de testes de Open Redirect.



Testa se o servidor e vulneravel a redirecionamentos abusivos:

  - Redirect via query params (url, next, redirect, etc.)

  - Redirect via paths (/redirect, /login, /go, etc.)

  - Redirect via headers (Referer, Location)

  - Bypass de filtros (encoding, protocol-relative, null byte, etc.)



Open Redirect permite que um atacante redirecione usuarios para sites

maliciosos, facilitando phishing e roubo de credenciais.



Fluxo:

  1. Envia requisicao baseline sem redirect

  2. Envia requisicoes com payloads de redirect

  3. Verifica se Location header aponta para dominio externo

  4. Classifica cada tecnica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import logging
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import quote, urlparse, urlunparse

import httpx

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    Cyber,
    color,
    create_async_client,
    print_exploit_info,
    run_concurrent,
)

logger = logging.getLogger("mytools.openredirect")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "param": [
        "param_url",
        "param_next",
        "param_redirect",
        "param_return",
        "param_dest",
    ],
    "path": ["path_redirect", "path_login", "path_go", "path_link"],
    "header": ["header_referer", "header_callback"],
    "bypass": [
        "bypass_protocol",
        "bypass_nullbyte",
        "bypass_userinfo",
        "bypass_backslash",
        "bypass_percent",
        "bypass_double_slash",
        "bypass_subdomain",
    ],
}


_REDIRECT_PARAMS_DEFAULT: list[str] = [
    "url",
    "next",
    "redirect",
    "redirect_to",
    "return",
    "return_to",
    "go",
    "goto",
    "out",
    "continue",
    "dest",
    "destination",
]


_REDIRECT_PATHS_DEFAULT: list[str] = [
    "/redirect",
    "/login",
    "/signin",
    "/auth",
    "/link",
    "/go",
]


_EVIL_DOMAIN_DEFAULT: str = "evil.com"


_BYPASS_TECHNIQUES_DEFAULT: list[tuple[str, str, str]] = [
    ("bypass_protocol", "url", "//evil.com"),
    ("bypass_nullbyte", "url", "http://evil.com%00.example.com"),
    ("bypass_userinfo", "url", "http://evil.com@example.com"),
    ("bypass_backslash", "url", "http://evil.com\\@.example.com"),
    ("bypass_percent", "url", "http://evil%2ecom"),
    ("bypass_double_slash", "url", "///evil.com"),
    ("bypass_subdomain", "url", "http://evil.com%E3%80%82example.com"),
]


def _load_category_map():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "openredirect", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )
    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


def _load_redirect_params():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "openredirect", default={"redirect_params": _REDIRECT_PARAMS_DEFAULT}
    )
    return data.get("redirect_params", _REDIRECT_PARAMS_DEFAULT)


def _load_redirect_paths():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "openredirect", default={"redirect_paths": _REDIRECT_PATHS_DEFAULT}
    )
    return data.get("redirect_paths", _REDIRECT_PATHS_DEFAULT)


def _load_evil_domain():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "openredirect", default={"evil_domain": _EVIL_DOMAIN_DEFAULT}
    )
    return data.get("evil_domain", _EVIL_DOMAIN_DEFAULT)


def _load_bypass_techniques():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "openredirect", default={"bypass_techniques": _BYPASS_TECHNIQUES_DEFAULT}
    )
    raw = data.get("bypass_techniques", _BYPASS_TECHNIQUES_DEFAULT)
    return [tuple(item) for item in raw]


_CATEGORY_MAP = _load_category_map()
_REDIRECT_PARAMS = _load_redirect_params()
_REDIRECT_PATHS = _load_redirect_paths()
_EVIL_DOMAIN = _load_evil_domain()
_BYPASS_TECHNIQUES = _load_bypass_techniques()


@dataclass(frozen=True, slots=True)
class OpenRedirectAttempt:
    """Tentativa individual de open redirect."""

    technique: str

    category: str

    url: str

    payload: str

    status_baseline: int

    status_test: int

    size_baseline: int

    size_test: int

    status_changed: bool

    size_changed: bool

    redirect_location: str

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""

    dom_confirmed: bool = False


@dataclass(frozen=True, slots=True)
class OpenRedirectResult:
    """Resultado consolidado do scan de open redirect."""

    target: str

    baseline_status: int

    baseline_size: int

    tls: bool

    attempts: list[OpenRedirectAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def _is_external_redirect(location: str, target_domain: str) -> bool:
    """Verifica se o Location aponta para dominio externo."""

    if not location:
        return False

    parsed = urlparse(location)

    return (bool(parsed.hostname) and parsed.hostname != target_domain) or (
        location.startswith("//") and not location.startswith(f"//{target_domain}")
    )


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""

    try:
        resp = await client.get(url, follow_redirects=False)

        return resp.status_code, len(resp.content), resp.content

    except httpx.RequestError:
        return 0, 0, b""


async def _test_param_redirect(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[OpenRedirectAttempt]:
    """Testa open redirect via query parameters."""

    attempts: list[OpenRedirectAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    target_domain = parsed.hostname or ""

    base_url = urlunparse(parsed._replace(query=""))

    for param in _REDIRECT_PARAMS:
        test_url = f"{base_url}?{param}={_EVIL_DOMAIN}"

        technique = f"param_{param}"

        try:
            resp = await client.get(test_url, follow_redirects=False)

            t_status = resp.status_code

            t_size = len(resp.content)

            location = resp.headers.get("location", "")

            status_changed = t_status != b_status

            vuln = _is_external_redirect(location, target_domain)

            attempts.append(
                OpenRedirectAttempt(
                    technique=technique,
                    category="param",
                    url=test_url,
                    payload=f"{param}={_EVIL_DOMAIN}",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    status_changed=status_changed,
                    size_changed=abs(t_size - b_size) > 50,
                    redirect_location=location,
                    vulnerable=vuln,
                    details=f"Redirect -> {location}"
                    if vuln
                    else f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem redirect",
                    error="",
                    exploit="<TARGET>/redirect?url=https://evil.com" if vuln else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                OpenRedirectAttempt(
                    technique=technique,
                    category="param",
                    url=test_url,
                    payload=f"{param}={_EVIL_DOMAIN}",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    redirect_location="",
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    return attempts


async def _test_path_redirect(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[OpenRedirectAttempt]:
    """Testa open redirect via paths."""

    attempts: list[OpenRedirectAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    target_domain = parsed.hostname or ""

    base_url = urlunparse(parsed._replace(path="", query=""))

    for path in _REDIRECT_PATHS:
        test_url = f"{base_url}{path}?url={_EVIL_DOMAIN}"

        technique = f"path_{path.lstrip('/')}"

        try:
            resp = await client.get(test_url, follow_redirects=False)

            t_status = resp.status_code

            t_size = len(resp.content)

            location = resp.headers.get("location", "")

            status_changed = t_status != b_status

            vuln = _is_external_redirect(location, target_domain)

            attempts.append(
                OpenRedirectAttempt(
                    technique=technique,
                    category="path",
                    url=test_url,
                    payload=f"{path}?url={_EVIL_DOMAIN}",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    status_changed=status_changed,
                    size_changed=abs(t_size - b_size) > 50,
                    redirect_location=location,
                    vulnerable=vuln,
                    details=f"Redirect -> {location}"
                    if vuln
                    else f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem redirect",
                    error="",
                    exploit="<TARGET>/redirect?url=https://evil.com" if vuln else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                OpenRedirectAttempt(
                    technique=technique,
                    category="path",
                    url=test_url,
                    payload=f"{path}?url={_EVIL_DOMAIN}",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    redirect_location="",
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    return attempts


async def _test_header_redirect(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[OpenRedirectAttempt]:
    """Testa open redirect via headers."""

    attempts: list[OpenRedirectAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    target_domain = parsed.hostname or ""

    header_payloads = [
        ("header_referer", "Referer", f"http://{_EVIL_DOMAIN}"),
        ("header_callback", "Referer", f"http://{_EVIL_DOMAIN}/callback"),
    ]

    for technique, header_name, header_value in header_payloads:
        try:
            resp = await client.get(
                url, headers={header_name: header_value}, follow_redirects=False
            )

            t_status = resp.status_code

            t_size = len(resp.content)

            location = resp.headers.get("location", "")

            status_changed = t_status != b_status

            vuln = _is_external_redirect(location, target_domain)

            attempts.append(
                OpenRedirectAttempt(
                    technique=technique,
                    category="header",
                    url=url,
                    payload=f"{header_name}: {header_value}",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    status_changed=status_changed,
                    size_changed=abs(t_size - b_size) > 50,
                    redirect_location=location,
                    vulnerable=vuln,
                    details=f"Redirect -> {location}"
                    if vuln
                    else f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem redirect",
                    error="",
                    exploit="<TARGET>/redirect?url=https://evil.com" if vuln else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                OpenRedirectAttempt(
                    technique=technique,
                    category="header",
                    url=url,
                    payload=f"{header_name}: {header_value}",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    redirect_location="",
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    return attempts


async def _test_bypass_redirect(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[OpenRedirectAttempt]:
    """Testa open redirect via bypass de filtros."""

    attempts: list[OpenRedirectAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    target_domain = parsed.hostname or ""

    base_url = urlunparse(parsed._replace(query=""))

    for technique, param, payload in _BYPASS_TECHNIQUES:
        test_url = f"{base_url}?{param}={quote(payload, safe='')}"

        try:
            resp = await client.get(test_url, follow_redirects=False)

            t_status = resp.status_code

            t_size = len(resp.content)

            location = resp.headers.get("location", "")

            status_changed = t_status != b_status

            vuln = _is_external_redirect(location, target_domain)

            attempts.append(
                OpenRedirectAttempt(
                    technique=technique,
                    category="bypass",
                    url=test_url,
                    payload=f"{param}={payload}",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    status_changed=status_changed,
                    size_changed=abs(t_size - b_size) > 50,
                    redirect_location=location,
                    vulnerable=vuln,
                    details=f"Redirect -> {location}"
                    if vuln
                    else f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem redirect",
                    error="",
                    exploit="<TARGET>/redirect?url=https://evil.com" if vuln else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                OpenRedirectAttempt(
                    technique=technique,
                    category="bypass",
                    url=test_url,
                    payload=f"{param}={payload}",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    redirect_location="",
                    vulnerable=False,
                    details="",
                    error=str(exc),
                )
            )

    return attempts


_REDIRECT_LOCATION_SCRIPT = (
    "() => { try { return window.location.href; } catch (e) { return ''; } }"
)


async def _confirm_headless_redirects(
    attempts: list[OpenRedirectAttempt],
    *,
    timeout: float,
    proxy: str | None,
) -> list[OpenRedirectAttempt]:
    """Confirma redirects via navegacao real (meta refresh / JS redirect)."""
    from mytools.core.headless import evaluate

    vuln = [a for a in attempts if a.vulnerable and a.url]
    if not vuln:
        return attempts

    confirmed: set[str] = set()
    for att in vuln:
        try:
            href = await evaluate(
                att.url, _REDIRECT_LOCATION_SCRIPT, timeout=timeout, proxy=proxy
            )
        except Exception as exc:
            logger.debug("headless redirect falhou para %s: %s", att.url, exc)
            continue
        if isinstance(href, str) and _is_external_redirect(
            href, urlparse(att.url).hostname or ""
        ):
            confirmed.add(att.url)

    return [
        replace(
            att,
            dom_confirmed=True,
            details=(att.details + " [confirmado via headless]").strip(),
        )
        if att.vulnerable and att.url in confirmed
        else att
        for att in attempts
    ]


async def scan_open_redirect(
    url: str,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
    category: str | None = None,
    concurrency: int = 5,
    headless: bool = False,
) -> OpenRedirectResult:
    """Executa scan de open redirect contra a URL alvo."""

    parsed = urlparse(url)

    if not parsed.scheme:
        url = f"http://{url}"

        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent=user_agent or "MyTools/openredirect",
        proxy=proxy,
        timeout=timeout,
        verify=verify,
    ) as client:
        b_status, b_size, b_body = await _test_baseline(client, url)

        baseline = (b_status, b_size, b_body)

        coros = []

        selected = _CATEGORY_MAP.get(category, []) if category else []

        if not category or category == "param":
            coros.append(_test_param_redirect(client, url, baseline))

        if not category or category == "path":
            coros.append(_test_path_redirect(client, url, baseline))

        if not category or category == "header":
            coros.append(_test_header_redirect(client, url, baseline))

        if not category or category == "bypass":
            coros.append(_test_bypass_redirect(client, url, baseline))

        if category and not selected:
            return OpenRedirectResult(
                target=url,
                baseline_status=b_status,
                baseline_size=b_size,
                tls=tls,
                attempts=[],
                vulnerable_techniques=[],
                blocked_techniques=[],
                issues=[f"Categoria desconhecida: {category}"],
                overall_status="error",
            )

        results = await run_concurrent(coros, concurrency)

        all_attempts: list[OpenRedirectAttempt] = []

        for r in results:
            if isinstance(r, list):
                all_attempts.extend(r)

    if headless:
        all_attempts = await _confirm_headless_redirects(
            all_attempts, timeout=timeout, proxy=proxy
        )

    vulnerable: list[str] = []

    blocked: list[str] = []

    issues: list[str] = []

    seen: set[str] = set()

    for att in all_attempts:
        if att.technique not in seen:
            seen.add(att.technique)

            if att.vulnerable:
                vulnerable.append(att.technique)

            elif att.status_changed:
                blocked.append(att.technique)

    if vulnerable:
        issues.append(f"{len(vulnerable)} tecnicas de open redirect vulneraveis")

    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return OpenRedirectResult(
        target=url,
        baseline_status=b_status,
        baseline_size=b_size,
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=vulnerable,
        blocked_techniques=blocked,
        issues=issues,
        overall_status=overall,
    )


def print_results_fn(result: OpenRedirectResult) -> None:
    """Exibe os resultados do scan formatados."""

    print()

    print(color("=" * 60, Cyber.CYAN))

    print(color("  OPEN REDIRECT SCAN", Cyber.CYAN))

    print(color("=" * 60, Cyber.CYAN))

    print(color(f"  Target: {result.target}", Cyber.WHITE))

    print(
        color(
            f"  Baseline: {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.GRAY,
        )
    )

    print(color(f"  TLS: {'Sim' if result.tls else 'Nao'}", Cyber.GRAY))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN

    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    if result.vulnerable_techniques:
        print(color("\n  [VULNERAVEL]", Cyber.RED))

        for tech in result.vulnerable_techniques:
            print(color(f"    - {tech}", Cyber.RED))

            a = next((a for a in result.attempts if a.technique == tech), None)

            if a:
                if a.dom_confirmed:
                    print(
                        color("      DOM:       confirmado via headless", Cyber.GREEN)
                    )
                print_exploit_info(a.exploit, a.tool)

    if result.blocked_techniques:
        print(color("\n  [BLOQUEADO]", Cyber.GREEN))

        for tech in result.blocked_techniques:
            print(color(f"    - {tech}", Cyber.GREEN))

    if result.issues:
        print(color("\n  Observacoes:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))

    print(color("=" * 60, Cyber.CYAN))


class OpenredirectScanner(BaseScanner):
    """Scanner de Open Redirect — detecta redirecionamentos abusivos em web apps.."""

    prog = "mytools-openredirect"
    description = "Open Redirect — detecta redirecionamentos abusivos em web apps."
    prompt = "redirect> "
    module_name = "mytools.openredirect"
    banner_text = r"""


     _   _                      ___                         _

    | \ | |                    / _ \                       | |

    |  \| | _____  ___   _   / /_\ \ ___ ___ _ __  ___  __| | ___  _ __

    | . ` |/ _ \ \/ / | | | |  _  |/ __/ __| '_ \/ _ \/ _` |/ _ \| '_ \

    | |\  |  __/>  <| |_| | | | | | (_| (__| | | |  __/ (_| | (_) | | | |

    |_| \_|\___/_/\_\\__, |  \_| |_/\___\___|_| |_|\___|\__,_|\___/|_| |_|

                      __/ |

                     |___/
    """
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("url", nargs="?", help="URL alvo para teste")
        parser.add_argument(
            "-c",
            "--category",
            choices=list(_CATEGORY_MAP.keys()),
            help="Categoria de teste (param, path, header, bypass)",
        )
        parser.add_argument(
            "--concurrency",
            type=int,
            default=5,
            help="Numero de requisicoes simultaneas (default: 5)",
        )
        parser.add_argument(
            "--headless",
            action="store_true",
            help="Confirma redirects navegando de verdade (requer 'uv run playwright install chromium').",
        )

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        kwargs = super()._build_run_once_kwargs(args)
        kwargs["headless"] = getattr(args, "headless", False)
        return kwargs

    async def run_scan(self, **kwargs):  # type: ignore[override]
        return await scan_open_redirect(**kwargs)

    def print_results(self, result: object) -> None:
        print_results_fn(result)  # type: ignore[arg-type]

    def _example(self) -> str:
        return "https://target.com -c param"

    def _help(self) -> str:
        return (
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            " https://target.com\n"
            " https://target.com -c param\n"
            " https://target.com -c bypass\n"
            " https://target.com -c path --proxy http://127.0.0.1:8080\n"
            " https://target.com --headless"
        )


scanner = OpenredirectScanner()
main = scanner.main
run_once = scanner.run_once
banner_art = scanner._make_banner()

# Backward-compatible re-exports for tests
build_parser = scanner.build_parser
print_results = print_results_fn

if __name__ == "__main__":
    raise SystemExit(main())
