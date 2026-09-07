#!/usr/bin/env python3
"""Modulo de deteccao e teste ativo de CSRF (Cross-Site Request Forgery).

Diferente do attackaudit (que so detecta passivamente se o campo csrf existe),
este modulo faz testes ativos:

  form_detection:
    - Parse HTML, lista forms com method POST/PUT/DELETE/PATCH
    - Identifica campos CSRF por nome conhecido
    - Conta forms sem protecao CSRF

  cookie_analysis:
    - Verifica atributos SameSite, HttpOnly, Secure em cookies CSRF
    - Flags ausentes = risco de bypass via cross-site

  origin_referer:
    - Envia POST cross-origin sem token CSRF
    - Envia POST com Origin/Referer diferente
    - Se servidor aceita = vulneravel

  token_analysis:
    - Analisa entropia do token CSRF
    - Token curto, numerico ou previsivel = fraco
"""

import argparse
import logging
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import urlparse, urlunparse

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    init_scanner,
    print_exploit_info,
    print_json,
    run_concurrent,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.csrfscan")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CSRF_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "csrf_token",
        "_csrf",
        "csrf",
        "csrftoken",
        "_token",
        "authenticity_token",
        "xsrf-token",
        "_xsrf",
        "_csrf_token",
        "csrfmiddlewaretoken",
        "__requestverificationtoken",
    }
)

_CSRF_COOKIE_NAMES: frozenset[str] = frozenset(
    {
        "csrf_token",
        "csrftoken",
        "xsrf-token",
        "_csrf",
        "x-csrf-token",
        "csrfproof",
    }
)

_CONTENT_SIGNATURES: dict[str, list[bytes]] = {
    "form": [b"<form", b"<FORM"],
    "csrf_field": [b"csrf_token", b"_token", b"csrfmiddlewaretoken", b"csrftoken"],
    "same_site": [b"SameSite"],
    "error": [b"403", b"Forbidden", b"CSRF", b"Invalid token"],
}


# ---------------------------------------------------------------------------
# Token analysis
# ---------------------------------------------------------------------------


def analyze_token(token: str) -> str:
    """Analisa entropia de um token CSRF.

    Returns:
        "good" | "moderate" | "low_entropy" | "sequential" | "low_charset"
    """
    if len(token) < 16:
        return "low_entropy"
    if token.isdigit():
        return "sequential"
    if len(set(token)) < len(token) * 0.3:
        return "low_charset"
    if len(token) >= 32:
        return "good"
    return "moderate"


# ---------------------------------------------------------------------------
# HTML form parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParsedForm:
    """Form parseado do HTML."""

    action: str
    method: str
    fields: dict[str, str]
    has_csrf: bool
    csrf_field_name: str


class _FormParser(HTMLParser):
    """Parser HTML que extrai forms e campos CSRF."""

    def __init__(self) -> None:
        super().__init__()
        self._in_form = False
        self._form_action = ""
        self._form_method = "GET"
        self._form_fields: dict[str, str] = {}
        self._has_csrf = False
        self._csrf_field = ""
        self.forms: list[ParsedForm] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._in_form = True
            self._form_action = attr_dict.get("action", "")
            self._form_method = attr_dict.get("method", "GET").upper()
            self._form_fields = {}
            self._has_csrf = False
            self._csrf_field = ""
        elif tag == "input" and self._in_form:
            name = attr_dict.get("name", "")
            value = attr_dict.get("value", "")
            if name:
                self._form_fields[name] = value
                if name.lower() in _CSRF_FIELD_NAMES:
                    self._has_csrf = True
                    self._csrf_field = name

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form:
            self._in_form = False
            self.forms.append(
                ParsedForm(
                    action=self._form_action,
                    method=self._form_method,
                    fields=dict(self._form_fields),
                    has_csrf=self._has_csrf,
                    csrf_field_name=self._csrf_field,
                )
            )


def _parse_forms(html: bytes) -> list[ParsedForm]:
    """Parse HTML e retorna lista de forms."""
    parser = _FormParser()
    text = html.decode("utf-8", errors="ignore")
    parser.feed(text)
    return parser.forms


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CSRFAttempt:
    """Tentativa individual de teste CSRF."""

    technique: str
    category: str
    url: str
    method: str
    field_detected: bool
    cookie_detected: bool
    origin_bypassed: bool
    token_entropy: str
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class CSRFResult:
    """Resultado consolidado do scan de CSRF."""

    target: str
    baseline_status: int
    tls: bool
    attempts: list[CSRFAttempt]
    forms_found: int
    forms_missing_csrf: int
    cookies_analyzed: int
    issues: list[str]
    overall_status: str


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


async def _test_baseline(
    client: httpx.AsyncClient,
    url: str,
) -> tuple[int, bytes, dict[str, str]]:
    """Envia requisicao baseline para obter HTML + cookies."""
    try:
        resp = await client.get(url, follow_redirects=True)
        cookies: dict[str, str] = dict(resp.cookies.items())
        return resp.status_code, resp.content, cookies
    except httpx.RequestError:
        return 0, b"", {}


# ---------------------------------------------------------------------------
# Category tests
# ---------------------------------------------------------------------------


async def _test_form_detection(
    client: httpx.AsyncClient,
    url: str,
    html: bytes,
) -> list[CSRFAttempt]:
    """Detecta forms e verifica presenca de campos CSRF."""
    attempts: list[CSRFAttempt] = []
    forms = _parse_forms(html)

    for form in forms:
        if form.method in ("POST", "PUT", "DELETE", "PATCH"):
            form_url = (
                urlunparse(urlparse(url)._replace(path=form.action))
                if form.action
                else url
            )
            vulnerable = not form.has_csrf

            exploit = ""
            if vulnerable:
                post_data = "&".join(f"{k}={v}" for k, v in form.fields.items())
                exploit = f"curl -X {form.method} {form_url} -d '{post_data}'"

            attempts.append(
                CSRFAttempt(
                    technique="form_detection",
                    category="form_detection",
                    url=form_url,
                    method=form.method,
                    field_detected=form.has_csrf,
                    cookie_detected=False,
                    origin_bypassed=False,
                    token_entropy="",
                    vulnerable=vulnerable,
                    details=(
                        f"Form {form.method} {form_url} sem campo CSRF"
                        if vulnerable
                        else f"Form {form.method} {form_url} com CSRF: {form.csrf_field_name}"
                    ),
                    error="",
                    exploit=exploit,
                    tool="curl",
                )
            )

    return attempts


async def _test_cookie_analysis(
    client: httpx.AsyncClient,
    url: str,
    cookies: dict[str, str],
) -> list[CSRFAttempt]:
    """Analisa cookies CSRF para atributos SameSite, HttpOnly, Secure."""
    attempts: list[CSRFAttempt] = []

    for cookie_name in cookies:
        if cookie_name.lower() in {c.lower() for c in _CSRF_COOKIE_NAMES}:
            vulnerable = True
            details_parts: list[str] = []

            resp = await client.get(url, follow_redirects=True)
            for header in resp.headers.get_list("set-cookie"):
                if cookie_name.lower() in header.lower():
                    header_lower = header.lower()
                    has_samesite = "samesite" in header_lower
                    has_httponly = "httponly" in header_lower
                    has_secure = "secure" in header_lower

                    if not has_samesite:
                        details_parts.append("SameSite ausente")
                    if not has_httponly:
                        details_parts.append("HttpOnly ausente")
                    if not has_secure:
                        details_parts.append("Secure ausente")

                    if has_samesite:
                        same_site_val = (
                            header_lower.split("samesite=")[-1].split(";")[0].strip()
                        )
                        if same_site_val not in ("lax", "strict"):
                            details_parts.append(
                                f"SameSite={same_site_val or '?'} invalido para CSRF"
                            )
                        else:
                            vulnerable = False

            details = (
                f"Cookie '{cookie_name}': {', '.join(details_parts)}"
                if details_parts
                else f"Cookie '{cookie_name}' protegido"
            )

            attempts.append(
                CSRFAttempt(
                    technique="cookie_analysis",
                    category="cookie_analysis",
                    url=url,
                    method="",
                    field_detected=False,
                    cookie_detected=True,
                    origin_bypassed=False,
                    token_entropy="",
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

    return attempts


async def _test_origin_referer(
    client: httpx.AsyncClient,
    url: str,
    html: bytes,
) -> list[CSRFAttempt]:
    """Testa validacao de Origin/Referer via POST cross-origin."""
    attempts: list[CSRFAttempt] = []
    forms = _parse_forms(html)

    for form in forms:
        if form.method in ("POST", "PUT", "DELETE", "PATCH"):
            form_url = (
                urlunparse(urlparse(url)._replace(path=form.action))
                if form.action
                else url
            )

            try:
                post_data = "&".join(f"{k}={v}" for k, v in form.fields.items())
                resp = await client.post(
                    form_url,
                    content=post_data,
                    headers={
                        "Origin": "https://evil.com",
                        "Referer": "https://evil.com/attack",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    follow_redirects=False,
                )

                origin_bypassed = resp.status_code in (200, 301, 302, 303)

                exploit = ""
                if origin_bypassed:
                    exploit = f"curl -X POST {form_url} -H 'Origin: https://evil.com' -d '{post_data}'"

                attempts.append(
                    CSRFAttempt(
                        technique="origin_referer",
                        category="origin_referer",
                        url=form_url,
                        method=form.method,
                        field_detected=form.has_csrf,
                        cookie_detected=False,
                        origin_bypassed=origin_bypassed,
                        token_entropy="",
                        vulnerable=origin_bypassed,
                        details=(
                            f"Cross-origin POST aceito (Status {resp.status_code})"
                            if origin_bypassed
                            else f"Cross-origin rejeitado (Status {resp.status_code})"
                        ),
                        error="",
                        exploit=exploit,
                        tool="curl",
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    CSRFAttempt(
                        technique="origin_referer",
                        category="origin_referer",
                        url=form_url,
                        method=form.method,
                        field_detected=False,
                        cookie_detected=False,
                        origin_bypassed=False,
                        token_entropy="",
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


async def _test_token_analysis(
    client: httpx.AsyncClient,
    url: str,
    html: bytes,
) -> list[CSRFAttempt]:
    """Analisa entropia dos tokens CSRF encontrados."""
    attempts: list[CSRFAttempt] = []
    forms = _parse_forms(html)

    for form in forms:
        if form.has_csrf and form.csrf_field_name:
            token_value = form.fields.get(form.csrf_field_name, "")
            entropy = analyze_token(token_value) if token_value else "no_value"

            vulnerable = entropy in ("low_entropy", "sequential", "low_charset")

            details = (
                f"Token '{form.csrf_field_name}' = '{token_value[:20]}...' ({entropy})"
                if token_value
                else f"Campo '{form.csrf_field_name}' vazio"
            )

            attempts.append(
                CSRFAttempt(
                    technique="token_analysis",
                    category="token_analysis",
                    url=url,
                    method=form.method,
                    field_detected=True,
                    cookie_detected=False,
                    origin_bypassed=False,
                    token_entropy=entropy,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

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
) -> CSRFResult:
    """Executa o scan de CSRF contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent="MyTools/csrfscan",
        timeout=timeout,
    ) as client:
        b_status, b_body, b_cookies = await _test_baseline(client, url)

        if b_status == 0:
            return CSRFResult(
                target=url,
                baseline_status=0,
                tls=tls,
                attempts=[],
                forms_found=0,
                forms_missing_csrf=0,
                cookies_analyzed=0,
                issues=["Falha ao conectar no alvo"],
                overall_status="error",
            )

        logger.info("Baseline: %d (%d bytes)", b_status, len(b_body))

        forms = _parse_forms(b_body)
        state_forms = [
            f for f in forms if f.method in ("POST", "PUT", "DELETE", "PATCH")
        ]
        logger.info("Forms state-changing: %d", len(state_forms))

        coros = []

        if category in ("all", "form_detection"):
            coros.append(_test_form_detection(client, url, b_body))
        if category in ("all", "cookie_analysis"):
            coros.append(_test_cookie_analysis(client, url, b_cookies))
        if category in ("all", "origin_referer"):
            coros.append(_test_origin_referer(client, url, b_body))
        if category in ("all", "token_analysis"):
            coros.append(_test_token_analysis(client, url, b_body))

        if category not in (
            "all",
            "form_detection",
            "cookie_analysis",
            "origin_referer",
            "token_analysis",
        ):
            return CSRFResult(
                target=url,
                baseline_status=b_status,
                tls=tls,
                attempts=[],
                forms_found=len(state_forms),
                forms_missing_csrf=0,
                cookies_analyzed=0,
                issues=[f"Categoria desconhecida: {category}"],
                overall_status="error",
            )

        results = await run_concurrent(coros, concurrency)

        all_attempts: list[CSRFAttempt] = []
        for r in results:
            if isinstance(r, list):
                all_attempts.extend(r)

    issues: list[str] = []
    vulnerable_techniques: set[str] = set()

    for att in all_attempts:
        if att.vulnerable:
            vulnerable_techniques.add(att.technique)

    forms_missing = sum(1 for f in state_forms if not f.has_csrf)
    cookies_count = len(b_cookies)

    if forms_missing > 0:
        issues.append(f"{forms_missing} formulario(s) POST sem campo CSRF")
    if forms_missing > 0 and cookies_count == 0:
        issues.append("Nenhum cookie CSRF configurado")
    if "origin_referer" in vulnerable_techniques:
        issues.append("Servidor nao valida Origin/Referer")
    if "token_analysis" in vulnerable_techniques:
        issues.append("Tokens CSRF com baixa entropia")

    overall = "vulnerable" if vulnerable_techniques else "secure"

    return CSRFResult(
        target=url,
        baseline_status=b_status,
        tls=tls,
        attempts=all_attempts,
        forms_found=len(state_forms),
        forms_missing_csrf=forms_missing,
        cookies_analyzed=cookies_count,
        issues=issues,
        overall_status=overall,
    )


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


def print_results(result: CSRFResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  CSRF SCANNER", Cyber.CYAN))
    print(color("=" * 60, Cyber.CYAN))
    print(color(f"  Target: {result.target}", Cyber.WHITE))
    print(color(f"  Baseline: {result.baseline_status}", Cyber.GRAY))
    print(color(f"  TLS: {'Sim' if result.tls else 'Nao'}", Cyber.GRAY))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN
    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    print(color(f"\n  Forms encontrados: {result.forms_found}", Cyber.WHITE))
    print(
        color(
            f"  Forms sem CSRF: {result.forms_missing_csrf}",
            Cyber.YELLOW if result.forms_missing_csrf else Cyber.GREEN,
        )
    )
    print(color(f"  Cookies analisados: {result.cookies_analyzed}", Cyber.WHITE))

    vuln_attempts = [a for a in result.attempts if a.vulnerable]
    if vuln_attempts:
        print(color("\n  [VULNERAVEL]", Cyber.RED))
        for a in vuln_attempts:
            print(color(f"    - {a.technique}: {a.details}", Cyber.RED))
            print_exploit_info(a.exploit, a.tool)

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
    ____ _____ ____  ______     __
   / ___|_   _|  _ \/ ___\ \   / /
   \___ \ | | | |_) \___ \ \ / /
    ___) || | |  _ < ___) \ V /
   |____/ |_| |_| \_\____/ \_/
    """,
    "CSRF Scanner — detecta e testa protecao CSRF em web apps",
)


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta parser CLI para mytools-csrf."""
    parser = argparse.ArgumentParser(
        prog="mytools-csrf",
        description="CSRF Scanner — detecta e testa protecao CSRF.",
    )
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c",
        "--category",
        choices=[
            "form_detection",
            "cookie_analysis",
            "origin_referer",
            "token_analysis",
            "all",
        ],
        default="all",
        help="Categoria de testes (default: all)",
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
    """Executa um scan CSRF a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("CSRF scan iniciado para %s", args.url)

    result = safe_asyncio_run(
        run_scan(
            url=args.url,
            category=getattr(args, "category", "all"),
            timeout=getattr(args, "timeout", 10.0),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
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
        prompt="csrf> ",
        description="CSRF Scanner interativo.",
        example="https://target.com/login",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com/login\n"
            "  https://target.com/ -c form_detection\n"
            "  https://target.com/ -c cookie_analysis\n"
            "  https://target.com/ --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
