#!/usr/bin/env python3

"""Modulo de deteccao de Header Injection via URL params.



Testa se o servidor e vulneravel a injecao de headers HTTP via

parametros de URL que sao refletidos em responses:

  - param_reflected — Parametros refletidos em headers de resposta

  - header_overwrite — Sobrescrever headers de seguranca

  - redirect_header — Headers injetados em respostas de redirect

  - cookie_inject — Injetar Set-Cookie via parametros de URL

  - bypass — encoding, case variation, double writing



Fluxo:

  1. Envia request baseline para obter resposta de referencia

  2. Envia requests com parametros de URL que injetam headers

  3. Verifica se headers sao injetados indevidamente

  4. Classifica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import logging
from dataclasses import asdict, dataclass

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.headerinject")


_CATEGORY_MAP: dict[str, list[str]] = {
    "param_reflected": [
        "x_injected",
        "x_custom",
        "x_forwarded",
        "x_real_ip",
        "x_requested",
    ],
    "header_overwrite": [
        "overwrite_xfo",
        "overwrite_csp",
        "overwrite_ct",
        "overwrite_p3p",
        "overwrite_hsts",
    ],
    "redirect_header": [
        "redirect_x_injected",
        "redirect_set_cookie",
        "redirect_auth",
        "redirect_location",
        "redirect_xss",
    ],
    "cookie_inject": [
        "cookie_path",
        "cookie_domain",
        "cookie_httponly",
        "cookie_secure",
        "cookie_samesite",
    ],
    "bypass": [
        "bypass_encoding",
        "bypass_case",
        "bypass_double",
        "bypass_newline",
        "bypass_nullbyte",
    ],
}


_MARKER = "HDRINJECT_TEST"


def _url_with_param(url: str, param_name: str, param_value: str) -> str:
    """Monta URL de teste mantendo query string existente (sem ``??``)."""

    base, _, query = url.partition("?")

    param = param_name if "=" in param_name else f"{param_name}={param_value}"

    if query:
        return f"{base}?{query}&{param}"

    return f"{base}?{param}"


async def _test_param_reflected(
    client: httpx.AsyncClient,
    url: str,
) -> list[HeaderInjectAttempt]:
    """Testa se parametros de URL sao refletidos em headers de resposta."""

    results: list[HeaderInjectAttempt] = []

    test_cases: list[tuple[str, str, str]] = [
        ("x_injected", "X-Injected", _MARKER),
        ("x_custom", "X-Custom-Header", _MARKER),
        ("x_forwarded", "X-Forwarded-For", _MARKER),
        ("x_real_ip", "X-Real-IP", _MARKER),
        ("x_requested", "X-Requested-With", _MARKER),
    ]

    for technique, param_name, marker in test_cases:
        try:
            url_with_param = _url_with_param(url, param_name, marker)

            resp = await client.get(url_with_param, follow_redirects=True)

            resp_headers = dict(resp.headers)

            vulnerable = False

            details = ""

            for hdr_name, hdr_val in resp_headers.items():
                if marker in str(hdr_val):
                    vulnerable = True

                    details = f"Header injetado via URL param: {hdr_name}: {hdr_val}"

                    break

            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="param_reflected",
                    param_name=param_name,
                    param_value=marker,
                    injected_header="",
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    exploit='curl -H "X-Injected: malicious" <TARGET>'
                    if vulnerable
                    else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="param_reflected",
                    param_name=param_name,
                    param_value=marker,
                    injected_header="",
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_header_overwrite(
    client: httpx.AsyncClient,
    url: str,
) -> list[HeaderInjectAttempt]:
    """Testa se headers de seguranca podem ser sobrescritos via URL params."""

    results: list[HeaderInjectAttempt] = []

    overwrite_tests: list[tuple[str, str, str, str]] = [
        ("overwrite_xfo", "X-Frame-Options", "ALLOWALL", "x-frame-options"),
        (
            "overwrite_csp",
            "Content-Security-Policy",
            "default-src *",
            "content-security-policy",
        ),
        ("overwrite_ct", "X-Content-Type-Options", "nosniff", "x-content-type-options"),
        (
            "overwrite_p3p",
            "P3P",
            'CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"',
            "p3p",
        ),
        (
            "overwrite_hsts",
            "Strict-Transport-Security",
            "max-age=0",
            "strict-transport-security",
        ),
    ]

    for technique, param_name, marker, header_check in overwrite_tests:
        try:
            url_with_param = _url_with_param(url, param_name, marker)

            resp = await client.get(url_with_param, follow_redirects=True)

            resp_headers = dict(resp.headers)

            vulnerable = False

            details = ""

            injected_val = resp_headers.get(header_check, "")

            if marker.lower() in injected_val.lower():
                vulnerable = True

                details = (
                    f"Header de seguranca sobrescrito: {header_check}: {injected_val}"
                )

            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="header_overwrite",
                    param_name=param_name,
                    param_value=marker,
                    injected_header=header_check,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="header_overwrite",
                    param_name=param_name,
                    param_value=marker,
                    injected_header=header_check,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_redirect_header(
    client: httpx.AsyncClient,
    url: str,
) -> list[HeaderInjectAttempt]:
    """Testa se headers injetados aparecem em respostas de redirect."""

    results: list[HeaderInjectAttempt] = []

    redirect_tests: list[tuple[str, str, str]] = [
        ("redirect_x_injected", "X-Injected", _MARKER),
        ("redirect_set_cookie", "Set-Cookie", f"evil={_MARKER}"),
        ("redirect_auth", "Authorization", f"Bearer {_MARKER}"),
        ("redirect_location", "Location", f"http://evil.com/?{_MARKER}"),
        ("redirect_xss", "X-XSS-Protection", f"1; report=http://evil.com/?{_MARKER}"),
    ]

    for technique, param_name, marker in redirect_tests:
        try:
            url_with_param = _url_with_param(url, param_name, marker)

            resp = await client.get(url_with_param, follow_redirects=False)

            resp_headers = dict(resp.headers)

            vulnerable = False

            details = ""

            for hdr_name, hdr_val in resp_headers.items():
                if marker in str(hdr_val) and hdr_name.lower() != "x-injected":
                    vulnerable = True

                    details = f"Header injetado em redirect: {hdr_name}: {hdr_val}"

                    break

            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="redirect_header",
                    param_name=param_name,
                    param_value=marker,
                    injected_header="",
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="redirect_header",
                    param_name=param_name,
                    param_value=marker,
                    injected_header="",
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_cookie_inject(
    client: httpx.AsyncClient,
    url: str,
) -> list[HeaderInjectAttempt]:
    """Testa se Set-Cookie pode ser injetado via URL params."""

    results: list[HeaderInjectAttempt] = []

    cookie_tests: list[tuple[str, str, str]] = [
        ("cookie_path", "Set-Cookie", f"evil={_MARKER}; Path=/admin"),
        ("cookie_domain", "Set-Cookie", f"evil={_MARKER}; Domain=.evil.com"),
        ("cookie_httponly", "Set-Cookie", f"evil={_MARKER}; HttpOnly"),
        ("cookie_secure", "Set-Cookie", f"evil={_MARKER}; Secure"),
        ("cookie_samesite", "Set-Cookie", f"evil={_MARKER}; SameSite=None"),
    ]

    for technique, param_name, marker in cookie_tests:
        try:
            url_with_param = _url_with_param(url, param_name, marker)

            resp = await client.get(url_with_param, follow_redirects=True)

            get_list = getattr(resp.headers, "get_list", None)

            set_cookies = get_list("set-cookie") if get_list else []

            if not set_cookies:
                raw = resp.headers.get("set-cookie", "")

                set_cookies = [raw] if raw else []

            vulnerable = False

            details = ""

            if any(_MARKER in sc for sc in set_cookies):
                vulnerable = True

                details = (
                    f"Set-Cookie injetado via URL param: {', '.join(set_cookies)[:120]}"
                )

            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="cookie_inject",
                    param_name=param_name,
                    param_value=marker,
                    injected_header="set-cookie",
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="cookie_inject",
                    param_name=param_name,
                    param_value=marker,
                    injected_header="set-cookie",
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
) -> list[HeaderInjectAttempt]:
    """Testa bypass de validacao de headers via encoding e tricks."""

    results: list[HeaderInjectAttempt] = []

    bypass_tests: list[tuple[str, str, str]] = [
        ("bypass_encoding", "X-Injected", "%58-%49%4E%4A%45%43%54ED"),
        ("bypass_case", "x-injected", _MARKER.lower()),
        ("bypass_double", "X-X-Injected", _MARKER),
        ("bypass_newline", "X-Injected", f"test%0d%0aX-Evil: {_MARKER}"),
        ("bypass_nullbyte", "X-Injected", f"{_MARKER}%00XSS"),
    ]

    for technique, param_name, marker in bypass_tests:
        try:
            url_with_param = _url_with_param(url, param_name, marker)

            resp = await client.get(url_with_param, follow_redirects=True)

            resp_headers = dict(resp.headers)

            vulnerable = False

            details = ""

            for hdr_name, hdr_val in resp_headers.items():
                if (
                    _MARKER.lower() in str(hdr_val).lower()
                    or "xss" in str(hdr_val).lower()
                ):
                    vulnerable = True

                    details = f"Bypass via param: {hdr_name}: {hdr_val}"

                    break

            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="bypass",
                    param_name=param_name,
                    param_value=marker,
                    injected_header="",
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HeaderInjectAttempt(
                    technique=technique,
                    category="bypass",
                    param_name=param_name,
                    param_value=marker,
                    injected_header="",
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


@dataclass(frozen=True, slots=True)
class HeaderInjectAttempt:
    """Tentativa individual de Header Injection via URL params."""

    technique: str

    category: str

    param_name: str

    param_value: str

    injected_header: str

    status: int

    size: int

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class HeaderInjectResult:
    """Resultado consolidado do scan de Header Injection via URL params."""

    target: str

    tls: bool

    attempts: list[HeaderInjectAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def print_results(result: HeaderInjectResult) -> None:
    """Exibe os resultados do scan de Header Injection via URL params."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- Header Injection via URL Params ---", Cyber.CYAN, Cyber.BOLD))

    print(color(f"  Alvo:         {result.target}", Cyber.WHITE))

    print(color(f"  TLS:          {'sim' if result.tls else 'nao'}", Cyber.WHITE))

    print(color(f"  Testes:       {len(result.attempts)}", Cyber.WHITE))

    print(color(f"  Vulneraveis:  {len(vuln)}", Cyber.GREEN if vuln else Cyber.GRAY))

    print(color(f"  Bloqueados:   {len(blocked)}", Cyber.GRAY))

    print(color(f"  Erros:        {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if vuln:
        print(color("\n  [+] Vulnerabilidades detectadas:", Cyber.GREEN, Cyber.BOLD))

        seen: set[str] = set()

        for a in vuln:
            key = f"{a.technique}:{a.param_name}"

            if key in seen:
                continue

            seen.add(key)

            print(color(f"    [{a.category}] {a.technique}", Cyber.GREEN))

            print(color(f"      Param: {a.param_name}", Cyber.WHITE))

            print(color(f"      Status: {a.status}", Cyber.WHITE))

            if a.details:
                print(color(f"      Detalhes: {a.details}", Cyber.GRAY))

            print_exploit_info(a.exploit, a.tool)

        print(
            color(
                f"\n  Total: {len(result.attempts)} testes, {len(vuln)} vulneraveis",
                Cyber.WHITE,
            )
        )

    else:
        print(
            color(
                "\n  [-] Nenhum Header Injection detectado via URL params", Cyber.YELLOW
            )
        )

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
) -> int:
    """Executa o scan de Header Injection via URL params."""

    logger.info("Header Injection scan para %s", target)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout) as client:
        all_attempts: list[HeaderInjectAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            if cat == "param_reflected":
                all_attempts.extend(await _test_param_reflected(client, target))

            elif cat == "header_overwrite":
                all_attempts.extend(await _test_header_overwrite(client, target))

            elif cat == "redirect_header":
                all_attempts.extend(await _test_redirect_header(client, target))

            elif cat == "cookie_inject":
                all_attempts.extend(await _test_cookie_inject(client, target))

            elif cat == "bypass":
                all_attempts.extend(await _test_bypass(client, target))

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )

        issues: list[str] = []

        if not vuln_techs and not blocked_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = HeaderInjectResult(
            target=target,
            tls=tls,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked_techs,
            issues=issues,
            overall_status="vulnerable"
            if vuln_techs
            else ("safe" if blocked_techs else "unknown"),
        )

        print_results(result)

        logger.info(
            "Header Injection scan concluido: %d testes, %d vulneraveis",
            len(all_attempts),
            len(vuln_techs),
        )

        if output_file:
            write_output(output_file, asdict(result))

            logger.info("Resultados salvos em %s", output_file)

        return 1 if vuln_techs else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""

    art = r"""

    _   ___  _  _  ___     _   _  ___  ___  ___  ___

   | | | _ \| \| |/ __|   /_\ | |/ _ \| _ \/ _ \/ __|

   | |_| __/| .` | (__   / _ \| | (_) |   / (_) \__ \

   |____|___|_|\_|\___| /_/ \_\_|\___/|_|_\\___/|___/

"""

    create_banner(
        art,
        "   header injection via url params: reflected, overwrite, redirect, cookie, bypass",
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-headerinject",
        description="Header Injection via URL params — testa injecao de headers HTTP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-headerinject https://target.com\n"
            "  mytools-headerinject https://target.com -c param_reflected\n"
            "  mytools-headerinject https://target.com -c header_overwrite\n"
            "  mytools-headerinject https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo para o scan")

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=[
            "all",
            "param_reflected",
            "header_overwrite",
            "redirect_header",
            "cookie_inject",
            "bypass",
        ],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Header Injection a partir de argumentos parseados."""

    logger.info("Header Injection scan iniciado para %s", args.url)

    categories: list[str] = []

    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]

    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
        ),
    )


def main() -> int:
    """Entry point do modulo Header Injection."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="headerinject> ",
        description="Header Injection via URL params interativo.",
        example="https://target.com -c param_reflected",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c param_reflected\n"
            "  https://target.com -c header_overwrite\n"
            "  https://target.com -c bypass\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
