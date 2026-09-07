#!/usr/bin/env python3

"""Modulo de deteccao de Clickjacking via Embedded Frames.



Testa se o servidor e vulneravel a clickjacking via:

  - XFrame — verificacao de X-Frame-Options header

  - CSP — verificacao de Content-Security-Policy frame-ancestors

  - Bypass — tecnicas de bypass (null origin, content-type, meta)

  - Meta — meta tags de protecao (robots, referrer)

  - Legacy — bypass em browsers legados



Fluxo:

  1. Envia request baseline para obter headers de resposta

  2. Verifica presenca e valor de X-Frame-Options

  3. Verifica presenca e valor de CSP frame-ancestors

  4. Testa tecnicas de bypass

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
    print_json,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.clickjacking")


_CATEGORY_MAP: dict[str, list[str]] = {
    "xframe": [
        "xframe_absent",
        "xframe_deny",
        "xframe_sameorigin",
        "xframe_allow_from",
        "xframe_invalid",
    ],
    "csp": [
        "csp_absent",
        "csp_frame_ancestors",
        "csp_wildcard",
        "csp_self",
        "csp_mixed",
    ],
    "bypass": [
        "null_origin",
        "content_type",
        "meta_refresh",
        "javascript_url",
        "data_uri",
    ],
    "meta": [
        "meta_referrer",
        "meta_robots",
        "meta_permissions",
        "meta_http_equiv",
        "meta_refresh",
    ],
    "legacy": [
        "ie_double",
        "ie_edge",
        "chrome_bypass",
        "firefox_bypass",
        "safari_bypass",
    ],
}


async def _test_baseline(
    client: httpx.AsyncClient, url: str
) -> tuple[int, dict[str, str], bytes]:
    """Envia request baseline para obter headers e corpo de referencia."""

    try:
        resp = await client.get(url, follow_redirects=True)

        return resp.status_code, dict(resp.headers), resp.content

    except httpx.RequestError:
        return 0, {}, b""


def _check_xframe_options(headers: dict[str, str]) -> tuple[bool, str]:
    """Verifica se X-Frame-Options esta configurado corretamente."""

    xfo = headers.get("x-frame-options", "").lower()

    if not xfo:
        return False, "X-Frame-Options ausente"

    if xfo not in ("deny", "sameorigin"):
        return True, f"X-Frame-Options invalido: {xfo}"

    return True, f"X-Frame-Options configurado: {xfo}"


def _check_csp_frame_ancestors(headers: dict[str, str]) -> tuple[bool, str]:
    """Verifica se CSP frame-ancestors esta configurado corretamente."""

    csp = headers.get("content-security-policy", "").lower()

    if not csp:
        return False, "CSP ausente"

    if "frame-ancestors" not in csp:
        return False, "CSP sem frame-ancestors"

    if "'none'" in csp:
        return True, "CSP frame-ancestors: 'none'"

    if "'self'" in csp:
        return True, "CSP frame-ancestors: 'self'"

    if "*" in csp:
        return True, "CSP frame-ancestors: wildcard (*)"

    return True, "CSP frame-ancestors configurado"


async def _test_xframe(
    client: httpx.AsyncClient,
    url: str,
    baseline_headers: dict[str, str],
) -> list[ClickjackAttempt]:
    """Testa protecao X-Frame-Options."""

    results: list[ClickjackAttempt] = []

    b_headers = baseline_headers

    xfo = b_headers.get("x-frame-options", "")

    xfo_lower = xfo.lower()

    results.append(
        ClickjackAttempt(
            technique="xframe_absent",
            category="xframe",
            header_tested="X-Frame-Options",
            header_value=xfo,
            vulnerable=xfo == "",
            details="X-Frame-Options nao configurado" if xfo == "" else "",
            error="",
            exploit='<iframe src="<TARGET>" style="opacity:0.0001"></iframe>'
            if xfo == ""
            else "",
            tool="curl",
        )
    )

    results.append(
        ClickjackAttempt(
            technique="xframe_deny",
            category="xframe",
            header_tested="X-Frame-Options",
            header_value=xfo,
            vulnerable=False,
            details="X-Frame-Options: DENY — protecao ativa"
            if xfo_lower == "deny"
            else "",
            error="",
        )
    )

    results.append(
        ClickjackAttempt(
            technique="xframe_sameorigin",
            category="xframe",
            header_tested="X-Frame-Options",
            header_value=xfo,
            vulnerable=False,
            details="X-Frame-Options: SAMEORIGIN — protecao ativa"
            if xfo_lower == "sameorigin"
            else "",
            error="",
        )
    )

    results.append(
        ClickjackAttempt(
            technique="xframe_allow_from",
            category="xframe",
            header_tested="X-Frame-Options",
            header_value=xfo,
            vulnerable="allow-from" in xfo_lower,
            details=f"X-Frame-Options ALLOW-FROM (deprecated): {xfo}"
            if "allow-from" in xfo_lower
            else "",
            error="",
            exploit='<iframe src="<TARGET>" style="opacity:0.0001"></iframe>'
            if "allow-from" in xfo_lower
            else "",
            tool="curl",
        )
    )

    is_invalid = bool(xfo and xfo_lower not in ("deny", "sameorigin", "allow-from"))

    results.append(
        ClickjackAttempt(
            technique="xframe_invalid",
            category="xframe",
            header_tested="X-Frame-Options",
            header_value=xfo,
            vulnerable=is_invalid,
            details=f"X-Frame-Options valor invalido: {xfo}" if is_invalid else "",
            error="",
            exploit='<iframe src="<TARGET>" style="opacity:0.0001"></iframe>'
            if is_invalid
            else "",
            tool="curl",
        )
    )

    return results


async def _test_csp(
    client: httpx.AsyncClient,
    url: str,
    baseline_headers: dict[str, str],
) -> list[ClickjackAttempt]:
    """Testa protecao CSP frame-ancestors."""

    results: list[ClickjackAttempt] = []

    b_headers = baseline_headers

    csp = b_headers.get("content-security-policy", "")

    csp_lower = csp.lower()

    has_frame_ancestors = "frame-ancestors" in csp_lower

    results.append(
        ClickjackAttempt(
            technique="csp_absent",
            category="csp",
            header_tested="Content-Security-Policy",
            header_value=csp[:100] if csp else "",
            vulnerable=not csp,
            details="CSP nao configurado" if not csp else "",
            error="",
            exploit='<iframe src="<TARGET>" style="opacity:0.0001"></iframe>'
            if not csp
            else "",
            tool="curl",
        )
    )

    results.append(
        ClickjackAttempt(
            technique="csp_frame_ancestors",
            category="csp",
            header_tested="Content-Security-Policy",
            header_value=csp[:100],
            vulnerable=bool(csp) and not has_frame_ancestors,
            details=f"CSP presente sem frame-ancestors: {csp[:50]}"
            if csp and not has_frame_ancestors
            else "",
            error="",
        )
    )

    has_wildcard = "*" in csp_lower and has_frame_ancestors

    results.append(
        ClickjackAttempt(
            technique="csp_wildcard",
            category="csp",
            header_tested="Content-Security-Policy",
            header_value=csp[:100],
            vulnerable=has_wildcard,
            details=f"CSP frame-ancestors com wildcard: {csp[:50]}"
            if has_wildcard
            else "",
            error="",
        )
    )

    has_self = "'self'" in csp_lower and has_frame_ancestors

    results.append(
        ClickjackAttempt(
            technique="csp_self",
            category="csp",
            header_tested="Content-Security-Policy",
            header_value=csp[:100],
            vulnerable=has_frame_ancestors and not has_self,
            details=f"CSP frame-ancestors sem 'self': {csp[:50]}"
            if has_frame_ancestors and not has_self
            else "",
            error="",
        )
    )

    has_mixed = has_frame_ancestors and (
        "frame-src" in csp_lower or "child-src" in csp_lower
    )

    results.append(
        ClickjackAttempt(
            technique="csp_mixed",
            category="csp",
            header_tested="Content-Security-Policy",
            header_value=csp[:100],
            vulnerable=has_mixed,
            details=f"CSP com frame-ancestors e frame-src/child-src: {csp[:50]}"
            if has_mixed
            else "",
            error="",
        )
    )

    return results


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
    baseline_headers: dict[str, str],
    baseline_body: bytes,
) -> list[ClickjackAttempt]:
    """Testa tecnicas de bypass de clickjacking."""

    results: list[ClickjackAttempt] = []

    b_headers = baseline_headers

    b_body = baseline_body

    xfo = b_headers.get("x-frame-options", "").lower()

    csp = b_headers.get("content-security-policy", "").lower()

    is_protected = bool(xfo in ("deny", "sameorigin") or "frame-ancestors" in csp)

    try:
        resp = await client.get(url, headers={"Origin": "null"}, follow_redirects=True)

        resp_headers = dict(resp.headers)

        resp_xfo = resp_headers.get("x-frame-options", "").lower()

        resp_csp = resp_headers.get("content-security-policy", "").lower()

        vulnerable = (
            resp_xfo not in ("deny", "sameorigin") and "frame-ancestors" not in resp_csp
        )

        results.append(
            ClickjackAttempt(
                technique="null_origin",
                category="bypass",
                header_tested="Origin: null",
                header_value=f"XFO={resp_xfo or 'absent'}, CSP={resp_csp[:30] or 'absent'}",
                vulnerable=vulnerable,
                details="Null origin bypass possivel" if vulnerable else "",
                error="",
                exploit='<iframe src="<TARGET>" sandbox="allow-scripts" origin="null"></iframe>'
                if vulnerable
                else "",
                tool="curl",
            )
        )

    except httpx.RequestError as e:
        results.append(
            ClickjackAttempt(
                technique="null_origin",
                category="bypass",
                header_tested="Origin: null",
                header_value="",
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    try:
        resp = await client.get(
            url, headers={"Content-Type": "text/plain"}, follow_redirects=True
        )

        resp_headers = dict(resp.headers)

        resp_xfo = resp_headers.get("x-frame-options", "").lower()

        vulnerable = is_protected and resp_xfo not in ("deny", "sameorigin")

        results.append(
            ClickjackAttempt(
                technique="content_type",
                category="bypass",
                header_tested="Content-Type: text/plain",
                header_value=f"XFO={resp_xfo or 'absent'}",
                vulnerable=vulnerable,
                details="Content-Type bypass possivel" if vulnerable else "",
                error="",
            )
        )

    except httpx.RequestError as e:
        results.append(
            ClickjackAttempt(
                technique="content_type",
                category="bypass",
                header_tested="Content-Type: text/plain",
                header_value="",
                vulnerable=False,
                details="",
                error=str(e)[:100],
            )
        )

    has_meta_refresh = b"<meta" in b_body.lower() and b"refresh" in b_body.lower()

    results.append(
        ClickjackAttempt(
            technique="meta_refresh",
            category="bypass",
            header_tested="Meta Refresh",
            header_value="found" if has_meta_refresh else "",
            vulnerable=has_meta_refresh,
            details="Meta refresh encontrado na pagina" if has_meta_refresh else "",
            error="",
        )
    )

    has_js_url = b"javascript:" in b_body.lower()

    results.append(
        ClickjackAttempt(
            technique="javascript_url",
            category="bypass",
            header_tested="JavaScript URL",
            header_value="found" if has_js_url else "",
            vulnerable=has_js_url,
            details="JavaScript URL encontrado na pagina" if has_js_url else "",
            error="",
        )
    )

    has_data_uri = b"data:" in b_body.lower()

    results.append(
        ClickjackAttempt(
            technique="data_uri",
            category="bypass",
            header_tested="Data URI",
            header_value="found" if has_data_uri else "",
            vulnerable=has_data_uri,
            details="Data URI encontrado na pagina" if has_data_uri else "",
            error="",
        )
    )

    return results


async def _test_meta(
    client: httpx.AsyncClient,
    url: str,
    baseline_body: bytes,
) -> list[ClickjackAttempt]:
    """Testa meta tags de protecao."""

    results: list[ClickjackAttempt] = []

    b_body = baseline_body

    body_lower = b_body.lower()

    for technique, name in [
        ("meta_referrer", "referrer"),
        ("meta_robots", "robots"),
        ("meta_permissions", "permissions-policy"),
    ]:
        has_it = b"<meta" in body_lower and f'name="{name}"'.encode() in body_lower

        results.append(
            ClickjackAttempt(
                technique=technique,
                category="meta",
                header_tested=f"Meta {name}",
                header_value="found" if has_it else "",
                vulnerable=has_it,
                details=f"Meta {name} encontrado" if has_it else "",
                error="",
            )
        )

    has_http_equiv = b"<meta" in body_lower and b"http-equiv" in body_lower

    results.append(
        ClickjackAttempt(
            technique="meta_http_equiv",
            category="meta",
            header_tested="Meta HTTP-Equiv",
            header_value="found" if has_http_equiv else "",
            vulnerable=has_http_equiv,
            details="Meta http-equiv encontrado" if has_http_equiv else "",
            error="",
        )
    )

    has_refresh = b"<meta" in body_lower and b"refresh" in body_lower

    results.append(
        ClickjackAttempt(
            technique="meta_refresh",
            category="meta",
            header_tested="Meta Refresh",
            header_value="found" if has_refresh else "",
            vulnerable=has_refresh,
            details="Meta refresh encontrado" if has_refresh else "",
            error="",
        )
    )

    return results


async def _test_legacy(
    client: httpx.AsyncClient,
    url: str,
) -> list[ClickjackAttempt]:
    """Testa bypass em browsers legados."""

    results: list[ClickjackAttempt] = []

    test_cases = [
        ("ie_double", "X-Frame-Options: ALLOWALL"),
        ("ie_edge", "X-Frame-Options: DENY"),
        ("chrome_bypass", "X-Frame-Options: SAMEORIGIN"),
        ("firefox_bypass", "X-Frame-Options: DENY"),
        ("safari_bypass", "X-Frame-Options: SAMEORIGIN"),
    ]

    for technique, header_tested in test_cases:
        try:
            resp = await client.get(url, follow_redirects=True)

            resp_headers = dict(resp.headers)

            resp_xfo = resp_headers.get("x-frame-options", "").lower()

            vulnerable = resp_xfo == "" or resp_xfo not in ("deny", "sameorigin")

            results.append(
                ClickjackAttempt(
                    technique=technique,
                    category="legacy",
                    header_tested=header_tested,
                    header_value=resp_xfo or "absent",
                    vulnerable=vulnerable,
                    details=f"{technique} bypass possivel" if vulnerable else "",
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                ClickjackAttempt(
                    technique=technique,
                    category="legacy",
                    header_tested=header_tested,
                    header_value="",
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


@dataclass(frozen=True, slots=True)
class ClickjackAttempt:
    """Tentativa individual de Clickjacking."""

    technique: str

    category: str

    header_tested: str

    header_value: str

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class ClickjackResult:
    """Resultado consolidado do scan de Clickjacking."""

    target: str

    tls: bool

    attempts: list[ClickjackAttempt]

    vulnerable_techniques: list[str]

    protected_techniques: list[str]

    issues: list[str]

    overall_status: str


def print_results(result: ClickjackResult) -> None:
    """Exibe os resultados do scan de Clickjacking."""

    vuln = [a for a in result.attempts if a.vulnerable]

    protected = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- Clickjacking via Embedded Frames ---", Cyber.CYAN, Cyber.BOLD))

    print(color(f"  Alvo:         {result.target}", Cyber.WHITE))

    print(color(f"  TLS:          {'sim' if result.tls else 'nao'}", Cyber.WHITE))

    print(color(f"  Testes:       {len(result.attempts)}", Cyber.WHITE))

    print(color(f"  Vulneraveis:  {len(vuln)}", Cyber.RED if vuln else Cyber.GRAY))

    print(
        color(
            f"  Protegidos:   {len(protected)}",
            Cyber.GREEN if protected else Cyber.GRAY,
        )
    )

    print(color(f"  Erros:        {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if vuln:
        print(color("\n  [!] Vulnerabilidades detectadas:", Cyber.RED, Cyber.BOLD))

        seen: set[str] = set()

        for a in vuln:
            key = f"{a.technique}:{a.header_tested}"

            if key in seen:
                continue

            seen.add(key)

            print(color(f"    [{a.category}] {a.technique}", Cyber.RED))

            print(color(f"      Header: {a.header_tested}", Cyber.WHITE))

            print(color(f"      Valor: {a.header_value or 'ausente'}", Cyber.WHITE))

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
        print(color("\n  [+] Nenhum Clickjacking detectado", Cyber.GREEN))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
    json_output: bool = False,
) -> int:
    """Executa o scan de Clickjacking."""

    logger.info("Clickjacking scan para %s", target)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout) as client:
        _baseline_status, baseline_headers, baseline_body = await _test_baseline(
            client, target
        )

        all_attempts: list[ClickjackAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            if cat == "xframe":
                all_attempts.extend(
                    await _test_xframe(client, target, baseline_headers)
                )

            elif cat == "csp":
                all_attempts.extend(await _test_csp(client, target, baseline_headers))

            elif cat == "bypass":
                all_attempts.extend(
                    await _test_bypass(client, target, baseline_headers, baseline_body)
                )

            elif cat == "meta":
                all_attempts.extend(await _test_meta(client, target, baseline_body))

            elif cat == "legacy":
                all_attempts.extend(await _test_legacy(client, target))

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        protected_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )

        issues: list[str] = []

        if not vuln_techs and not protected_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = ClickjackResult(
            target=target,
            tls=tls,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            protected_techniques=protected_techs,
            issues=issues,
            overall_status="vulnerable"
            if vuln_techs
            else ("safe" if protected_techs else "unknown"),
        )

        if json_output:
            print_json(asdict(result))

            logger.info(
                "Clickjacking scan concluido: %d testes, %d vulneraveis",
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

    _  _           _        _           _

   | || |___ _ __ | |__  __| |___ _ __| |__

   | __ / -_) '_ \| '_ \/ _` / -_) '_| / /

   |_||_\___| .__/|_.__/\__,_\___|_| |_\_\

            |_|

"""

    create_banner(art, "   clickjacking: xframe, csp, bypass, meta, legacy")()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-clickjack",
        description="Clickjacking — testa X-Frame-Options/CSP e bypasses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-clickjack https://target.com\n"
            "  mytools-clickjack https://target.com -c xframe\n"
            "  mytools-clickjack https://target.com -c csp\n"
            "  mytools-clickjack https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo para o scan")

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=["all", "xframe", "csp", "bypass", "meta", "legacy"],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Clickjacking a partir de argumentos parseados."""

    logger.info("Clickjacking scan iniciado para %s", args.url)

    categories: list[str] = []

    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]

    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
            json_output=getattr(args, "json_output", False),
        ),
    )


def main() -> int:
    """Entry point do modulo Clickjacking."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="clickjack> ",
        description="Clickjacking interativo.",
        example="https://target.com -c xframe",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c xframe\n"
            "  https://target.com -c csp\n"
            "  https://target.com -c bypass\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
