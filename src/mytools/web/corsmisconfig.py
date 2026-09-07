#!/usr/bin/env python3

"""Modulo de deteccao de CORS Misconfiguration profundo.



Testa se o servidor e vulneravel a misconfiguration CORS via:

  - Null Origin â€” Origin: null aceito indevidamente

  - Subdomain â€” qualquer subdominio aceito

  - Credentials â€” Access-Control-Allow-Credentials com wildcard

  - Reflected â€” Origin refletido diretamente no ACAO

  - Bypass â€” prefix/suffix/regex tricks para contornar filtros



Fluxo:

  1. Envia request baseline sem Origin para obter headers de referencia

  2. Envia requests com Origin maliciosos

  3. Verifica se ACAO/ACAC retornam indevidamente

  4. Classifica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import asyncio
import logging
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

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

logger = logging.getLogger("mytools.corsmisconfig")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "null_origin": [
        "null_origin",
        "null_origin_acac",
        "null_origin_preflight",
        "null_origin_flash",
        "null_origin_ie",
    ],
    "subdomain": [
        "evil_subdomain",
        "deep_subdomain",
        "prefix_subdomain",
        "suffix_subdomain",
        "regex_bypass",
    ],
    "credentials": [
        "wildcard_credentials",
        "null_credentials",
        "subdomain_credentials",
        "prefix_credentials",
        "reflected_credentials",
    ],
    "reflected": [
        "reflected_origin",
        "reflected_subdomain",
        "reflected_path",
        "reflected_port",
        "reflected_protocol",
    ],
    "bypass": [
        "prefix_match",
        "suffix_match",
        "regex_match",
        "dot_prefix",
        "double_dot",
    ],
}


def _load_category_map() -> dict[str, list[str]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "corsmisconfig", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )

    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()


def _get_domain_variants(domain: str) -> list[str]:
    """Gera variacoes de dominio para teste de CORS."""

    base = domain.replace("https://", "").replace("http://", "").split("/")[0]

    return [
        f"https://evil-{base}.com",
        f"https://sub.{base}.evil.com",
        f"https://{base}.evil.com",
        f"https://evil.com/{base}",
        f"https://evil.com@{base}",
    ]


def _check_cors_headers(
    headers: dict[str, str],
    origin: str,
) -> tuple[bool, str]:
    """Verifica se os headers CORS indicam misconfiguration.



    Retorna (vulnerable, detalhes).

    """

    acao = headers.get("access-control-allow-origin", "").lower()

    acac = headers.get("access-control-allow-credentials", "").lower()

    if not acao:
        return False, ""

    # Null origin aceito

    if origin.lower() == "null" and acao == "null":
        return True, f"ACAOrigin: null aceito, ACAC: {acac}"

    # Wildcard com credenciais â€” real vulnerability

    if acao == "*" and acac == "true":
        return True, "Wildcard (*) com credenciais permitidas"

    # Origin refletido diretamente

    if acao == origin.lower():
        return True, f"Origin refletido diretamente: {origin}"

    # Subdomain wildcard (*.domain.com) â€” potentially dangerous

    if acao.startswith("*."):
        return True, f"Wildcard de subdominio no ACAO: {acao}"

    # Bare * without credentials â€” spec-compliant, not vulnerable

    if acao == "*":
        return False, ""

    return False, ""


async def _test_null_origin(
    client: httpx.AsyncClient,
    url: str,
) -> list[CORSAttempt]:
    """Testa se Origin: null e aceito indevidamente."""

    results: list[CORSAttempt] = []

    techniques = [
        ("null_origin", "null", "text/html"),
        ("null_origin_acac", "null", "application/x-www-form-urlencoded"),
        ("null_origin_preflight", "null", "text/plain"),
        ("null_origin_flash", "null", "text/xml"),
        ("null_origin_ie", "null", "text/html"),
    ]

    for technique, origin, content_type in techniques:
        try:
            headers = {"Origin": origin, "Content-Type": content_type}

            resp = await client.get(url, headers=headers, follow_redirects=True)

            resp_headers = dict(resp.headers)

            vulnerable, details = _check_cors_headers(resp_headers, origin)

            results.append(
                CORSAttempt(
                    technique=technique,
                    category="null_origin",
                    origin=origin,
                    acao=resp_headers.get("access-control-allow-origin", ""),
                    acac=resp_headers.get("access-control-allow-credentials", ""),
                    status=resp.status_code,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    exploit='curl -H "Origin: evil.com" -v <TARGET>'
                    if vulnerable
                    else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as e:
            results.append(
                CORSAttempt(
                    technique=technique,
                    category="null_origin",
                    origin=origin,
                    acao="",
                    acac="",
                    status=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_subdomain(
    client: httpx.AsyncClient,
    url: str,
    target_domain: str,
) -> list[CORSAttempt]:
    """Testa se subdominios maliciosos sao aceitos."""

    results: list[CORSAttempt] = []

    variants = _get_domain_variants(target_domain)

    techniques = [
        "evil_subdomain",
        "deep_subdomain",
        "prefix_subdomain",
        "suffix_subdomain",
        "regex_bypass",
    ]

    for technique, origin in zip(techniques, variants, strict=True):
        try:
            resp = await client.get(
                url, headers={"Origin": origin}, follow_redirects=True
            )

            resp_headers = dict(resp.headers)

            vulnerable, details = _check_cors_headers(resp_headers, origin)

            results.append(
                CORSAttempt(
                    technique=technique,
                    category="subdomain",
                    origin=origin,
                    acao=resp_headers.get("access-control-allow-origin", ""),
                    acac=resp_headers.get("access-control-allow-credentials", ""),
                    status=resp.status_code,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                CORSAttempt(
                    technique=technique,
                    category="subdomain",
                    origin=origin,
                    acao="",
                    acac="",
                    status=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_credentials(
    client: httpx.AsyncClient,
    url: str,
    target_domain: str,
) -> list[CORSAttempt]:
    """Testa se credenciais sao permitidas com origens maliciosas."""

    results: list[CORSAttempt] = []

    variants = _get_domain_variants(target_domain)

    techniques = [
        "wildcard_credentials",
        "null_credentials",
        "subdomain_credentials",
        "prefix_credentials",
        "reflected_credentials",
    ]

    for technique, origin in zip(techniques, variants, strict=True):
        try:
            headers = {
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            }

            resp = await client.options(url, headers=headers, follow_redirects=True)

            resp_headers = dict(resp.headers)

            vulnerable, details = _check_cors_headers(resp_headers, origin)

            if not vulnerable:
                acao = resp_headers.get("access-control-allow-origin", "").lower()

                acac = resp_headers.get("access-control-allow-credentials", "").lower()

                if acao == "*" and acac == "true":
                    vulnerable = True

                    details = "Wildcard com credenciais via preflight"

                elif acao != "" and acac == "true":
                    vulnerable = True

                    details = f"Origem maliciosa aceita com credenciais: {origin}"

            results.append(
                CORSAttempt(
                    technique=technique,
                    category="credentials",
                    origin=origin,
                    acao=resp_headers.get("access-control-allow-origin", ""),
                    acac=resp_headers.get("access-control-allow-credentials", ""),
                    status=resp.status_code,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                CORSAttempt(
                    technique=technique,
                    category="credentials",
                    origin=origin,
                    acao="",
                    acac="",
                    status=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_reflected(
    client: httpx.AsyncClient,
    url: str,
    target_domain: str,
) -> list[CORSAttempt]:
    """Testa se o Origin e refletido diretamente no ACAO."""

    results: list[CORSAttempt] = []

    parsed = urlparse(target_domain)

    base = parsed.hostname or target_domain

    origins = [
        ("reflected_origin", f"https://evil-{base}.com"),
        ("reflected_subdomain", f"https://sub.{base}.evil.com"),
        ("reflected_path", f"https://evil.com/{base}"),
        ("reflected_port", f"https://{base}:8080"),
        ("reflected_protocol", f"http://{base}"),
    ]

    for technique, origin in origins:
        try:
            resp = await client.get(
                url, headers={"Origin": origin}, follow_redirects=True
            )

            resp_headers = dict(resp.headers)

            acao = resp_headers.get("access-control-allow-origin", "")

            vulnerable = acao.lower() == origin.lower()

            details = f"Origin refletido: {acao}" if vulnerable else ""

            results.append(
                CORSAttempt(
                    technique=technique,
                    category="reflected",
                    origin=origin,
                    acao=acao,
                    acac=resp_headers.get("access-control-allow-credentials", ""),
                    status=resp.status_code,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                CORSAttempt(
                    technique=technique,
                    category="reflected",
                    origin=origin,
                    acao="",
                    acac="",
                    status=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
    target_domain: str,
) -> list[CORSAttempt]:
    """Testa bypass de filtros CORS (prefix, suffix, regex)."""

    results: list[CORSAttempt] = []

    parsed = urlparse(target_domain)

    base = parsed.hostname or target_domain

    origins = [
        ("prefix_match", f"https://evil-{base}.com"),
        ("suffix_match", f"https://{base}-evil.com"),
        ("regex_match", f"https://{base}evil.com"),
        ("dot_prefix", f"https://.evil{base}.com"),
        ("double_dot", f"https://evil..{base}.com"),
    ]

    for technique, origin in origins:
        try:
            resp = await client.get(
                url, headers={"Origin": origin}, follow_redirects=True
            )

            resp_headers = dict(resp.headers)

            vulnerable, details = _check_cors_headers(resp_headers, origin)

            results.append(
                CORSAttempt(
                    technique=technique,
                    category="bypass",
                    origin=origin,
                    acao=resp_headers.get("access-control-allow-origin", ""),
                    acac=resp_headers.get("access-control-allow-credentials", ""),
                    status=resp.status_code,
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                CORSAttempt(
                    technique=technique,
                    category="bypass",
                    origin=origin,
                    acao="",
                    acac="",
                    status=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


@dataclass(frozen=True, slots=True)
class CORSAttempt:
    """Tentativa individual de CORS Misconfiguration."""

    technique: str

    category: str

    origin: str

    acao: str

    acac: str

    status: int

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class CORSResult:
    """Resultado consolidado do scan de CORS Misconfiguration."""

    target: str

    tls: bool

    attempts: list[CORSAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def print_results(result: CORSResult) -> None:
    """Exibe os resultados do scan de CORS Misconfiguration."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- CORS Misconfiguration ---", Cyber.CYAN, Cyber.BOLD))

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
            key = f"{a.technique}:{a.origin}"

            if key in seen:
                continue

            seen.add(key)

            print(color(f"    [{a.category}] {a.technique}", Cyber.GREEN))

            print(color(f"      Origin: {a.origin}", Cyber.WHITE))

            print(color(f"      ACAO: {a.acao}", Cyber.WHITE))

            print(color(f"      ACAC: {a.acac}", Cyber.WHITE))

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
        print(color("\n  [-] Nenhuma CORS Misconfiguration detectada", Cyber.YELLOW))

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
    """Executa o scan de CORS Misconfiguration."""

    logger.info("CORS Misconfiguration scan para %s", target)

    tls = target.startswith("https://")

    parsed = urlparse(target)

    target_domain = parsed.hostname or target

    async with create_async_client(timeout=timeout) as client:
        all_attempts: list[CORSAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        dispatch = {
            "null_origin": lambda: _test_null_origin(client, target),
            "subdomain": lambda: _test_subdomain(client, target, target_domain),
            "credentials": lambda: _test_credentials(client, target, target_domain),
            "reflected": lambda: _test_reflected(client, target, target_domain),
            "bypass": lambda: _test_bypass(client, target, target_domain),
        }
        valid_cats = [c for c in test_categories if c in dispatch]
        if valid_cats:
            results = await asyncio.gather(
                *(dispatch[c]() for c in valid_cats),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    all_attempts.extend(r)

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )

        issues: list[str] = []

        if not vuln_techs and not blocked_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = CORSResult(
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

        if json_output:
            print_json(asdict(result))

            logger.info(
                "CORS scan concluido: %d testes, %d vulneraveis",
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

    ____  ____  ________   _______  __

   / __ \/ __ \/ ____/ /  / / ___/ / /

  / /_/ / / / / __/ / /  / /\__ \ / /

 / _, _/ /_/ / /___/ /__/ /___/ // /

/_/ |_|\____/_____/\____//____//_/

"""

    create_banner(
        art,
        "   cors misconfiguration: null origin, subdomain, credentials, reflected, bypass",
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-cors",
        description="CORS Misconfiguration â€” testa null origin, subdomain, credenciais, reflected.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-cors https://target.com\n"
            "  mytools-cors https://target.com -c null_origin\n"
            "  mytools-cors https://target.com -c credentials\n"
            "  mytools-cors https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo para o scan")

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=[
            "all",
            "null_origin",
            "subdomain",
            "credentials",
            "reflected",
            "bypass",
        ],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan CORS a partir de argumentos parseados."""

    logger.info("CORS Misconfiguration scan iniciado para %s", args.url)

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
    """Entry point do modulo CORS Misconfiguration."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="cors> ",
        description="CORS Misconfiguration interativo.",
        example="https://target.com -c null_origin",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c null_origin\n"
            "  https://target.com -c credentials\n"
            "  https://target.com -c reflected\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
