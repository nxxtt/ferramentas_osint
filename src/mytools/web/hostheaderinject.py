#!/usr/bin/env python3

"""Modulo de deteccao de Host Header Injection.



Testa se o servidor e vulneravel a Host Header Injection via:

  - Reflected — Host refletido em responses (Location, body, headers)

  - Password Reset — Host injetado em links de reset de senha

  - SSRF — Host header causando request interno

  - Cache — Host header causando cache poisoning

  - Bypass — encoding, double host, X-Forwarded-Host tricks



Fluxo:

  1. Envia request baseline para obter resposta de referencia

  2. Envia requests com Host header malicioso

  3. Verifica se Host e refletido indevidamente

  4. Classifica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
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
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.hostheaderinject")


_CATEGORY_MAP: dict[str, list[str]] = {
    "reflected": [
        "host_reflected",
        "host_location",
        "host_body",
        "host_link",
        "host_meta",
    ],
    "password_reset": [
        "reset_host",
        "reset_link",
        "reset_token",
        "reset_domain",
        "reset_subdomain",
    ],
    "ssrf": [
        "ssrf_internal",
        "ssrf_localhost",
        "ssrf_metadata",
        "ssrf_dns",
        "ssrf_cloud",
    ],
    "cache": ["cache_host", "cache_vary", "cache_cdn", "cache_proxy", "cache_edge"],
    "bypass": ["double_host", "xforwarded", "xhost", "forwarded_for", "proxy_host"],
}


_INJECTED_HOST = "evil.attacker.com"


async def _test_baseline(
    client: httpx.AsyncClient, url: str
) -> tuple[int, int, dict[str, str], bytes]:
    """Envia request baseline para obter status, tamanho, headers e corpo."""

    try:
        resp = await client.get(url, follow_redirects=True)

        return resp.status_code, len(resp.content), dict(resp.headers), resp.content

    except httpx.RequestError:
        return 0, 0, {}, b""


async def _test_reflected(
    client: httpx.AsyncClient,
    url: str,
    injected_host: str,
) -> list[HostInjectAttempt]:
    """Testa se Host header e refletido em responses."""

    results: list[HostInjectAttempt] = []

    _b_status, _b_size, _b_headers, _b_body = await _test_baseline(client, url)

    test_cases = [
        ("host_reflected", "Host", injected_host),
        ("host_location", "Host", injected_host),
        ("host_body", "Host", injected_host),
        ("host_link", "Host", injected_host),
        ("host_meta", "Host", injected_host),
    ]

    for technique, header_name, header_value in test_cases:
        try:
            headers = {header_name: header_value}

            resp = await client.get(url, headers=headers, follow_redirects=True)

            resp_headers = dict(resp.headers)

            resp_body = resp.content.decode("utf-8", errors="ignore")

            location = resp_headers.get("location", "")

            vulnerable = False

            details = ""

            if injected_host.lower() in resp_body.lower():
                vulnerable = True

                details = f"Host refletido no body: {injected_host}"

            elif injected_host.lower() in location.lower():
                vulnerable = True

                details = f"Host refletido em Location: {location}"

            elif any(
                injected_host.lower() in str(v).lower() for v in resp_headers.values()
            ):
                vulnerable = True

                details = "Host refletido em headers"

            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="reflected",
                    header_name=header_name,
                    header_value=header_value,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                    exploit='curl -H "Host: evil.com" <TARGET>' if vulnerable else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="reflected",
                    header_name=header_name,
                    header_value=header_value,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_password_reset(
    client: httpx.AsyncClient,
    url: str,
    injected_host: str,
) -> list[HostInjectAttempt]:
    """Testa se Host header e usado em links de password reset."""

    results: list[HostInjectAttempt] = []

    reset_paths = [
        "/forgot-password",
        "/reset",
        "/password/reset",
        "/auth/forgot",
        "/recover",
    ]

    techniques = [
        "reset_host",
        "reset_link",
        "reset_token",
        "reset_domain",
        "reset_subdomain",
    ]

    for technique, path in zip(techniques, reset_paths, strict=True):
        try:
            reset_url = url.rstrip("/") + path

            resp = await client.post(
                reset_url,
                content="email=test@test.com",
                headers={
                    "Host": injected_host,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                follow_redirects=True,
            )

            resp_body = resp.content.decode("utf-8", errors="ignore")

            location = resp.headers.get("location", "")

            vulnerable = False

            details = ""

            if injected_host.lower() in resp_body.lower():
                vulnerable = True

                details = "Host injetado em pagina de reset"

            elif injected_host.lower() in location.lower():
                vulnerable = True

                details = "Host injetado em redirect de reset"

            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="password_reset",
                    header_name="Host",
                    header_value=injected_host,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="password_reset",
                    header_name="Host",
                    header_value=injected_host,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_ssrf(
    client: httpx.AsyncClient,
    url: str,
) -> list[HostInjectAttempt]:
    """Testa se Host header causa SSRF interno."""

    results: list[HostInjectAttempt] = []

    ssrf_hosts = [
        ("ssrf_internal", "127.0.0.1"),
        ("ssrf_localhost", "localhost"),
        ("ssrf_metadata", "169.254.169.254"),
        ("ssrf_dns", "dns.google"),
        ("ssrf_cloud", "metadata.google.internal"),
    ]

    for technique, ssrf_host in ssrf_hosts:
        try:
            resp = await client.get(
                url,
                headers={"Host": ssrf_host},
                follow_redirects=True,
            )

            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False

            details = ""

            internal_indicators = ["internal", "admin", "root", "metadata", "ami"]

            if any(ind in resp_body.lower() for ind in internal_indicators):
                vulnerable = True

                details = f"Possivel SSRF via Host: {ssrf_host}"

            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="ssrf",
                    header_name="Host",
                    header_value=ssrf_host,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="ssrf",
                    header_name="Host",
                    header_value=ssrf_host,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_cache(
    client: httpx.AsyncClient,
    url: str,
    injected_host: str,
) -> list[HostInjectAttempt]:
    """Testa se Host header causa cache poisoning."""

    results: list[HostInjectAttempt] = []

    techniques = ["cache_host", "cache_vary", "cache_cdn", "cache_proxy", "cache_edge"]

    for technique in techniques:
        try:
            resp = await client.get(
                url,
                headers={"Host": injected_host},
                follow_redirects=True,
            )

            resp_headers = dict(resp.headers)

            cache_hit = resp_headers.get("x-cache", "").lower()

            via = resp_headers.get("via", "").lower()

            age = resp_headers.get("age", "")

            vulnerable = False

            details = ""

            if cache_hit == "hit":
                vulnerable = True

                details = "Cache HIT com Host injetado"

            elif "hit" in via:
                vulnerable = True

                details = "Cache HIT via Via header"

            elif age and age.isdigit() and int(age) > 0:
                vulnerable = True

                details = f"Cache com age={age}"

            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="cache",
                    header_name="Host",
                    header_value=injected_host,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="cache",
                    header_name="Host",
                    header_value=injected_host,
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
    target_domain: str,
    injected_host: str,
) -> list[HostInjectAttempt]:
    """Testa bypass de Host header validation."""

    results: list[HostInjectAttempt] = []

    bypass_tests = [
        ("double_host", "Host", f"{target_domain}, {injected_host}"),
        ("xforwarded", "X-Forwarded-Host", injected_host),
        ("xhost", "X-Host", injected_host),
        ("forwarded_for", "Forwarded", f"host={injected_host}"),
        ("proxy_host", "X-Real-IP", injected_host),
    ]

    for technique, header_name, header_value in bypass_tests:
        try:
            resp = await client.get(
                url,
                headers={header_name: header_value},
                follow_redirects=True,
            )

            resp_body = resp.content.decode("utf-8", errors="ignore")

            resp_headers = dict(resp.headers)

            location = resp_headers.get("location", "")

            vulnerable = False

            details = ""

            if injected_host.lower() in resp_body.lower():
                vulnerable = True

                details = f"Bypass via {header_name}: Host refletido"

            elif injected_host.lower() in location.lower():
                vulnerable = True

                details = f"Bypass via {header_name}: Host em Location"

            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="bypass",
                    header_name=header_name,
                    header_value=header_value,
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )

        except httpx.RequestError as e:
            results.append(
                HostInjectAttempt(
                    technique=technique,
                    category="bypass",
                    header_name=header_name,
                    header_value=header_value,
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


@dataclass(frozen=True, slots=True)
class HostInjectAttempt:
    """Tentativa individual de Host Header Injection."""

    technique: str

    category: str

    header_name: str

    header_value: str

    status: int

    size: int

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class HostInjectResult:
    """Resultado consolidado do scan de Host Header Injection."""

    target: str

    injected_host: str

    tls: bool

    attempts: list[HostInjectAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def print_results(result: HostInjectResult) -> None:
    """Exibe os resultados do scan de Host Header Injection."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- Host Header Injection ---", Cyber.CYAN, Cyber.BOLD))

    print(color(f"  Alvo:         {result.target}", Cyber.WHITE))

    print(color(f"  Host Injetado: {result.injected_host}", Cyber.RED))

    print(color(f"  TLS:          {'sim' if result.tls else 'nao'}", Cyber.WHITE))

    print(color(f"  Testes:       {len(result.attempts)}", Cyber.WHITE))

    print(color(f"  Vulneraveis:  {len(vuln)}", Cyber.GREEN if vuln else Cyber.GRAY))

    print(color(f"  Bloqueados:   {len(blocked)}", Cyber.GRAY))

    print(color(f"  Erros:        {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if vuln:
        print(color("\n  [+] Vulnerabilidades detectadas:", Cyber.GREEN, Cyber.BOLD))

        seen: set[str] = set()

        for a in vuln:
            key = f"{a.technique}:{a.header_name}"

            if key in seen:
                continue

            seen.add(key)

            print(color(f"    [{a.category}] {a.technique}", Cyber.GREEN))

            print(
                color(f"      Header: {a.header_name}: {a.header_value}", Cyber.WHITE)
            )

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
        print(color("\n  [-] Nenhum Host Header Injection detectado", Cyber.YELLOW))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    injected_host: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
) -> int:
    """Executa o scan de Host Header Injection."""

    logger.info(
        "Host Header Injection scan para %s (host injetado: %s)", target, injected_host
    )

    tls = target.startswith("https://")

    parsed = urlparse(target)

    target_domain = parsed.hostname or target

    async with create_async_client(timeout=timeout) as client:
        all_attempts: list[HostInjectAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            if cat == "reflected":
                all_attempts.extend(
                    await _test_reflected(client, target, injected_host)
                )

            elif cat == "password_reset":
                all_attempts.extend(
                    await _test_password_reset(client, target, injected_host)
                )

            elif cat == "ssrf":
                all_attempts.extend(await _test_ssrf(client, target))

            elif cat == "cache":
                all_attempts.extend(await _test_cache(client, target, injected_host))

            elif cat == "bypass":
                all_attempts.extend(
                    await _test_bypass(client, target, target_domain, injected_host)
                )

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )

        issues: list[str] = []

        if not vuln_techs and not blocked_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = HostInjectResult(
            target=target,
            injected_host=injected_host,
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
            "Host Header Injection scan concluido: %d testes, %d vulneraveis",
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

    _   _  ___  ____  _____    _    _   _ _ __ ___  _ __

   | | | |/ _ \|  _ \|__  /   / \  | | | | '_ ` _ \| '_ \

   | |_| | | | | | | / / /   / _ \ | |_| | | | | | | |_) |

   |  _  | |_| | |/ //_ <   / ___ \|  _  | |_| | |_| | __/

   |_| |_|\___/|____/___/  /_/   \_\_| |_|____/|____/|_|

"""

    create_banner(
        art, "   host header injection: reflected, password reset, ssrf, cache, bypass"
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-hostinject",
        description="Host Header Injection — testa injecao via Host header em responses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-hostinject https://target.com\n"
            "  mytools-hostinject https://target.com --inject-host evil.com\n"
            "  mytools-hostinject https://target.com -c reflected\n"
            "  mytools-hostinject https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo para o scan")

    parser.add_argument(
        "--inject-host",
        default=_INJECTED_HOST,
        help=f"Host a injetar (default: {_INJECTED_HOST})",
    )

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=["all", "reflected", "password_reset", "ssrf", "cache", "bypass"],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Host Header Injection a partir de argumentos parseados."""

    logger.info("Host Header Injection scan iniciado para %s", args.url)

    categories: list[str] = []

    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]

    return safe_asyncio_run(
        run_scan(
            target=args.url,
            injected_host=getattr(args, "inject_host", _INJECTED_HOST),
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
        ),
    )


def main() -> int:
    """Entry point do modulo Host Header Injection."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="hostinject> ",
        description="Host Header Injection interativo.",
        example="https://target.com -c reflected",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com --inject-host evil.com\n"
            "  https://target.com -c reflected\n"
            "  https://target.com -c password_reset\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
