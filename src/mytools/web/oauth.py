#!/usr/bin/env python3

"""Modulo de deteccao de misconfigurations OAuth 2.0.



Testa se uma implementacao OAuth e vulneravel a ataques:

  - misconfig: state ausente, implicit flow, token em URL, nonce ausente, secret fraco

  - scope_escalation: scopes extras, admin scope, JWT scope injection

  - redirect_uri: subdomain wildcard, path traversal, encoding bypass, open redirect, null byte

  - pkce_bypass: code_challenge ausente, plain method, verifier curto

  - refresh_token: reuse de token antigo, token antigo valido, concurrent refresh



Fluxo:

  1. Envia request para a URL alvo (baseline)

  2. Analisa a pagina de authorize/consent

  3. Para cada categoria, envia payloads e verifica resposta

  4. Retorna resultado consolidado com severidade

"""

import argparse
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from urllib.parse import urljoin

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.oauth")


_CATEGORY_MAP: dict[str, list[str]] = {
    "misconfig": [
        "missing_state",
        "empty_state",
        "implicit_flow",
        "token_in_url",
        "missing_nonce",
        "weak_secret",
    ],
    "scope_escalation": [
        "extra_scopes",
        "admin_scope",
        "token_scope",
        "incremental_consent",
        "cross_api_scope",
    ],
    "redirect_uri": [
        "subdomain_wildcard",
        "path_traversal",
        "encoding_bypass",
        "open_redirect",
        "null_byte",
        "http_downgrade",
        "fragment_inject",
    ],
    "pkce_bypass": [
        "no_code_challenge",
        "plain_method",
        "short_verifier",
        "cross_client_code",
    ],
    "refresh_token": [
        "reuse_old_token",
        "old_token_valid",
        "concurrent_refresh",
        "no_absolute_expiry",
        "no_family_tracking",
    ],
}


_WEAK_SECRETS = [
    "secret",
    "password",
    "changeme",
    "client_secret",
    "123456",
    "test",
    "admin",
    "default",
    "oauth_secret",
    "api_secret",
]


_REDIRECT_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    ("subdomain_wildcard", "https://evil.example.com/callback", ["evil", "redirect"]),
    (
        "path_traversal",
        "https://target.com/../../evil.com/callback",
        ["evil", "redirect"],
    ),
    ("encoding_bypass", "https://evil%2ecom/callback", ["evil", "redirect"]),
    (
        "open_redirect",
        "https://target.com/redirect?url=https://evil.com/callback",
        ["evil"],
    ),
    ("null_byte", "https://target.com%00.evil.com/callback", ["evil", "redirect"]),
    ("http_downgrade", "http://target.com/callback", ["http://", "redirect"]),
    ("fragment_inject", "https://target.com/callback#https://evil.com", ["evil"]),
]


@dataclass(frozen=True, slots=True)
class OAuthAttempt:
    technique: str

    category: str

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
class OAuthResult:
    target: str

    tls: bool

    baseline_status: int

    baseline_size: int

    authorize_url: str | None

    attempts: list[OAuthAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def _find_authorize_url(url: str, body: str) -> str | None:
    """Tenta encontrar URL de authorize na pagina."""

    patterns = [
        r'href=["\']([^"\']*?/authorize[^"\']*)["\']',
        r'href=["\']([^"\']*?/oauth/authorize[^"\']*)["\']',
        r'href=["\']([^"\']*?/auth[^"\']*)["\']',
        r'action=["\']([^"\']*?/authorize[^"\']*)["\']',
        r'action=["\']([^"\']*?/auth[^"\']*)["\']',
        r'(https?://[^"\'<>\s]+/authorize[^"\'<>\s]*)',
    ]

    for pat in patterns:
        m = re.search(pat, body, re.IGNORECASE)

        if m:
            found = m.group(1)

            if found.startswith("http"):
                return found

            return urljoin(url, found)

    return None


def _check_response_indicators(body: str, indicators: list[str]) -> bool:
    """Verifica se indicadores estao presentes na resposta."""

    lower = body.lower()

    return any(ind.lower() in lower for ind in indicators)


async def _test_misconfig_category(
    client: httpx.AsyncClient,
    authorize_url: str,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[OAuthAttempt]:
    """Testa misconfigurations OAuth."""

    results: list[OAuthAttempt] = []

    base_params = (
        "response_type=code&client_id=test&redirect_uri=https://example.com/callback"
    )

    tests = [
        (
            "missing_state",
            f"{authorize_url}?{base_params}",
            "state ausente na requisicao authorize",
        ),
        (
            "empty_state",
            f"{authorize_url}?{base_params}&state=",
            "state vazio na requisicao",
        ),
        (
            "implicit_flow",
            f"{authorize_url}?response_type=token&client_id=test&redirect_uri=https://example.com/callback",
            "response_type=token (implicit flow)",
        ),
        (
            "token_in_url",
            f"{authorize_url}?{base_params}",
            "token na URL via fragment/query",
        ),
        (
            "missing_nonce",
            f"{authorize_url}?{base_params}",
            "nonce ausente em flow OIDC",
        ),
        ("weak_secret", url, "testando secrets OAuth comuns no token endpoint"),
    ]

    for technique, test_url, details in tests:
        try:
            resp = await client.get(test_url, timeout=timeout, follow_redirects=True)

            body = resp.text

            body_lower = body.lower()

            is_error = any(
                kw in body_lower
                for kw in ["error", "invalid", "denied", "unauthorized"]
            )

            has_auth_code = "code=" in body or "authorization_code" in body

            vulnerable = resp.status_code == 200 and not is_error and not has_auth_code

            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="misconfig",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=details if vulnerable else "",
                    error="",
                    exploit="redirect_uri_manipulation" if vulnerable else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="misconfig",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_scope_escalation_category(
    client: httpx.AsyncClient,
    authorize_url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[OAuthAttempt]:
    """Testa scope escalation."""

    results: list[OAuthAttempt] = []

    base = "response_type=code&client_id=test&redirect_uri=https://example.com/callback&state=test"

    scope_tests = [
        ("extra_scopes", f"{base}&scope=read+write+admin", "scopes extras solicitados"),
        ("admin_scope", f"{base}&scope=admin", "scope admin solicitado"),
        (
            "token_scope",
            f"{base}&scope=openid+profile+email+address+phone",
            "scopes OIDC multiplicados",
        ),
        ("incremental_consent", f"{base}&scope=read", "incremental consent bypass"),
        (
            "cross_api_scope",
            f"{base}&scope=https://graph.microsoft.com/.default",
            "scope cross-API Azure AD",
        ),
    ]

    for technique, params, details in scope_tests:
        try:
            test_url = f"{authorize_url}?{params}"

            resp = await client.get(test_url, timeout=timeout, follow_redirects=True)

            body = resp.text

            vulnerable = resp.status_code == 200 and (
                "consent" in body.lower()
                or "authorize" in body.lower()
                or "scope" in body.lower()
            )

            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="scope_escalation",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=details if vulnerable else "",
                    error="",
                    exploit="redirect_uri_manipulation" if vulnerable else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="scope_escalation",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_redirect_uri_category(
    client: httpx.AsyncClient,
    authorize_url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[OAuthAttempt]:
    """Testa redirect URI manipulation."""

    results: list[OAuthAttempt] = []

    base = "response_type=code&client_id=test&state=test"

    for technique, redirect_uri, indicators in _REDIRECT_BYPASS_PAYLOADS:
        try:
            test_url = f"{authorize_url}?{base}&redirect_uri={redirect_uri}"

            resp = await client.get(test_url, timeout=timeout, follow_redirects=False)

            body = resp.text

            location = resp.headers.get("location", "")

            vulnerable = (
                resp.status_code in (301, 302, 303, 307, 308)
                and any(ind.lower() in location.lower() for ind in indicators)
            ) or _check_response_indicators(body, indicators)

            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="redirect_uri",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=f"redirect_uri={redirect_uri}" if vulnerable else "",
                    error="",
                    exploit="redirect_uri_manipulation" if vulnerable else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="redirect_uri",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_pkce_bypass_category(
    client: httpx.AsyncClient,
    authorize_url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[OAuthAttempt]:
    """Testa PKCE bypass."""

    results: list[OAuthAttempt] = []

    base = "response_type=code&client_id=test&redirect_uri=https://example.com/callback&state=test"

    tests = [
        (
            "no_code_challenge",
            f"{authorize_url}?{base}",
            "code_challenge ausente — PKCE nao obrigatorio",
        ),
        (
            "plain_method",
            f"{authorize_url}?{base}&code_challenge=test&code_challenge_method=plain",
            "code_challenge_method=plain aceito",
        ),
        (
            "short_verifier",
            f"{authorize_url}?{base}&code_challenge=a&code_challenge_method=S256",
            "code_verifier curto aceito",
        ),
        (
            "cross_client_code",
            f"{authorize_url}?{base}",
            "cross-client code reuse testado",
        ),
    ]

    for technique, test_url, details in tests:
        try:
            resp = await client.get(test_url, timeout=timeout, follow_redirects=True)

            body = resp.text

            body_lower = body.lower()

            is_error = any(
                kw in body_lower for kw in ["error", "invalid", "denied", "unsupported"]
            )

            has_auth_code = "code=" in body or "authorization_code" in body

            vulnerable = resp.status_code == 200 and not is_error and not has_auth_code

            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="pkce_bypass",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=details if vulnerable else "",
                    error="",
                    exploit="redirect_uri_manipulation" if vulnerable else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="pkce_bypass",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


async def _test_refresh_token_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[OAuthAttempt]:
    """Testa refresh token rotation bypass."""

    results: list[OAuthAttempt] = []

    token_url = urljoin(url, "/token")

    tests = [
        (
            "reuse_old_token",
            "grant_type=refresh_token&refresh_token=old_token",
            "reuse de refresh token antigo",
        ),
        (
            "old_token_valid",
            "grant_type=refresh_token&refresh_token=old_token",
            "token antigo ainda valido apos rotacao",
        ),
        (
            "concurrent_refresh",
            "grant_type=refresh_token&refresh_token=old_token",
            "refresh concorrente detectado",
        ),
        (
            "no_absolute_expiry",
            "grant_type=refresh_token&refresh_token=old_token",
            "sem expiracao absoluta no refresh token",
        ),
        (
            "no_family_tracking",
            "grant_type=refresh_token&refresh_token=old_token",
            "sem token family tracking",
        ),
    ]

    for technique, data, details in tests:
        try:
            resp = await client.post(
                token_url,
                content=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=timeout,
            )

            body = resp.text

            vulnerable = resp.status_code == 200 and "access_token" in body

            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="refresh_token",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=details if vulnerable else "",
                    error="",
                    exploit="redirect_uri_manipulation" if vulnerable else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                OAuthAttempt(
                    technique=technique,
                    category="refresh_token",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                )
            )

    return results


_CATEGORY_TESTERS: dict[str, Callable[..., Awaitable[list[OAuthAttempt]]]] = {
    "misconfig": _test_misconfig_category,
    "scope_escalation": _test_scope_escalation_category,
    "redirect_uri": _test_redirect_uri_category,
    "pkce_bypass": _test_pkce_bypass_category,
    "refresh_token": _test_refresh_token_category,
}


def print_results(result: OAuthResult) -> None:
    """Exibe os resultados do scan de OAuth."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(
        color("\n--- OAuth 2.0 Misconfiguration Detection ---", Cyber.CYAN, Cyber.BOLD)
    )

    print(color(f"  Alvo:      {result.target}", Cyber.WHITE))

    print(color(f"  TLS:       {'sim' if result.tls else 'nao'}", Cyber.WHITE))

    print(color(f"  Authorize: {result.authorize_url or 'auto-detect'}", Cyber.WHITE))

    print(
        color(
            f"  Baseline:  {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.WHITE,
        )
    )

    print(color(f"  Testes:    {len(result.attempts)}", Cyber.WHITE))

    print(color(f"  Vulneraveis: {len(vuln)}", Cyber.RED if vuln else Cyber.GREEN))

    print(color(f"  Bloqueados:  {len(blocked)}", Cyber.GRAY))

    print(color(f"  Erros:       {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if vuln:
        print(color("\n  [!] Vulnerabilidades encontradas:", Cyber.RED))

        seen: set[str] = set()

        for a in vuln:
            if a.technique in seen:
                continue

            seen.add(a.technique)

            print(color(f"    [{a.category}] {a.technique}", Cyber.RED))

            if a.details:
                print(color(f"      {a.details}", Cyber.GRAY))

            print_exploit_info(a.exploit, a.tool)

        print(
            color(
                f"\n  Total: {len(vuln)} vulneraveis de {len(result.attempts)} testes",
                Cyber.WHITE,
            )
        )

    else:
        print(color("\n  [+] Nenhuma vulnerabilidade OAuth detectada", Cyber.GREEN))

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
    """Executa o scan de OAuth Misconfiguration."""

    logger.info("OAuth scan para %s", target)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout) as client:
        try:
            b_status, _b_headers, b_body, _b_raw = await fetch(
                client, target, timeout=timeout
            )

            b_size = len(b_body)

        except Exception as e:
            print(color(f"Erro ao acessar {target}: {e}", Cyber.RED))

            return 1

        body_str = b_body.decode(errors="replace")

        authorize_url = _find_authorize_url(target, body_str)

        all_attempts: list[OAuthAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            tester = _CATEGORY_TESTERS.get(cat)

            if tester is None:
                continue

            try:
                if cat == "misconfig":
                    raw = await tester(
                        client,
                        authorize_url or target,
                        target,
                        timeout,
                        b_status,
                        b_size,
                    )

                elif cat == "refresh_token":
                    raw = await tester(client, target, timeout, b_status, b_size)

                else:
                    raw = await tester(
                        client, authorize_url or target, timeout, b_status, b_size
                    )

                all_attempts.extend(raw)

            except Exception as e:
                all_attempts.append(
                    OAuthAttempt(
                        technique=f"{cat}_error",
                        category=cat,
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )

        issues: list[str] = []

        if not all_attempts:
            issues.append("Nenhum teste de OAuth executado")

        if not authorize_url:
            issues.append("URL de authorize nao detectada — testando URL principal")

        result = OAuthResult(
            target=target,
            tls=tls,
            baseline_status=b_status,
            baseline_size=b_size,
            authorize_url=authorize_url,
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
            "OAuth scan concluido: %d testes, %d vulneraveis",
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

     ___ _

    / __| |_ __ _ __ __ _ _ _  __ _

    \__ \  _/ _` / _` | ' \/ _` |

    |___/\__\__,_\__, |_||_\__,_|

                  |___/

"""

    create_banner(
        art,
        "   oauth: misconfig, scope_escalation, redirect_uri, pkce_bypass, refresh_token",
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-oauth",
        description="OAuth 2.0 Misconfiguration — detecta misconfigurations, scope escalation, redirect URI bypass.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-oauth https://target.com/authorize\n"
            "  mytools-oauth https://target.com -c misconfig\n"
            "  mytools-oauth https://target.com -c redirect_uri\n"
            "  mytools-oauth https://target.com -c pkce_bypass\n"
            "  mytools-oauth https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo (authorize endpoint ou dominio)")

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=[
            "all",
            "misconfig",
            "scope_escalation",
            "redirect_uri",
            "pkce_bypass",
            "refresh_token",
        ],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan OAuth a partir de argumentos parseados."""

    logger.info("OAuth scan iniciado para %s", args.url)

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
    """Entry point do modulo OAuth 2.0 Misconfiguration."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="oauth> ",
        description="OAuth 2.0 Misconfiguration interativo.",
        example="https://target.com/authorize -c misconfig",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com/authorize\n"
            "  https://target.com -c misconfig\n"
            "  https://target.com -c redirect_uri\n"
            "  https://target.com -c pkce_bypass\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
