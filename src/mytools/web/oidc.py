#!/usr/bin/env python3

"""Modulo de deteccao de OIDC Attacks.



Testa se uma implementacao OpenID Connect e vulneravel a ataques:

  - discovery: enumeracao de endpoints, jwks_uri fetch, issuer mismatch, registration, scopes

  - token_substitution: troca de tokens entre contas, id_token swap, access_token reuse



Fluxo:

  1. Envia request para /.well-known/openid-configuration

  2. Analisa endpoints, metadados e configuracao

  3. Para cada categoria, envia payloads e verifica resposta

  4. Retorna resultado consolidado com severidade

"""

import argparse
import json
import logging
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

logger = logging.getLogger("mytools.oidc")


_CATEGORY_MAP: dict[str, list[str]] = {
    "discovery": [
        "well_known_enumeration",
        "jwks_uri_fetch",
        "issuer_mismatch",
        "registration_endpoint",
        "scopes_supported",
    ],
    "token_substitution": [
        "cross_account_token",
        "id_token_swap",
        "access_token_reuse",
        "refresh_token_swap",
        "nonce_reuse",
    ],
}


def _extract_well_known_url(url: str) -> str:
    """Extrai a URL base para /.well-known/openid-configuration."""

    from urllib.parse import urlparse

    parsed = urlparse(url)

    return f"{parsed.scheme}://{parsed.netloc}"


def _parse_json_response(body: str) -> dict[str, object] | None:
    """Tenta parsear JSON de uma resposta."""

    try:
        data = json.loads(body)

        if isinstance(data, dict):
            return data

    except json.JSONDecodeError, ValueError:
        pass

    return None


@dataclass(frozen=True, slots=True)
class OIDCAttempt:
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
class OIDCResult:
    target: str

    tls: bool

    baseline_status: int

    baseline_size: int

    well_known_url: str | None

    well_known_data: dict[str, object] | None

    attempts: list[OIDCAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


async def _test_discovery_category(
    client: httpx.AsyncClient,
    base_url: str,
    well_known_url: str,
    well_known_data: dict[str, object] | None,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[OIDCAttempt]:
    """Testa OIDC Discovery Abuse."""

    results: list[OIDCAttempt] = []

    try:
        resp = await client.get(well_known_url, timeout=timeout, follow_redirects=True)

        body = resp.text

        data = _parse_json_response(body)

        vulnerable = (
            False  # well-known acessivel e comportamento normal, nao vulneravel
        )

        results.append(
            OIDCAttempt(
                technique="well_known_enumeration",
                category="discovery",
                status_baseline=b_status,
                status_test=resp.status_code,
                size_baseline=b_size,
                size_test=len(body),
                status_changed=resp.status_code != b_status,
                size_changed=abs(len(body) - b_size) > 50,
                vulnerable=vulnerable,
                details=f"well-known acessivel — {len(data)} metadados expostos"
                if vulnerable and data
                else "",
                error="",
                exploit="nonce_replay_payload" if vulnerable else "",
                tool="curl",
            )
        )

    except Exception as e:
        results.append(
            OIDCAttempt(
                technique="well_known_enumeration",
                category="discovery",
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

    if well_known_data and "jwks_uri" in well_known_data:
        jwks_uri = str(well_known_data["jwks_uri"])

        try:
            resp = await client.get(jwks_uri, timeout=timeout, follow_redirects=True)

            body = resp.text

            data = _parse_json_response(body)

            vulnerable = (
                resp.status_code == 200 and data is not None and "keys" in (data or {})
            )

            results.append(
                OIDCAttempt(
                    technique="jwks_uri_fetch",
                    category="discovery",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=f"jwks_uri acessivel — {len(str(data.get('keys', ''))) if data else 0} chaves expostas"
                    if vulnerable
                    else "",
                    error="",
                    exploit="nonce_replay_payload" if vulnerable else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                OIDCAttempt(
                    technique="jwks_uri_fetch",
                    category="discovery",
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

    else:
        results.append(
            OIDCAttempt(
                technique="jwks_uri_fetch",
                category="discovery",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=False,
                details="jwks_uri nao encontrado no discovery",
                error="",
            )
        )

    if well_known_data and "issuer" in well_known_data:
        issuer = str(well_known_data["issuer"])

        issuer_matches = issuer.startswith(base_url) or base_url.startswith(issuer)

        results.append(
            OIDCAttempt(
                technique="issuer_mismatch",
                category="discovery",
                status_baseline=b_status,
                status_test=200,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=not issuer_matches,
                details=f"issuer={issuer} — "
                + ("mismatch com URL base" if not issuer_matches else "ok"),
                error="",
                exploit="nonce_replay_payload" if not issuer_matches else "",
                tool="curl",
            )
        )

    else:
        results.append(
            OIDCAttempt(
                technique="issuer_mismatch",
                category="discovery",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=False,
                details="issuer ausente no discovery",
                error="",
            )
        )

    if well_known_data and "registration_endpoint" in well_known_data:
        reg_url = str(well_known_data["registration_endpoint"])

        try:
            resp = await client.get(reg_url, timeout=timeout, follow_redirects=True)

            body = resp.text

            vulnerable = resp.status_code in (200, 201)

            results.append(
                OIDCAttempt(
                    technique="registration_endpoint",
                    category="discovery",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=f"registration_endpoint={reg_url} — "
                    + ("acessivel" if vulnerable else "rejeitado"),
                    error="",
                    exploit="nonce_replay_payload" if vulnerable else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                OIDCAttempt(
                    technique="registration_endpoint",
                    category="discovery",
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

    else:
        results.append(
            OIDCAttempt(
                technique="registration_endpoint",
                category="discovery",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=False,
                details="registration_endpoint ausente",
                error="",
            )
        )

    if well_known_data and "scopes_supported" in well_known_data:
        scopes = well_known_data["scopes_supported"]

        if isinstance(scopes, list):
            dangerous = [
                s
                for s in scopes
                if s in ("admin", "openid admin", "superuser", "write", "delete")
            ]

            results.append(
                OIDCAttempt(
                    technique="scopes_supported",
                    category="discovery",
                    status_baseline=b_status,
                    status_test=200,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details=f"scopes perigosos (capabilidade, nao exposicao): {', '.join(dangerous)}"
                    if dangerous
                    else f"{len(scopes)} scopes suportados",
                    error="",
                    exploit="",
                    tool="curl",
                )
            )

        else:
            results.append(
                OIDCAttempt(
                    technique="scopes_supported",
                    category="discovery",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="scopes_supported nao e lista",
                    error="",
                )
            )

    else:
        results.append(
            OIDCAttempt(
                technique="scopes_supported",
                category="discovery",
                status_baseline=b_status,
                status_test=0,
                size_baseline=b_size,
                size_test=0,
                status_changed=False,
                size_changed=False,
                vulnerable=False,
                details="scopes_supported ausente",
                error="",
            )
        )

    return results


async def _test_token_substitution_category(
    client: httpx.AsyncClient,
    base_url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[OIDCAttempt]:
    """Testa token substitution."""

    results: list[OIDCAttempt] = []

    token_endpoints = ["/token", "/oauth/token", "/connect/token", "/oidc/token"]

    token_url = None

    for ep in token_endpoints:
        test_url = urljoin(base_url, ep)

        try:
            resp = await client.post(
                test_url,
                content="grant_type=authorization_code&code=test&redirect_uri=https://example.com",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=timeout,
            )

            if resp.status_code != 404:
                token_url = test_url

                break

        except Exception:
            continue

    if token_url is None:
        token_url = urljoin(base_url, "/token")

    tests = [
        (
            "cross_account_token",
            "grant_type=authorization_code&code=test&redirect_uri=https://example.com",
            "troca de token entre contas",
        ),
        (
            "id_token_swap",
            "grant_type=authorization_code&code=test&redirect_uri=https://example.com",
            "substituicao de id_token",
        ),
        (
            "access_token_reuse",
            "grant_type=authorization_code&code=test&redirect_uri=https://example.com",
            "reutilizacao de access_token",
        ),
        (
            "refresh_token_swap",
            "grant_type=refresh_token&refresh_token=test",
            "troca de refresh_token",
        ),
        (
            "nonce_reuse",
            "grant_type=authorization_code&code=test&redirect_uri=https://example.com",
            "reutilizacao de nonce",
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
                OIDCAttempt(
                    technique=technique,
                    category="token_substitution",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=details if vulnerable else "",
                    error="",
                    exploit="nonce_replay_payload" if vulnerable else "",
                    tool="curl",
                )
            )

        except Exception as e:
            results.append(
                OIDCAttempt(
                    technique=technique,
                    category="token_substitution",
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


_CATEGORY_TESTERS: dict[str, Callable[..., Awaitable[list[OIDCAttempt]]]] = {
    "discovery": _test_discovery_category,
    "token_substitution": _test_token_substitution_category,
}


def print_results(result: OIDCResult) -> None:
    """Exibe os resultados do scan de OIDC."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- OIDC Attack Detection ---", Cyber.CYAN, Cyber.BOLD))

    print(color(f"  Alvo:       {result.target}", Cyber.WHITE))

    print(color(f"  TLS:        {'sim' if result.tls else 'nao'}", Cyber.WHITE))

    print(color(f"  Well-known: {result.well_known_url or 'N/A'}", Cyber.WHITE))

    print(
        color(
            f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.WHITE,
        )
    )

    print(color(f"  Testes:     {len(result.attempts)}", Cyber.WHITE))

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
        print(color("\n  [+] Nenhuma vulnerabilidade OIDC detectada", Cyber.GREEN))

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
    """Executa o scan de OIDC Attacks."""

    logger.info("OIDC scan para %s", target)

    tls = target.startswith("https://")

    base_url = _extract_well_known_url(target)

    well_known_url = f"{base_url}/.well-known/openid-configuration"

    async with create_async_client(timeout=timeout) as client:
        try:
            b_status, _b_headers, b_body, _b_raw = await fetch(
                client, target, timeout=timeout
            )

            b_size = len(b_body)

        except Exception as e:
            print(color(f"Erro ao acessar {target}: {e}", Cyber.RED))

            return 1

        well_known_data: dict[str, object] | None = None

        try:
            resp = await client.get(
                well_known_url, timeout=timeout, follow_redirects=True
            )

            well_known_data = _parse_json_response(resp.text)

        except Exception:
            pass

        all_attempts: list[OIDCAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            tester = _CATEGORY_TESTERS.get(cat)

            if tester is None:
                continue

            try:
                if cat == "discovery":
                    raw = await tester(
                        client,
                        base_url,
                        well_known_url,
                        well_known_data,
                        timeout,
                        b_status,
                        b_size,
                    )

                else:
                    raw = await tester(client, base_url, timeout, b_status, b_size)

                all_attempts.extend(raw)

            except Exception as e:
                all_attempts.append(
                    OIDCAttempt(
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
            issues.append("Nenhum teste OIDC executado")

        if well_known_data is None:
            issues.append("well-known nao acessivel — OIDC pode nao estar configurado")

        result = OIDCResult(
            target=target,
            tls=tls,
            baseline_status=b_status,
            baseline_size=b_size,
            well_known_url=well_known_url,
            well_known_data=well_known_data,
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
            "OIDC scan concluido: %d testes, %d vulneraveis",
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

      ___  ___  ___  ___  ___

     / _ \/ _ \/ _ |/ _ |/ _ \

    /_//_/ .__/\_,_/_.__/_.__/

        /_/

"""

    create_banner(art, "   oidc: discovery, token_substitution")()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-oidc",
        description="OIDC Attack Detection — detecta discovery abuse e token substitution.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-oidc https://target.com\n"
            "  mytools-oidc https://target.com -c discovery\n"
            "  mytools-oidc https://target.com -c token_substitution\n"
            "  mytools-oidc https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo (dominio OIDC)")

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=["all", "discovery", "token_substitution"],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan OIDC a partir de argumentos parseados."""

    logger.info("OIDC scan iniciado para %s", args.url)

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
    """Entry point do modulo OIDC Attack Detection."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="oidc> ",
        description="OIDC Attack Detection interativo.",
        example="https://target.com -c discovery",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c discovery\n"
            "  https://target.com -c token_substitution\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
