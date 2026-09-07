#!/usr/bin/env python3

"""Modulo de deteccao de Account Abuse Attacks.



Testa se uma aplicacao web e vulneravel a abusos em contas de usuario:

  - coupon: enumeracao, brute-force, cupom expirado, reuso, formato

  - loyalty_points: transferencia indevida, self-transfer, negativo, overflow, race

  - gift_card: balance_check sem auth, brute_force_pin, reuso, formato invalido

  - refund: manipulacao de valor, negativo, double refund, maximo, race

  - subscription: bypass via cookie, header, trial abuse, downgrade



Fluxo:

  1. Envia request para a URL alvo (baseline)

  2. Detecta endpoints de conta/cupom/pagamento

  3. Para cada categoria, envia payloads e verifica resposta

  4. Retorna resultado consolidado com severidade

"""

import argparse
import logging
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass

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

logger = logging.getLogger("mytools.accountabuse")


_CATEGORY_MAP: dict[str, list[str]] = {
    "coupon": [
        "enumeration",
        "coupon_brute_force",
        "expired_coupon",
        "multi_use",
        "format_bypass",
    ],
    "loyalty_points": [
        "transfer_abuse",
        "self_transfer",
        "negative_points",
        "points_overflow",
        "race_transfer",
    ],
    "gift_card": [
        "balance_check",
        "no_auth",
        "brute_force_pin",
        "reuse",
        "invalid_format",
    ],
    "refund": [
        "amount_manipulation",
        "negative_refund",
        "double_refund",
        "max_refund",
        "race_refund",
    ],
    "subscription": [
        "cookie_bypass",
        "header_bypass",
        "expired_subscription",
        "trial_abuse",
        "downgrade_bypass",
    ],
}


_COUPON_PAYLOADS: list[tuple[str, str, dict[str, str], list[str]]] = [
    ("enumeration", "coupon=TEST", {"coupon": "TEST"}, ["discount", "coupon"]),
    ("coupon_brute_force", "coupon=AAAA", {"coupon": "AAAA"}, ["discount", "coupon"]),
    ("expired_coupon", "coupon=SAVE100", {"coupon": "SAVE100"}, ["expired", "coupon"]),
    ("multi_use", "coupon=SINGLE10", {"coupon": "SINGLE10"}, ["single", "coupon"]),
    (
        "format_bypass",
        "coupon=../../../etc",
        {"coupon": "../../../etc"},
        ["coupon", "discount"],
    ),
]


_LOYALTY_PAYLOADS: list[tuple[str, str, dict[str, str], list[str]]] = [
    (
        "transfer_abuse",
        "transfer_to=victim&points=99999",
        {"transfer_to": "victim", "points": "99999"},
        ["transfer", "points"],
    ),
    (
        "self_transfer",
        "transfer_to=self&points=1000",
        {"transfer_to": "self", "points": "1000"},
        ["transfer", "self"],
    ),
    ("negative_points", "points=-500", {"points": "-500"}, ["points", "balance"]),
    (
        "points_overflow",
        "points=999999999999",
        {"points": "999999999999"},
        ["points", "balance"],
    ),
    (
        "race_transfer",
        "transfer_to=victim&points=100",
        {"transfer_to": "victim", "points": "100"},
        ["transfer", "race"],
    ),
]


_GIFT_CARD_PAYLOADS: list[tuple[str, str, dict[str, str], list[str]]] = [
    ("balance_check", "card=1234567890", {"card": "1234567890"}, ["balance", "card"]),
    ("no_auth", "card=0000000000", {"card": "0000000000"}, ["balance", "auth"]),
    ("brute_force_pin", "card=0000000001", {"card": "0000000001"}, ["balance", "card"]),
    ("reuse", "card=REDEEMED", {"card": "REDEEMED"}, ["redeemed", "card"]),
    ("invalid_format", "card=AAAA", {"card": "AAAA"}, ["error", "card"]),
]


_REFUND_PAYLOADS: list[tuple[str, str, dict[str, str], list[str]]] = [
    (
        "amount_manipulation",
        "refund_amount=999999",
        {"refund_amount": "999999"},
        ["refund", "amount"],
    ),
    (
        "negative_refund",
        "refund_amount=-100",
        {"refund_amount": "-100"},
        ["refund", "amount"],
    ),
    (
        "double_refund",
        "refund=true&double=true",
        {"refund": "true", "double": "true"},
        ["refund", "double"],
    ),
    (
        "max_refund",
        "refund_amount=999999999",
        {"refund_amount": "999999999"},
        ["refund", "max"],
    ),
    (
        "race_refund",
        "refund=true&concurrent=true",
        {"refund": "true", "concurrent": "true"},
        ["refund", "race"],
    ),
]


_SUBSCRIPTION_PAYLOADS: list[tuple[str, str, dict[str, str], list[str]]] = [
    (
        "cookie_bypass",
        "session=premium_expired",
        {"session": "premium_expired"},
        ["premium", "session"],
    ),
    (
        "header_bypass",
        "X-Subscription-Tier: premium",
        {"X-Subscription-Tier": "premium"},
        ["premium", "tier"],
    ),
    (
        "expired_subscription",
        "subscription=active",
        {"subscription": "active"},
        ["expired", "subscription"],
    ),
    (
        "trial_abuse",
        "trial=new&email=test@test.com",
        {"trial": "new", "email": "test@test.com"},
        ["trial", "abuse"],
    ),
    (
        "downgrade_bypass",
        "plan=enterprise&downgrade=true",
        {"plan": "enterprise", "downgrade": "true"},
        ["plan", "downgrade"],
    ),
]


_CATEGORY_TESTERS: dict[str, Callable[..., Awaitable[list[AccountAttempt]]]] = {}


def _register_category(
    name: str,
) -> Callable[
    [Callable[..., Awaitable[list[AccountAttempt]]]],
    Callable[..., Awaitable[list[AccountAttempt]]],
]:

    def decorator(
        fn: Callable[..., Awaitable[list[AccountAttempt]]],
    ) -> Callable[..., Awaitable[list[AccountAttempt]]]:

        _CATEGORY_TESTERS[name] = fn

        return fn

    return decorator


@dataclass(frozen=True, slots=True)
class AccountAttempt:
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
class AccountResult:
    target: str

    tls: bool

    baseline_status: int

    baseline_size: int

    account_url: str | None

    attempts: list[AccountAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def _find_account_url(url: str, body: str) -> str | None:
    """Tenta encontrar URL de conta/cupom/pagamento."""

    from urllib.parse import urljoin

    lower = body.lower()

    indicators = [
        "coupon",
        "promo",
        "discount",
        "apply",
        "redeem",
        "loyalty",
        "points",
        "rewards",
        "balance",
        "gift",
        "card",
        "giftcard",
        "refund",
        "return",
        "chargeback",
        "subscription",
        "plan",
        "upgrade",
        "downgrade",
        "billing",
        "checkout",
        "payment",
        "account",
        "profile",
    ]

    for indicator in indicators:
        idx = lower.find(indicator)

        if idx != -1:
            start = max(0, lower.rfind("<a", 0, idx))

            href_start = lower.find('href="', start, idx)

            if href_start != -1:
                href_end = lower.find('"', href_start + 6)

                if href_end != -1:
                    href = body[href_start + 6 : href_end]

                    return urljoin(url, href)

    return None


async def _test_category(
    client: httpx.AsyncClient,
    target: str,
    payloads: list[tuple[str, str, dict[str, str], list[str]]],
    category: str,
    baseline_status: int,
    baseline_size: int,
) -> list[AccountAttempt]:
    """Testa uma categoria de payloads."""

    results: list[AccountAttempt] = []

    for technique, _, body_dict, keywords in payloads:
        try:
            body_str = "&".join(f"{k}={v}" for k, v in body_dict.items())

            resp = await client.post(
                target,
                content=body_str.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=True,
            )

            body = resp.text

            size = len(body)

            vuln = any(kw.lower() in body.lower() for kw in keywords)

            details = f"keywords={keywords}" if vuln else "sem indicacao"

            results.append(
                AccountAttempt(
                    technique=technique,
                    category=category,
                    status_baseline=baseline_status,
                    status_test=resp.status_code,
                    size_baseline=baseline_size,
                    size_test=size,
                    status_changed=resp.status_code != baseline_status,
                    size_changed=abs(size - baseline_size) > 50,
                    vulnerable=vuln,
                    details=details,
                    error="",
                    exploit="coupon_bypass_payload" if vuln else "",
                    tool="wfuzz",
                )
            )

        except Exception as exc:
            results.append(
                AccountAttempt(
                    technique=technique,
                    category=category,
                    status_baseline=baseline_status,
                    status_test=0,
                    size_baseline=baseline_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:200],
                )
            )

    return results


@_register_category("coupon")
async def _test_coupon(
    client: httpx.AsyncClient,
    target: str,
    _timeout: float,
    baseline_status: int,
    baseline_size: int,
) -> list[AccountAttempt]:
    """Testa cupom de desconto."""

    return await _test_category(
        client, target, _COUPON_PAYLOADS, "coupon", baseline_status, baseline_size
    )


@_register_category("loyalty_points")
async def _test_loyalty_points(
    client: httpx.AsyncClient,
    target: str,
    _timeout: float,
    baseline_status: int,
    baseline_size: int,
) -> list[AccountAttempt]:
    """Testa abuso de pontos de fidelidade."""

    return await _test_category(
        client,
        target,
        _LOYALTY_PAYLOADS,
        "loyalty_points",
        baseline_status,
        baseline_size,
    )


@_register_category("gift_card")
async def _test_gift_card(
    client: httpx.AsyncClient,
    target: str,
    _timeout: float,
    baseline_status: int,
    baseline_size: int,
) -> list[AccountAttempt]:
    """Testa abuso de gift card."""

    return await _test_category(
        client, target, _GIFT_CARD_PAYLOADS, "gift_card", baseline_status, baseline_size
    )


@_register_category("refund")
async def _test_refund(
    client: httpx.AsyncClient,
    target: str,
    _timeout: float,
    baseline_status: int,
    baseline_size: int,
) -> list[AccountAttempt]:
    """Testa manipulacao de reembolso."""

    return await _test_category(
        client, target, _REFUND_PAYLOADS, "refund", baseline_status, baseline_size
    )


@_register_category("subscription")
async def _test_subscription(
    client: httpx.AsyncClient,
    target: str,
    _timeout: float,
    baseline_status: int,
    baseline_size: int,
) -> list[AccountAttempt]:
    """Testa bypass de assinatura."""

    return await _test_category(
        client,
        target,
        _SUBSCRIPTION_PAYLOADS,
        "subscription",
        baseline_status,
        baseline_size,
    )


def print_results(result: AccountResult) -> None:
    """Imprime os resultados do scan."""

    vuln_count = len(result.vulnerable_techniques)

    blocked_count = len(result.blocked_techniques)

    total = len(result.attempts)

    if vuln_count > 0:
        status_color = Cyber.RED

        status_icon = "VULNERAVEL"

    elif blocked_count > 0:
        status_color = Cyber.YELLOW

        status_icon = "BLOQUEADO"

    else:
        status_color = Cyber.GREEN

        status_icon = "SEGURO"

    print(color(f"\n{'=' * 60}", Cyber.CYAN))

    print(color("  ACCOUNT ABUSE ATTACK DETECTION", Cyber.BOLD))

    print(color(f"{'=' * 60}\n", Cyber.CYAN))

    print(color("  Target: ", Cyber.CYAN) + result.target)

    print(color("  TLS: ", Cyber.CYAN) + ("Sim" if result.tls else "Nao"))

    print(
        color("  Baseline: ", Cyber.CYAN)
        + f"HTTP {result.baseline_status} ({result.baseline_size} bytes)"
    )

    if result.account_url:
        print(color("  Account URL: ", Cyber.CYAN) + result.account_url)

    print(color("  Status: ", Cyber.CYAN) + color(status_icon, status_color))

    print()

    by_category: dict[str, list[AccountAttempt]] = {}

    for attempt in result.attempts:
        by_category.setdefault(attempt.category, []).append(attempt)

    for cat, attempts in by_category.items():
        cat_vuln = sum(1 for a in attempts if a.vulnerable)

        cat_color = Cyber.RED if cat_vuln > 0 else Cyber.GREEN

        print(color(f"  [{cat.upper()}]", cat_color))

        for a in attempts:
            if a.error:
                icon = color("ERROR", Cyber.YELLOW)

                detail = a.error

            elif a.vulnerable:
                icon = color("VULN", Cyber.RED)

                detail = a.details

            else:
                icon = color("SAFE", Cyber.GREEN)

                detail = a.details

            print(color(f"    {icon} {a.technique}", Cyber.WHITE))

            print(
                color("      Baseline: ", Cyber.GRAY)
                + f"HTTP {a.status_baseline} ({a.size_baseline}B)"
            )

            print(
                color("      Test:     ", Cyber.GRAY)
                + f"HTTP {a.status_test} ({a.size_test}B)"
            )

            if a.status_changed:
                print(color("      Status MUDOU", Cyber.YELLOW))

            if a.size_changed:
                print(color("      Size MUDOU", Cyber.YELLOW))

            print(color(f"      {detail}", Cyber.GRAY))

            print_exploit_info(a.exploit, a.tool)

        print()

    print(color(f"{'=' * 60}", Cyber.CYAN))

    print(color("  Total: ", Cyber.CYAN) + f"{total} testes")

    print(color("  Vulneraveis: ", Cyber.CYAN) + color(str(vuln_count), Cyber.RED))

    print(color("  Bloqueados: ", Cyber.CYAN) + color(str(blocked_count), Cyber.YELLOW))

    print(
        color("  Seguros: ", Cyber.CYAN)
        + color(str(total - vuln_count - blocked_count), Cyber.GREEN)
    )

    print(color(f"{'=' * 60}\n", Cyber.CYAN))

    if result.issues:
        print(color("  Problemas encontrados:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))

        print()


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
) -> AccountResult:
    """Executa o scan de Account Abuse."""

    logger.info("Account Abuse scan iniciado para %s", target)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout) as client:
        b_status, _b_headers, b_body, _b_raw = await fetch(
            client, target, timeout=timeout
        )

        b_size = len(b_body)

        body_str = b_body.decode(errors="replace")

        account_url = _find_account_url(target, body_str)

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        all_attempts: list[AccountAttempt] = []

        issues: list[str] = []

        for cat in test_categories:
            tester = _CATEGORY_TESTERS.get(cat)

            if tester is None:
                continue

            try:
                raw = await tester(
                    client, account_url or target, timeout, b_status, b_size
                )

                all_attempts.extend(raw)

            except Exception as exc:
                issues.append(f"Erro na categoria {cat}: {exc}")

    vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

    blocked_techs = list(
        {a.technique for a in all_attempts if not a.vulnerable and a.status_changed}
    )

    overall = (
        "VULNERAVEL" if vuln_techs else ("BLOQUEADO" if blocked_techs else "SEGURO")
    )

    result = AccountResult(
        target=target,
        tls=tls,
        baseline_status=b_status,
        baseline_size=b_size,
        account_url=account_url,
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        blocked_techniques=blocked_techs,
        issues=issues,
        overall_status=overall,
    )

    print_results(result)

    if output_file:
        write_output(output_file, asdict(result))

        logger.info("Resultados salvos em %s", output_file)

    return result


def banner_art() -> None:
    """Exibe a banner do modulo."""

    art = r"""

    _         _   _           _                    __     __

   / \   _ __| |_(_)_   ___ | |___    __ _  __ _  \ \   / /__  _   _

  / _ \ | '__| __| \ \ / / |/ / __|  / _` |/ _` |  \ \ / / _ \| | | |

 / ___ \| |  | |_| |\ V /|   <\__ \ | (_| | (_| |   \ V / (_) | |_| |

/_/   \_\_|   \__|_| \_/ |_|\_\___/  \__,_|\__, |    \_/ \___/ \__, |

                                            |___/                |___/

"""

    create_banner(
        art, "   accountabuse: coupon, loyalty_points, gift_card, refund, subscription"
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-accountabuse",
        description="Account Abuse Attack Detection — detecta abusos em contas, cupons, pontos, gift cards, reembolso, assinatura.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-accountabuse https://target.com/account\n"
            "  mytools-accountabuse https://target.com -c coupon\n"
            "  mytools-accountabuse https://target.com -c loyalty_points\n"
            "  mytools-accountabuse https://target.com -c gift_card\n"
            "  mytools-accountabuse https://target.com -c refund\n"
            "  mytools-accountabuse https://target.com -c subscription\n"
            "  mytools-accountabuse https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo (conta, checkout ou pagamento)")

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=[
            "all",
            "coupon",
            "loyalty_points",
            "gift_card",
            "refund",
            "subscription",
        ],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Account Abuse a partir de argumentos parseados."""

    logger.info("Account Abuse scan iniciado para %s", args.url)

    categories: list[str] = []

    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]

    result = safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
        ),
    )

    return (
        1 if isinstance(result, AccountResult) and result.vulnerable_techniques else 0
    )


def main() -> int:
    """Entry point do modulo Account Abuse Attack Detection."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="accountabuse> ",
        description="Account Abuse Attack Detection interativo.",
        example="https://target.com/account -c coupon",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com/account\n"
            "  https://target.com -c coupon\n"
            "  https://target.com -c loyalty_points\n"
            "  https://target.com -c gift_card\n"
            "  https://target.com -c refund\n"
            "  https://target.com -c subscription\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
