#!/usr/bin/env python3

"""Modulo de deteccao de Business Logic Attacks.



Testa se uma aplicacao web e vulneravel a ataques de logica de negocio:

  - integer_overflow: overflow em precos, descontos, quantidades, total, max_int

  - negative_quantity: quantidades negativas, zero, decimais, desconto negativo, refund abuse

  - race_condition: race conditions em checkout, double spend, race purchase/refund/apply



Fluxo:

  1. Envia request para a URL alvo (baseline)

  2. Detecta endpoint de checkout/pagamento

  3. Para cada categoria, envia payloads e verifica resposta

  4. Retorna resultado consolidado com severidade

"""

import argparse
import asyncio
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

logger = logging.getLogger("mytools.businesslogic")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "integer_overflow": [
        "price_overflow",
        "discount_overflow",
        "quantity_overflow",
        "negative_total",
        "max_int",
    ],
    "negative_quantity": [
        "negative_qty",
        "zero_qty",
        "decimal_qty",
        "negative_discount",
        "refund_abuse",
    ],
    "race_condition": [
        "concurrent_checkout",
        "double_spend",
        "race_purchase",
        "race_refund",
        "race_apply",
    ],
}


def _load_category_map() -> dict[str, list[str]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "businesslogic", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )

    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()


_OVERFLOW_PAYLOADS_DEFAULT: list[tuple[str, str, dict[str, str], list[str]]] = [
    (
        "price_overflow",
        "price=999999999999",
        {"price": "999999999999"},
        ["overflow", "total"],
    ),
    (
        "discount_overflow",
        "discount=999999",
        {"discount": "999999"},
        ["discount", "total"],
    ),
    ("quantity_overflow", "qty=999999999", {"qty": "999999999"}, ["quantity", "total"]),
    ("negative_total", "price=-1", {"price": "-1"}, ["total", "price"]),
    ("max_int", "price=2147483647", {"price": "2147483647"}, ["total", "price"]),
]


def _load_overflow_payloads() -> list[tuple[str, str, dict[str, str], list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "businesslogic",
        default={"overflow_payloads": [list(t) for t in _OVERFLOW_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "overflow_payloads", [list(t) for t in _OVERFLOW_PAYLOADS_DEFAULT]
        )
    ]


_OVERFLOW_PAYLOADS = _load_overflow_payloads()


_NEGATIVE_QTY_PAYLOADS_DEFAULT: list[tuple[str, str, dict[str, str], list[str]]] = [
    ("negative_qty", "qty=-1", {"qty": "-1"}, ["total", "qty"]),
    ("zero_qty", "qty=0", {"qty": "0"}, ["total", "qty"]),
    ("decimal_qty", "qty=0.5", {"qty": "0.5"}, ["total", "qty"]),
    ("negative_discount", "discount=-50", {"discount": "-50"}, ["discount", "total"]),
    (
        "refund_abuse",
        "refund=true&amount=99999",
        {"refund": "true", "amount": "99999"},
        ["refund", "amount"],
    ),
]


def _load_negative_qty_payloads() -> list[tuple[str, str, dict[str, str], list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "businesslogic",
        default={
            "negative_qty_payloads": [list(t) for t in _NEGATIVE_QTY_PAYLOADS_DEFAULT]
        },
    )

    return [
        tuple(x)
        for x in data.get(
            "negative_qty_payloads", [list(t) for t in _NEGATIVE_QTY_PAYLOADS_DEFAULT]
        )
    ]


_NEGATIVE_QTY_PAYLOADS = _load_negative_qty_payloads()


@dataclass(frozen=True, slots=True)
class BizLogicAttempt:
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
class BizLogicResult:
    target: str

    tls: bool

    baseline_status: int

    baseline_size: int

    checkout_url: str | None

    attempts: list[BizLogicAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def _find_checkout_url(url: str, body: str) -> str | None:
    """Tenta encontrar URL de checkout/pagamento."""

    import re

    patterns = [
        r'href=["\']([^"\']*?/checkout[^"\']*)["\']',
        r'href=["\']([^"\']*?/payment[^"\']*)["\']',
        r'href=["\']([^"\']*?/cart[^"\']*)["\']',
        r'action=["\']([^"\']*?/checkout[^"\']*)["\']',
        r'action=["\']([^"\']*?/payment[^"\']*)["\']',
        r'(https?://[^"\'<>\s]+/checkout[^"\'<>\s]*)',
    ]

    for pat in patterns:
        m = re.search(pat, body, re.IGNORECASE)

        if m:
            found = m.group(1)

            if found.startswith("http"):
                return found

            return urljoin(url, found)

    return None


async def _test_integer_overflow_category(
    client: httpx.AsyncClient,
    checkout_url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[BizLogicAttempt]:
    """Testa integer overflow em precos."""

    results: list[BizLogicAttempt] = []

    for technique, data, _fields, indicators in _OVERFLOW_PAYLOADS:
        try:
            resp = await client.post(
                checkout_url,
                content=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=timeout,
            )

            body = resp.text

            vulnerable = resp.status_code == 200 and any(
                ind in body.lower() for ind in indicators
            )

            results.append(
                BizLogicAttempt(
                    technique=technique,
                    category="integer_overflow",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=f"payload: {data}" if vulnerable else "",
                    error="",
                    exploit="price_quantity_manipulation" if vulnerable else "",
                    tool="wfuzz",
                )
            )

        except Exception as e:
            results.append(
                BizLogicAttempt(
                    technique=technique,
                    category="integer_overflow",
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


async def _test_negative_quantity_category(
    client: httpx.AsyncClient,
    checkout_url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[BizLogicAttempt]:
    """Testa negative quantity abuse."""

    results: list[BizLogicAttempt] = []

    for technique, data, _fields, indicators in _NEGATIVE_QTY_PAYLOADS:
        try:
            resp = await client.post(
                checkout_url,
                content=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=timeout,
            )

            body = resp.text

            vulnerable = resp.status_code == 200 and any(
                ind in body.lower() for ind in indicators
            )

            results.append(
                BizLogicAttempt(
                    technique=technique,
                    category="negative_quantity",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(body),
                    status_changed=resp.status_code != b_status,
                    size_changed=abs(len(body) - b_size) > 50,
                    vulnerable=vulnerable,
                    details=f"payload: {data}" if vulnerable else "",
                    error="",
                    exploit="price_quantity_manipulation" if vulnerable else "",
                    tool="wfuzz",
                )
            )

        except Exception as e:
            results.append(
                BizLogicAttempt(
                    technique=technique,
                    category="negative_quantity",
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


async def _test_race_condition_category(
    client: httpx.AsyncClient,
    checkout_url: str,
    timeout: float,
    b_status: int,
    b_size: int,
) -> list[BizLogicAttempt]:
    """Testa race conditions em checkout."""

    results: list[BizLogicAttempt] = []

    concurrent_count = 5

    data = "qty=1&price=10"

    base = checkout_url.rstrip("/")

    tests = [
        (
            "concurrent_checkout",
            concurrent_count,
            checkout_url,
            "qty=1&price=10&coupon=SAVE50",
        ),
        (
            "double_spend",
            concurrent_count,
            f"{base}/pay",
            "qty=1&price=10&payment_id=txn_123",
        ),
        ("race_purchase", concurrent_count, checkout_url, "qty=2&price=20"),
        ("race_refund", concurrent_count, f"{base}/refund", "order_id=123&refund=true"),
        ("race_apply", concurrent_count, f"{base}/apply", "coupon=SAVE50&qty=1"),
    ]

    for technique, count, endpoint, data in tests:
        try:
            tasks = [
                client.post(
                    endpoint,
                    content=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=timeout,
                )
                for _ in range(count)
            ]

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = sum(
                1
                for r in responses
                if isinstance(r, httpx.Response) and r.status_code == 200
            )

            vulnerable = success_count > 1

            results.append(
                BizLogicAttempt(
                    technique=technique,
                    category="race_condition",
                    status_baseline=b_status,
                    status_test=200 if success_count else 0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=success_count > 0,
                    size_changed=False,
                    vulnerable=vulnerable,
                    details=f"{success_count}/{count} requests bem-sucedidos"
                    if vulnerable
                    else "",
                    error="",
                    exploit="price_quantity_manipulation" if vulnerable else "",
                    tool="wfuzz",
                )
            )

        except Exception as e:
            results.append(
                BizLogicAttempt(
                    technique=technique,
                    category="race_condition",
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


_CATEGORY_TESTERS: dict[str, Callable[..., Awaitable[list[BizLogicAttempt]]]] = {
    "integer_overflow": _test_integer_overflow_category,
    "negative_quantity": _test_negative_quantity_category,
    "race_condition": _test_race_condition_category,
}


def print_results(result: BizLogicResult) -> None:
    """Exibe os resultados do scan de Business Logic."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- Business Logic Attack Detection ---", Cyber.CYAN, Cyber.BOLD))

    print(color(f"  Alvo:      {result.target}", Cyber.WHITE))

    print(color(f"  TLS:       {'sim' if result.tls else 'nao'}", Cyber.WHITE))

    print(color(f"  Checkout:  {result.checkout_url or 'auto-detect'}", Cyber.WHITE))

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
        print(
            color(
                "\n  [+] Nenhuma vulnerabilidade de Business Logic detectada",
                Cyber.GREEN,
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
    """Executa o scan de Business Logic Attacks."""

    logger.info("Business Logic scan para %s", target)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout) as client:
        try:
            b_status, _b_headers, b_body, _b_raw = await fetch(
                client, target, timeout=timeout
            )

            b_size = len(b_body)

        except Exception as e:
            logger.warning("Erro ao acessar %s: %s", target, e)

            return 1

        body_str = b_body.decode(errors="replace")

        checkout_url = _find_checkout_url(target, body_str)

        all_attempts: list[BizLogicAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            tester = _CATEGORY_TESTERS.get(cat)

            if tester is None:
                continue

            try:
                raw = await tester(
                    client, checkout_url or target, timeout, b_status, b_size
                )

                all_attempts.extend(raw)

            except Exception as e:
                all_attempts.append(
                    BizLogicAttempt(
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
            issues.append("Nenhum teste de Business Logic executado")

        if not checkout_url:
            issues.append(
                "Endpoint de checkout nao detectado â€” testando URL principal"
            )

        result = BizLogicResult(
            target=target,
            tls=tls,
            baseline_status=b_status,
            baseline_size=b_size,
            checkout_url=checkout_url,
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
            "Business Logic scan concluido: %d testes, %d vulneraveis",
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

    ____                      _ _               __  __

   | __ )  ___  __ _ ______ _(_) |_ ___  _ __  |  \/  | __ _ _ __   __ _

   |  _ \ / _ \/ _` |_  / _` | | __/ _ \| '__| | |\/| |/ _` | '_ \ / _` |

   | |_) |  __/ (_| |/ / (_| | | || (_) | |    | |  | | (_| | | | | (_| |

   |____/ \___|\__,_/___\__,_|_|\__\___/|_|    |_|  |_|\__,_|_| |_|\__,_|

"""

    create_banner(
        art, "   bizlogic: integer_overflow, negative_quantity, race_condition"
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-bizlogic",
        description="Business Logic Attack Detection â€” detecta integer overflow, negative quantity, race conditions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-bizlogic https://target.com/checkout\n"
            "  mytools-bizlogic https://target.com -c integer_overflow\n"
            "  mytools-bizlogic https://target.com -c negative_quantity\n"
            "  mytools-bizlogic https://target.com -c race_condition\n"
            "  mytools-bizlogic https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo (checkout ou pagamento)")

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=["all", "integer_overflow", "negative_quantity", "race_condition"],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Business Logic a partir de argumentos parseados."""

    logger.info("Business Logic scan iniciado para %s", args.url)

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
    """Entry point do modulo Business Logic Attack Detection."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="bizlogic> ",
        description="Business Logic Attack Detection interativo.",
        example="https://target.com/checkout -c race_condition",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com/checkout\n"
            "  https://target.com -c integer_overflow\n"
            "  https://target.com -c negative_quantity\n"
            "  https://target.com -c race_condition\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
