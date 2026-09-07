#!/usr/bin/env python3
"""Modulo de verificacao de vazamentos de emails (Email Breach Check).

Verifica se emails apareceram em vazamentos de dados usando multiplas fontes:
  - XposedOrNot (gratis, sem API key, 2 req/s)
  - LeakCheck (gratis, sem API key, 1 req/s)
  - HIBP (pago, API key necessaria, 10 req/min)

Fluxo por email:
  1. Consulta fontes gratuitas primeiro (XposedOrNot, LeakCheck)
  2. Se HIBP configurado, consulta tambem
  3. Mescla resultados sem duplicatas
  4. Exibe resumo colorido por severidade
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import quote

import httpx
from tqdm import tqdm

from mytools.core.utils import (
    Cyber,
    FetchError,
    RateLimiter,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    ensure_output_dir,
    fetch,
    init_scanner,
    print_exploit_info,
    print_json,
    print_table,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.emailbreachcheck")


XPOSEDORNOT_URL = "https://api.xposedornot.com/v1/check-email/{email}"
XPOSEDORNOT_ANALYTICS_URL = (
    "https://api.xposedornot.com/v1/breach-analytics?email={email}"
)
LEAKCHECK_URL = "https://leakcheck.io/api/public?check={email}"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

DEFAULT_SOURCES = ["xposedornot", "leakcheck"]

banner = create_banner(
    r"""
    ______               __  ______
   / ____/___  _________/ /_/ ____/_______ ___
  / /_  / __ \/ ___/ __  / / /_  / ___/ __ `__ \
 / __/ / /_/ / /  / /_/ / / __/ / /  / / / / / /
/_/    \____/_/   \__,_/_/_/  /_/   /_/ /_/ /_/
""",
    "Email Breach Check | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class EmailBreach:
    """Representa um vazamento encontrado para um email."""

    email: str
    breach_name: str
    breach_date: str = ""
    pwn_count: int = 0
    data_classes: str = ""
    source: str = ""
    exploit: str = ""
    tool: str = ""


async def _query_xposedornot(
    client: httpx.AsyncClient,
    email: str,
    timeout: float,
    rate_limiter: RateLimiter,
) -> list[EmailBreach]:
    """Consulta XposedOrNot."""
    await rate_limiter.wait()
    url = XPOSEDORNOT_URL.format(email=quote(email, safe=""))

    try:
        status, _headers, body, _ = await fetch(
            client,
            url,
            timeout=timeout,
            max_retries=1,
            rate_limiter=rate_limiter,
        )
    except FetchError:
        return []

    if status != 200:
        return []

    try:
        data = json.loads(body)
    except json.JSONDecodeError, ValueError:
        return []
    if not isinstance(data, dict):
        return []

    breaches_raw = data.get("breaches", [])
    if not breaches_raw:
        return []

    breaches: list[EmailBreach] = []
    exploit_url = f"https://haveibeenpwned.com/account/{email}"
    if isinstance(breaches_raw, list):
        for b in breaches_raw:
            if isinstance(b, str):
                breaches.append(
                    EmailBreach(
                        email=email,
                        breach_name=b,
                        source="xposedornot",
                        exploit=exploit_url,
                        tool="xposedornot",
                    )
                )
            elif isinstance(b, dict):
                breaches.append(
                    EmailBreach(
                        email=email,
                        breach_name=b.get("name", b.get("breach", "unknown")),
                        breach_date=b.get("date", b.get("breach_date", "")),
                        pwn_count=b.get("pwn_count", 0),
                        data_classes=b.get("data_classes", ""),
                        source="xposedornot",
                        exploit=exploit_url,
                        tool="xposedornot",
                    )
                )
    elif isinstance(breaches_raw, dict):
        breaches.extend(
            EmailBreach(
                email=email,
                breach_name=name,
                source="xposedornot",
                exploit=exploit_url,
                tool="xposedornot",
            )
            for name in breaches_raw
        )

    return breaches


async def _query_leakcheck(
    client: httpx.AsyncClient,
    email: str,
    timeout: float,
    rate_limiter: RateLimiter,
) -> list[EmailBreach]:
    """Consulta LeakCheck public API."""
    await rate_limiter.wait()
    url = LEAKCHECK_URL.format(email=quote(email, safe=""))

    try:
        status, _headers, body, _ = await fetch(
            client,
            url,
            timeout=timeout,
            max_retries=1,
            rate_limiter=rate_limiter,
        )
    except FetchError:
        return []

    if status != 200:
        return []

    try:
        data = json.loads(body)
    except json.JSONDecodeError, ValueError:
        return []
    if not isinstance(data, dict):
        return []

    if not data.get("success") or not data.get("found"):
        return []

    breaches: list[EmailBreach] = []
    exploit_url = f"https://haveibeenpwned.com/account/{email}"
    sources = data.get("sources", [])
    if isinstance(sources, list):
        for src in sources:
            if isinstance(src, dict):
                breaches.append(
                    EmailBreach(
                        email=email,
                        breach_name=src.get("name", "unknown"),
                        breach_date=src.get("date", ""),
                        source="leakcheck",
                        exploit=exploit_url,
                        tool="leakcheck",
                    )
                )
            elif isinstance(src, str):
                breaches.append(
                    EmailBreach(
                        email=email,
                        breach_name=src,
                        source="leakcheck",
                        exploit=exploit_url,
                        tool="leakcheck",
                    )
                )

    return breaches


async def _query_hibp(
    client: httpx.AsyncClient,
    email: str,
    api_key: str,
    timeout: float,
    rate_limiter: RateLimiter,
) -> list[EmailBreach]:
    """Consulta HaveIBeenPwned API v3 (requer API key)."""
    if not api_key:
        return []

    await rate_limiter.wait()
    url = HIBP_URL.format(email=quote(email, safe=""))

    try:
        status, _headers, body, _ = await fetch(
            client,
            url,
            timeout=timeout,
            max_retries=1,
            rate_limiter=rate_limiter,
            headers={"hibp-api-key": api_key},
        )
    except FetchError:
        return []

    if status == 404:
        return []
    if status != 200:
        return []

    try:
        items = json.loads(body)
    except json.JSONDecodeError, ValueError:
        return []

    if not isinstance(items, list):
        return []

    exploit_url = f"https://haveibeenpwned.com/account/{email}"
    breaches: list[EmailBreach] = [
        EmailBreach(
            email=email,
            breach_name=item.get("Name", "unknown"),
            breach_date=item.get("BreachDate", ""),
            pwn_count=item.get("PwnCount", 0),
            data_classes=", ".join(item.get("DataClasses") or []),
            source="hibp",
            exploit=exploit_url,
            tool="hibp",
        )
        for item in items
    ]

    return breaches


def _dedup_breaches(breaches: list[EmailBreach]) -> list[EmailBreach]:
    """Remove duplicatas por (email, breach_name), mantendo primeira ocorrencia."""
    seen: set[tuple[str, str]] = set()
    result: list[EmailBreach] = []
    for b in breaches:
        key = (b.email.lower(), b.breach_name.lower())
        if key not in seen:
            seen.add(key)
            result.append(b)
    return result


async def _query_email(
    client: httpx.AsyncClient,
    email: str,
    sources: list[str],
    api_keys: dict[str, str | None],
    timeout: float,
    rate_limiter: RateLimiter,
) -> list[EmailBreach]:
    """Consulta um email em todas as fontes configuradas."""
    all_breaches: list[EmailBreach] = []

    for source in sources:
        if source == "xposedornot":
            breaches = await _query_xposedornot(client, email, timeout, rate_limiter)
            all_breaches.extend(breaches)
        elif source == "leakcheck":
            breaches = await _query_leakcheck(client, email, timeout, rate_limiter)
            all_breaches.extend(breaches)
        elif source == "hibp":
            key = api_keys.get("hibp") or ""
            breaches = await _query_hibp(client, email, key, timeout, rate_limiter)
            all_breaches.extend(breaches)

    return all_breaches


async def check_breaches(
    emails: list[str],
    sources: list[str],
    api_keys: dict[str, str | None],
    timeout: float,
    concurrency: int,
    user_agent: str,
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 0.0,
) -> list[EmailBreach]:
    """Verifica vazamentos para lista de emails."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)

    logger.info("Emails: %d", len(emails))
    logger.info("Fontes: %s", ", ".join(sources))

    sem = asyncio.Semaphore(concurrency)
    all_breaches: list[EmailBreach] = []

    async def _check_one(email: str) -> list[EmailBreach]:
        async with sem:
            breaches = await _query_email(
                client, email, sources, api_keys, timeout, rate_limiter
            )
            pbar.update(1)
            return breaches

    pbar = tqdm(
        total=len(emails), desc="  Emails verificados", leave=False, file=sys.stderr
    )
    try:
        async with asyncio.TaskGroup() as tg:
            futures = [tg.create_task(_check_one(e)) for e in emails]
        for f in futures:
            all_breaches.extend(f.result())
    finally:
        pbar.close()
        await client.aclose()

    all_breaches = _dedup_breaches(all_breaches)

    elapsed = time.monotonic() - started
    n_found = len({b.email for b in all_breaches})
    n_breaches = len(all_breaches)
    logger.info(
        "Finalizado em %.2fs. Emails com vazamentos: %d/%d. Total de vazamentos: %d",
        elapsed,
        n_found,
        len(emails),
        n_breaches,
    )

    return all_breaches


def print_results(breaches: list[EmailBreach]) -> None:
    """Imprime tabela resumo dos vazamentos encontrados."""
    if not breaches:
        print(
            color(
                "\nNenhum vazamento encontrado para os emails verificados.", Cyber.GREEN
            )
        )
        return

    print(color("\n  Vazamentos Encontrados", Cyber.RED, Cyber.BOLD))

    hdrs = ("EMAIL", "VAZAMENTO", "DATA", "REGISTROS", "DADOS", "FONTE")
    rows: list[tuple[str, ...]] = [
        (
            b.email,
            b.breach_name[:30],
            b.breach_date or "-",
            str(b.pwn_count) if b.pwn_count else "-",
            b.data_classes[:30] or "-",
            b.source,
        )
        for b in breaches
    ]

    def _row_styles(_row: tuple[str, ...]) -> list[tuple[str, ...]]:
        return [
            (Cyber.WHITE,),
            (Cyber.RED, Cyber.BOLD),
            (Cyber.YELLOW,),
            (Cyber.CYAN,),
            (Cyber.GRAY,),
            (Cyber.MAGENTA,),
        ]

    print_table(
        headers=hdrs,
        rows=rows,
        empty_message="Nenhum vazamento encontrado.",
        alignments=["left", "left", "left", "right", "left", "left"],
        row_styles_fn=_row_styles,
    )

    for b in breaches:
        print_exploit_info(b.exploit, b.tool)


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Verificacao de vazamentos de emails (Email Breach Check).",
    )
    add_common_args(parser, "osint")
    parser.add_argument("emails", nargs="*", help="Email(s) para consultar.")
    parser.add_argument(
        "-f", "--file", dest="email_file", help="Arquivo com emails (um por linha)."
    )
    parser.add_argument(
        "--source",
        action="append",
        choices=["xposedornot", "leakcheck", "hibp"],
        dest="sources",
        help="Fonte para consulta (pode repetir). Padrao: xposedornot,leakcheck.",
    )
    parser.add_argument(
        "--hibp-api-key",
        dest="hibp_api_key",
        help="API key do HaveIBeenPwned (obrigatoria para --source hibp).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Concorrencia assincrona. Padrao: 5",
    )
    return parser


def _load_emails(args: argparse.Namespace) -> list[str]:
    """Carrega emails de args.emails + arquivo."""
    emails = list(args.emails) if args.emails else []

    email_file = getattr(args, "email_file", None)
    if email_file:
        try:
            with Path(email_file).open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and "@" in line:
                        emails.append(line)
        except FileNotFoundError:
            logger.error("Arquivo nao encontrado: %s", email_file)

    return list(dict.fromkeys(emails))


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)
    emails = _load_emails(args)

    if not emails:
        logger.error(
            "Nenhum email informado. Use: mytools-breach email1@example.com email2@example.com"
        )
        return 1

    if getattr(args, "dry_run", False):
        logger.warning("Nenhuma requisicao HTTP sera enviada.")
        for email in emails:
            logger.info("Email: %s", email)
        return 0

    sources = args.sources or list(DEFAULT_SOURCES)
    api_keys: dict[str, str | None] = {
        "hibp": getattr(args, "hibp_api_key", None),
    }

    for s in sources:
        if s == "hibp" and not api_keys.get(s):
            logger.warning("hibp requer API key (use --hibp-api-key)")

    breaches = await check_breaches(
        emails=emails,
        sources=sources,
        api_keys=api_keys,
        timeout=args.timeout,
        concurrency=getattr(args, "concurrency", 5),
        user_agent=args.user_agent,
        proxy=args.proxy,
        verify=getattr(args, "verify", False),
        requests_per_second=args.delay,
    )

    if getattr(args, "json_output", False):
        print_json([asdict(b) for b in breaches])
    elif not quiet:
        print_results(breaches)

    if getattr(args, "output_dir", None):
        out_path = f"{args.output_dir}/emails.json"
        ensure_output_dir(args.output_dir)
        write_output(
            out_path,
            [asdict(b) for b in breaches],
            [
                "email",
                "breach_name",
                "breach_date",
                "pwn_count",
                "data_classes",
                "source",
            ],
            quiet=quiet,
        )

    if args.output:
        write_output(
            args.output,
            [asdict(b) for b in breaches],
            [
                "email",
                "breach_name",
                "breach_date",
                "pwn_count",
                "data_classes",
                "source",
            ],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Email Breach Check."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.emails or getattr(a, "email_file", None)),
        prompt="breach> ",
        description="Email Breach Check interativo.",
        example="user@example.com --source xposedornot",
        contextual_help=(
            "Uso: <emails...> [opcoes]\n"
            "Exemplos:\n"
            "  user@example.com\n"
            "  user1@test.com user2@test.com\n"
            "  user@example.com --source hibp --hibp-api-key KEY\n"
            "  -f emails.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
