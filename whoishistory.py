#!/usr/bin/env python3
"""Consulta historico de WHOIS de um dominio via APIs OSINT.

Fontes suportadas:
  - SecurityTrails (gratuito, 50 req/mes): historico completo de WHOIS
  - WhoisXML API (500 credits free): historico detalhado com raw text

Fluxo principal:
  1. Consulta a fonte selecionada via API HTTP
  2. Parseia a resposta JSON em WhoisHistoryRecord
  3. Consolida, ordena por data e exibe tabela
  4. Salva saida em JSON se --output especificado
"""
import argparse
import contextlib
import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import UTC

from utils import (
    Cyber,
    FetchError,
    add_base_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    init_scanner,
    print_table,
    run_main_loop,
    write_output,
)

logger = logging.getLogger("mytools.whoishistory")

BANNER_ART = r"""
 _    _  ___  ______  _____ ______  ________  ___
| |  | |/ _ \ | ___ \/  ___||  ___| |_   _|  \/  |
| |/\| / /_\ \| |_/ /\ `--. | |_      | | | .  . |
\  /\  |  _  |    /  `--. \|  _|     | | | |\/| |
 \/  \__| | | | |\ \ /\__/ /| |     _| |_| |  | |
     \__/\_| |_\_| \_|\____/ \_|     \___/\_|  |_/
"""

DEFAULT_TIMEOUT = 15.0


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WhoisHistoryRecord:
    """Um registro historico de WHOIS."""

    domain: str
    date: str
    registrar: str = ""
    registrant_name: str = ""
    registrant_org: str = ""
    registrant_country: str = ""
    name_servers: str = ""
    status: str = ""
    created_date: str = ""
    expires_date: str = ""
    updated_date: str = ""
    source: str = ""


# ---------------------------------------------------------------------------
# SecurityTrails
# ---------------------------------------------------------------------------

_ST_URL = "https://api.securitytrails.com/v1/history/{domain}/whois"


def _parse_securitytrails(body: bytes, domain: str) -> list[WhoisHistoryRecord]:
    """Parseia resposta JSON do SecurityTrails WHOIS History API."""
    try:
        data = json.loads(body)
    except ValueError:
        return []

    records: list[WhoisHistoryRecord] = []
    items = data.get("result", {}).get("items", [])

    for item in items:
        ended = item.get("ended")
        date_str = ""
        if ended:
            from datetime import datetime

            try:
                date_str = datetime.fromtimestamp(ended / 1000, tz=UTC).strftime("%Y-%m-%d")
            except ValueError, OSError:
                date_str = str(ended)

        ns_list = item.get("nameServers", [])
        name_servers = ", ".join(ns_list[:5])

        registrant_name = ""
        registrant_org = ""
        registrant_country = ""
        registrar = ""
        for contact in item.get("contact", []):
            ctype = contact.get("type", "")
            if ctype == "registrant":
                registrant_name = contact.get("name", "")
                registrant_org = contact.get("organization", "")
                registrant_country = contact.get("country", "")
            if not registrar and contact.get("organization"):
                registrar = contact.get("organization", "")

        created = ""
        if item.get("createdDate"):
            from datetime import datetime

            with contextlib.suppress(ValueError, OSError):
                created = datetime.fromtimestamp(item["createdDate"] / 1000, tz=UTC).strftime("%Y-%m-%d")

        expires = ""
        if item.get("expiresDate"):
            from datetime import datetime

            with contextlib.suppress(ValueError, OSError):
                expires = datetime.fromtimestamp(item["expiresDate"] / 1000, tz=UTC).strftime("%Y-%m-%d")

        records.append(WhoisHistoryRecord(
            domain=domain,
            date=date_str,
            registrar=registrar,
            registrant_name=registrant_name,
            registrant_org=registrant_org,
            registrant_country=registrant_country,
            name_servers=name_servers,
            created_date=created,
            expires_date=expires,
            source="securitytrails",
        ))

    return records


# ---------------------------------------------------------------------------
# WhoisXML API
# ---------------------------------------------------------------------------

_WHOISXML_URL = "https://whois-history.whoisxmlapi.com/api/v1"


def _parse_whoisxml(body: bytes, domain: str) -> list[WhoisHistoryRecord]:
    """Parseia resposta JSON do WhoisXML History API."""
    try:
        data = json.loads(body)
    except ValueError:
        return []

    records: list[WhoisHistoryRecord] = []

    for item in data.get("records", []):
        date_str = ""
        created = item.get("createdDateISO8601", "")
        if created:
            date_str = created[:10]

        registrant = item.get("registrantContact", {}) or {}
        registrant_name = registrant.get("name", "")
        registrant_org = registrant.get("organization", "")
        registrant_country = registrant.get("country", "")

        ns_list = item.get("nameServers", [])
        name_servers = ", ".join(ns_list[:5])

        statuses = item.get("status", [])
        status_str = ", ".join(statuses[:3]) if isinstance(statuses, list) else str(statuses)

        expires = item.get("expiresDateISO8601", "")[:10] if item.get("expiresDateISO8601") else ""
        updated = item.get("updatedDateISO8601", "")[:10] if item.get("updatedDateISO8601") else ""

        records.append(WhoisHistoryRecord(
            domain=domain,
            date=date_str,
            registrar=item.get("registrarName", ""),
            registrant_name=registrant_name,
            registrant_org=registrant_org,
            registrant_country=registrant_country,
            name_servers=name_servers,
            status=status_str,
            created_date=created[:10] if created else "",
            expires_date=expires,
            updated_date=updated,
            source="whoisxml",
        ))

    return records


# ---------------------------------------------------------------------------
# Query dispatcher
# ---------------------------------------------------------------------------


async def _query_source(
    source: str,
    domain: str,
    api_key: str | None,
    timeout: float,
) -> list[WhoisHistoryRecord]:
    """Consulta uma unica fonte e retorna registros historicos."""
    client = create_async_client(timeout=timeout)
    try:
        if source == "securitytrails":
            if not api_key:
                logger.debug("SecurityTrails precisa de API key")
                return []
            url = _ST_URL.format(domain=domain)
            status, _headers, body, _raw = await fetch(client, url, timeout=timeout)
            if status == 200:
                return _parse_securitytrails(body, domain)
            if status == 429:
                logger.debug("SecurityTrails rate limited para %s", domain)
                return []
            logger.debug("SecurityTrails retornou %d para %s", status, domain)
            return []

        if source == "whoisxml":
            if not api_key:
                logger.debug("WhoisXML precisa de API key")
                return []
            url = f"{_WHOISXML_URL}?apiKey={api_key}&domainName={domain}&mode=purchase"
            status, _headers, body, _raw = await fetch(client, url, timeout=timeout)
            if status == 200:
                return _parse_whoisxml(body, domain)
            logger.debug("WhoisXML retornou %d para %s", status, domain)
            return []

        return []
    except FetchError as exc:
        logger.debug("Erro ao consultar %s para %s: %s", source, domain, exc)
        return []
    finally:
        await client.aclose()


async def _query_all_sources(
    domain: str,
    sources: list[str],
    api_keys: dict[str, str | None],
    timeout: float,
) -> list[WhoisHistoryRecord]:
    """Consulta todas as fontes em paralelo."""
    import asyncio

    sem = asyncio.Semaphore(3)

    async def _limited(source: str) -> list[WhoisHistoryRecord]:
        async with sem:
            return await _query_source(source, domain, api_keys.get(source), timeout)

    tasks = [_limited(s) for s in sources]
    async with asyncio.TaskGroup() as tg:
        futures = [tg.create_task(t) for t in tasks]
    results = [f.result() for f in futures]

    all_records: list[WhoisHistoryRecord] = []
    for result in results:
        if isinstance(result, list):
            all_records.extend(result)

    seen: set[tuple[str, str]] = set()
    unique: list[WhoisHistoryRecord] = []
    for r in all_records:
        key = (r.date, r.registrar)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    unique.sort(key=lambda x: x.date)
    return unique


def run_history(
    domain: str,
    sources: list[str],
    api_keys: dict[str, str | None] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[WhoisHistoryRecord]:
    """Executa consulta de historico WHOIS (sync wrapper)."""
    from utils import safe_asyncio_run

    if not sources:
        return []

    keys = api_keys or {}
    return safe_asyncio_run(
        _query_all_sources(domain, sources, keys, timeout)
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-whoishistory",
        description="Consulta historico de WHOIS de um dominio.",
    )
    parser.add_argument("domain", nargs="?", help="Dominio alvo (ex: example.com).")
    parser.add_argument(
        "--source",
        action="append",
        choices=["securitytrails", "whoisxml"],
        help="Fonte para consulta (pode usar mais de um). Default: securitytrails.",
    )
    parser.add_argument("--st-api-key", dest="st_api_key", help="API key do SecurityTrails.")
    parser.add_argument("--whoisxml-api-key", dest="whoisxml_key", help="API key do WhoisXML.")
    add_base_args(parser, timeout_default=DEFAULT_TIMEOUT)
    return parser


def _print_history(records: list[WhoisHistoryRecord]) -> None:
    """Imprime tabela de registros historicos."""
    if not records:
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Nenhum registro historico de WHOIS encontrado.")
        return

    print_table(
        headers=("Date", "Registrar", "Registrant", "Org", "Country", "NS (5)", "Source"),
        rows=[(
            r.date or "-",
            (r.registrar or "-")[:25],
            (r.registrant_name or "-")[:20],
            (r.registrant_org or "-")[:20],
            (r.registrant_country or "-")[:12],
            (r.name_servers or "-")[:30],
            r.source,
        ) for r in records],
        column_styles=[
            (Cyber.YELLOW,),
            (Cyber.CYAN,),
            (Cyber.WHITE,),
            (Cyber.WHITE,),
            (Cyber.GREEN,),
            (Cyber.GRAY,),
            (Cyber.GREEN,),
        ],
    )


def run_once(args: argparse.Namespace) -> int:
    """Executa uma unica consulta de historico WHOIS."""
    init_scanner(args)

    domain = args.domain.strip().lower()
    sources = getattr(args, "source", None) or ["securitytrails"]

    api_keys: dict[str, str | None] = {
        "securitytrails": getattr(args, "st_api_key", None),
        "whoisxml": getattr(args, "whoisxml_key", None),
    }

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma consulta sera realizada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(domain, Cyber.WHITE, Cyber.BOLD)}")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Fontes: {color(', '.join(sources), Cyber.WHITE, Cyber.BOLD)}")
        return 0

    start = time.time()
    records = run_history(
        domain,
        sources=sources,
        api_keys=api_keys,
        timeout=args.timeout,
    )
    elapsed = time.time() - start

    print()
    _print_history(records)
    print()

    for s in sources:
        if not api_keys.get(s):
            flag = "--st-api-key" if s == "securitytrails" else "--whoisxml-api-key"
            print(color("[!]", Cyber.YELLOW, Cyber.BOLD),
                  f"{s} requer API key (use {flag})")

    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Records: {color(str(len(records)), Cyber.GREEN, Cyber.BOLD)} | "
        f"Elapsed: {color(f"{elapsed:.1f}s", Cyber.YELLOW)} | "
        f"Sources: {color(', '.join(sources), Cyber.WHITE, Cyber.BOLD)}",
    )

    if getattr(args, "output", None):
        write_output(args.output, [asdict(r) for r in records])
        print(color("[+]", Cyber.GREEN, Cyber.BOLD), f"Output salvo em: {args.output}")

    return 0


def main() -> int:
    """Entry point CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.domain:
        return run_main_loop(
            parser=parser,
            banner_fn=create_banner(BANNER_ART, "WHOIS History"),
            run_fn=run_once,
            has_target=lambda a: bool(getattr(a, "domain", None)),
            prompt="whois-history> ",
            description="Consulta historico de WHOIS de um dominio.",
            example="example.com",
            contextual_help=(
                "Uso: <dominio> [opcoes]\n"
                "Exemplos:\n"
                "  example.com\n"
                "  example.com --source securitytrails --st-api-key KEY\n"
                "  example.com --source whoisxml --whoisxml-api-key KEY\n"
                "  example.com -o whois-history.json\n"
                "  Use -l para arquivo com dominios (um por linha)"
            ),
        )

    return run_once(args)


if __name__ == "__main__":
    raise SystemExit(main())
