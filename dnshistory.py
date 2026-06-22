#!/usr/bin/env python3
"""Consulta historico de registros DNS de um dominio via APIs OSINT.

Fontes suportadas:
  - DNSlytics (gratuito, 2500 req/dia): A, AAAA, MX, NS, SPF/TXT
  - SecurityTrails (gratuito, 50 req/mes): A, AAAA, MX, NS, SOA, TXT
  - ViewDNS.info (trial 250 queries): A (com location/owner)

Fluxo principal:
  1. Consulta a fonte selecionada via API HTTP
  2. Parseia a resposta JSON em DnsHistoryRecord
  3. Consolida, ordena por data e exibe tabela
  4. Salva saida em JSON se --output especificado
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import asdict, dataclass

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

logger = logging.getLogger("mytools.dnshistory")

BANNER_ART = r"""
 ____  _   _  ___  ___  ___  _  __
|  _ \| | | |/ _ \/ __|| _ \| |/ /
| | | | |_| | (_) \__ \|  _/|   <
|_| |_|\___/ \___/|___/|_| |_|\_\
"""

RECORD_TYPES = ("a", "aaaa", "mx", "ns", "soa", "txt", "spf", "cname")

DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True, slots=True)
class DnsHistoryRecord:
    """Um registro historico DNS."""

    record_type: str
    value: str
    first_seen: str | None = None
    last_seen: str | None = None
    location: str | None = None
    owner: str | None = None
    source: str = ""


# ---------------------------------------------------------------------------
# DNSlytics
# ---------------------------------------------------------------------------

_DNSLYTICS_URL = "https://api.dnslytics.net/v1/hostinghistory/{domain}"


def _parse_dnslytics(body: bytes, domain: str) -> list[DnsHistoryRecord]:
    """Parseia resposta JSON do DNSlytics Hosting History API."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []

    if data.get("status") != "succeed":
        return []

    records: list[DnsHistoryRecord] = []
    nested = data.get("data", {})

    for item in nested.get("ipv4", []):
        records.append(DnsHistoryRecord(
            record_type="a",
            value=item.get("ip", ""),
            last_seen=item.get("updatedate"),
            source="dnslytics",
        ))

    for item in nested.get("ipv6", []):
        records.append(DnsHistoryRecord(
            record_type="aaaa",
            value=item.get("ip", ""),
            last_seen=item.get("updatedate"),
            source="dnslytics",
        ))

    for item in nested.get("dns", []):
        records.append(DnsHistoryRecord(
            record_type="ns",
            value=item.get("dns", ""),
            last_seen=item.get("updatedate"),
            source="dnslytics",
        ))

    for item in nested.get("mx", []):
        records.append(DnsHistoryRecord(
            record_type="mx",
            value=item.get("mx", ""),
            last_seen=item.get("updatedate"),
            source="dnslytics",
        ))

    for item in nested.get("spf", []):
        records.append(DnsHistoryRecord(
            record_type="txt",
            value=item.get("record", ""),
            last_seen=item.get("updatedate"),
            source="dnslytics",
        ))

    return records


# ---------------------------------------------------------------------------
# SecurityTrails
# ---------------------------------------------------------------------------

_ST_URL = "https://api.securitytrails.com/v1/history/{domain}/dns/{record_type}"


def _parse_securitytrails(body: bytes, domain: str) -> list[DnsHistoryRecord]:
    """Parseia resposta JSON do SecurityTrails DNS History API."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []

    records: list[DnsHistoryRecord] = []
    for item in data.get("records", []):
        first = item.get("first_seen")
        last = item.get("last_seen")
        orgs = item.get("organizations", [])
        owner = orgs[0] if orgs else None

        for val_obj in item.get("values", []):
            value = val_obj.get("ip") or val_obj.get("host") or val_obj.get("txt") or ""
            records.append(DnsHistoryRecord(
                record_type=data.get("type", "a").split("/")[0],
                value=str(value),
                first_seen=first,
                last_seen=last,
                owner=owner,
                source="securitytrails",
            ))

    return records


# ---------------------------------------------------------------------------
# ViewDNS.info
# ---------------------------------------------------------------------------

_VIEWDNS_URL = "https://api.viewdns.info/iphistory/"


def _parse_viewdns(body: bytes, domain: str) -> list[DnsHistoryRecord]:
    """Parseia resposta JSON do ViewDNS.info IP History API."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []

    records: list[DnsHistoryRecord] = []
    for item in data.get("response", {}).get("records", []):
        records.append(DnsHistoryRecord(
            record_type="a",
            value=item.get("ip", ""),
            last_seen=item.get("lastseen"),
            location=item.get("location"),
            owner=item.get("owner"),
            source="viewdns",
        ))

    return records


# ---------------------------------------------------------------------------
# Query dispatcher
# ---------------------------------------------------------------------------

async def _query_source(
    source: str,
    domain: str,
    api_key: str | None,
    record_types: list[str],
    timeout: float,
) -> list[DnsHistoryRecord]:
    """Consulta uma unica fonte e retorna registros historicos."""
    client = create_async_client(timeout=timeout)
    try:
        if source == "dnslytics":
            url = _DNSLYTICS_URL.format(domain=domain)
            if api_key:
                url += f"?apikey={api_key}"
            status, _headers, body, _raw = await fetch(client, url, timeout=timeout)
            if status != 200:
                logger.debug("DNSlytics retornou %d para %s", status, domain)
                return []
            return _parse_dnslytics(body, domain)

        if source == "securitytrails":
            if not api_key:
                logger.debug("SecurityTrails precisa de API key")
                return []
            all_records: list[DnsHistoryRecord] = []
            for rtype in record_types:
                url = _ST_URL.format(domain=domain, record_type=rtype)
                status, _headers, body, _raw = await fetch(
                    client, url, timeout=timeout,
                    method="GET",
                )
                if status == 200:
                    all_records.extend(_parse_securitytrails(body, domain))
                elif status == 429:
                    logger.debug("SecurityTrails rate limited para %s/%s", domain, rtype)
                    break
                else:
                    logger.debug("SecurityTrails retornou %d para %s/%s", status, domain, rtype)
            return all_records

        if source == "viewdns":
            if not api_key:
                logger.debug("ViewDNS precisa de API key")
                return []
            url = f"{_VIEWDNS_URL}?domain={domain}&apikey={api_key}&output=json"
            status, _headers, body, _raw = await fetch(client, url, timeout=timeout)
            if status != 200:
                logger.debug("ViewDNS retornou %d para %s", status, domain)
                return []
            return _parse_viewdns(body, domain)

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
    record_types: list[str],
    timeout: float,
) -> list[DnsHistoryRecord]:
    """Consulta todas as fontes em paralelo."""
    import asyncio

    sem = asyncio.Semaphore(3)

    async def _limited(source: str) -> list[DnsHistoryRecord]:
        async with sem:
            return await _query_source(source, domain, api_keys.get(source), record_types, timeout)

    tasks = [_limited(s) for s in sources]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_records: list[DnsHistoryRecord] = []
    for result in results:
        if isinstance(result, list):
            all_records.extend(result)

    seen: set[tuple[str, str, str]] = set()
    unique: list[DnsHistoryRecord] = []
    for r in all_records:
        key = (r.record_type, r.value, r.last_seen or "")
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def run_history(
    domain: str,
    sources: list[str],
    api_keys: dict[str, str | None] | None = None,
    record_types: list[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[DnsHistoryRecord]:
    """Executa consulta de historico DNS (sync wrapper)."""
    from utils import safe_asyncio_run

    if not sources:
        return []

    keys = api_keys or {}
    rtypes = list(record_types or ["a", "aaaa", "mx", "ns", "txt"])
    return safe_asyncio_run(
        _query_all_sources(domain, sources, keys, rtypes, timeout)
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Monta o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-dnshistory",
        description="Consulta historico de registros DNS de um dominio.",
    )
    parser.add_argument("domain", nargs="?", help="Dominio alvo (ex: example.com).")
    parser.add_argument(
        "--source",
        action="append",
        choices=["dnslytics", "securitytrails", "viewdns"],
        help="Fonte para consulta (pode usar mais de um). Default: dnslytics.",
    )
    parser.add_argument("--dnslytics-key", dest="dnslytics_key", help="API key do DNSlytics (opcional).")
    parser.add_argument("--st-api-key", dest="st_api_key", help="API key do SecurityTrails.")
    parser.add_argument("--viewdns-api-key", dest="viewdns_key", help="API key do ViewDNS.")
    parser.add_argument(
        "--record-types",
        dest="record_types",
        help="Tipos de registro para SecurityTrails (comma-separated). Default: a,aaaa,mx,ns,txt.",
    )
    add_base_args(parser, timeout_default=DEFAULT_TIMEOUT)
    return parser


def _print_history(records: list[DnsHistoryRecord]) -> None:
    """Imprime tabela de registros historicos."""
    if not records:
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Nenhum registro historico encontrado.")
        return

    print_table(
        headers=("Type", "Value", "First Seen", "Last Seen", "Owner", "Source"),
        rows=[(r.record_type.upper(), r.value[:50], r.first_seen or "-", r.last_seen or "-", (r.owner or "-")[:20], r.source) for r in records],
        column_styles=[
            (Cyber.YELLOW + Cyber.BOLD,),
            (Cyber.WHITE,),
            (Cyber.GRAY,),
            (Cyber.GRAY,),
            (Cyber.CYAN,),
            (Cyber.GREEN,),
        ],
    )


def run_once(args: argparse.Namespace) -> int:
    """Executa uma unica consulta de historico DNS."""
    init_scanner(args)

    domain = args.domain.strip().lower()
    sources = getattr(args, "source", None) or ["dnslytics"]
    record_types_raw = getattr(args, "record_types", None)
    record_types = record_types_raw.split(",") if record_types_raw else ["a", "aaaa", "mx", "ns", "txt"]

    api_keys: dict[str, str | None] = {
        "dnslytics": getattr(args, "dnslytics_key", None),
        "securitytrails": getattr(args, "st_api_key", None),
        "viewdns": getattr(args, "viewdns_key", None),
    }

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma consulta sera realizada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(domain, Cyber.WHITE, Cyber.BOLD)}")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Fontes: {color(', '.join(sources), Cyber.WHITE, Cyber.BOLD)}")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Record types: {color(', '.join(record_types), Cyber.WHITE, Cyber.BOLD)}")
        return 0

    start = time.time()
    records = run_history(
        domain,
        sources=sources,
        api_keys=api_keys,
        record_types=record_types,
        timeout=args.timeout,
    )
    elapsed = time.time() - start

    print()
    _print_history(records)
    print()

    for s in sources:
        if s != "dnslytics" and not api_keys.get(s):
            print(color("[!]", Cyber.YELLOW, Cyber.BOLD),
                  f"{s} requer API key (use --{s.replace('securitytrails', 'st').replace('viewdns', 'viewdns')}-api-key)")

    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Records: {color(str(len(records)), Cyber.GREEN, Cyber.BOLD)} | "
        f"Elapsed: {color(f'{elapsed:.1f}s', Cyber.YELLOW)} | "
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
            banner_fn=create_banner(BANNER_ART, "DNS History"),
            run_fn=run_once,
            has_target=lambda a: bool(getattr(a, "domain", None)),
            prompt="dns-history> ",
            description="Consulta historico de registros DNS de um dominio.",
            example="example.com",
            contextual_help=(
                "Uso: <dominio> [opcoes]\n"
                "Exemplos:\n"
                "  example.com\n"
                "  example.com --source securitytrails --st-api-key KEY\n"
                "  example.com --record-types a,mx,ns -o history.json\n"
                "  Use -l para arquivo com dominios (um por linha)"
            ),
        )

    return run_once(args)


if __name__ == "__main__":
    raise SystemExit(main())
