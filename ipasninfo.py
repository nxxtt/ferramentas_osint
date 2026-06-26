#!/usr/bin/env python3
"""Enriquece IPs com dados BGP (ASN, organizacao, pais) via APIs OSINT.

Fontes suportadas:
  - ipwho.is (gratuito, 60 req/min): ASN, org, ISP, pais, cidade, hosting
  - ip-api.com (gratuito, 45 req/min single, 15 batch): ASN, ISP, pais, hosting, proxy

Fluxo principal:
  1. Consulta a fonte primaria (ipwho.is) para cada IP
  2. Em caso de falha, faz fallback para ip-api.com
  3. Para batch (100+ IPs), usa ip-api.com/batch
  4. Consolida e exibe tabela ou salva JSON
"""
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

logger = logging.getLogger("mytools.ipasninfo")

BANNER_ART = r"""
 ___  ___  _____     _   ___
|   \| _ \/ __\ \   / / | __|
| |) |   / (__ \ V / V /| _|
|___/|_|_\\___/ \_/  /_/ |___|
"""

DEFAULT_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IpAsnInfo:
    """Informacao ASN/BGP de um IP."""

    ip: str
    asn: str = ""
    org: str = ""
    isp: str = ""
    country: str = ""
    country_code: str = ""
    city: str = ""
    is_hosting: bool = False
    is_proxy: bool = False
    source: str = ""


# ---------------------------------------------------------------------------
# ipwho.is parser
# ---------------------------------------------------------------------------


def _parse_ipwhois(body: bytes) -> IpAsnInfo | None:
    """Parseia resposta JSON do ipwho.is."""
    try:
        data = json.loads(body)
    except ValueError:
        return None

    if not data.get("success", False):
        return None

    conn = data.get("connection", {})
    asn_num = conn.get("asn", "")
    asn = f"AS{asn_num}" if isinstance(asn_num, int) else str(asn_num)

    return IpAsnInfo(
        ip=data.get("ip", ""),
        asn=asn,
        org=conn.get("org", ""),
        isp=conn.get("isp", ""),
        country=data.get("country", ""),
        country_code=data.get("country_code", ""),
        city=data.get("city", ""),
        source="ipwhois",
    )


# ---------------------------------------------------------------------------
# ip-api.com parser
# ---------------------------------------------------------------------------


def _parse_ipapi(body: bytes) -> IpAsnInfo | None:
    """Parseia resposta JSON do ip-api.com."""
    try:
        data = json.loads(body)
    except ValueError:
        return None

    if data.get("status") != "success":
        return None

    return IpAsnInfo(
        ip=data.get("query", ""),
        asn=data.get("as", "").split(" ", 1)[0] if data.get("as") else "",
        org=data.get("org", ""),
        isp=data.get("isp", ""),
        country=data.get("country", ""),
        country_code=data.get("countryCode", ""),
        city=data.get("city", ""),
        is_hosting=data.get("hosting", False),
        is_proxy=data.get("proxy", False),
        source="ipapi",
    )


# ---------------------------------------------------------------------------
# ip-api.com batch parser
# ---------------------------------------------------------------------------


def _parse_ipapi_batch(body: bytes) -> list[IpAsnInfo]:
    """Parseia resposta JSON batch do ip-api.com."""
    try:
        items = json.loads(body)
    except ValueError:
        return []

    if not isinstance(items, list):
        return []

    results: list[IpAsnInfo] = []
    for item in items:
        if item.get("status") != "success":
            continue
        results.append(IpAsnInfo(
            ip=item.get("query", ""),
            asn=item.get("as", "").split(" ", 1)[0] if item.get("as") else "",
            org=item.get("org", ""),
            isp=item.get("isp", ""),
            country=item.get("country", ""),
            country_code=item.get("countryCode", ""),
            city=item.get("city", ""),
            is_hosting=item.get("hosting", False),
            is_proxy=item.get("proxy", False),
            source="ipapi",
        ))

    return results


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------


async def _query_single(ip: str, timeout: float) -> IpAsnInfo | None:
    """Consulta um unico IP via ipwho.is com fallback para ip-api.com."""
    client = create_async_client(timeout=timeout)
    try:
        # ipwho.is (HTTPS, no key)
        try:
            url = f"https://ipwho.is/{ip}"
            status, _headers, body, _raw = await fetch(client, url, timeout=timeout)
            if status == 200:
                result = _parse_ipwhois(body)
                if result:
                    return result
        except FetchError:
            pass

        # Fallback: ip-api.com (HTTP)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=query,as,asname,isp,org,country,countryCode,city,hosting,proxy"
            status, _headers, body, _raw = await fetch(client, url, timeout=timeout)
            if status == 200:
                return _parse_ipapi(body)
        except FetchError:
            pass

        return None
    finally:
        await client.aclose()


async def _query_batch(ips: list[str], timeout: float) -> list[IpAsnInfo]:
    """Consulta multiplos IPs via ip-api.com/batch (ate 100 por request)."""
    if not ips:
        return []

    client = create_async_client(timeout=timeout)
    try:
        results: list[IpAsnInfo] = []

        # Processa em lotes de 100
        for i in range(0, len(ips), 100):
            batch = ips[i:i + 100]
            url = "http://ip-api.com/batch?fields=query,as,asname,isp,org,country,countryCode,city,hosting,proxy"
            try:
                resp = await client.post(url, content=json.dumps(batch).encode(), timeout=timeout)
                if resp.status_code == 200:
                    results.extend(_parse_ipapi_batch(resp.content))
            except Exception:
                logger.debug("ip-api.com batch falhou para lote %d-%d", i, i + len(batch))

            # Respeitar rate limit do batch (15 req/min)
            if i + 100 < len(ips):
                import asyncio
                await asyncio.sleep(4.0)

        return results
    finally:
        await client.aclose()


def lookup_ip_asn(
    ips: list[str],
    timeout: float = DEFAULT_TIMEOUT,
) -> list[IpAsnInfo]:
    """Consulta ASN/BGP para lista de IPs (sync wrapper)."""
    from utils import safe_asyncio_run

    if not ips:
        return []

    # Para batch (5+ IPs), usa ip-api.com batch
    if len(ips) >= 5:
        return safe_asyncio_run(_query_batch(ips, timeout))

    # Para poucos IPs, consulta individual via ipwho.is
    async def _lookup_all() -> list[IpAsnInfo]:
        import asyncio

        sem = asyncio.Semaphore(3)
        results: list[IpAsnInfo] = []

        async def _limited(ip: str) -> IpAsnInfo | None:
            async with sem:
                return await _query_single(ip, timeout)

        tasks = [_limited(ip) for ip in ips]
        async with asyncio.TaskGroup() as tg:
            futures = [tg.create_task(t) for t in tasks]
        gathered = [f.result() for f in futures]
        for r in gathered:
            if isinstance(r, IpAsnInfo):
                results.append(r)
        return results

    return safe_asyncio_run(_lookup_all())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-ipasn",
        description="Enriquece IPs com dados BGP (ASN, organizacao, pais).",
    )
    parser.add_argument("ips", nargs="*", help="IP(s) para consultar (ex: 8.8.8.8 1.1.1.1).")
    parser.add_argument("-f", "--file", dest="ip_file", help="Arquivo com IPs (um por linha).")
    parser.add_argument("--batch", action="store_true", help="Forca modo batch via ip-api.com.")
    add_base_args(parser, timeout_default=DEFAULT_TIMEOUT)
    return parser


def _print_results(results: list[IpAsnInfo]) -> None:
    """Imprime tabela de resultados."""
    if not results:
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Nenhuma informacao ASN encontrada.")
        return

    print_table(
        headers=("IP", "ASN", "Org", "ISP", "Country", "City", "Hosting", "Proxy"),
        rows=[(
            r.ip,
            r.asn or "-",
            (r.org or "-")[:25],
            (r.isp or "-")[:25],
            f"{r.country_code} ({r.country[:15]})" if r.country_code else "-",
            (r.city or "-")[:15],
            "Yes" if r.is_hosting else "-",
            "Yes" if r.is_proxy else "-",
        ) for r in results],
        column_styles=[
            (Cyber.WHITE,),
            (Cyber.YELLOW + Cyber.BOLD,),
            (Cyber.CYAN,),
            (Cyber.GREEN,),
            (Cyber.BLUE,),
            (Cyber.GRAY,),
            (Cyber.MAGENTA,),
            (Cyber.RED,),
        ],
    )


def _load_ips_from_args(args: argparse.Namespace) -> list[str]:
    """Carrega lista de IPs dos argumentos CLI."""
    ips: list[str] = []

    if args.ips:
        ips.extend(ip.strip() for args_ip in args.ips for ip in [args_ip] if ip.strip())

    if getattr(args, "ip_file", None):
        try:
            with open(args.ip_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips.append(line)
        except FileNotFoundError:
            print(color("[!]", Cyber.RED, Cyber.BOLD), f"Arquivo nao encontrado: {args.ip_file}")
            return []

    return ips


def run_once(args: argparse.Namespace) -> int:
    """Executa consulta ASN para IPs."""
    init_scanner(args)

    ips = _load_ips_from_args(args)

    if not ips:
        print(color("[!]", Cyber.RED, Cyber.BOLD), "Nenhum IP especificado. Use posicao ou --file.")
        return 1

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma consulta sera realizada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"IPs: {color(str(len(ips)), Cyber.WHITE, Cyber.BOLD)}")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Modo: {'batch' if getattr(args, 'batch', False) or len(ips) >= 5 else 'individual'}")
        return 0

    start = time.time()
    results = lookup_ip_asn(ips, timeout=args.timeout)
    elapsed = time.time() - start

    print()
    _print_results(results)
    print()

    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"IPs: {color(str(len(results)), Cyber.GREEN, Cyber.BOLD)} | "
        f"Elapsed: {color(f"{elapsed:.1f}s", Cyber.YELLOW)} | "
        f"Mode: {color('auto', Cyber.WHITE, Cyber.BOLD)}",
    )

    if getattr(args, "output", None):
        write_output(args.output, [asdict(r) for r in results])
        print(color("[+]", Cyber.GREEN, Cyber.BOLD), f"Output salvo em: {args.output}")

    return 0


def main() -> int:
    """Entry point CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.ips and not getattr(args, "ip_file", None):
        return run_main_loop(
            parser=parser,
            banner_fn=create_banner(BANNER_ART, "IP ASN Info"),
            run_fn=run_once,
            has_target=lambda a: bool(a.ips) or bool(getattr(a, "ip_file", None)),
            prompt="ip-asn> ",
            description="Enriquece IPs com dados BGP (ASN, organizacao, pais).",
            example="8.8.8.8 1.1.1.1",
            contextual_help=(
                "Uso: <ips...> [opcoes]\n"
                "Exemplos:\n"
                "  8.8.8.8\n"
                "  8.8.8.8 1.1.1.1 208.67.222.222\n"
                "  -f ips.txt\n"
                "  -f ips.txt --batch\n"
                "  -f ips.txt -o results.json"
            ),
        )

    return run_once(args)


if __name__ == "__main__":
    raise SystemExit(main())
