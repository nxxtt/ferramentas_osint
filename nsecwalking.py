#!/usr/bin/env python3
"""Modulo de enumeracao NSEC — NSEC Walking.

Enumera todos os registros de uma zona DNSSEC-assinada seguindo a cadeia
de NSEC (Next Secure) records. Ferramenta ofensiva de enumeracao de zonas.

NSEC records apontam para o proximo nome canônico na zona.
Ao consultar nomes inexistentes, a resposta NXDOMAIN inclui o proximo
NSEC, permitindo "caminhar" toda a zona.

ATENCAO LEGAL:
  Esta ferramenta e para auditoria e pentest autorizado.
  Use apenas em zonas que voce tem autorizacao para enumerar.
  Enumeracao de zonas sem autorizacao pode violar leis de privacidade.

Fluxo:
  1. Consulta nome aleatorio no dominio
  2. Resposta NXDOMAIN inclui NSEC com next_domain
  3. Consulta next_domain para obter proximo NSEC
  4. Repete ate completar o ciclo (volta ao inicio)
  5. NSEC3 detectado → informa limitacoes (hashed names)
"""
import argparse
import logging
import random
import string
from dataclasses import asdict, dataclass

import dns.exception
import dns.flags
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from utils import (
    Cyber,
    add_base_args,
    color,
    create_banner,
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.nsecwalking")

DEFAULT_MAX_HOPS = 500
DEFAULT_TIMEOUT = 3.0

TYPE_BITMAPS = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 52: "TLSA",
    65: "HTTPS", 252: "ANY", 255: "ALL",
}


@dataclass(frozen=True, slots=True)
class NsecEntry:
    """Entrada individual da cadeia NSEC."""

    name: str
    next_name: str
    record_types: list[str]


@dataclass(frozen=True, slots=True)
class NsecResult:
    """Resultado da enumeracao NSEC."""

    domain: str
    names_found: list[str]
    total_names: int
    has_nsec3: bool
    zone_enumerated: bool
    entries: list[NsecEntry]
    max_hops: int
    hops_used: int


def _parse_nsec_types(nsec_rdata: object) -> list[str]:
    """Extrai tipos de registros do bitmap NSEC."""
    types = []
    try:
        window_str = str(nsec_rdata)
        for part in window_str.split():
            clean = part.strip("()")
            if clean in TYPE_BITMAPS:
                types.append(TYPE_BITMAPS[clean])
            elif clean.startswith("TYPE"):
                try:
                    type_num = int(clean[4:])
                    types.append(f"TYPE{type_num}")
                except ValueError:
                    types.append(clean)
            else:
                types.append(clean)
    except Exception:
        pass
    return types


def _random_label(length: int = 12) -> str:
    """Gera label aleatorio para consulta."""
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _query_nsec(domain: str, nameserver: str, timeout: float) -> tuple[str, str, list[str], bool]:
    """Consulta NSEC para um nome e retorna (name, next_name, types, is_nsec3)."""
    random_name = f"{_random_label()}.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answer = resolver.resolve(random_name, "NSEC")
        for rr in answer:
            next_name = str(rr.next)
            record_types = _parse_nsec_types(rr)
            return (random_name, next_name, record_types, False)
    except dns.resolver.NoAnswer:
        try:
            answer = resolver.resolve(random_name, "NSEC3")
            for rr in answer:
                next_name = str(rr.next_hashed)
                return (random_name, next_name, ["NSEC3"], True)
        except Exception:
            pass
    except dns.resolver.NXDOMAIN:
        try:
            answer = resolver.resolve(random_name, "NSEC")
            for rr in answer:
                next_name = str(rr.next)
                record_types = _parse_nsec_types(rr)
                return (random_name, next_name, record_types, False)
        except dns.resolver.NoAnswer:
            try:
                answer = resolver.resolve(random_name, "NSEC3")
                for rr in answer:
                    next_name = str(rr.next_hashed)
                    return (random_name, next_name, ["NSEC3"], True)
            except Exception:
                pass
        except Exception:
            pass
    except dns.exception.Timeout:
        pass
    except dns.exception.DNSException:
        pass

    return ("", "", [], False)


def scan_nsec(
    domain: str,
    nameserver: str = "8.8.8.8",
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TIMEOUT,
) -> NsecResult:
    """Executa a enumeracao NSEC walking."""
    entries: list[NsecEntry] = []
    names_found: list[str] = []
    has_nsec3 = False
    hops = 0

    start_name = None

    while hops < max_hops:
        name, next_name, types, is_nsec3 = _query_nsec(domain, nameserver, timeout)

        if is_nsec3:
            has_nsec3 = True
            break

        if not next_name:
            break

        if start_name is None:
            start_name = next_name

        entries.append(NsecEntry(name=name, next_name=next_name, record_types=types))

        if next_name not in names_found:
            names_found.append(next_name)

        hops += 1

        if next_name.lower() == domain.lower() or next_name.lower() == start_name:
            break

    return NsecResult(
        domain=domain,
        names_found=sorted(names_found),
        total_names=len(names_found),
        has_nsec3=has_nsec3,
        zone_enumerated=not has_nsec3 and hops > 0,
        entries=entries,
        max_hops=max_hops,
        hops_used=hops,
    )


def print_results(result: NsecResult) -> None:
    """Exibe o relatorio de enumeracao NSEC."""
    print(color("\n[+] NSEC Walking — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Dominio: {color(result.domain, Cyber.WHITE, Cyber.BOLD)}")
    print()

    print(f"  NSEC3: {color('SIM', Cyber.YELLOW) if result.has_nsec3 else color('NAO', Cyber.GREEN)}")
    print(f"  Enumerado: {color('SIM', Cyber.GREEN, Cyber.BOLD) if result.zone_enumerated else color('NAO', Cyber.RED)}")
    print(f"  Hops: {color(str(result.hops_used), Cyber.WHITE)} / {result.max_hops}")
    print(f"  Nomes encontrados: {color(str(result.total_names), Cyber.CYAN, Cyber.BOLD)}")
    print()

    if result.has_nsec3:
        print(color("  [!] NSEC3 detectado — zona usa hashed names", Cyber.YELLOW))
        print(color("  [!] Enumeracao direta nao e possivel com NSEC3", Cyber.YELLOW))
        print(color("  [!] Requer brute-force offline ou rainbow tables", Cyber.YELLOW))
    elif result.entries:
        print(color("  Nomes descobertos:", Cyber.YELLOW, Cyber.BOLD))
        for entry in result.entries[:50]:
            types_str = ", ".join(entry.record_types) if entry.record_types else "?"
            print(f"    {color(entry.next_name, Cyber.WHITE)} [{types_str}]")
        if len(result.entries) > 50:
            print(f"    ... e mais {len(result.entries) - 50} nomes")

        print()
        print(color("  [!] ATENCAO: Esta enumeracao revela todos os hosts da zona", Cyber.RED, Cyber.BOLD))
        print(color("  [!] Use apenas em zonas com autorizacao para pentest", Cyber.RED))
    else:
        print(color("  [-] Nenhum registro NSEC encontrado", Cyber.RED))
        print(color("  [-] Zona pode nao ter DNSSEC ou usar NSEC3", Cyber.YELLOW))


def banner() -> None:
    """Exibe o banner do NSEC Walking."""
    art = r"""
    __  _______  __        ___       __     __
   /  |/  / __ \/ /__  __/   |     / /__  / /_
  / /|_/ / / / / / _ \/ / /| |    / / _ \/ __/
 / /  / / /_/ / /  __/ / ___ |   / /  __/ /_
/_/  /_/\____/_/\___/_/_/  |_|  /_/\___/\__/
"""
    create_banner(art, "   nsec walking: enumeracao de zonas via NSEC records")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="NSEC Walking — enumera zona via NSEC records em DNSSEC.",
        epilog="ATENCAO: Use apenas em zonas com autorizacao para enumerar.",
    )
    add_base_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo para enumeracao.")
    parser.add_argument(
        "--nameserver", "-s",
        default="8.8.8.8",
        help="Nameserver para queries. Padrao: 8.8.8.8",
    )
    parser.add_argument(
        "--max-hops", "-m",
        type=int,
        default=DEFAULT_MAX_HOPS,
        help=f"Numero maximo de hops. Padrao: {DEFAULT_MAX_HOPS}",
    )
    parser.add_argument(
        "--query-timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Timeout por query em segundos. Padrao: 3",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    domain = getattr(args, "domain", None)
    if not domain:
        print(color("[!] Informe um dominio.", Cyber.RED))
        return 1

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma query DNS sera enviada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(domain, Cyber.WHITE, Cyber.BOLD)}")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Nameserver: {args.nameserver}")
        return 0

    print(color("[!]", Cyber.RED, Cyber.BOLD), "ATENCAO: Enumeracao NSEC — ferramenta ofensiva")
    print(color("[!]", Cyber.RED, Cyber.BOLD), f"Alvo: {domain}")
    print()

    result = scan_nsec(
        domain=domain,
        nameserver=args.nameserver,
        max_hops=args.max_hops,
        timeout=args.query_timeout,
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["domain", "total_names", "has_nsec3", "zone_enumerated",
             "max_hops", "hops_used"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do NSEC Walking."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain),
        prompt="nsec> ",
        description="NSEC Walking interativo.",
        example="example.com --max-hops 500",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --max-hops 500\n"
            "  example.com --nameserver 1.1.1.1"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
