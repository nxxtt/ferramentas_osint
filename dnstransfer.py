#!/usr/bin/env python3
"""Scanner de DNS Zone Transfer (AXFR) para detecção de configurações inseguras.

Fluxo principal:
  1. Consulta registros NS do dominio (dns.resolver.resolve)
  2. Resolve cada NS em IP (dns.resolver.resolve A record)
  3. Tenta AXFR (zone transfer) contra cada NS
  4. Retorna todos os registros DNS se bem-sucedido

O que e zone transfer (AXFR)?
  Protocolo DNS que permite copiar toda a zona DNS de um servidor.
  Se habilitado indevidamente, revela todos os registros (subdominios,
  IPs, MX, etc.) para qualquer pessoa que consulte.

Vulnerabilidade:
  Nameservers mal configurados permitem AXFR de qualquer IP.
  Isso expoe a estrutura interna da rede para enumeracao.

Uso do dnspython:
  - dns.resolver.resolve: consultas DNS standard
  - dns.query.inbound_xfr: tentativa de zone transfer AXFR
  - dns.zone: parsing da zona transferida
"""
import argparse
import logging
import sys
import time
from dataclasses import asdict, dataclass, field

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from utils import (
    Cyber,
    add_base_args,
    color,
    create_banner,
    init_scanner,
    run_main_loop,
    write_output,
)

logger = logging.getLogger("mytools.dnstransfer")

BANNER_ART = r"""
 ____  _   _ _____     _   ___  _  __
|  _ \| | | |  ___|   | \ | \ \/ /
| | | | | | | |_ ______|  \| |\  /
| |_| | |_| |  _|_____| |\  / /  \
|____/ \___/|_|       |_| \_/_/\_\
"""

DNS_PORT = 53
AXFR_TIMEOUT = 10


banner = create_banner(BANNER_ART, "   DNS zone transfer (AXFR) scanner")


@dataclass(frozen=True, slots=True)
class XfrResult:
    """Resultado de uma tentativa de zone transfer contra um nameserver."""
    domain: str
    nameserver: str
    ns_ip: str
    zone_transferred: bool
    record_count: int = 0
    records: list[str] = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0


def get_nameservers(domain: str) -> list[str]:
    """Consulta os nameservers (NS) autoritativos para um domínio.

    Args:
        domain: Nome de domínio alvo (ex: "example.com").

    Returns:
        Lista de hostnames de nameservers.
    """
    try:
        answer = dns.resolver.resolve(domain, "NS")
        return sorted(str(rr.target).rstrip(".") for rr in answer)
    except dns.resolver.NoAnswer:
        logger.debug("nenhum registro NS encontrado para %s", domain)
        return []
    except dns.resolver.NXDOMAIN:
        logger.debug("dominio %s nao existe (NXDOMAIN)", domain)
        return []
    except dns.exception.DNSException as error:
        logger.debug("erro ao resolver NS para %s: %s", domain, error)
        return []


def resolve_ns_to_ip(ns_hostname: str) -> str:
    """Resolve o hostname de um nameserver em seu endereço IP.

    Args:
        ns_hostname: Hostname do nameserver (ex: "ns1.example.com").

    Returns:
        Endereço IP resolvido.

    Raises:
        ValueError: Se não for possível resolver o hostname.
    """
    try:
        answers = dns.resolver.resolve(ns_hostname, "A")
        return str(answers[0])
    except dns.exception.DNSException as error:
        raise ValueError(f"nao foi possivel resolver {ns_hostname}: {error}") from error


def try_zone_transfer(
    domain: str,
    ns_hostname: str,
    ns_ip: str,
    timeout: float = AXFR_TIMEOUT,
) -> XfrResult:
    """Tenta realizar um zone transfer (AXFR) contra um nameserver.

    Args:
        domain: Domínio alvo.
        ns_hostname: Hostname do nameserver.
        ns_ip: Endereço IP do nameserver.
        timeout: Timeout em segundos para a operação AXFR.

    Returns:
        XfrResult com o resultado da tentativa.
    """
    start = time.monotonic()
    try:
        zone = dns.query.inbound_xfr(
            ns_ip,
            domain,  # pyright: ignore[reportArgumentType]
            timeout=timeout,
            lifetime=timeout,
        )
        elapsed = time.monotonic() - start

        if zone is None:
            return XfrResult(
                domain=domain,
                nameserver=ns_hostname,
                ns_ip=ns_ip,
                zone_transferred=False,
                error="nameserver retornou zona vazia",
                elapsed=elapsed,
            )

        records: list[str] = []
        for name, node in zone.nodes.items():  # pyright: ignore[reportGeneralTypeIssues]
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")

        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=True,
            record_count=len(records),
            records=sorted(records),
            elapsed=elapsed,
        )

    except dns.exception.FormError as error:
        elapsed = time.monotonic() - start
        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=False,
            error=f"AXFR recusado (FormError): {error}",
            elapsed=elapsed,
        )
    except dns.exception.Timeout as error:
        elapsed = time.monotonic() - start
        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=False,
            error=f"timeout apos {timeout}s: {error}",
            elapsed=elapsed,
        )
    except dns.exception.DNSException as error:
        elapsed = time.monotonic() - start
        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=False,
            error=f"erro DNS: {error}",
            elapsed=elapsed,
        )
    except Exception as error:
        elapsed = time.monotonic() - start
        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=False,
            error=f"erro inesperado: {error}",
            elapsed=elapsed,
        )


def run_xfr_scan(
    domain: str,
    timeout: float = AXFR_TIMEOUT,
) -> list[XfrResult]:
    """Executa o scan completo de zone transfer para todas as nameservers de um domínio.

    Args:
        domain: Domínio alvo.
        timeout: Timeout em segundos para cada tentativa AXFR.

    Returns:
        Lista de XfrResult, uma entrada por nameserver testado.
    """
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("informe um dominio valido")

    ns_list = get_nameservers(domain)
    if not ns_list:
        print(color("[!]", Cyber.RED, Cyber.BOLD), f"Nenhum nameserver encontrado para {color(domain, Cyber.WHITE, Cyber.BOLD)}")
        return []

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Nameservers encontrados: {color(str(len(ns_list)), Cyber.WHITE, Cyber.BOLD)}")
    for ns in ns_list:
        print(color("    ->", Cyber.BLUE), color(ns, Cyber.WHITE))
    print()

    results: list[XfrResult] = []
    for ns in ns_list:
        try:
            ns_ip = resolve_ns_to_ip(ns)
        except ValueError as error:
            print(color("[!]", Cyber.RED, Cyber.BOLD), f"{ns}: {error}")
            results.append(XfrResult(
                domain=domain,
                nameserver=ns,
                ns_ip="",
                zone_transferred=False,
                error=str(error),
            ))
            continue

        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Testando AXFR em {color(ns, Cyber.WHITE, Cyber.BOLD)} ({color(ns_ip, Cyber.CYAN)})...", end=" ")
        sys.stdout.flush()

        result = try_zone_transfer(domain, ns, ns_ip, timeout)
        results.append(result)

        if result.zone_transferred:
            print(color("VULNERAVEL!", Cyber.RED, Cyber.BOLD))
        else:
            print(color("recusado", Cyber.GREEN))

    return results


def _print_results(results: list[XfrResult]) -> None:
    """Exibe os resultados em formato de tabela no terminal."""
    vulnerable = [r for r in results if r.zone_transferred]

    if vulnerable:
        print()
        print(color("[!]", Cyber.RED, Cyber.BOLD), color(
            f"ZONA TRANSFER PERMITIDA! {len(vulnerable)} nameserver(s) vulneravel(is)!",
            Cyber.RED, Cyber.BOLD,
        ))
        for result in vulnerable:
            print()
            print(color("  Nameserver:", Cyber.CYAN, Cyber.BOLD), color(result.nameserver, Cyber.WHITE))
            print(color("  IP:", Cyber.CYAN, Cyber.BOLD), color(result.ns_ip, Cyber.WHITE))
            print(color("  Registros:", Cyber.CYAN, Cyber.BOLD), color(str(result.record_count), Cyber.YELLOW, Cyber.BOLD))
            print(color("  Tempo:", Cyber.CYAN, Cyber.BOLD), color(f"{result.elapsed:.2f}s", Cyber.YELLOW))
            if result.records:
                print(color("  Primeiros registros:", Cyber.CYAN))
                for record in result.records[:20]:
                    print(color(f"    {record}", Cyber.GRAY))
                if len(result.records) > 20:
                    print(color(f"    ... e mais {len(result.records) - 20} registros", Cyber.GRAY))
    else:
        print()
        print(color("[*]", Cyber.GREEN, Cyber.BOLD), color(
            "Nenhum nameserver permitiu zone transfer.",
            Cyber.GREEN,
        ))


def build_parser() -> argparse.ArgumentParser:
    """Constrói e retorna o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        description="Scanner de DNS Zone Transfer (AXFR) para detecção de configurações inseguras.",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domínio alvo. Ex: example.com",
    )
    add_base_args(parser, timeout_default=AXFR_TIMEOUT)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa uma única varredura de zone transfer."""
    quiet = init_scanner(args)

    if args.timeout <= 0:
        raise ValueError("timeout precisa ser maior que zero")

    domain = args.domain.strip().lower()

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma consulta DNS sera realizada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(domain, Cyber.WHITE, Cyber.BOLD)}")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Nameservers: serao consultados na execucao real")
        return 0

    start = time.monotonic()
    results = run_xfr_scan(domain, timeout=args.timeout)
    elapsed = time.monotonic() - start

    if not quiet:
        _print_results(results)
        print(
            color("[*]", Cyber.CYAN, Cyber.BOLD),
            f"Finalizado em {color(f"{elapsed:.2f}s", Cyber.YELLOW)}. "
            f"Nameservers: {color(str(len(results)), Cyber.WHITE, Cyber.BOLD)}. "
            f"Vulneraveis: {color(str(sum(1 for r in results if r.zone_transferred)), Cyber.RED, Cyber.BOLD)}",
        )

    if args.output:
        rows = [asdict(r) for r in results]
        write_output(
            args.output,
            rows,
            ["domain", "nameserver", "ns_ip", "zone_transferred", "record_count", "records", "error", "elapsed"],
            quiet=quiet,
        )

    return 1 if any(r.zone_transferred for r in results) else 0


def main() -> int:
    """Ponto de entrada principal do scanner."""

    def _validate(args: argparse.Namespace) -> None:
        if not args.domain:
            raise ValueError("Informe um dominio alvo.")

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain),
        prompt="dnsxfer> ",
        description="DNS Zone Transfer Scanner interativo.",
        example="example.com -t 15",
        validate_fn=_validate,
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com -t 15 -o xfr.json\n"
            "  Use -l para arquivo com dominios (um por linha)"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
