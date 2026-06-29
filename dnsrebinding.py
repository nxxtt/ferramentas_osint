#!/usr/bin/env python3
"""Modulo de deteccao de DNS Rebinding (DNS Rebinding Detection).

Testa se um dominio e vulneravel a ataques de DNS rebinding verificando:
  - TTL baixo (< 5s) — indicador forte de rebinding
  - IPs privados/reservados nas respostas DNS
  - CNAME chains que resolvem para IPs privados
  - Wildcard DNS (resolucao de subdominios aleatorios)
  - IP flip — resolucoes que alternam entre IPs publicos e privados

DNS Rebinding e um ataque TOCTOU (Time-of-Check-Time-of-Use):
  1. Dominio malicioso retorna IP publico (passa checks de seguranca)
  2. TTL baixo faz o record expirar rapidamente
  3. Proxima resolucao retorna IP privado (bypass same-origin policy)
  4. Aplicacao conecta ao servico interno

Fluxo:
  1. Resolve dominio para A/AAAA
  2. Verifica TTL, IPs retornados, CNAME chains
  3. Testa wildcard com subdominios aleatorios
  4. Resolve multiplas vezes para detectar IP flip
  5. Classifica severidade de cada achado
"""
import argparse
import ipaddress
import logging
import random
import string
from dataclasses import asdict, dataclass, field

import dns.exception
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

logger = logging.getLogger("mytools.dnsrebinding")

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::ffff:0:0/96"),
]

CLOUD_METADATA_IPS = frozenset({"169.254.169.254", "100.100.100.200"})


@dataclass(frozen=True, slots=True)
class RebindingResult:
    """Resultado de um check de DNS rebinding."""

    domain: str
    check: str
    severity: str
    detail: str
    records: list[str] = field(default_factory=list)


def _is_private_ip(ip_str: str) -> bool:
    """Verifica se um IP e privado/reservado."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in PRIVATE_NETWORKS)


def _is_cloud_metadata(ip_str: str) -> bool:
    """Verifica se um IP e endpoint de metadata de cloud."""
    return ip_str in CLOUD_METADATA_IPS


def _check_ttl(domain: str, answers: dns.resolver.Answer) -> RebindingResult | None:
    """Verifica se TTL e perigosamente baixo."""
    ttl = answers.rrset.ttl if answers.rrset is not None else 0

    if ttl == 0:
        return RebindingResult(
            domain=domain, check="ttl", severity="critical",
            detail="TTL=0 — indicador forte de rebinding",
            records=[f"TTL={ttl}"],
        )
    if ttl <= 2:
        return RebindingResult(
            domain=domain, check="ttl", severity="high",
            detail=f"TTL={ttl}s — possivel rebinding",
            records=[f"TTL={ttl}"],
        )
    if ttl <= 5:
        return RebindingResult(
            domain=domain, check="ttl", severity="medium",
            detail=f"TTL={ttl}s — suspeito, investigar",
            records=[f"TTL={ttl}"],
        )
    if ttl <= 30:
        return RebindingResult(
            domain=domain, check="ttl", severity="low",
            detail=f"TTL={ttl}s — baixo mas possivelmente legitimo",
            records=[f"TTL={ttl}"],
        )
    return None


def _check_private_ips(domain: str, answers: dns.resolver.Answer) -> list[RebindingResult]:
    """Verifica se alguma resolucao retorna IP privado."""
    results: list[RebindingResult] = []

    for rdata in answers:
        ip_str = rdata.address
        if _is_cloud_metadata(ip_str):
            results.append(RebindingResult(
                domain=domain, check="private_ip", severity="critical",
                detail=f"IP {ip_str} e endpoint de metadata cloud (AWS/GCP/Azure)",
                records=[ip_str],
            ))
        elif _is_private_ip(ip_str):
            results.append(RebindingResult(
                domain=domain, check="private_ip", severity="critical",
                detail=f"IP {ip_str} e reservado/privado (RFC1918)",
                records=[ip_str],
            ))

    return results


def _check_cname_chain(domain: str, answers: dns.resolver.Answer) -> RebindingResult | None:
    """Verifica CNAME chain por IPs privados ou TTL baixo."""
    try:
        chaining = answers.chaining_result
    except AttributeError:
        return None

    min_ttl = chaining.minimum_ttl
    cnames = chaining.cnames

    if not cnames:
        return None

    cname_names = [str(cname) for cname in cnames]
    chain_depth = len(cname_names)

    final_ip = ""
    try:
        final_answers = dns.resolver.resolve(chaining.canonical_name, "A")
        for rdata in final_answers:
            final_ip = rdata.address
            break
    except dns.exception.DNSException:
        pass

    if final_ip and _is_private_ip(final_ip):
        return RebindingResult(
            domain=domain, check="cname_chain", severity="high",
            detail=f"CNAME chain ({chain_depth} hops) resolve para IP privado {final_ip}",
            records=[*cname_names, final_ip],
        )

    if min_ttl is not None and min_ttl <= 5:
        return RebindingResult(
            domain=domain, check="cname_chain", severity="medium",
            detail=f"CNAME chain com TTL minimo={min_ttl}s ({chain_depth} hops)",
            records=cname_names,
        )

    if chain_depth >= 4:
        return RebindingResult(
            domain=domain, check="cname_chain", severity="low",
            detail=f"CNAME chain profunda ({chain_depth} hops) — pode ocultar destino",
            records=cname_names,
        )

    return None


def _check_wildcard(domain: str, resolver: dns.resolver.Resolver) -> RebindingResult | None:
    """Testa se o dominio tem wildcard DNS."""
    random_subdomains = [
        "".join(random.choices(string.ascii_lowercase, k=12)) for _ in range(5)
    ]

    resolved_any = False
    resolved_ips: list[str] = []

    for sub in random_subdomains:
        test_domain = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(test_domain, "A")
            resolved_any = True
            for rdata in answers:
                resolved_ips.append(rdata.address)
        except dns.exception.DNSException:
            continue

    if not resolved_any:
        return None

    unique_ips = list(set(resolved_ips))
    return RebindingResult(
        domain=domain, check="wildcard", severity="medium",
        detail=f"Wildcard DNS detectado — subdominios aleatorios resolvem para {len(unique_ips)} IP(s)",
        records=unique_ips[:5],
    )


def _check_ip_flip(domain: str, resolver: dns.resolver.Resolver, queries: int = 5) -> RebindingResult | None:
    """Resolve multiplas vezes e detecta alternancia entre IPs publicos e privados."""
    seen_public: set[str] = set()
    seen_private: set[str] = set()

    for _ in range(queries):
        try:
            answers = resolver.resolve(domain, "A")  # type: ignore[call-overload]
            for rdata in answers:
                ip = rdata.address
                if _is_private_ip(ip):
                    seen_private.add(ip)
                else:
                    seen_public.add(ip)
        except dns.exception.DNSException:
            continue

    if seen_public and seen_private:
        return RebindingResult(
            domain=domain, check="ip_flip", severity="critical",
            detail=f"IP flip detectado — publicos: {seen_public}, privados: {seen_private}",
            records=list(seen_public | seen_private),
        )

    return None


def scan_rebinding(
    domain: str,
    timeout: float = 5.0,
    queries: int = 5,
) -> list[RebindingResult]:
    """Executa todos os checks de DNS rebinding contra um dominio."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results: list[RebindingResult] = []

    try:
        answers = resolver.resolve(domain, "A")
    except dns.resolver.NXDOMAIN:
        logger.warning("Dominio %s nao existe (NXDOMAIN)", domain)
        return [RebindingResult(
            domain=domain, check="resolve", severity="info",
            detail="Dominio nao existe (NXDOMAIN)",
        )]
    except dns.resolver.NoAnswer:
        logger.warning("Dominio %s nao retorna registros A", domain)
        return [RebindingResult(
            domain=domain, check="resolve", severity="info",
            detail="Sem registros A para o dominio",
        )]
    except dns.exception.Timeout:
        logger.warning("Timeout resolvendo %s", domain)
        return [RebindingResult(
            domain=domain, check="resolve", severity="info",
            detail="Timeout na resolucao DNS",
        )]
    except dns.exception.DNSException as e:
        logger.warning("Erro DNS resolvendo %s: %s", domain, e)
        return [RebindingResult(
            domain=domain, check="resolve", severity="info",
            detail=f"Erro DNS: {e}",
        )]

    ttl_result = _check_ttl(domain, answers)
    if ttl_result:
        results.append(ttl_result)

    results.extend(_check_private_ips(domain, answers))

    cname_result = _check_cname_chain(domain, answers)
    if cname_result:
        results.append(cname_result)

    wildcard_result = _check_wildcard(domain, resolver)
    if wildcard_result:
        results.append(wildcard_result)

    flip_result = _check_ip_flip(domain, resolver, queries)
    if flip_result:
        results.append(flip_result)

    return results


def print_results(results: list[RebindingResult]) -> None:
    """Exibe os resultados de DNS rebinding de forma colorida."""
    if not results:
        print(color("[*] Nenhuma vulnerabilidade de DNS rebinding encontrada.", Cyber.GREEN))
        return

    severity_colors: dict[str, str] = {
        "critical": Cyber.RED,
        "high": Cyber.ORANGE,
        "medium": Cyber.YELLOW,
        "low": Cyber.CYAN,
        "info": Cyber.GRAY,
    }

    vulns = [r for r in results if r.severity in ("critical", "high", "medium", "low")]
    infos = [r for r in results if r.severity == "info"]

    if vulns:
        print(color(f"\n[!] {len(vulns)} vulnerabilidade(s) de DNS rebinding:", Cyber.RED, Cyber.BOLD))
        for r in vulns:
            sev_color = severity_colors.get(r.severity, Cyber.GRAY)
            print(f"  {color(r.severity.upper(), sev_color, Cyber.BOLD)} | {r.detail}")
            if r.records:
                print(f"    Registros: {', '.join(r.records)}")

    if infos:
        print(color(f"\n[*] {len(infos)} info(s):", Cyber.CYAN))
        for r in infos:
            print(f"  {r.detail}")

    if not vulns:
        print(color("\n[+] Nenhuma vulnerabilidade critica/alta encontrada.", Cyber.GREEN))


def banner() -> None:
    """Exibe o banner do DNS Rebinding Detection."""
    art = r"""
    _____ _____ ____  __  __ ____  _     ___   ____
   |  _ \_   _|  _ \|  \/  | __ )| |   / _ \ / ___|
   | |_) || | | |_) | |\/| |  _ \| |  | | | | |  _
   |  __/ | | |  __/| |  | | |_) | |__| |_| | |_| |
   |_|    |_| |_|   |_|  |_|____/|_____\___/ \____|
"""
    create_banner(art, "   dns rebinding detection: ttl + private ip + cname + wildcard + flip")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Deteccao de DNS Rebinding — testa se dominio e vulneravel a rebinding.",
    )
    add_base_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo para testar (ex: example.com).")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com dominios (um por linha).")
    parser.add_argument(
        "--queries", "-n",
        type=int,
        default=5,
        help="Numero de resolucoes para detectar IP flip. Padrao: 5",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    domain = getattr(args, "domain", None)
    target_list = getattr(args, "target_list", None)

    if not domain and target_list:
        try:
            with open(target_list, encoding="utf-8") as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(color(f"[!] Arquivo nao encontrado: {target_list}", Cyber.RED))
            return 1
    elif domain:
        domains = [domain]
    else:
        print(color("[!] Informe um dominio ou use -l <arquivo>.", Cyber.RED))
        return 1

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma consulta DNS sera enviada.")
        for d in domains:
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(d, Cyber.WHITE, Cyber.BOLD)}")
        return 0

    all_results: list[RebindingResult] = []
    for d in domains:
        results = scan_rebinding(
            domain=d,
            timeout=args.timeout,
            queries=getattr(args, "queries", 5),
        )
        all_results.extend(results)

    if not quiet:
        print_results(all_results)

    if args.output:
        write_output(
            args.output,
            [asdict(r) for r in all_results],
            ["domain", "check", "severity", "detail", "records"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do DNS Rebinding Detection."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain or getattr(a, "target_list", None)),
        prompt="rebind> ",
        description="DNS Rebinding Detection interativo.",
        example="example.com --queries 10",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --queries 10\n"
            "  -l domains.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
