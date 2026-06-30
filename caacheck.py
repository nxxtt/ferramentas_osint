#!/usr/bin/env python3
"""Modulo de verificacao CAA — CAA Record Check.

Verifica registros CAA (Certificate Authority Authorization) de um dominio.
CAA determina quais Certificate Authorities podem emitir certificados
para o dominio, prevenindo emissao nao autorizada.

Tags CAA:
  - issue: CA autorizada a emitir certificados normais
  - issuewild: CA autorizada a emitir certificados wildcard
  - iodef: URI para reportar tentativas de emissao invalida

Fluxo:
  1. Consulta registros CAA do dominio
  2. Analisa tags (issue, issuewild, iodef)
  3. Identifica CAs autorizadas
  4. Avalia politica (restrictive/permissive/open)
"""
import argparse
import logging
from dataclasses import asdict, dataclass

import dns.exception
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

logger = logging.getLogger("mytools.caacheck")

CAA_TAGS = {0: "issue", 1: "issuewild", 2: "iodef"}

KNOWN_CAS = {
    "letsencrypt.org": "Let's Encrypt",
    "digicert.com": "DigiCert",
    "globalsign.com": "GlobalSign",
    "comodoca.com": "Comodo/Sectigo",
    "sectigo.com": "Sectigo",
    "godaddy.com": "GoDaddy",
    "amazon.com": "Amazon Trust",
    "cloudflare.com": "Cloudflare",
    "google.com": "Google Trust Services",
    "actalis.com": "Actalis",
}


@dataclass(frozen=True, slots=True)
class CaaRecord:
    """Registro CAA individual."""

    tag: str
    value: str
    flags: int


@dataclass(frozen=True, slots=True)
class CaaResult:
    """Resultado da verificacao CAA."""

    domain: str
    records: list[CaaRecord]
    has_caa: bool
    authorized_cas: list[str]
    has_iodef: bool
    policy_status: str  # restrictive, permissive, open, none


def _identify_ca(value: str) -> str:
    """Identifica a CA pelo nome."""
    value_lower = value.lower().rstrip(".")
    for domain, name in KNOWN_CAS.items():
        if domain in value_lower:
            return name
    return value


def _parse_caa_rdata(rdata: object) -> CaaRecord | None:
    """Parse do rdata CAA para extrair tag, value, flags."""
    try:
        parts = str(rdata).split(" ", 2)
        if len(parts) >= 3:
            flags = int(parts[0])
            tag = parts[1]
            value = parts[2].strip('"')
            return CaaRecord(tag=tag, value=value, flags=flags)
    except (ValueError, IndexError):
        pass
    return None


def scan_caa(
    domain: str,
    nameserver: str = "8.8.8.8",
    timeout: float = 5.0,
) -> CaaResult:
    """Executa a verificacao CAA."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    records: list[CaaRecord] = []

    try:
        answer = resolver.resolve(domain, "CAA")
        for rdata in answer:
            rec = _parse_caa_rdata(rdata)
            if rec:
                records.append(rec)
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except dns.exception.Timeout:
        pass
    except dns.exception.DNSException:
        pass

    has_caa = len(records) > 0
    has_iodef = any(r.tag == "iodef" for r in records)

    cas = set()
    for r in records:
        if r.tag == "issue" and r.value != ";":
            cas.add(_identify_ca(r.value))
    authorized_cas = sorted(cas)

    issue_count = sum(1 for r in records if r.tag == "issue" and r.value != ";")
    if not has_caa:
        policy = "none"
    elif issue_count <= 1:
        policy = "restrictive"
    elif issue_count <= 3:
        policy = "permissive"
    else:
        policy = "open"

    return CaaResult(
        domain=domain,
        records=records,
        has_caa=has_caa,
        authorized_cas=authorized_cas,
        has_iodef=has_iodef,
        policy_status=policy,
    )


def print_results(result: CaaResult) -> None:
    """Exibe o relatorio de verificacao CAA."""
    print(color("\n[+] CAA Record Check — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Dominio: {color(result.domain, Cyber.WHITE, Cyber.BOLD)}")
    print()

    print(f"  CAA Configurado: {color('SIM', Cyber.GREEN) if result.has_caa else color('NAO', Cyber.RED)}")
    print(f"  Politica: {color(result.policy_status.upper(), Cyber.GREEN if result.policy_status == 'restrictive' else (Cyber.YELLOW if result.policy_status == 'permissive' else Cyber.RED))}")
    print(f"  IODEF (report): {color('SIM', Cyber.GREEN) if result.has_iodef else color('NAO', Cyber.YELLOW)}")
    print()

    if result.authorized_cas:
        print(color("  CAs Autorizadas:", Cyber.YELLOW, Cyber.BOLD))
        for ca in result.authorized_cas:
            print(f"    {color(ca, Cyber.WHITE)}")

    if result.records:
        print()
        print(color("  Registros CAA:", Cyber.YELLOW, Cyber.BOLD))
        for rec in result.records:
            tag_color = Cyber.GREEN if rec.tag == "issue" else (Cyber.CYAN if rec.tag == "issuewild" else Cyber.YELLOW)
            print(f"    {color(rec.tag, tag_color)} = {rec.value} (flags: {rec.flags})")

    print()
    if not result.has_caa:
        print(color("  [-] Nenhum registro CAA encontrado", Cyber.RED))
        print(color("  [-] Qualquer CA pode emitir certificados para este dominio", Cyber.RED))
        print(color("  [-] Recomendacao: adicionar registros CAA para restringir CAs", Cyber.YELLOW))
    elif result.policy_status == "restrictive":
        print(color("  [+] Politica restritiva — poucas CAs autorizadas", Cyber.GREEN, Cyber.BOLD))
    elif result.policy_status == "permissive":
        print(color("  [!] Politica permissiva — multiplas CAs autorizadas", Cyber.YELLOW))
    else:
        print(color("  [!] Politica aberta — muitas CAs autorizadas", Cyber.YELLOW))


def banner() -> None:
    """Exibe o banner do CAA Record Check."""
    art = r"""
    __  _______  __          ______ __
   /  |/  / __ \/ /__  __   / ____/_ /__
  / /|_/ / / / / / _ \/ /  / /   / // _ \
 / /  / / /_/ / /  __/ /  / /___/ //  __/
/_/  /_/\____/_/\___/_/   \____/_/ \___/
"""
    create_banner(art, "   caa record check: verifica registros CAA de certificados")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="CAA Record Check — verifica registros CAA de certificados.",
        epilog="Verifica quais Certificate Authorities podem emitir certificados para o dominio.",
    )
    add_base_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo para verificacao CAA.")
    parser.add_argument(
        "--nameserver", "-s",
        default="8.8.8.8",
        help="Nameserver para queries. Padrao: 8.8.8.8",
    )
    parser.add_argument(
        "--query-timeout",
        type=float,
        default=5.0,
        help="Timeout por query em segundos. Padrao: 5",
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
        return 0

    result = scan_caa(
        domain=domain,
        nameserver=args.nameserver,
        timeout=args.query_timeout,
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["domain", "has_caa", "authorized_cas", "has_iodef", "policy_status"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do CAA Record Check."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain),
        prompt="caa> ",
        description="CAA Record Check interativo.",
        example="example.com --nameserver 8.8.8.8",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --nameserver 1.1.1.1"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
