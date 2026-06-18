#!/usr/bin/env python3
"""Enumerador de subdominios via DNS brute-force."""
from __future__ import annotations

import argparse
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field

import dns.exception
import dns.resolver

from utils import (
    Cyber,
    add_base_args,
    color,
    run_interactive_shell,
    set_color,
    setup_logging,
    show_banner,
    write_output,
)

logger = logging.getLogger("mytools.subdomainenum")

BANNER_ART = r"""
 ____        _          ____
/ ___|  __ _| | _____  | __ )  __ _ _ __   __ _ ___ ___
\___ \ / _` | |/ / _ \ |  _ \ / _` | '_ \ / _` / __/ __|
 ___) | (_| |   <  __/ | |_) | (_| | | | | (_| \__ \__ \
|____/ \__,_|_|\_\___| |____/ \__,_|_| |_|\__,_|___/___/
"""

# Wordlist embutida com subdominios comuns
BUILTIN_WORDLIST: tuple[str, ...] = (
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
    "cpanel", "whm", "webdisk", "autodiscover", "autoconfig", "m", "mobile",
    "imap", "remote", "blog", "test", "dev", "staging", "api", "app", "admin",
    "portal", "intranet", "dashboard", "cdn", "static", "media", "img", "images",
    "files", "download", "uploads", "docs", "wiki", "kb", "help", "support",
    "forum", "community", "shop", "store", "checkout", "cart", "billing",
    "accounts", "my", "login", "auth", "sso", "vpn", "gateway", "proxy",
    "relay", "mx", "mx1", "mx2", "mx3", "ldap", "ad", "dc", "dns",
    "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence",
    "status", "monitor", "grafana", "kibana", "elastic", "prometheus",
    "db", "database", "mysql", "postgres", "redis", "mongo", "memcached",
    "search", "solr", "mq", "rabbitmq", "kafka", "queue",
    "ci", "cd", "deploy", "build", "release", "artifact", "registry",
    "docker", "k8s", "kubernetes", "rancher", "vault", "consul", "nomad",
    "web", "site", "home", "secure", "ssl", "vpn2", "backup", "bak",
    "old", "legacy", "archive", "temp", "tmp", "cache", "assets",
    "css", "js", "static2", "cdn2", "media2", "img2", "images2",
    "events", "calendar", "meet", "webconf", "video", "stream", "tv",
    "radio", "music", "podcast", "rss", "feed", "news", "press",
    "careers", "jobs", "hr", "recruit", "apply", "resume",
    "partners", "vendors", "suppliers", "contract", "legal", "terms",
    "privacy", "security", "abuse", "report", "compliance",
    "api2", "api3", "v1", "v2", "v3", "rest", "graphql", "ws", "socket",
    "beta", "alpha", "canary", "preview", "demo", "sandbox", "lab",
    "edge", "node", "worker", "runner", "agent", "handler",
    "mx-backup", "mail2", "email", "email2", "webmail2",
    "exchange", "owa", "active-sync", "autodiscover2",
    "lync", "sip", "teams", "zoom", "meet2",
    "crm", "erp", "hrm", "project", "pm", "task", "tracker",
    "shop2", "store2", "pay", "stripe", "billing2", "invoice",
    "analytics", "stats", "metrics", "logs", "log", "syslog",
    "ntp", "time", "snmp", "monitoring", "nagios", "zabbix", "icinga",
)

DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 3.0
DNS_TIMEOUT = 3.0


@dataclass(frozen=True)
class SubdomainResult:
    """Resultado da enumeracao de um subdominio."""

    subdomain: str
    ip_addresses: list[str] = field(default_factory=list)
    status: str = "resolved"


def load_wordlist(path: str | None = None) -> list[str]:
    """Carrega wordlist de subdominios de arquivo ou usa a lista embutida.

    Args:
        path: Caminho para arquivo com um subdominio por linha. None usa embutida.

    Returns:
        Lista de subdominios para testar.
    """
    if path is None:
        return list(BUILTIN_WORDLIST)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            words = [line.strip().lower() for line in fh if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        raise ValueError(f"wordlist nao encontrada: {path}")

    if not words:
        raise ValueError("wordlist esta vazia")

    return words


def _resolve_subdomain(subdomain: str, domain: str, timeout: float) -> SubdomainResult:
    """Resolve um unico subdominio via DNS A record.

    Args:
        subdomain: Prefixo do subdominio (ex: "www").
        domain: Dominio base (ex: "example.com").
        timeout: Timeout em segundos.

    Returns:
        SubdomainResult com os IPs encontrados ou erro.
    """
    fqdn = f"{subdomain}.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    try:
        answers = resolver.resolve(fqdn, "A")
        ips = sorted(str(rdata) for rdata in answers)
        logger.debug("resolvido %s -> %s", fqdn, ips)
        return SubdomainResult(subdomain=fqdn, ip_addresses=ips, status="resolved")
    except dns.resolver.NXDOMAIN:
        logger.debug("NXDOMAIN: %s", fqdn)
        return SubdomainResult(subdomain=fqdn, status="nxdomain")
    except dns.resolver.NoAnswer:
        logger.debug("NoAnswer: %s", fqdn)
        return SubdomainResult(subdomain=fqdn, status="noanswer")
    except dns.resolver.Timeout:
        logger.debug("timeout: %s", fqdn)
        return SubdomainResult(subdomain=fqdn, status="timeout")
    except dns.exception.DNSException as error:
        logger.debug("erro DNS %s: %s", fqdn, error)
        return SubdomainResult(subdomain=fqdn, status="error")
    except Exception as error:
        logger.debug("erro inesperado %s: %s", fqdn, error)
        return SubdomainResult(subdomain=fqdn, status="error")


def enumerate_subdomains(
    domain: str,
    wordlist: list[str],
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[SubdomainResult]:
    """Executa enumeracao de subdominios via DNS brute-force.

    Args:
        domain: Dominio alvo (ex: "example.com").
        wordlist: Lista de subdominios para testar.
        threads: Numero de threads simultaneas.
        timeout: Timeout DNS em segundos.

    Returns:
        Lista de SubdomainResult apenas para subdominios resolvidos.
    """
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("informe um dominio valido")

    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Testando {color(str(len(wordlist)), Cyber.WHITE, Cyber.BOLD)} subdominios "
        f"em {color(domain, Cyber.WHITE, Cyber.BOLD)} com {color(str(threads), Cyber.WHITE, Cyber.BOLD)} threads...",
    )
    print()

    resolved: list[SubdomainResult] = []
    start = time.monotonic()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_resolve_subdomain, word, domain, timeout): word
            for word in wordlist
        }

        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            result = future.result()
            if done_count % 20 == 0 or done_count == len(wordlist):
                sys.stdout.write(f"\r  Progresso: {done_count}/{len(wordlist)} subdominios testados...")
                sys.stdout.flush()
            if result.status == "resolved":
                sys.stdout.write("\r" + " " * 60 + "\r")
                sys.stdout.flush()
                resolved.append(result)
                ips_str = ", ".join(result.ip_addresses)
                print(
                    color("[+]", Cyber.GREEN, Cyber.BOLD),
                    f"{color(result.subdomain, Cyber.WHITE, Cyber.BOLD)} -> {color(ips_str, Cyber.CYAN)}",
                )

    elapsed = time.monotonic() - start
    print()
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}. "
        f"Testados: {color(str(len(wordlist)), Cyber.WHITE, Cyber.BOLD)}. "
        f"Resolvidos: {color(str(len(resolved)), Cyber.GREEN, Cyber.BOLD)}.",
    )

    return resolved


def run_enum_scan(
    domain: str,
    wordlist_path: str | None = None,
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[SubdomainResult]:
    """Orquestra a enumeracao de subdominios.

    Args:
        domain: Dominio alvo.
        wordlist_path: Caminho para wordlist customizada. None usa embutida.
        threads: Numero de threads.
        timeout: Timeout DNS.

    Returns:
        Lista de subdominios resolvidos.
    """
    wordlist = load_wordlist(wordlist_path)
    return enumerate_subdomains(domain, wordlist, threads=threads, timeout=timeout)


def build_parser() -> argparse.ArgumentParser:
    """Constrói e retorna o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        description="Enumerador de subdominios via DNS brute-force.",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Dominio alvo. Ex: example.com",
    )
    parser.add_argument(
        "-w", "--wordlist",
        dest="wordlist",
        help="Arquivo com subdominios (um por linha). Usa lista embutida se omitido.",
    )
    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Numero de threads. Padrao: {DEFAULT_THREADS}",
    )
    add_base_args(parser, timeout_default=DEFAULT_TIMEOUT)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa uma unica enumeracao de subdominios."""
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    quiet = getattr(args, "quiet", False)
    if getattr(args, "color", None) is not None:
        set_color(args.color)

    if args.threads < 1:
        raise ValueError("threads precisa ser maior que zero")
    if args.timeout <= 0:
        raise ValueError("timeout precisa ser maior que zero")

    domain = args.domain.strip().lower()
    results = run_enum_scan(
        domain,
        wordlist_path=getattr(args, "wordlist", None),
        threads=args.threads,
        timeout=args.timeout,
    )

    if args.output:
        rows = [asdict(r) for r in results]
        write_output(
            args.output,
            rows,
            ["subdomain", "ip_addresses", "status"],
            quiet=quiet,
        )

    return 0


def main() -> int:
    """Ponto de entrada principal do enumerador."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.domain:

        def _validate(args: argparse.Namespace) -> None:
            if not args.domain:
                raise ValueError("Informe um dominio alvo.")

        return run_interactive_shell(
            parser, "subenum> ", run_once,
            description="Subdomain Enumeration interativo.",
            example="example.com -T 30 -w wordlist.txt",
            validate_fn=_validate,
            banner_fn=lambda: show_banner(BANNER_ART, "DNS brute-force subdomain enumerator"),
        )

    quiet = getattr(args, "quiet", False)
    if quiet and not args.output:
        print(color("Erro: modo quiet requer -o/--output", Cyber.RED), file=sys.stderr)
        return 1

    try:
        if not quiet:
            show_banner(BANNER_ART, "DNS brute-force subdomain enumerator")
        return run_once(args)
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
