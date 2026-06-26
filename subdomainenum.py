#!/usr/bin/env python3
"""Enumerador de subdominios via DNS brute-force e enumeracao passiva.

Fluxo principal:
  1. (Opcional) Enumeracao passiva: consulta crt.sh, OTX, URLScan, VirusTotal,
     SecurityTrails, Shodan para subdominios ja conhecidos
  2. Carrega wordlist (built-in com ~170 subdominios ou customizada)
  3. Faz prefetch de registros MX e CNAME para subdominios rapidos
  4. Para cada subdominio da wordlist, tenta resolver A record
  5. Subdominios resolvidos sao listados com seus IPs

Estrategia de otimizacao:
  - Enumeracao passiva: encontra subdominios sem brute-force via CT logs e OSINT
  - Prefetch MX/CNAME: muitos subdominios sao revelados por registros
    MX (mail.example.com) e CNAME (www.example.com -> cdn.example.com)
  - ThreadPoolExecutor: resolve subdominios em paralelo
  - Resolver compartilhado: cache de resolucoes DNS entre threads
  - Progress bar: mostra progresso a cada 20 subdominios

Wordlist built-in:
  Inclui subdominios comuns: www, mail, ftp, api, dev, staging, admin,
  jenkins, gitlab, grafana, kibana, redis, docker, k8s, etc.
"""
import argparse
import asyncio
import json
import logging
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field

import dns.exception
import dns.resolver
import httpx

from utils import (
    Cyber,
    FetchError,
    add_base_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    init_scanner,
    read_target_lines,
    run_main_loop,
    safe_asyncio_run,
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


banner = create_banner(BANNER_ART, "   subdomain enumeration via DNS brute-force")


@dataclass(frozen=True, slots=True)
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

    words = read_target_lines(path, lowercase=True)
    if not words:
        raise ValueError("wordlist esta vazia")

    return words


def _resolve_subdomain(subdomain: str, domain: str, timeout: float, resolver: dns.resolver.Resolver) -> SubdomainResult:
    """Resolve um unico subdominio via DNS A record.

    Args:
        subdomain: Prefixo do subdominio (ex: "www").
        domain: Dominio base (ex: "example.com").
        timeout: Timeout em segundos.
        resolver: Resolver DNS compartilhado (com cache).

    Returns:
        SubdomainResult com os IPs encontrados ou erro.
    """
    fqdn = f"{subdomain}.{domain}"

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


def _prefetch_records(domain: str, resolver: dns.resolver.Resolver) -> list[SubdomainResult]:
    """Consulta MX e CNAME antes do brute-force para revelar subdominios rapidamente.

    Args:
        domain: Dominio base (ex: "example.com").
        resolver: Resolver DNS compartilhado.

    Returns:
        Lista de SubdomainResult para subdominios encontrados via MX/CNAME.
    """
    prefetched: list[SubdomainResult] = []
    seen: set[str] = set()

    for rtype in ("MX", "CNAME"):
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                target = str(rdata.exchange if rtype == "MX" else rdata).rstrip(".")
                prefix = target.replace(f".{domain}", "")
                if prefix and prefix != target and prefix not in seen:
                    seen.add(prefix)
                    fqdn = f"{prefix}.{domain}"
                    try:
                        a_answers = resolver.resolve(fqdn, "A")
                        ips = sorted(str(r) for r in a_answers)
                        print(
                            color("[+]", Cyber.GREEN, Cyber.BOLD),
                            f"{color(f"{fqdn} (via {rtype})", Cyber.WHITE, Cyber.BOLD)} -> {color(', '.join(ips), Cyber.CYAN)}",
                        )
                        prefetched.append(SubdomainResult(subdomain=fqdn, ip_addresses=ips, status="resolved"))
                    except dns.exception.DNSException:
                        pass
        except dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.exception.DNSException:
            continue

    return prefetched


# ── Enumeracao passiva (fontes externas) ─────────────────────────────

_PASSIVE_SOURCES: dict[str, dict[str, str]] = {
    "crtsh": {
        "url": "https://crt.sh/?q=%25.{domain}&output=json",
        "auth_header": "",
        "auth_type": "none",
    },
    "otx": {
        "url": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        "auth_header": "",
        "auth_type": "none",
    },
    "urlscan": {
        "url": "https://urlscan.io/api/v1/search/?q=domain:{domain}",
        "auth_header": "",
        "auth_type": "none",
    },
    "virustotal": {
        "url": "https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
        "auth_header": "x-apikey",
        "auth_type": "api_key",
    },
    "securitytrails": {
        "url": "https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        "auth_header": "apikey",
        "auth_type": "api_key",
    },
    "shodan": {
        "url": "https://api.shodan.io/dns/domain/{domain}?key={api_key}",
        "auth_header": "",
        "auth_type": "query_param",
    },
}

DEFAULT_PASSIVE_TIMEOUT = 10.0


def _parse_crtsh(body: bytes, domain: str) -> list[str]:
    """Extrai subdominios do JSON do crt.sh."""
    try:
        data = json.loads(body)
    except ValueError:
        return []
    seen: set[str] = set()
    for entry in data:
        raw = entry.get("name_value", "")
        for name in raw.split("\n"):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name and name.endswith(f".{domain}") and name != domain:
                seen.add(name)
    return sorted(seen)


def _parse_otx(body: bytes, domain: str) -> list[str]:
    """Extrai subdominios do JSON do AlienVault OTX."""
    try:
        data = json.loads(body)
    except ValueError:
        return []
    seen: set[str] = set()
    for entry in data.get("passive_dns", []):
        hostname = entry.get("hostname", "").strip().lower()
        if hostname and hostname.endswith(f".{domain}") and hostname != domain:
            seen.add(hostname)
    return sorted(seen)


def _parse_urlscan(body: bytes, domain: str) -> list[str]:
    """Extrai subdominios do JSON do URLScan.io."""
    try:
        data = json.loads(body)
    except ValueError:
        return []
    seen: set[str] = set()
    for result in data.get("results", []):
        page = result.get("page", {})
        hostname = page.get("domain", "").strip().lower()
        if hostname and hostname.endswith(f".{domain}") and hostname != domain:
            seen.add(hostname)
    return sorted(seen)


def _parse_virustotal(body: bytes, domain: str) -> list[str]:
    """Extrai subdominios do JSON do VirusTotal."""
    try:
        data = json.loads(body)
    except ValueError:
        return []
    seen: set[str] = set()
    for entry in data.get("data", []):
        sub = entry.get("id", "").strip().lower()
        if sub and sub.endswith(f".{domain}") and sub != domain:
            seen.add(sub)
    return sorted(seen)


def _parse_securitytrails(body: bytes, domain: str) -> list[str]:
    """Extrai subdominios do JSON do SecurityTrails."""
    try:
        data = json.loads(body)
    except ValueError:
        return []
    seen: set[str] = set()
    for sub in data.get("subdomains", []):
        fqdn = f"{sub.strip().lower()}.{domain}"
        if fqdn != domain:
            seen.add(fqdn)
    return sorted(seen)


def _parse_shodan(body: bytes, domain: str) -> list[str]:
    """Extrai subdominios do JSON do Shodan."""
    try:
        data = json.loads(body)
    except ValueError:
        return []
    seen: set[str] = set()
    for sub in data.get("data", []):
        name = sub.get("subdomain", "").strip().lower()
        fqdn = f"{name}.{domain}" if name else domain
        if fqdn != domain and fqdn.endswith(f".{domain}"):
            seen.add(fqdn)
    return sorted(seen)


_PASSIVE_PARSERS: dict[str, Callable[[bytes, str], list[str]]] = {
    "crtsh": _parse_crtsh,
    "otx": _parse_otx,
    "urlscan": _parse_urlscan,
    "virustotal": _parse_virustotal,
    "securitytrails": _parse_securitytrails,
    "shodan": _parse_shodan,
}


async def _query_source(
    source: str,
    domain: str,
    api_key: str | None,
    timeout: float,
) -> list[str]:
    """Consulta uma fonte passiva e retorna subdominios encontrados."""
    cfg = _PASSIVE_SOURCES[source]
    url = cfg["url"].format(domain=domain, api_key=api_key or "")

    headers: dict[str, str] = {}
    if cfg["auth_type"] == "api_key" and api_key:
        headers[cfg["auth_header"]] = api_key

    client = create_async_client(timeout=timeout)
    try:
        status, _headers, body, _raw = await fetch(
            client, url, timeout=timeout, max_retries=1, allow_redirects=True,
        )
        if status != 200:
            logger.debug("%s returned HTTP %d for %s", source, status, domain)
            return []
        parser = _PASSIVE_PARSERS[source]
        return parser(body, domain)
    except (FetchError, httpx.RequestError) as error:
        logger.debug("%s failed for %s: %s", source, domain, error)
        return []
    finally:
        await client.aclose()


async def _passive_enumerate_async(
    domain: str,
    sources: list[str],
    api_keys: dict[str, str | None],
    timeout: float,
) -> list[str]:
    """Executa enumeracao passiva em paralelo via asyncio."""
    tasks = []
    for source in sources:
        api_key = api_keys.get(source)
        tasks.append(_query_source(source, domain, api_key, timeout))
    async with asyncio.TaskGroup() as tg:
        futures = [tg.create_task(t) for t in tasks]
    results = [f.result() for f in futures]
    seen: set[str] = set()
    for result in results:
        if not isinstance(result, list):
            continue
        for fqdn in result:
            seen.add(fqdn)
    return sorted(seen)


def passive_enumeration(
    domain: str,
    sources: list[str],
    api_keys: dict[str, str | None] | None = None,
    timeout: float = DEFAULT_PASSIVE_TIMEOUT,
) -> list[SubdomainResult]:
    """Executa enumeracao passiva e retorna SubdomainResult com status 'passive'.

    Args:
        domain: Dominio alvo.
        sources: Lista de nomes de fontes (ex: ['crtsh', 'otx']).
        api_keys: Dict mapeando nome da fonte para API key (ou None).
        timeout: Timeout por requisicao em segundos.

    Returns:
        Lista de SubdomainResult com subdominios encontrados.
    """
    if not sources:
        return []

    keys = api_keys or {}
    fqdns = safe_asyncio_run(
        _passive_enumerate_async(domain, sources, keys, timeout)
    )
    seen: set[str] = set()
    unique: list[SubdomainResult] = []
    for fqdn in sorted(fqdns):
        if fqdn not in seen:
            seen.add(fqdn)
            unique.append(SubdomainResult(subdomain=fqdn, status="passive"))
    return unique


def enumerate_subdomains(
    domain: str,
    wordlist: list[str],
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    skip_names: set[str] | None = None,
) -> list[SubdomainResult]:
    """Executa enumeracao de subdominios via DNS brute-force.

    Args:
        domain: Dominio alvo (ex: "example.com").
        wordlist: Lista de subdominios para testar.
        threads: Numero de threads simultaneas.
        timeout: Timeout DNS em segundos.
        skip_names: FQDNs ja encontrados (passive) para pular no brute-force.

    Returns:
        Lista de SubdomainResult apenas para subdominios resolvidos.
    """
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("informe um dominio valido")

    skipped = skip_names or set()

    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Testando {color(str(len(wordlist)), Cyber.WHITE, Cyber.BOLD)} subdominios "
        f"em {color(domain, Cyber.WHITE, Cyber.BOLD)} com {color(str(threads), Cyber.WHITE, Cyber.BOLD)} threads...",
    )
    if skipped:
        print(
            color("[*]", Cyber.CYAN, Cyber.BOLD),
            f"Pulando {color(str(len(skipped)), Cyber.GREEN, Cyber.BOLD)} subdominios ja encontrados (passive).",
        )
    print()

    resolved: list[SubdomainResult] = []
    start = time.monotonic()

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    prefetched = _prefetch_records(domain, resolver)
    resolved.extend(prefetched)
    prefetched_names = {r.subdomain for r in prefetched}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        skip_all = prefetched_names | skipped
        remaining = [w for w in wordlist if f"{w}.{domain}" not in skip_all]
        futures = {
            executor.submit(_resolve_subdomain, word, domain, timeout, resolver): word
            for word in remaining
        }

        total_brute = len(remaining)
        for done_count, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if done_count % 20 == 0 or done_count == total_brute:
                sys.stdout.write(f"\r  Progresso: {done_count}/{total_brute} subdominios testados...")
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
        f"Finalizado em {color(f"{elapsed:.2f}s", Cyber.YELLOW)}. "
        f"Testados: {color(str(total_brute), Cyber.WHITE, Cyber.BOLD)}. "
        f"Resolvidos: {color(str(len(resolved)), Cyber.GREEN, Cyber.BOLD)}.",
    )

    return resolved


def run_enum_scan(
    domain: str,
    wordlist_path: str | None = None,
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    skip_names: set[str] | None = None,
) -> list[SubdomainResult]:
    """Orquestra a enumeracao de subdominios.

    Args:
        domain: Dominio alvo.
        wordlist_path: Caminho para wordlist customizada. None usa embutida.
        threads: Numero de threads.
        timeout: Timeout DNS.
        skip_names: FQDNs ja encontrados (passive) para pular.

    Returns:
        Lista de subdominios resolvidos.
    """
    wordlist = load_wordlist(wordlist_path)
    return enumerate_subdomains(domain, wordlist, threads=threads, timeout=timeout, skip_names=skip_names)


def build_parser() -> argparse.ArgumentParser:
    """Constrói e retorna o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        description="Enumerador de subdominios via DNS brute-force e enumeracao passiva.",
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
    parser.add_argument(
        "-P", "--passive",
        action="store_true",
        default=False,
        help="Ativa enumeracao passiva (crt.sh, OTX, URLScan). Use --vt-api-key etc. para mais fontes.",
    )
    parser.add_argument(
        "--vt-api-key",
        dest="vt_api_key",
        help="API key do VirusTotal (ativa fonte VirusTotal no modo passivo).",
    )
    parser.add_argument(
        "--st-api-key",
        dest="st_api_key",
        help="API key do SecurityTrails (ativa fonte SecurityTrails no modo passivo).",
    )
    parser.add_argument(
        "--shodan-api-key",
        dest="shodan_api_key",
        help="API key do Shodan (ativa fonte Shodan no modo passivo).",
    )
    add_base_args(parser, timeout_default=DEFAULT_TIMEOUT)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa uma unica enumeracao de subdominios."""
    quiet = init_scanner(args)

    raw_threads = getattr(args, "threads", None)
    threads = DEFAULT_THREADS if raw_threads is None else raw_threads
    if threads < 1:
        raise ValueError("threads precisa ser maior que zero")
    if args.timeout <= 0:
        raise ValueError("timeout precisa ser maior que zero")

    domain = args.domain.strip().lower()
    wordlist = load_wordlist(getattr(args, "wordlist", None))

    passive_results: list[SubdomainResult] = []
    if getattr(args, "passive", False):
        sources = ["crtsh", "otx", "urlscan"]
        api_keys: dict[str, str | None] = {}
        if getattr(args, "vt_api_key", None):
            sources.append("virustotal")
            api_keys["virustotal"] = args.vt_api_key
        if getattr(args, "st_api_key", None):
            sources.append("securitytrails")
            api_keys["securitytrails"] = args.st_api_key
        if getattr(args, "shodan_api_key", None):
            sources.append("shodan")
            api_keys["shodan"] = args.shodan_api_key

        print(
            color("[*]", Cyber.CYAN, Cyber.BOLD),
            f"Enumeracao passiva: {color(', '.join(sources), Cyber.WHITE, Cyber.BOLD)}...",
        )
        passive_results = passive_enumeration(
            domain, sources, api_keys, timeout=args.timeout,
        )
        passive_names = {r.subdomain for r in passive_results}
        for r in passive_results:
            print(
                color("[+]", Cyber.GREEN, Cyber.BOLD),
                f"{color(r.subdomain, Cyber.WHITE, Cyber.BOLD)} {color('(passive)', Cyber.GRAY)}",
            )
        print(
            color("[*]", Cyber.CYAN, Cyber.BOLD),
            f"Passive: {color(str(len(passive_results)), Cyber.GREEN, Cyber.BOLD)} subdominios encontrados.",
        )
        print()

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma consulta DNS sera realizada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(domain, Cyber.WHITE, Cyber.BOLD)}")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Wordlist: {color(str(len(wordlist)), Cyber.WHITE, Cyber.BOLD)} subdominios")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Threads: {color(str(threads), Cyber.WHITE, Cyber.BOLD)} | Timeout: {color(f"{args.timeout}s", Cyber.YELLOW)}")
        if passive_results:
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Passive: {color(str(len(passive_results)), Cyber.GREEN, Cyber.BOLD)} subdominios (ja resolvidos via DNS)")
        return 0

    passive_names = {r.subdomain for r in passive_results}

    results = run_enum_scan(
        domain,
        wordlist_path=getattr(args, "wordlist", None),
        threads=threads,
        timeout=args.timeout,
        skip_names=passive_names,
    )

    all_results = passive_results + results

    if args.output:
        rows = [asdict(r) for r in all_results]
        write_output(
            args.output,
            rows,
            ["subdomain", "ip_addresses", "status"],
            quiet=quiet,
        )

    return 0


def main() -> int:
    """Ponto de entrada principal do enumerador."""

    def _validate(args: argparse.Namespace) -> None:
        if not args.domain:
            raise ValueError("Informe um dominio alvo.")

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain),
        prompt="subenum> ",
        description="Subdomain Enumeration interativo.",
        example="example.com -T 30 -w wordlist.txt",
        validate_fn=_validate,
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com -T 30 -w wordlist.txt\n"
            "  example.com -o subs.json\n"
            "  Use -l para arquivo com dominios (um por linha)"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
