#!/usr/bin/env python3
"""Modulo de deteccao de Subdomain Takeover.

Detecta dangling CNAMEs apontando para servicos nao reclamados:
  - S3, CloudFront, Azure, Heroku, GitHub Pages, Fastly, Shopify, etc.

Fluxo:
  1. Enumera subdominios (wordlist embutida + crt.sh passivo)
  2. Resolve CNAME records para cada subdominio
  3. Se CNAME aponta para servico conhecido, faz HTTP request
  4. Compara response body com fingerprints do servico
  5. Reporta subdominios takeover-vulnerable

NOTA: vulnerable = cname_dangling AND http_match
  CNAMEs ativos com DNS apontando errado podem gerar falsos positivos.
  Sempre valide manualmente antes de exploitar.
"""

import argparse
import asyncio
import logging
from dataclasses import asdict, dataclass
from typing import Any

import dns.exception
import dns.resolver
import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    init_scanner,
    print_json,
    run_concurrent,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.subdomaintakeover")

# ---------------------------------------------------------------------------
# Wordlist embutida
# ---------------------------------------------------------------------------

_WORDLIST_DEFAULT: list[str] = [
    "www",
    "mail",
    "ftp",
    "localhost",
    "webmail",
    "smtp",
    "pop",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "cdn",
    "api",
    "dev",
    "staging",
    "test",
    "beta",
    "demo",
    "admin",
    "portal",
    "blog",
    "webdisk",
    "cpanel",
    "whm",
    "webhost",
    "remote",
    "gateway",
    "vpn",
    "shop",
    "store",
    "app",
    "m",
    "mobile",
    "forum",
    "support",
    "help",
    "docs",
    "wiki",
    "status",
    "monitor",
    "jenkins",
    "gitlab",
    "git",
    "bitbucket",
    "jira",
    "confluence",
    "grafana",
    "kibana",
    "elastic",
    "prometheus",
    "zabbix",
    "nagios",
    "docker",
    "registry",
    "k8s",
    "kube",
    "kubernetes",
    "helm",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "elastic",
    "search",
    "cache",
    "queue",
    "mq",
    "rabbitmq",
    "kafka",
    "ci",
    "cd",
    "build",
    "deploy",
    "release",
    "artifact",
    "log",
    "logs",
    "s3",
    "minio",
    "blob",
    "storage",
    "assets",
    "static",
    "img",
    "images",
    "media",
    "video",
    "files",
    "download",
    "ns",
    "dns",
    "mx",
    "mx1",
    "mx2",
    "imap",
    "pop3",
    "intranet",
    "internal",
    "private",
    "secure",
    "auth",
    "sso",
    "login",
    "old",
    "new",
    "temp",
    "tmp",
    "backup",
    "bak",
]


# ---------------------------------------------------------------------------
# Service fingerprint loading
# ---------------------------------------------------------------------------

_SERVICES_DEFAULT: dict[str, dict[str, Any]] = {}


def _load_services() -> dict[str, Any]:
    from mytools.data import load_payloads

    return load_payloads(
        "web", "subdomain_takeover", default={"services": _SERVICES_DEFAULT}
    )


def _get_services() -> dict[str, dict[str, Any]]:
    data = _load_services()
    services = data.get("services", _SERVICES_DEFAULT)
    if isinstance(services, dict):
        return services  # type: ignore[return-value]
    return _SERVICES_DEFAULT


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------


def _resolve_cname(subdomain: str, timeout: float = 5.0) -> str | None:
    """Resolve CNAME record de um subdominio. Retorna target ou None."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            target = str(rdata.target).rstrip(".")
            logger.debug("CNAME %s -> %s", subdomain, target)
            return target
    except dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers:
        logger.debug("Sem CNAME para %s", subdomain)
    except dns.resolver.Timeout:
        logger.debug("Timeout resolvendo CNAME para %s", subdomain)
    except dns.exception.DNSException as e:
        logger.debug("Erro DNS para %s: %s", subdomain, e)
    return None


def _resolve_a(subdomain: str, timeout: float = 5.0) -> list[str]:
    """Resolve A records de um subdominio."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    ips: list[str] = []
    try:
        answers = resolver.resolve(subdomain, "A")
        ips.extend(str(rdata) for rdata in answers)
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.Timeout,
        dns.exception.DNSException,
    ):
        pass
    return ips


# ---------------------------------------------------------------------------
# Subdomain enumeration
# ---------------------------------------------------------------------------


def _enumerate_wordlist(domain: str, extra_file: str | None = None) -> list[str]:
    """Gera subdominios a partir da wordlist embutida + arquivo extra."""
    prefixes = list(_WORDLIST_DEFAULT)
    if extra_file:
        try:
            from pathlib import Path

            text = Path(extra_file).read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    prefixes.append(line)
        except OSError as e:
            logger.warning("Erro lendo wordlist extra: %s", e)

    seen: set[str] = set()
    result: list[str] = []
    for prefix in prefixes:
        sub = f"{prefix}.{domain}"
        if sub not in seen:
            seen.add(sub)
            result.append(sub)
    return result


def _enumerate_crtsh(domain: str, timeout: float = 10.0) -> list[str]:
    """Consulta crt.sh para subdominios via Certificate Transparency.

    Implementa retry simples com fallback para wordlist-only se crt.sh
    retornar 429, timeout, ou qualquer erro HTTP/DNS.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    max_retries = 2
    for attempt in range(max_retries):
        try:
            resp = httpx.get(
                url,
                timeout=timeout,
                follow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; MyTools/subtakeover)",
                },
            )
            if resp.status_code == 429:
                logger.warning(
                    "crt.sh rate limited (tentativa %d/%d)", attempt + 1, max_retries
                )
                if attempt < max_retries - 1:
                    import time

                    time.sleep(2 * (attempt + 1))
                continue
            resp.raise_for_status()
            entries = resp.json()
            subs: set[str] = set()
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lower()
                    if (
                        line.endswith(f".{domain}") or line == domain
                    ) and not line.startswith("*"):
                        subs.add(line)
            logger.info("crt.sh retornou %d subdominios para %s", len(subs), domain)
            return sorted(subs)
        except httpx.TimeoutException:
            logger.warning("crt.sh timeout (tentativa %d/%d)", attempt + 1, max_retries)
        except httpx.HTTPStatusError as e:
            logger.warning(
                "crt.sh HTTP %d (tentativa %d/%d)",
                e.response.status_code,
                attempt + 1,
                max_retries,
            )
        except Exception as e:
            logger.warning(
                "crt.sh erro: %s (tentativa %d/%d)", e, attempt + 1, max_retries
            )

    logger.warning("crt.sh indisponivel, usando wordlist apenas")
    return []


def _enumerate_subdomains(
    domain: str,
    extra_wordlist: str | None = None,
) -> list[str]:
    """Enumera subdominios (wordlist + crt.sh com fallback)."""
    wordlist_subs = _enumerate_wordlist(domain, extra_wordlist)
    crtsh_subs = _enumerate_crtsh(domain)
    seen: set[str] = set()
    result: list[str] = []
    for sub in wordlist_subs + crtsh_subs:
        if sub not in seen:
            seen.add(sub)
            result.append(sub)
    return result


# ---------------------------------------------------------------------------
# Service matching
# ---------------------------------------------------------------------------


def _match_service(
    cname_target: str, services: dict[str, dict[str, Any]]
) -> tuple[str, str] | None:
    """Verifica se CNAME target corresponde a um servico conhecido.

    Retorna (service_name, cname_suffix) ou None.
    """
    cname_lower = cname_target.lower()
    for svc_name, svc_data in services.items():
        suffix = svc_data.get("cname_suffix", "")
        if isinstance(suffix, str) and suffix and cname_lower.endswith(suffix.lower()):
            return svc_name, suffix
    return None


# ---------------------------------------------------------------------------
# HTTP fingerprint check
# ---------------------------------------------------------------------------


async def _check_http_fingerprint(
    client: httpx.AsyncClient,
    subdomain: str,
    signatures: list[str],
) -> tuple[int, bool, str]:
    """Faz HTTP GET e verifica se body contem alguma signature.

    Retorna (status_code, match_found, matched_signature).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}/"
        try:
            resp = await client.get(url, follow_redirects=True)
            body = resp.text[:50_000]
            body_lower = body.lower()
            for sig in signatures:
                if sig.lower() in body_lower:
                    logger.debug("HTTP match: %s em %s", sig, url)
                    return resp.status_code, True, sig
            return resp.status_code, False, ""
        except httpx.TimeoutException:
            logger.debug("HTTP timeout: %s", url)
        except httpx.ConnectError:
            logger.debug("HTTP connect error: %s", url)
        except Exception as e:
            logger.debug("HTTP erro %s: %s", url, e)
    return 0, False, ""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TakeoverAttempt:
    """Tentativa individual de subdomain takeover."""

    subdomain: str
    cname_target: str
    service: str
    http_status: int
    http_match: bool
    vulnerable: bool
    details: str
    error: str = ""


@dataclass(frozen=True, slots=True)
class TakeoverResult:
    """Resultado consolidado do scan de subdomain takeover."""

    target: str
    subdomains_scanned: int
    dangling_cnames: int
    attempts: list[TakeoverAttempt]
    vulnerable_subdomains: list[str]
    overall_status: str


# ---------------------------------------------------------------------------
# Core scan
# ---------------------------------------------------------------------------


async def run_scan(
    domain: str,
    timeout: int = 10,
    concurrency: int = 10,
    output_file: str | None = None,
    json_output: bool = False,
    wordlist: str | None = None,
) -> TakeoverResult:
    """Executa o scan de subdomain takeover contra o dominio alvo."""
    services = _get_services()
    if not services:
        logger.error("Nenhum service fingerprint carregado")
        return TakeoverResult(
            target=domain,
            subdomains_scanned=0,
            dangling_cnames=0,
            attempts=[],
            vulnerable_subdomains=[],
            overall_status="error",
        )

    logger.info("Enumerando subdominios de %s...", domain)
    subdomains = await asyncio.to_thread(_enumerate_subdomains, domain, wordlist)
    logger.info("Encontrados %d subdominios para %s", len(subdomains), domain)

    if not subdomains:
        return TakeoverResult(
            target=domain,
            subdomains_scanned=0,
            dangling_cnames=0,
            attempts=[],
            vulnerable_subdomains=[],
            overall_status="secure",
        )

    async with create_async_client(timeout=timeout) as client:
        attempts: list[TakeoverAttempt] = []

        async def _check_one(sub: str) -> TakeoverAttempt | None:
            cname = await asyncio.to_thread(_resolve_cname, sub, min(timeout, 5.0))
            if not cname:
                return None

            match = _match_service(cname, services)
            if not match:
                logger.debug("CNAME %s -> %s (servico desconhecido)", sub, cname)
                return None

            svc_name, _suffix = match
            signatures = services[svc_name].get("http_signatures", [])
            if not isinstance(signatures, list):
                signatures = []

            http_status, http_match, matched_sig = await _check_http_fingerprint(
                client,
                sub,
                signatures,
            )

            vulnerable = http_match
            details = (
                f"CNAME -> {cname} [{svc_name}], HTTP {http_status}, match: '{matched_sig}'"
                if http_match
                else f"CNAME -> {cname} [{svc_name}], HTTP {http_status}, sem match"
            )

            logger.info(
                "%s %s -> %s [%s] HTTP %d %s",
                "VULN" if vulnerable else "OK",
                sub,
                cname,
                svc_name,
                http_status,
                f"match='{matched_sig}'" if http_match else "",
            )

            return TakeoverAttempt(
                subdomain=sub,
                cname_target=cname,
                service=svc_name,
                http_status=http_status,
                http_match=http_match,
                vulnerable=vulnerable,
                details=details,
            )

        coros = [_check_one(sub) for sub in subdomains]
        results = await run_concurrent(coros, concurrency)

        dangling_count = 0
        vuln_subs: list[str] = []
        for r in results:
            if isinstance(r, TakeoverAttempt):
                attempts.append(r)
                if r.vulnerable:
                    dangling_count += 1
                    vuln_subs.append(r.subdomain)
            elif isinstance(r, Exception):
                logger.debug("Excecao em task: %s", r)

        overall = "vulnerable" if vuln_subs else "secure"

        result = TakeoverResult(
            target=domain,
            subdomains_scanned=len(subdomains),
            dangling_cnames=dangling_count,
            attempts=attempts,
            vulnerable_subdomains=vuln_subs,
            overall_status=overall,
        )

        if output_file:
            write_output(output_file, asdict(result))

        logger.info(
            "Subdomain takeover scan concluido: %d subdominios, %d dangling, %d vulneraveis",
            len(subdomains),
            dangling_count,
            len(vuln_subs),
        )

    return result


# ---------------------------------------------------------------------------
# Print results
# ---------------------------------------------------------------------------


def print_results(result: TakeoverResult) -> None:
    """Exibe os resultados do scan formatados."""
    print(color("\n" + "=" * 60, Cyber.GRAY))
    print(color("  SUBDOMAIN TAKEOVER SCANNER", Cyber.RED, Cyber.BOLD))
    print(color("=" * 60, Cyber.GRAY))
    print(color(f"  Dominio:       {result.target}", Cyber.CYAN))
    print(color(f"  Subdominios:   {result.subdomains_scanned} escaneados", Cyber.GRAY))
    print(
        color(f"  Dangling:      {result.dangling_cnames} CNAMEs pendentes", Cyber.GRAY)
    )

    vuln = [a for a in result.attempts if a.vulnerable]
    if vuln:
        print(
            color(f"\n  [!] {len(vuln)} SUBDOMINIOS VULNERAVEIS", Cyber.RED, Cyber.BOLD)
        )
        for a in vuln:
            print(color(f"      {a.subdomain}", Cyber.RED))
            print(color(f"        CNAME:  {a.cname_target}", Cyber.WHITE))
            print(color(f"        Servico: {a.service}", Cyber.WHITE))
            print(color(f"        HTTP:   {a.http_status}", Cyber.WHITE))
            print(color(f"        Match:  {a.details}", Cyber.YELLOW))
    else:
        print(
            color(
                "\n  [+] Nenhum subdomain takeover detectado", Cyber.GREEN, Cyber.BOLD
            )
        )

    non_vuln = [a for a in result.attempts if not a.vulnerable]
    if non_vuln:
        print(
            color(
                f"\n  [*] {len(non_vuln)} CNAMEs para servicos conhecidos (sem match HTTP)",
                Cyber.GRAY,
            )
        )

    print(color("=" * 60, Cyber.GRAY))


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

banner_art = create_banner(
    r"""
     _____           _       _   ____
    / ____|         | |     | | |  _ \
   | (___ _   _ _ __| |_ ___| | | | | |___  _ __ ___   __ _  __ _  ___
    \___ \| | | | '__| __/ _ \ | | | | / _ \| '_ ` _ \ / _` |/ _` |/ _ \
    ____) | |_| | | | ||  __/ | | | | (_) | | | | | | | (_| | (_| |  __/
   |_____/ \__,_|_|  \__\___|_| |_|  \___/|_| |_| |_|\__,_|\__, |\___|
                                                             __/ |
                                                            |___/
    """,
    "Subdomain Takeover — detecta dangling CNAMEs para servicos nao reclamados",
)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-subtakeover",
        description="Subdomain Takeover — detecta dangling CNAMEs para servicos nao reclamados",
    )
    parser.add_argument("domain", nargs="?", help="Dominio alvo (ex: example.com)")
    parser.add_argument(
        "--wordlist",
        help="Arquivo com subdominios extras (1 por linha)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Requisicoes simultaneas (default: 10)",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("Subdomain takeover scan iniciado para %s", args.domain)

    result = safe_asyncio_run(
        run_scan(
            domain=args.domain,
            timeout=getattr(args, "timeout", 10),
            concurrency=getattr(args, "concurrency", 10),
            output_file=getattr(args, "output", None),
            json_output=getattr(args, "json_output", False),
            wordlist=getattr(args, "wordlist", None),
        ),
    )

    if getattr(args, "json_output", False):
        print_json(asdict(result))
    else:
        print_results(result)

    return 1 if result.overall_status != "secure" else 0


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "domain", None)),
        prompt="subtakeover> ",
        description="Subdomain takeover interativo.",
        example="example.com",
        contextual_help=(
            "Uso: <domain> [opcoes]\nExemplos:\n  example.com\n  example.com --wordlist extras.txt\n  example.com --concurrency 20 --json-output"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
