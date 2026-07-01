#!/usr/bin/env python3
"""Wrapper que executa todos os modulos MyTools contra um alvo de uma vez.

Orquestracao:
  - Todos os modulos rodam em paralelo via asyncio.gather + asyncio.to_thread
  - Cada modulo e independente: cria seu proprio event loop e AsyncClient
  - Thread-safe: args e copiado (vars() -> Namespace), saida e atomic (print)

Fluxo:
  1. Determina se alvo e URL ou dominio
  2. Cria namespace base com argumentos compartilhados
  3. Monta lista de modulos para executar (respeitando --skip)
  4. Executa todos em paralelo via asyncio.gather
  5. Coleta erros e retorna total

Modulos disponiveis:
  - dnstransfer: DNS zone transfer (AXFR)
  - subenum: subdomain enumeration (DNS brute-force)
  - dnshistory: DNS history via OSINT APIs (A, AAAA, MX, NS, TXT)
  - portscanner: TCP port scan
  - dirscanner: HTTP directory brute-force
  - webrecon: HTTP passive recon (headers, CVE, WHOIS, emails)
  - attackaudit: red/blue web audit (XSS, SQLi, TLS, methods)
"""
import argparse
import asyncio
import os
import time
from collections.abc import Callable
from urllib.parse import urlparse

from mytools.config import backupfiledetect, configfiledetect
from mytools.core.utils import (
    Cyber,
    __version__,
    color,
    create_banner,
    parse_auth,
    safe_asyncio_run,
    setup_logging,
)
from mytools.dns import caacheck, dnsamplification, dnshistory, dnsrebinding, dnssecvalidation, dnstransfer, dnstunnel, dnswatorture, nsecwalking, subdomainenum
from mytools.email import (
    emailaddressbypass,
    emailattachmentbypass,
    emaillinktracking,
    emailsecurity,
    emailspoof,
    emailtemplateinject,
    smtpdowngrade,
    smtpinjection,
)
from mytools.network import dirscanner, portscanner
from mytools.network.portscanner import parse_ports
from mytools.osint import darkwebmonitor, emailbreachcheck, googledorking, ipasninfo, pasteleak, socialengrecon
from mytools.vcs import vcsleak
from mytools.web import (
    attackaudit,
    doubleurlencode,
    graphqlplayground,
    nullbyteinject,
    openapidiscovery,
    pathtraversal,
    rtloverride,
    sourcemapdiscovery,
    techfingerprint,
    webrecon,
)
from mytools.whois import whoishistory

ALL_MODULES = ["portscanner", "dnstransfer", "subenum", "dnshistory", "whoishistory", "ipasninfo", "techfingerprint", "openapidiscovery", "graphqlplayground", "sourcemapdiscovery", "vcsleak", "configfiledetect", "backupfiledetect", "googledorking", "emailbreachcheck", "socialengrecon", "pasteleak", "darkwebmonitor", "dnsrebinding", "dnswatorture", "dnsamplification", "dnstunnel", "dnssecvalidation", "nsecwalking",     "caacheck", "emailsecurity", "emailspoof", "smtpinjection", "smtpdowngrade", "emailtemplateinject", "emailattachmentbypass", "emailaddressbypass", "emaillinktracking", "nullbyteinject", "doubleurlencode", "pathtraversal", "overlongencoding", "bominjection", "charsetbypass", "openredirect", "crlfinjection", "sstidetect", "ssrfdetect", "xxedetect", "rtloverride", "dirscanner", "webrecon", "attackaudit"]

"""Recon completo: executa portscanner, dirscanner, webrecon, attackaudit, dnstransfer e subenum contra um alvo."""


def banner() -> None:
    art = r"""
    __  ___        ______            __
   /  |/  /_  __  /_  __/___  ____  / /____
  / /|_/ / / / /   / / / __ \/ __ \/ / ___/
 / /  / / /_/ /   / / / /_/ / /_/ / (__  )
/_/  /_/\__, /   /_/  \____/\____/_/____/
       /____/
"""
    create_banner(art, "   recon all-in-one: port + dir + web + audit + dns + subenum + dnshistory + whoishistory + ipasn + techfp + oas + gql + sm + vcs + cfg + bak + dork + breach + soceng + leak + dark + rebind + dwt + amp + tunnel + dnssec + nsec + caa + secemail + spoof + smtpinject + smtpdown + templeti + attachbypass + addrbypass + linktrack + nullbyte + dblurl + ptraversal + rtlo")()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mytools-reconall",
        description="Executa todos os modulos MyTools contra um alvo.",
    )
    parser.add_argument("target", help="Alvo: dominio (example.com) ou URL (https://example.com)")
    parser.add_argument("--deep", action="store_true", help="Modo profundo (crawl, path probing)")
    parser.add_argument("--test-vulns", action="store_true", help="Testa XSS/SQLi no attackaudit")
    parser.add_argument("--test-methods", action="store_true", help="Testa metodos HTTP (PUT/DELETE/PATCH)")
    parser.add_argument("--cve", action="store_true", help="Busca CVEs no webrecon")
    parser.add_argument("-p", "--ports", default="top100", type=parse_ports, help="Portas para portscanner. Padrao: top100")
    parser.add_argument("-o", "--output-dir", help="Diretorio para salvar resultados JSON de cada modulo")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Timeout em segundos. Padrao: 5")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostra mensagens de debug")
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso")
    parser.add_argument("--dry-run", action="store_true", help="Mostra o que faria sem executar nada")
    parser.add_argument("--auth", type=parse_auth, help="Autenticacao Basic (user:pass). Suporta @credencial do keyring.")
    parser.add_argument("--bearer-token", dest="bearer_token", help="Token Bearer para autenticacao. Suporta @credencial do keyring.")
    parser.add_argument("--cookie", help="Cookie para as requests. Suporta @credencial do keyring.")
    parser.add_argument("--header", action="append", default=[], help="Header customizado (pode repetir). Ex: 'X-Token: abc'")
    parser.add_argument("--skip", action="append", default=[],
                        choices=ALL_MODULES,
                        help=f"Modulo para pular (pode repetir). Opcoes: {', '.join(ALL_MODULES)}")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def _extract_domain(target: str) -> str:
    if _is_url(target):
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


def _make_args(target: str, extra: dict, base_args: argparse.Namespace) -> argparse.Namespace:
    ns = argparse.Namespace(**vars(base_args))
    for k, v in extra.items():
        setattr(ns, k, v)
    return ns


_PARSER_DEFAULTS: dict[str, object] | None = None

_ALL_MODS = (
    dirscanner, portscanner, dnstransfer, subdomainenum, dnshistory,
    whoishistory, ipasninfo, techfingerprint, openapidiscovery,
    graphqlplayground, sourcemapdiscovery, vcsleak, configfiledetect,
    backupfiledetect, googledorking, emailbreachcheck, socialengrecon,
    pasteleak, darkwebmonitor, dnsrebinding, dnswatorture,
    dnsamplification, dnstunnel, dnssecvalidation, nsecwalking,
    caacheck, emailsecurity, emailspoof, smtpinjection, smtpdowngrade, emailtemplateinject, emailattachmentbypass, emailaddressbypass, emaillinktracking, nullbyteinject, doubleurlencode, pathtraversal, rtloverride, webrecon, attackaudit,
)


def _get_parser_defaults() -> dict[str, object]:
    """Retorna defaults dos parsers dos modulos filhos, cacheados."""
    global _PARSER_DEFAULTS
    if _PARSER_DEFAULTS is None:
        _PARSER_DEFAULTS = {}
        for mod in _ALL_MODS:
            parser = mod.build_parser()
            _PARSER_DEFAULTS.update(vars(parser.parse_args([])))
    return _PARSER_DEFAULTS


def _build_base_ns(args: argparse.Namespace) -> argparse.Namespace:
    """Constroi base_ns derivando defaults dos parsers dos modulos filhos.

    Elimina hardcode de 37+ atributos. Quando um modulo adiciona um arg,
    ele aparece automaticamente aqui via build_parser().parse_args([]).
    """
    all_defaults = dict(_get_parser_defaults())

    # Overrides do reconall — valores que difinem do default do parser
    all_defaults.update({
        "output": None,
        "quiet": True,
        "log_file": None,
        "color": None,
        "verbose": args.verbose,
        "timeout": args.timeout,
        "dry_run": args.dry_run,
        "output_dir": args.output_dir,
        "user_agent": f"MyTools/{__version__}",
        "verify": False,
        "threads": None,
        "auth": getattr(args, "auth", None),
        "bearer_token": getattr(args, "bearer_token", None),
        "cookie": getattr(args, "cookie", None),
        "header": getattr(args, "header", None),
    })

    return argparse.Namespace(**all_defaults)


def run_all(args: argparse.Namespace) -> int:
    skipped = {s.lower() for s in args.skip}
    target = args.target
    is_url = _is_url(target)
    domain = _extract_domain(target)

    base_ns = _build_base_ns(args)

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)

    def _out(module_name: str) -> str | None:
        if not args.output_dir:
            return None
        return os.path.join(args.output_dir, f"{module_name}.json")

    modules: list[tuple[str, Callable[[argparse.Namespace], int], argparse.Namespace]] = []

    if "dnstransfer" not in skipped:
        modules.append(("dnstransfer", dnstransfer.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("dnstransfer")}, base_ns)))
    if "subenum" not in skipped:
        modules.append(("subenum", subdomainenum.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("subenum")}, base_ns)))

    if "dnshistory" not in skipped:
        modules.append(("dnshistory", dnshistory.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("dnshistory")}, base_ns)))

    if "whoishistory" not in skipped:
        modules.append(("whoishistory", whoishistory.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("whoishistory")}, base_ns)))

    if "ipasninfo" not in skipped:
        modules.append(("ipasninfo", ipasninfo.run_once,
                        _make_args(target, {"ips": [domain], "output": _out("ipasninfo")}, base_ns)))

    if "portscanner" not in skipped:
        modules.append(("portscanner", portscanner.run_once,
                        _make_args(target, {"targets": [domain], "ports": args.ports, "output": _out("portscanner")}, base_ns)))

    if "googledorking" not in skipped:
        modules.append(("googledorking", googledorking.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("googledorking")}, base_ns)))

    if "emailbreachcheck" not in skipped:
        admin_email = f"admin@{domain}"
        modules.append(("emailbreachcheck", emailbreachcheck.run_once,
                        _make_args(domain, {"emails": [admin_email], "output": _out("emailbreachcheck")}, base_ns)))

    if "socialengrecon" not in skipped:
        modules.append(("socialengrecon", socialengrecon.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("socialengrecon")}, base_ns)))

    if "pasteleak" not in skipped:
        modules.append(("pasteleak", pasteleak.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("pasteleak")}, base_ns)))

    if "darkwebmonitor" not in skipped:
        modules.append(("darkwebmonitor", darkwebmonitor.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("darkwebmonitor")}, base_ns)))

    if "dnsrebinding" not in skipped:
        modules.append(("dnsrebinding", dnsrebinding.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("dnsrebinding")}, base_ns)))

    if "dnswatorture" not in skipped:
        modules.append(("dnswatorture", dnswatorture.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("dnswatorture")}, base_ns)))

    if "dnsamplification" not in skipped:
        modules.append(("dnsamplification", dnsamplification.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("dnsamplification")}, base_ns)))

    if "dnstunnel" not in skipped:
        modules.append(("dnstunnel", dnstunnel.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("dnstunnel")}, base_ns)))

    if "dnssecvalidation" not in skipped:
        modules.append(("dnssecvalidation", dnssecvalidation.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("dnssecvalidation")}, base_ns)))

    if "nsecwalking" not in skipped:
        modules.append(("nsecwalking", nsecwalking.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("nsecwalking")}, base_ns)))

    if "caacheck" not in skipped:
        modules.append(("caacheck", caacheck.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("caacheck")}, base_ns)))

    if "emailsecurity" not in skipped:
        modules.append(("emailsecurity", emailsecurity.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("emailsecurity")}, base_ns)))

    if "emailspoof" not in skipped:
        modules.append(("emailspoof", emailspoof.run_once,
                        _make_args(domain, {"domain": domain, "output": _out("emailspoof")}, base_ns)))

    if "smtpinjection" not in skipped:
        modules.append(("smtpinjection", smtpinjection.run_once,
                        _make_args(target, {"target": domain, "output": _out("smtpinjection")}, base_ns)))

    if "smtpdowngrade" not in skipped:
        modules.append(("smtpdowngrade", smtpdowngrade.run_once,
                        _make_args(target, {"target": domain, "output": _out("smtpdowngrade")}, base_ns)))

    if "emailtemplateinject" not in skipped:
        modules.append(("emailtemplateinject", emailtemplateinject.run_once,
                        _make_args(target, {"target": domain, "output": _out("emailtemplateinject")}, base_ns)))

    if "emailattachmentbypass" not in skipped:
        modules.append(("emailattachmentbypass", emailattachmentbypass.run_once,
                        _make_args(target, {"target": domain, "output": _out("emailattachmentbypass")}, base_ns)))

    if "emailaddressbypass" not in skipped:
        modules.append(("emailaddressbypass", emailaddressbypass.run_once,
                        _make_args(target, {"target": domain, "output": _out("emailaddressbypass")}, base_ns)))

    if "emaillinktracking" not in skipped:
        modules.append(("emaillinktracking", emaillinktracking.run_once,
                        _make_args(target, {"target": domain, "output": _out("emaillinktracking")}, base_ns)))

    if "nullbyteinject" not in skipped and is_url:
        modules.append(("nullbyteinject", nullbyteinject.run_once,
                        _make_args(target, {"url": target, "output": _out("nullbyteinject")}, base_ns)))

    if "doubleurlencode" not in skipped and is_url:
        modules.append(("doubleurlencode", doubleurlencode.run_once,
                        _make_args(target, {"url": target, "output": _out("doubleurlencode")}, base_ns)))

    if "pathtraversal" not in skipped and is_url:
        modules.append(("pathtraversal", pathtraversal.run_once,
                        _make_args(target, {"url": target, "output": _out("pathtraversal")}, base_ns)))

    if is_url:
        if "techfingerprint" not in skipped:
            modules.append(("techfingerprint", techfingerprint.run_once,
                            _make_args(target, {"urls": [target], "output": _out("techfingerprint")}, base_ns)))
        if "openapidiscovery" not in skipped:
            modules.append(("openapidiscovery", openapidiscovery.run_once,
                            _make_args(target, {"url": target, "output": _out("openapidiscovery")}, base_ns)))
        if "graphqlplayground" not in skipped:
            modules.append(("graphqlplayground", graphqlplayground.run_once,
                            _make_args(target, {"url": target, "output": _out("graphqlplayground")}, base_ns)))
        if "sourcemapdiscovery" not in skipped:
            modules.append(("sourcemapdiscovery", sourcemapdiscovery.run_once,
                            _make_args(target, {"url": target, "output": _out("sourcemapdiscovery")}, base_ns)))
        if "vcsleak" not in skipped:
            modules.append(("vcsleak", vcsleak.run_once,
                            _make_args(target, {"url": target, "output": _out("vcsleak")}, base_ns)))
        if "configfiledetect" not in skipped:
            modules.append(("configfiledetect", configfiledetect.run_once,
                            _make_args(target, {"url": target, "output": _out("configfiledetect")}, base_ns)))
        if "backupfiledetect" not in skipped:
            modules.append(("backupfiledetect", backupfiledetect.run_once,
                            _make_args(target, {"url": target, "output": _out("backupfiledetect")}, base_ns)))
        if "dirscanner" not in skipped:
            modules.append(("dirscanner", dirscanner.run_once,
                            _make_args(target, {"url": target, "output": _out("dirscanner"), "extensions": ["php", "txt", "bak", "html"]}, base_ns)))
        if "webrecon" not in skipped:
            modules.append(("webrecon", webrecon.run_once,
                            _make_args(target, {"url": target, "output": _out("webrecon"), "cve": args.cve, "deep": args.deep}, base_ns)))
        if "attackaudit" not in skipped:
            modules.append(("attackaudit", attackaudit.run_once,
                            _make_args(target, {
                                "url": target,
                                "output": _out("attackaudit"),
                                "deep": args.deep,
                                "test_vulns": args.test_vulns,
                                "test_methods": args.test_methods,
                            }, base_ns)))

    if not modules:
        return 0

    async def _run_all_async() -> int:
        total_errors = 0

        async def _run_one(name: str, fn: Callable[[argparse.Namespace], int], a: argparse.Namespace) -> int:
            color_name = color(f"[{name}]", Cyber.CYAN, Cyber.BOLD)
            print(f"\n{'='*60}")
            print(f" {color_name} Iniciando {name}")
            print(f"{'='*60}")
            start = time.monotonic()
            try:
                result = await asyncio.to_thread(fn, a)
            except Exception as exc:
                print(color(f"  Erro em {name}: {exc}", Cyber.RED))
                return 1
            elapsed = time.monotonic() - start
            status = color("OK", Cyber.GREEN, Cyber.BOLD) if result == 0 else color(f"FALHA ({result})", Cyber.RED, Cyber.BOLD)
            print(f" {color_name} {status} ({elapsed:.1f}s)")
            return result

        tasks = [_run_one(name, fn, a) for name, fn, a in modules]
        async with asyncio.TaskGroup() as tg:
            futures = [tg.create_task(t) for t in tasks]
        for f in futures:
            total_errors += f.result()
        return total_errors

    return safe_asyncio_run(_run_all_async())


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    if args.dry_run:
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Modo dry-run ativado")
        print(color("  Alvo:", Cyber.CYAN), args.target)
        print(color("  Modulos:", Cyber.CYAN), ", ".join(m for m in ALL_MODULES if m not in args.skip))
        if args.deep:
            print(color("  Flags:", Cyber.CYAN), "--deep")
        if args.test_vulns:
            print(color("  Flags:", Cyber.CYAN), "--test-vulns")
        if args.cve:
            print(color("  Flags:", Cyber.CYAN), "--cve")
        if getattr(args, "bearer_token", None):
            print(color("  Auth:", Cyber.CYAN), "bearer-token")
        elif getattr(args, "auth", None):
            print(color("  Auth:", Cyber.CYAN), "basic")
        elif getattr(args, "cookie", None):
            print(color("  Auth:", Cyber.CYAN), "cookie")
        return 0

    banner()
    print(color(f"  Alvo: {args.target}", Cyber.WHITE, Cyber.BOLD))
    print(color(f"  Modulos: {', '.join(m for m in ALL_MODULES if m not in args.skip)}", Cyber.WHITE))

    start = time.monotonic()
    errors = run_all(args)
    elapsed = time.monotonic() - start

    print(f"\n{'='*60}")
    if errors == 0:
        print(color("  Recon concluido com sucesso!", Cyber.GREEN, Cyber.BOLD))
    else:
        print(color(f"  Recon concluido com {errors} erro(s)", Cyber.YELLOW, Cyber.BOLD))
    print(color(f"  Tempo total: {elapsed:.1f}s", Cyber.WHITE))
    print(f"{'='*60}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
