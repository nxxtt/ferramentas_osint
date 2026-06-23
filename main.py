#!/usr/bin/env python3
from __future__ import annotations

import sys

import attackaudit
import dirscanner
import dnshistory
import dnstransfer
import ipasninfo
import portscanner
import reconall
import subdomainenum
import techfingerprint
import webrecon
import whoishistory
from utils import Cyber, __version__, clear_console, color, create_banner, run_interactive_shell

"""Modulo principal que integra as ferramentas de segurança.

Painel interativo central que permite alternar entre:
  1. PortScanner  - TCP port scan com banner grabbing
  2. DirScanner   - HTTP directory brute-force
  3. WebRecon     - HTTP passive recon (headers, CVE, WHOIS)
  4. AttackAudit  - Red/blue web audit (XSS, SQLi, TLS)
  5. DNS Xfer     - DNS zone transfer (AXFR)
  6. SubEnum      - Subdomain enumeration (DNS brute-force)
  7. DNS History  - DNS history via OSINT APIs
  8. WHOIS History - WHOIS history via OSINT APIs
  9. ReconAll     - Todos os modulos contra um alvo

Cada modulo e lancado em modo interativo com seu proprio shell de comandos.
O usuario pode usar argumentos CLI normalmente dentro de cada shell.
Use 'exit' para voltar ao menu principal.
"""


def banner() -> None:
    """Exibe o banner artístico e informações do projeto."""
    art = r"""
    __  ___        ______            __
   /  |/  /_  __  /_  __/___  ____  / /____
  / /|_/ / / / /   / / / __ \/ __ \/ / ___/
 / /  / / /_/ /   / / / /_/ / /_/ / (__  )
/_/  /_/\__, /   /_/  \____/\____/_/____/
       /____/
"""
    create_banner(art, "   port scanner + dir scanner + web recon + attack audit + dns xfer + subenum + dnshistory + whoishistory",
                  extra=lambda: print(color("   by Default\n", Cyber.GRAY)))()


def menu() -> None:
    """Exibe o menu interativo com opções de ferramentas."""
    print(color("Escolha uma tool:", Cyber.WHITE, Cyber.BOLD))
    print(f"  {color('1', Cyber.GREEN, Cyber.BOLD)} {color('PortScanner', Cyber.CYAN)}      TCP ports, CIDR, banners, JSON/CSV")
    print(f"  {color('2', Cyber.GREEN, Cyber.BOLD)} {color('DirScanner', Cyber.CYAN)}       HTTP dirs/files, status filters, wordlist")
    print(f"  {color('3', Cyber.GREEN, Cyber.BOLD)} {color('WebRecon', Cyber.CYAN)}         HTTP headers, robots, security checks")
    print(f"  {color('4', Cyber.GREEN, Cyber.BOLD)} {color('AttackAudit', Cyber.CYAN)}      red/blue web audit pesado, score, JSON/CSV")
    print(f"  {color('5', Cyber.GREEN, Cyber.BOLD)} {color('DNS Xfer', Cyber.CYAN)}         DNS zone transfer (AXFR)")
    print(f"  {color('6', Cyber.GREEN, Cyber.BOLD)} {color('SubEnum', Cyber.CYAN)}          Subdomain enumeration (DNS brute-force)")
    print(f"  {color('7', Cyber.GREEN, Cyber.BOLD)} {color('DNS History', Cyber.CYAN)}      DNS history via OSINT APIs")
    print(f"  {color('8', Cyber.GREEN, Cyber.BOLD)} {color('WHOIS History', Cyber.CYAN)}   WHOIS history via OSINT APIs")
    print(f"  {color('9', Cyber.GREEN, Cyber.BOLD)} {color('IP ASN Info', Cyber.CYAN)}     IP -> ASN/org/ISP/country enrichment")
    print(f"  {color('10', Cyber.GREEN, Cyber.BOLD)} {color('Tech Fingerprint', Cyber.CYAN)} Detecta tecnologias com versoes exatas")
    print(f"  {color('11', Cyber.GREEN, Cyber.BOLD)} {color('ReconAll', Cyber.CYAN)}          Todos os modulos contra um alvo")
    print(f"  {color('12', Cyber.GREEN, Cyber.BOLD)} {color('Ajuda', Cyber.CYAN)}            exemplos rapidos")
    print(f"  {color('13', Cyber.GREEN, Cyber.BOLD)} {color('Limpar', Cyber.CYAN)}           limpar terminal")
    print(f"  {color('0', Cyber.RED, Cyber.BOLD)} {color('Sair', Cyber.CYAN)}")


def help_screen() -> None:
    """Exibe exemplos de uso rápido para cada ferramenta."""
    print(color("\nExemplos:", Cyber.WHITE, Cyber.BOLD))
    print(color("PortScanner:", Cyber.CYAN))
    print("  python3 portscanner.py 127.0.0.1 -p 22,80,443")
    print("  python3 portscanner.py 192.168.0.0/24 -p top100 -b")
    print(color("\nDirScanner:", Cyber.CYAN))
    print("  python3 dirscanner.py http://testphp.vulnweb.com -x php,txt,bak")
    print("  python3 dirscanner.py http://127.0.0.1:8000 -s 200,301,403")
    print(color("\nWebRecon:", Cyber.CYAN))
    print("  python3 webrecon.py https://example.com")
    print("  python3 webrecon.py https://example.com -o recon.json")
    print(color("\nAttackAudit:", Cyber.CYAN))
    print("  python3 attackaudit.py https://example.com --deep")
    print("  python3 attackaudit.py https://example.com --deep -o audit.json")
    print(color("\nDNS Xfer:", Cyber.CYAN))
    print("  python3 dnstransfer.py example.com")
    print("  python3 dnstransfer.py example.com -o xfr.json")
    print(color("\nSubEnum:", Cyber.CYAN))
    print("  python3 subdomainenum.py example.com")
    print("  python3 subdomainenum.py example.com -w wordlist.txt -o subs.json")
    print(color("\nDNS History:", Cyber.CYAN))
    print("  mytools-dnshistory example.com")
    print("  mytools-dnshistory example.com --source securitytrails --st-api-key KEY")
    print(color("\nWHOIS History:", Cyber.CYAN))
    print("  mytools-whoishistory example.com")
    print("  mytools-whoishistory example.com --source securitytrails --st-api-key KEY")
    print("  mytools-whoishistory example.com --source whoisxml --whoisxml-api-key KEY")
    print(color("\nIP ASN Info:", Cyber.CYAN))
    print("  mytools-ipasn 8.8.8.8 1.1.1.1")
    print("  mytools-ipasn -f ips.txt -o results.json")
    print(color("\nTech Fingerprint:", Cyber.CYAN))
    print("  mytools-techfp https://example.com")
    print("  mytools-techfp https://example.com -o tech.json")
    print("  mytools-techfp -l urls.txt -o results.json")
    print(color("\nReconAll:", Cyber.CYAN))
    print("  python3 reconall.py example.com")
    print("  python3 reconall.py example.com --deep --skip dnstransfer")
    print(color("\nDentro do menu:", Cyber.CYAN))
    print("  escolha uma tool e digite os argumentos como faria depois do nome do script.")
    print("  use 'exit' dentro de cada scanner para voltar ao menu.\n")


def launch_portscanner() -> None:
    """Inicia o módulo PortScanner em modo interativo."""
    parser = portscanner.build_parser()

    def _validate(args):
        if not args.targets:
            raise ValueError("Informe pelo menos um alvo.")

    run_interactive_shell(
        parser, "scanner> ", portscanner.run_once,
        description="PortScanner interativo.",
        example="192.168.0.10 -p 1-1024 -b",
        validate_fn=_validate,
        banner_fn=portscanner.banner,
        contextual_help=(
            "Uso: <target> [opcoes]\n"
            "  Targets: IP, hostname ou CIDR (IPv4/IPv6)\n"
            "Exemplos:\n"
            "  192.168.0.10 -p 22,80,443\n"
            "  scanme.nmap.org -p top100 -b\n"
            "  -l targets.txt -o results.json"
        ),
    )


def launch_dirscanner() -> None:
    """Inicia o módulo DirScanner em modo interativo."""
    parser = dirscanner.build_parser()
    run_interactive_shell(
        parser, "dirscan> ", dirscanner.run_once,
        description="DirScanner interativo.",
        example="http://localhost:8000 -x php,txt,bak -s 200,301,403",
        banner_fn=dirscanner.banner,
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://localhost:8000 -x php,txt,bak\n"
            "  http://target.com -s 200,301,403\n"
            "  -l urls.txt -o out.json"
        ),
    )


def launch_webrecon() -> None:
    """Inicia o módulo WebRecon em modo interativo."""
    parser = webrecon.build_parser()
    run_interactive_shell(
        parser, "webrecon> ", webrecon.run_once,
        description="WebRecon interativo.",
        example="https://example.com -o recon.json",
        banner_fn=webrecon.banner,
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://example.com\n"
            "  https://example.com --cve --deep\n"
            "  -l urls.txt -o recon.json"
        ),
    )


def launch_attackaudit() -> None:
    """Inicia o módulo AttackAudit em modo interativo."""
    parser = attackaudit.build_parser()
    run_interactive_shell(
        parser, "audit> ", attackaudit.run_once,
        description="AttackAudit interativo.",
        example="https://example.com --deep --test-vulns -o audit.json",
        banner_fn=attackaudit.banner,
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://example.com --deep\n"
            "  https://example.com --deep --test-vulns\n"
            "  -l urls.txt -o audit.json"
        ),
    )


def launch_dnstransfer() -> None:
    """Inicia o módulo DNS Zone Transfer em modo interativo."""
    parser = dnstransfer.build_parser()
    run_interactive_shell(
        parser, "dnsxfer> ", dnstransfer.run_once,
        description="DNS Zone Transfer interativo.",
        example="example.com -o xfr.json",
        banner_fn=dnstransfer.banner,
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com -o xfr.json"
        ),
    )


def launch_subdomainenum() -> None:
    """Inicia o módulo Subdomain Enumeration em modo interativo."""
    parser = subdomainenum.build_parser()
    run_interactive_shell(
        parser, "subenum> ", subdomainenum.run_once,
        description="Subdomain Enumeration interativo.",
        example="example.com -o subs.json",
        banner_fn=subdomainenum.banner,
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com -w wordlist.txt -o subs.json"
        ),
    )


def launch_dnshistory() -> None:
    """Inicia o módulo DNS History em modo interativo."""
    parser = dnshistory.build_parser()
    run_interactive_shell(
        parser, "dns-history> ", dnshistory.run_once,
        description="DNS History interativo — consulta historico de registros DNS via OSINT.",
        example="example.com --source dnslytics",
        banner_fn=create_banner(dnshistory.BANNER_ART, "DNS History"),
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --source securitytrails --st-api-key KEY\n"
            "  example.com --record-types a,mx,ns -o history.json"
        ),
    )


def launch_whoishistory() -> None:
    """Inicia o módulo WHOIS History em modo interativo."""
    parser = whoishistory.build_parser()
    run_interactive_shell(
        parser, "whois-history> ", whoishistory.run_once,
        description="WHOIS History interativo — consulta historico de WHOIS via OSINT.",
        example="example.com --source securitytrails",
        banner_fn=create_banner(whoishistory.BANNER_ART, "WHOIS History"),
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --source securitytrails --st-api-key KEY\n"
            "  example.com --source whoisxml --whoisxml-api-key KEY\n"
            "  example.com -o whois-history.json"
        ),
    )


def launch_ipasninfo() -> None:
    """Inicia o módulo IP ASN Info em modo interativo."""
    parser = ipasninfo.build_parser()
    run_interactive_shell(
        parser, "ip-asn> ", ipasninfo.run_once,
        description="IP ASN Info interativo — enriquece IPs com dados BGP (ASN, org, ISP, pais).",
        example="8.8.8.8 1.1.1.1",
        banner_fn=create_banner(ipasninfo.BANNER_ART, "IP ASN Info"),
        contextual_help=(
            "Uso: <ips...> [opcoes]\n"
            "Exemplos:\n"
            "  8.8.8.8\n"
            "  8.8.8.8 1.1.1.1 208.67.222.222\n"
            "  -f ips.txt -o results.json\n"
            "  --batch -f ips.txt (usa ip-api.com batch)"
        ),
    )


def launch_techfingerprint() -> None:
    """Inicia o modulo Tech Fingerprint em modo interativo."""
    parser = techfingerprint.build_parser()
    run_interactive_shell(
        parser, "techfp> ", techfingerprint.run_once,
        description="Tech Fingerprint interativo — detecta tecnologias com versoes exatas.",
        example="https://example.com -o tech.json",
        banner_fn=create_banner(techfingerprint.BANNER_ART, "Technology Fingerprint"),
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://example.com\n"
            "  https://example.com -o tech.json\n"
            "  -l urls.txt -o results.json"
        ),
    )


def launch_reconall() -> None:
    """Inicia o módulo ReconAll em modo interativo."""
    parser = reconall.build_parser()
    run_interactive_shell(
        parser, "reconall> ", reconall.run_all,
        description="ReconAll interativo — executa todos os modulos contra um alvo.",
        example="https://example.com --deep",
        banner_fn=reconall.banner,
        contextual_help=(
            "Uso: <target> [opcoes]\n"
            "  Target: URL ou dominio\n"
            "Exemplos:\n"
            "  example.com\n"
            "  https://example.com --deep\n"
            "  example.com --skip dnstransfer --skip subenum"
        ),
    )


def main() -> int:
    """Loop principal do menu interativo. Retorna 0 ao sair."""
    if "--version" in sys.argv or "-V" in sys.argv:
        print(f"mytools {__version__}")
        return 0
    while True:
        banner()
        menu()
        try:
            choice = input(color("\nuser-agent> ", Cyber.GREEN, Cyber.BOLD)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in {"0", "q", "quit", "exit"}:
            print(color("bye bye user!", Cyber.MAGENTA))
            return 0
        if choice in {"1", "port", "ports", "portscanner"}:
            launch_portscanner()
        elif choice in {"2", "dir", "dirs", "dirscanner"}:
            launch_dirscanner()
        elif choice in {"3", "web", "recon", "webrecon"}:
            launch_webrecon()
        elif choice in {"4", "audit", "attack", "attackaudit", "redblue"}:
            launch_attackaudit()
        elif choice in {"5", "dns", "xfer", "dnstransfer", "dnsxfer"}:
            launch_dnstransfer()
        elif choice in {"6", "sub", "subenum", "subdomainenum"}:
            launch_subdomainenum()
        elif choice in {"7", "dns-history", "dnshistory", "history"}:
            launch_dnshistory()
        elif choice in {"8", "whois-history", "whoishistory", "whois"}:
            launch_whoishistory()
        elif choice in {"9", "ip-asn", "ipasn", "asn"}:
            launch_ipasninfo()
        elif choice in {"10", "tech", "techfp", "fingerprint"}:
            launch_techfingerprint()
        elif choice in {"11", "recon", "reconall"}:
            launch_reconall()
        elif choice in {"12", "help", "ajuda", "h"}:
            help_screen()
            input(color("Enter para voltar...", Cyber.GRAY))
        elif choice in {"13", "clear", "limpar", "cls"}:
            clear_console()
            continue
        else:
            print(color("Opcao invalida.", Cyber.RED))
            input(color("Enter para continuar...", Cyber.GRAY))

        clear_console()


if __name__ == "__main__":
    raise SystemExit(main())
