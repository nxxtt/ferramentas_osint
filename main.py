#!/usr/bin/env python3
from __future__ import annotations

import sys

import attackaudit
import dirscanner
import dnstransfer
import portscanner
import subdomainenum
import webrecon
from utils import Cyber, clear_console, color, run_interactive_shell, show_banner, __version__

"""Módulo principal que integra as ferramentas de segurança: port scanner, dir scanner, web recon e attack audit."""


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
    show_banner(art, "   port scanner + dir scanner + web recon + attack audit + dns xfer + subenum")
    print(color("   by Default\n", Cyber.GRAY))


def menu() -> None:
    """Exibe o menu interativo com opções de ferramentas."""
    print(color("Escolha uma tool:", Cyber.WHITE, Cyber.BOLD))
    print(f"  {color('1', Cyber.GREEN, Cyber.BOLD)} {color('PortScanner', Cyber.CYAN)}      TCP ports, CIDR, banners, JSON/CSV")
    print(f"  {color('2', Cyber.GREEN, Cyber.BOLD)} {color('DirScanner', Cyber.CYAN)}       HTTP dirs/files, status filters, wordlist")
    print(f"  {color('3', Cyber.GREEN, Cyber.BOLD)} {color('WebRecon', Cyber.CYAN)}         HTTP headers, robots, security checks")
    print(f"  {color('4', Cyber.GREEN, Cyber.BOLD)} {color('AttackAudit', Cyber.CYAN)}      red/blue web audit pesado, score, JSON/CSV")
    print(f"  {color('5', Cyber.GREEN, Cyber.BOLD)} {color('DNS Xfer', Cyber.CYAN)}         DNS zone transfer (AXFR)")
    print(f"  {color('6', Cyber.GREEN, Cyber.BOLD)} {color('SubEnum', Cyber.CYAN)}          Subdomain enumeration (DNS brute-force)")
    print(f"  {color('7', Cyber.GREEN, Cyber.BOLD)} {color('Ajuda', Cyber.CYAN)}            exemplos rapidos")
    print(f"  {color('8', Cyber.GREEN, Cyber.BOLD)} {color('Limpar', Cyber.CYAN)}           limpar terminal")
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
    )


def launch_dirscanner() -> None:
    """Inicia o módulo DirScanner em modo interativo."""
    parser = dirscanner.build_parser()
    run_interactive_shell(
        parser, "dirscan> ", dirscanner.run_once,
        description="DirScanner interativo.",
        example="http://localhost:8000 -x php,txt,bak -s 200,301,403",
        banner_fn=dirscanner.banner,
    )


def launch_webrecon() -> None:
    """Inicia o módulo WebRecon em modo interativo."""
    parser = webrecon.build_parser()
    run_interactive_shell(
        parser, "webrecon> ", webrecon.run_once,
        description="WebRecon interativo.",
        example="https://example.com -o recon.json",
        banner_fn=webrecon.banner,
    )


def launch_attackaudit() -> None:
    """Inicia o módulo AttackAudit em modo interativo."""
    parser = attackaudit.build_parser()
    run_interactive_shell(
        parser, "audit> ", attackaudit.run_once,
        description="AttackAudit interativo.",
        example="https://example.com --deep --test-vulns -o audit.json",
        banner_fn=attackaudit.banner,
    )


def launch_dnstransfer() -> None:
    """Inicia o módulo DNS Zone Transfer em modo interativo."""
    parser = dnstransfer.build_parser()
    run_interactive_shell(
        parser, "dnsxfer> ", dnstransfer.run_once,
        description="DNS Zone Transfer interativo.",
        example="example.com -o xfr.json",
        banner_fn=dnstransfer.banner,
    )


def launch_subdomainenum() -> None:
    """Inicia o módulo Subdomain Enumeration em modo interativo."""
    parser = subdomainenum.build_parser()
    run_interactive_shell(
        parser, "subenum> ", subdomainenum.run_once,
        description="Subdomain Enumeration interativo.",
        example="example.com -o subs.json",
        banner_fn=subdomainenum.banner,
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
        elif choice in {"7", "help", "ajuda", "h"}:
            help_screen()
            input(color("Enter para voltar...", Cyber.GRAY))
        elif choice in {"8", "clear", "limpar", "cls"}:
            clear_console()
            continue
        else:
            print(color("Opcao invalida.", Cyber.RED))
            input(color("Enter para continuar...", Cyber.GRAY))

        clear_console()


if __name__ == "__main__":
    raise SystemExit(main())
