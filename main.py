#!/usr/bin/env python3
import sys

import attackaudit
import backupfiledetect
import configfiledetect
import dirscanner
import dnshistory
import dnstransfer
import emailbreachcheck
import googledorking
import graphqlplayground
import ipasninfo
import openapidiscovery
import portscanner
import reconall
import socialengrecon
import sourcemapdiscovery
import subdomainenum
import techfingerprint
import vcsleak
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
  9. IP ASN Info  - IP -> ASN/org/ISP enrichment
  10. Tech Fingerprint - Detecta tecnologias com versoes exatas
  11. OpenAPI/Swagger  - Busca specs OpenAPI/Swagger expostas
  12. GraphQL Playground - Descobre GraphQL playgrounds e introspection
  13. Source Map Discovery - Busca .map files de JavaScript expostos
  14. VCS Leak Detection - Detecta .git, .svn, .hg expostos
   15. Config File Detection - Busca .env, config.json, settings.py expostos
   16. Backup File Detection - Busca .bak, .old, .swp, .sql, .zip expostos
   17. Google Dorking - Gera dorks e busca via DuckDuckGo
   18. Email Breach Check - Verifica emails em vazamentos de dados
   19. Social Engineering Recon - Coleta emails, nomes, cargos de funcionarios
   20. ReconAll     - Todos os modulos contra um alvo

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
    create_banner(art, "   port scanner + dir scanner + web recon + attack audit + dns xfer + subenum + dnshistory + whoishistory + oas + bak + dork + breach + soceng",
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
    print(f"  {color('11', Cyber.GREEN, Cyber.BOLD)} {color('OpenAPI/Swagger', Cyber.CYAN)}  Busca specs OpenAPI/Swagger expostas")
    print(f"  {color('12', Cyber.GREEN, Cyber.BOLD)} {color('GraphQL Playground', Cyber.CYAN)} Descobre GraphQL playgrounds e introspection")
    print(f"  {color('13', Cyber.GREEN, Cyber.BOLD)} {color('Source Map Discovery', Cyber.CYAN)} Busca .map files de JavaScript expostos")
    print(f"  {color('14', Cyber.GREEN, Cyber.BOLD)} {color('VCS Leak Detection', Cyber.CYAN)} Detecta .git, .svn, .hg expostos")
    print(f"  {color('15', Cyber.GREEN, Cyber.BOLD)} {color('Config File Detection', Cyber.CYAN)} Busca .env, config.json, settings.py expostos")
    print(f"  {color('16', Cyber.GREEN, Cyber.BOLD)} {color('Backup File Detection', Cyber.CYAN)} Busca .bak, .old, .swp, .sql, .zip expostos")
    print(f"  {color('17', Cyber.GREEN, Cyber.BOLD)} {color('Google Dorking', Cyber.CYAN)}       Gera dorks, busca via DuckDuckGo")
    print(f"  {color('18', Cyber.GREEN, Cyber.BOLD)} {color('Email Breach Check', Cyber.CYAN)} Verifica emails em vazamentos")
    print(f"  {color('19', Cyber.GREEN, Cyber.BOLD)} {color('Social Eng Recon', Cyber.CYAN)}  Coleta emails, nomes, cargos")
    print(f"  {color('20', Cyber.GREEN, Cyber.BOLD)} {color('ReconAll', Cyber.CYAN)}          Todos os modulos contra um alvo")
    print(f"  {color('21', Cyber.GREEN, Cyber.BOLD)} {color('Ajuda', Cyber.CYAN)}            exemplos rapidos")
    print(f"  {color('22', Cyber.GREEN, Cyber.BOLD)} {color('Limpar', Cyber.CYAN)}           limpar terminal")
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
    print(color("\nOpenAPI/Swagger:", Cyber.CYAN))
    print("  mytools-oas http://target.com")
    print("  mytools-oas http://target.com --endpoints")
    print("  mytools-oas -l urls.txt -o oas.json")
    print(color("\nGraphQL Playground:", Cyber.CYAN))
    print("  mytools-gql http://target.com")
    print("  mytools-gql http://target.com --introspect")
    print("  mytools-gql http://target.com --introspect --schema")
    print(color("\nSource Map Discovery:", Cyber.CYAN))
    print("  mytools-sm http://target.com")
    print("  mytools-sm http://target.com --sources")
    print("  mytools-sm http://target.com --no-scan-scripts")
    print(color("\nVCS Leak Detection:", Cyber.CYAN))
    print("  mytools-vcs http://target.com")
    print("  mytools-vcs http://target.com --git-only")
    print("  mytools-vcs http://target.com --svn-only")
    print(color("\nConfig File Detection:", Cyber.CYAN))
    print("  mytools-cfg http://target.com")
    print("  mytools-cfg http://target.com --category env")
    print("  mytools-cfg http://target.com --sensitive-only")
    print("  mytools-cfg -l urls.txt -o results.json")
    print(color("\nBackup File Detection:", Cyber.CYAN))
    print("  mytools-bak http://target.com")
    print("  mytools-bak http://target.com --type sql")
    print("  mytools-bak http://target.com --type archive")
    print("  mytools-bak -l urls.txt -o results.json")
    print(color("\nGoogle Dorking:", Cyber.CYAN))
    print("  mytools-dork example.com")
    print("  mytools-dork example.com --category filetype")
    print("  mytools-dork example.com --category sensitive --search")
    print("  mytools-dork example.com --custom-dork 'inurl:api v1'")
    print("  mytools-dork -l domains.txt -o results.json")
    print(color("\nEmail Breach Check:", Cyber.CYAN))
    print("  mytools-breach user@example.com")
    print("  mytools-breach user1@test.com user2@test.com")
    print("  mytools-breach user@example.com --source hibp --hibp-api-key KEY")
    print("  mytools-breach -f emails.txt -o results.json")
    print(color("\nSocial Engineering Recon:", Cyber.CYAN))
    print("  mytools-soceng example.com")
    print("  mytools-soceng example.com --source github --source hunter")
    print("  mytools-soceng example.com --hunter-api-key KEY")
    print("  mytools-soceng -l domains.txt -o results.json")
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


def launch_openapidiscovery() -> None:
    """Inicia o modulo OpenAPI/Swagger Discovery em modo interativo."""
    parser = openapidiscovery.build_parser()
    run_interactive_shell(
        parser, "oas> ", openapidiscovery.run_once,
        description="OpenAPI/Swagger Discovery interativo — busca specs expostas.",
        example="http://target.com --endpoints",
        banner_fn=openapidiscovery.banner,
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --endpoints\n"
            "  -l urls.txt -o oas.json"
        ),
    )


def launch_graphqlplayground() -> None:
    """Inicia o modulo GraphQL Playground Discovery em modo interativo."""
    parser = graphqlplayground.build_parser()
    run_interactive_shell(
        parser, "gql> ", graphqlplayground.run_once,
        description="GraphQL Playground Discovery interativo — descobre endpoints GraphQL expostos.",
        example="http://target.com --introspect",
        banner_fn=graphqlplayground.banner,
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --introspect\n"
            "  http://target.com --introspect --schema\n"
            "  -l urls.txt -o results.json"
        ),
    )


def launch_sourcemapdiscovery() -> None:
    """Inicia o modulo Source Map Discovery em modo interativo."""
    parser = sourcemapdiscovery.build_parser()
    run_interactive_shell(
        parser, "sm> ", sourcemapdiscovery.run_once,
        description="Source Map Discovery interativo — busca .map files de JavaScript expostos.",
        example="http://target.com --sources",
        banner_fn=sourcemapdiscovery.banner,
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --sources\n"
            "  http://target.com --no-scan-scripts\n"
            "  -l urls.txt -o results.json"
        ),
    )


def launch_vcsleak() -> None:
    """Inicia o modulo VCS Leak Detection em modo interativo."""
    parser = vcsleak.build_parser()
    run_interactive_shell(
        parser, "vcs> ", vcsleak.run_once,
        description="VCS Leak Detection interativo — detecta .git, .svn, .hg expostos.",
        example="http://target.com --git-only",
        banner_fn=vcsleak.banner,
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --git-only\n"
            "  http://target.com --svn-only\n"
            "  -l urls.txt -o results.json"
        ),
    )


def launch_configfiledetect() -> None:
    """Inicia o modulo Config File Detection em modo interativo."""
    parser = configfiledetect.build_parser()
    run_interactive_shell(
        parser, "cfg> ", configfiledetect.run_once,
        description="Config File Detection interativo — busca .env, config.json, settings.py expostos.",
        example="http://target.com --category env",
        banner_fn=configfiledetect.banner,
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --category env\n"
            "  http://target.com --sensitive-only\n"
            "  -l urls.txt -o results.json"
        ),
    )


def launch_backupfiledetect() -> None:
    """Inicia o modulo Backup File Detection em modo interativo."""
    parser = backupfiledetect.build_parser()
    run_interactive_shell(
        parser, "bak> ", backupfiledetect.run_once,
        description="Backup File Detection interativo — busca .bak, .old, .swp, .sql, .zip expostos.",
        example="http://target.com --type sql",
        banner_fn=backupfiledetect.banner,
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --type sql\n"
            "  http://target.com --type archive\n"
            "  -l urls.txt -o results.json"
        ),
    )


def launch_googledorking() -> None:
    """Inicia o modulo Google Dorking em modo interativo."""
    parser = googledorking.build_parser()
    run_interactive_shell(
        parser, "dork> ", googledorking.run_once,
        description="Google Dorking interativo — gera dorks e busca via DuckDuckGo.",
        example="example.com --category sensitive",
        banner_fn=googledorking.banner,
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --category filetype\n"
            "  example.com --category sensitive --search\n"
            "  example.com --custom-dork 'inurl:api v1'\n"
            "  -l domains.txt -o results.json"
        ),
    )


def launch_emailbreachcheck() -> None:
    """Inicia o modulo Email Breach Check em modo interativo."""
    parser = emailbreachcheck.build_parser()
    run_interactive_shell(
        parser, "breach> ", emailbreachcheck.run_once,
        description="Email Breach Check interativo — verifica emails em vazamentos de dados.",
        example="user@example.com --source xposedornot",
        banner_fn=emailbreachcheck.banner,
        contextual_help=(
            "Uso: <emails...> [opcoes]\n"
            "Exemplos:\n"
            "  user@example.com\n"
            "  user1@test.com user2@test.com\n"
            "  user@example.com --source hibp --hibp-api-key KEY\n"
            "  -f emails.txt -o results.json"
        ),
    )


def launch_socialengrecon() -> None:
    """Inicia o modulo Social Engineering Recon em modo interativo."""
    parser = socialengrecon.build_parser()
    run_interactive_shell(
        parser, "soceng> ", socialengrecon.run_once,
        description="Social Engineering Recon interativo — coleta emails, nomes, cargos de funcionarios.",
        example="example.com --source github",
        banner_fn=socialengrecon.banner,
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --source github --source hunter\n"
            "  example.com --hunter-api-key KEY\n"
            "  -l domains.txt -o results.json"
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
        except EOFError, KeyboardInterrupt:
            print()
            return 0

        if choice in {"0", "q", "quit", "exit"}:
            print(color("bye bye user!", Cyber.MAGENTA))
            return 0
        match choice:
            case "1" | "port" | "ports" | "portscanner":
                launch_portscanner()
            case "2" | "dir" | "dirs" | "dirscanner":
                launch_dirscanner()
            case "3" | "web" | "webrecon":
                launch_webrecon()
            case "4" | "audit" | "attack" | "attackaudit" | "redblue":
                launch_attackaudit()
            case "5" | "dns" | "xfer" | "dnstransfer" | "dnsxfer":
                launch_dnstransfer()
            case "6" | "sub" | "subenum" | "subdomainenum":
                launch_subdomainenum()
            case "7" | "dns-history" | "dnshistory" | "history":
                launch_dnshistory()
            case "8" | "whois-history" | "whoishistory" | "whois":
                launch_whoishistory()
            case "9" | "ip-asn" | "ipasn" | "asn":
                launch_ipasninfo()
            case "10" | "tech" | "techfp" | "fingerprint":
                launch_techfingerprint()
            case "11" | "oas" | "openapi" | "swagger" | "openapidiscovery":
                launch_openapidiscovery()
            case "12" | "gql" | "graphql" | "playground" | "graphqlplayground":
                launch_graphqlplayground()
            case "13" | "sourcemap" | "sm" | "sourcemaps" | "sourcemapdiscovery":
                launch_sourcemapdiscovery()
            case "14" | "vcs" | "vcsleak" | "git" | "svn" | "hg":
                launch_vcsleak()
            case "15" | "config" | "cfg" | "env" | "configfiledetect":
                launch_configfiledetect()
            case "16" | "bak" | "backup" | "backupfiledetect":
                launch_backupfiledetect()
            case "17" | "dork" | "google" | "googledorking":
                launch_googledorking()
            case "18" | "breach" | "email" | "hibp" | "emailbreachcheck":
                launch_emailbreachcheck()
            case "19" | "soceng" | "social" | "employee" | "socialengrecon":
                launch_socialengrecon()
            case "20" | "reconall" | "all" | "full":
                launch_reconall()
            case "21" | "help" | "ajuda" | "h":
                help_screen()
                input(color("Enter para voltar...", Cyber.GRAY))
            case "22" | "clear" | "limpar" | "cls":
                clear_console()
                continue
            case _:
                print(color("Opcao invalida.", Cyber.RED))
                input(color("Enter para continuar...", Cyber.GRAY))

        clear_console()


if __name__ == "__main__":
    raise SystemExit(main())
