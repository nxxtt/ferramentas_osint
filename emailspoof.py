#!/usr/bin/env python3
"""Modulo de analise de Email Spoofing via DNS.

Verifica se SPF/DKIM/DMARC previnem spoofing de email:
  - From Address Spoofing: SPF ausente ou +all
  - Subdomain Spoofing: DMARC sp ausente ou sp=none
  - Bounce/Direct-to-MX: SPF bypass via forwarders
  - DMARC p=none: apenas monitora, nao rejeita
  - Low DMARC pct: bypass parcial
  - Sem DKIM: sem assinatura verificavel
  - Sem relatorio (rua): sem visibilidade

Reutiliza emailsecurity.scan_email_security() como base.
"""
import argparse
import logging
from dataclasses import asdict, dataclass

from emailsecurity import scan_email_security
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

logger = logging.getLogger("mytools.emailspoof")


@dataclass(frozen=True, slots=True)
class SpoofVector:
    """Vetor de ataque de spoofing identificado."""
    name: str
    severity: str  # critical, high, medium, low, info
    description: str
    remediation: str


@dataclass(frozen=True, slots=True)
class SpoofResult:
    """Resultado da analise de spoofing."""
    domain: str
    risk_score: str  # critical, high, medium, low, none
    vectors: list[SpoofVector]
    issues: list[str]
    spf_status: str
    dmarc_status: str
    dkim_status: str
    overall_protection: str  # vulnerable, partially_protected, protected


_RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "info": 0}


def _max_severity(vectors: list[SpoofVector]) -> str:
    """Retorna a severidade maxima entre os vetores."""
    if not vectors:
        return "none"
    return max(vectors, key=lambda v: _RISK_ORDER.get(v.severity, 0)).severity


def analyze_spoofing(
    domain: str,
    nameserver: str = "8.8.8.8",
    selectors: list[str] | None = None,
    timeout: float = 5.0,
) -> SpoofResult:
    """Analisa vulnerabilidade a spoofing de email."""
    base = scan_email_security(domain, nameserver, selectors, timeout)
    vectors: list[SpoofVector] = []
    issues: list[str] = []

    # --- SPF Analysis ---
    spf_status = "missing"
    if base.spf:
        if not base.spf.has_all:
            spf_status = "weak"
            vectors.append(SpoofVector(
                name="SPF sem terminador all",
                severity="high",
                description="Registro SPF nao termina com 'all' — regras podem ser ignoradas",
                remediation="Adicione '-all' ou '~all' ao final do registro SPF",
            ))
        elif base.spf.all_qualifier == "+":
            spf_status = "critical"
            vectors.append(SpoofVector(
                name="SPF +all",
                severity="critical",
                description="SPF com +all permite que qualquer IP envie email pelo dominio",
                remediation="Mude '+all' para '-all' (hard fail) ou '~all' (soft fail)",
            ))
        elif base.spf.all_qualifier == "~":
            spf_status = "softfail"
            issues.append("SPF ~all: emails de IPs nao listados sao marcados mas nao rejeitados")
        elif base.spf.all_qualifier == "-":
            spf_status = "strict"
        elif base.spf.all_qualifier == "?":
            spf_status = "neutral"
            vectors.append(SpoofVector(
                name="SPF ?all",
                severity="high",
                description="SPF com ?all (neutral) — nenhum resultado para IPs nao listados",
                remediation="Mude '?all' para '-all' ou '~all'",
            ))
    else:
        spf_status = "missing"
        vectors.append(SpoofVector(
            name="SPF ausente",
            severity="critical",
            description="Dominio nao possui registro SPF — qualquer IP pode enviar email",
            remediation="Adicione registro SPF: 'v=spf1 include:_spf.google.com -all'",
        ))

    # --- DMARC Analysis ---
    dmarc_status = "missing"
    if base.dmarc:
        if base.dmarc.policy == "none":
            dmarc_status = "monitor_only"
            vectors.append(SpoofVector(
                name="DMARC p=none",
                severity="high",
                description="DMARC em modo monitor — nao rejeita emails falhos",
                remediation="Mude 'p=none' para 'p=quarantine' ou 'p=reject'",
            ))
        elif base.dmarc.policy == "quarantine":
            dmarc_status = "quarantine"
            issues.append("DMARC quarantine: emails falhos vao para spam, nao rejeitados")
        elif base.dmarc.policy == "reject":
            dmarc_status = "reject"

        if base.dmarc.pct < 100:
            vectors.append(SpoofVector(
                name=f"DMARC pct={base.dmarc.pct}",
                severity="medium" if base.dmarc.pct >= 50 else "high",
                description=f"DMARC aplicado a apenas {base.dmarc.pct}% dos emails — bypass parcial",
                remediation="Aumente pct para 100 para protecao completa",
            ))

        # Subdomain policy
        if base.dmarc.sp == "none" or (not base.dmarc.sp and base.dmarc.policy == "reject"):
            sp_default = base.dmarc.sp or "(herda p=)"
            if sp_default == "(herda p=)":
                pass  # herda politica forte, ok
            else:
                vectors.append(SpoofVector(
                    name="DMARC sp=none",
                    severity="high",
                    description="Subdominios nao protegidos — spoofing via subdominios viavel",
                    remediation="Adicione 'sp=reject' ou 'sp=quarantine' ao registro DMARC",
                ))

        if not base.dmarc.rua:
            vectors.append(SpoofVector(
                name="DMARC sem relatorio rua",
                severity="low",
                description="Sem relatorio aggregate — sem visibilidade sobre tentativas de spoofing",
                remediation="Adicione 'rua=mailto:dmarc@seudominio.com' ao registro DMARC",
            ))
    else:
        dmarc_status = "missing"
        vectors.append(SpoofVector(
            name="DMARC ausente",
            severity="critical",
            description="Dominio nao possui DMARC — sem politica de alinhamento",
            remediation="Adicione DMARC: 'v=DMARC1; p=reject; rua=mailto:d@dominio.com'",
        ))

    # --- DKIM Analysis ---
    dkim_status = "present" if base.dkim_selectors else "missing"
    if not base.dkim_selectors:
        vectors.append(SpoofVector(
            name="DKIM ausente",
            severity="medium",
            description="Nenhum seletor DKIM encontrado — email nao pode ser assinado digitalmente",
            remediation="Configure DKIM com seletor padrao (ex: default._domainkey)",
        ))

    # --- Bypass via Forwarders ---
    if base.spf and base.spf.has_all and base.spf.all_qualifier == "-":
        if base.dmarc and base.dmarc.policy in ("quarantine", "reject"):
            issues.append("Forwarders podem bypassar SPF — DMARC com DKIM mitiga")
        else:
            vectors.append(SpoofVector(
                name="Bypass via forwarders",
                severity="medium",
                description="SPF -all com DMARC fraco — forwarders podem causar falha legítima",
                remediation="Configure DKIM para alinhamento via DMARC",
            ))

    # --- Overall Protection ---
    risk = _max_severity(vectors)
    if risk == "critical":
        protection = "vulnerable"
    elif risk in ("high", "medium"):
        protection = "partially_protected"
    else:
        protection = "protected"

    return SpoofResult(
        domain=domain,
        risk_score=risk,
        vectors=vectors,
        issues=issues,
        spf_status=spf_status,
        dmarc_status=dmarc_status,
        dkim_status=dkim_status,
        overall_protection=protection,
    )


def print_results(result: SpoofResult) -> None:
    """Exibe o relatorio de spoofing."""
    print(color("\n[+] Email Spoofing Analysis — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Dominio: {color(result.domain, Cyber.WHITE, Cyber.BOLD)}")
    print()

    risk_colors = {
        "critical": (Cyber.RED, Cyber.BOLD),
        "high": (Cyber.RED, ""),
        "medium": (Cyber.YELLOW, ""),
        "low": (Cyber.CYAN, ""),
        "none": (Cyber.GREEN, Cyber.BOLD),
    }
    rc = risk_colors.get(result.risk_score, (Cyber.WHITE, ""))
    print(f"  Risco: {color(result.risk_score.upper(), *rc)}")

    prot_colors = {
        "vulnerable": (Cyber.RED, Cyber.BOLD),
        "partially_protected": (Cyber.YELLOW, ""),
        "protected": (Cyber.GREEN, Cyber.BOLD),
    }
    pc = prot_colors.get(result.overall_protection, (Cyber.WHITE, ""))
    print(f"  Protecao: {color(result.overall_protection.upper(), *pc)}")
    print()

    status_icon = {
        "critical": color("[!]", Cyber.RED),
        "missing": color("[-]", Cyber.RED),
        "weak": color("[!]", Cyber.YELLOW),
        "softfail": color("[~]", Cyber.YELLOW),
        "neutral": color("[?]", Cyber.YELLOW),
        "monitor_only": color("[!]", Cyber.YELLOW),
        "quarantine": color("[+]", Cyber.CYAN),
        "reject": color("[+]", Cyber.GREEN),
        "strict": color("[+]", Cyber.GREEN),
        "present": color("[+]", Cyber.GREEN),
    }

    print(f"  SPF:     {status_icon.get(result.spf_status, '?')} {result.spf_status}")
    print(f"  DMARC:   {status_icon.get(result.dmarc_status, '?')} {result.dmarc_status}")
    print(f"  DKIM:    {status_icon.get(result.dkim_status, '?')} {result.dkim_status}")
    print()

    if result.vectors:
        print(color("  Vetores de Ataque:", Cyber.RED, Cyber.BOLD))
        for v in result.vectors:
            sev_color = risk_colors.get(v.severity, (Cyber.WHITE, ""))
            print(f"    {color(v.severity.upper(), *sev_color)} — {v.name}")
            print(f"      {v.description}")
            print(f"      {color('Remedio:', Cyber.CYAN)} {v.remediation}")
            print()

    if result.issues:
        print(color("  Observacoes:", Cyber.YELLOW, Cyber.BOLD))
        for issue in result.issues:
            print(f"    {color('[~]', Cyber.YELLOW)} {issue}")
        print()

    if result.risk_score == "none":
        print(color("  [+] Dominio protegido contra spoofing de email", Cyber.GREEN, Cyber.BOLD))
    elif result.risk_score == "critical":
        print(color("  [-] Dominio VULNERAVEL a spoofing — acao urgente necessaria", Cyber.RED, Cyber.BOLD))
    elif result.risk_score == "high":
        print(color("  [!] Dominio parcialmente vulneravel — melhorias recomendadas", Cyber.YELLOW))
    else:
        print(color("  [i] Dominio com protecao basica — considerar melhorias", Cyber.CYAN))


def banner() -> None:
    """Exibe o banner do Email Spoofing."""
    art = r"""
   ________                _____ __           __
  / ____/ /_  ____ _____  / ___// /_  ______ / /____
 / / __/ __ \/ __ `/ __ \ \__ \/ __ \/ ___/ / ___/
/ /_/ / / / / /_/ / /_/ /___/ / / / (__  ) (__  )
\____/_/ /_/\__,_/ .___/____/_/ /_/____/_/____/
                 /_/
"""
    create_banner(art, "   email spoofing: analise SPF/DKIM/DMARC contra spoofing")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Email Spoofing — analise de vulnerabilidade a spoofing de email.",
        epilog="Verifica se SPF/DKIM/DMARC protegem contra spoofing.",
    )
    add_base_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo para analise.")
    parser.add_argument(
        "--nameserver", "-s",
        default="8.8.8.8",
        help="Nameserver para queries. Padrao: 8.8.8.8",
    )
    parser.add_argument(
        "--selectors",
        default="default,google,selector1,selector2,s1,s2,dkim,mail",
        help="Seletores DKIM (separados por virgula). Padrao: default,google,selector1,...",
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

    selectors = [s.strip() for s in args.selectors.split(",") if s.strip()]

    result = analyze_spoofing(
        domain=domain,
        nameserver=args.nameserver,
        selectors=selectors,
        timeout=args.query_timeout,
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["domain", "risk_score", "overall_protection", "issues"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Email Spoofing."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain),
        prompt="spoof> ",
        description="Email Spoofing — analise de vulnerabilidade a spoofing.",
        example="example.com --selectors default,google",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --selectors default,google,s1\n"
            "  example.com --nameserver 1.1.1.1"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
