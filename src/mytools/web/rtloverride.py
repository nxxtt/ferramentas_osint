#!/usr/bin/env python3
"""Modulo de testes de RTL Override (U+202E).

Testa se o servidor/aplicacao filtra caracteres Unicode de direcao
Right-to-Left Override (U+202E, U+202D, U+2066-U+2069) que podem
ser usados para confundir display de URLs e filenames.

Funcionalidades:
  1. rtl_gen — gera variantes RTL de uma URL
  2. rtl_detect — detecta caracteres RTL em uma URL
  3. rtl_scan — testa se o servidor filtra caracteres RTL

Fluxo:
  1. Gera variantes da URL com RTL Override em diferentes posicoes
  2. Envia requests e compara respostas (baseline vs RTL)
  3. Classifica cada variante: vulnerable, blocked, safe, error
  4. Retorna resultado consolidado
"""
import argparse
import logging
import unicodedata
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

import httpx

from mytools.core.utils import (
    Cyber,
    FetchError,
    add_common_args,
    color,
    create_async_client,
    fetch,
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.rtloverride")

_RTL_CHARS: dict[str, str] = {
    "rlo": "\u202e",
    "rle": "\u202b",
    "lro": "\u202d",
    "lri": "\u2066",
    "rli": "\u2067",
    "fsi": "\u2068",
    "pdi": "\u2069",
}

_RTL_LABELS: dict[str, str] = {
    "rlo": "Right-to-Left Override",
    "rle": "Right-to-Left Embedding",
    "lro": "Left-to-Right Override",
    "lri": "Left-to-Right Isolate",
    "rli": "Right-to-Left Isolate",
    "fsi": "First Strong Isolate",
    "pdi": "Pop Directional Isolate",
}


@dataclass(frozen=True, slots=True)
class RTLAttempt:
    """Tentativa individual de RTL override."""

    technique: str
    label: str
    url_display: str
    url_real: str
    rtl_char: str
    position: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    status_changed: bool
    size_changed: bool
    vulnerable: bool
    details: str
    error: str


@dataclass(frozen=True, slots=True)
class RTLResult:
    """Resultado consolidado do scan de RTL override."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[RTLAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _insert_rtl(url: str, rtl_char: str, position: str) -> str:
    """Insere caractere RTL em uma posicao da URL."""
    parsed = urlparse(url)
    if position == "before_domain":
        return f"{parsed.scheme}://{rtl_char}{parsed.netloc}{parsed.path}" + ("?" + parsed.query if parsed.query else "")
    if position == "in_path":
        parts = parsed.path.split("/")
        if len(parts) > 2:
            mid = len(parts) // 2
            parts.insert(mid, rtl_char)
        return f"{parsed.scheme}://{parsed.netloc}{'/'.join(parts)}" + ("?" + parsed.query if parsed.query else "")
    if position == "in_query":
        return url + rtl_char
    if position == "before_path":
        return f"{parsed.scheme}://{parsed.netloc}{rtl_char}{parsed.path}" + ("?" + parsed.query if parsed.query else "")
    return url


def _generate_variants(url: str) -> list[tuple[str, str, str, str]]:
    """Gera variantes RTL de uma URL. Retorna (label, rtl_char, position, modified_url)."""
    variants: list[tuple[str, str, str, str]] = []
    positions = ["before_domain", "in_path", "before_path", "in_query"]
    for key, rtl_char in _RTL_CHARS.items():
        label = _RTL_LABELS[key]
        for position in positions:
            modified = _insert_rtl(url, rtl_char, position)
            if modified != url:
                variants.append((label, rtl_char, position, modified))
    return variants


def detect_rtl(text: str) -> list[tuple[str, str, int]]:
    """Detecta caracteres RTL em um texto. Retorna (nome, char, posicao)."""
    found: list[tuple[str, str, int]] = []
    for i, c in enumerate(text):
        code = ord(c)
        if code in (0x202E, 0x202B, 0x202D, 0x2066, 0x2067, 0x2068, 0x2069):
            name = unicodedata.name(c, f"U+{code:04X}")
            found.append((name, c, i))
    return found


def _make_display(url: str) -> str:
    """Cria versao 'display' da URL removendo caracteres invisiveis."""
    return "".join(c for c in url if ord(c) not in (0x202E, 0x202B, 0x202D, 0x2066, 0x2067, 0x2068, 0x2069))


async def _test_variant(
    client: httpx.AsyncClient,
    url_real: str,
    url_baseline: str,
    timeout: float,
) -> tuple[int, int, int, int, str]:
    """Testa uma variante RTL contra o servidor. Retorna (baseline_status, test_status, baseline_size, test_size, details)."""
    try:
        b_status, _, b_content, _ = await fetch(client, url_baseline, timeout=timeout)
    except FetchError as exc:
        return (0, 0, 0, 0, f"baseline error: {exc}")

    try:
        t_status, _, t_content, _ = await fetch(client, url_real, timeout=timeout)
    except FetchError as exc:
        return (b_status, 0, len(b_content), 0, f"test error: {exc}")

    return (b_status, t_status, len(b_content), len(t_content), "")


def print_results(result: RTLResult) -> None:
    """Imprime resultados do scan de RTL override."""
    print()
    print(color("RTL Override Bypass - Resultado", Cyber.RED, Cyber.BOLD))
    print(color("=" * 50, Cyber.RED))
    print(f"  Alvo: {color(result.target, Cyber.WHITE, Cyber.BOLD)}")
    print(f"  TLS: {color('Sim' if result.tls else 'Nao', Cyber.GREEN if result.tls else Cyber.RED)}")
    print(f"  Baseline: {color(str(result.baseline_status), Cyber.YELLOW)} ({result.baseline_size}B)")
    print()

    if result.vulnerable_techniques:
        print(color("[!] VULNERAVEL", Cyber.RED, Cyber.BOLD))
        for tech in result.vulnerable_techniques:
            print(f"  - {color(tech, Cyber.RED)}")
        print()

    if result.blocked_techniques:
        print(color("[+] BLOQUEADO", Cyber.GREEN, Cyber.BOLD))
        for tech in result.blocked_techniques:
            print(f"  - {color(tech, Cyber.GREEN)}")
        print()

    for att in result.attempts:
        if att.vulnerable:
            icon = color("[!]", Cyber.RED, Cyber.BOLD)
            status_str = color("VULNERAVEL", Cyber.RED)
        elif att.status_changed or att.size_changed:
            icon = color("[*]", Cyber.YELLOW, Cyber.BOLD)
            status_str = color("DIFERENTE", Cyber.YELLOW)
        elif att.error:
            icon = color("[-]", Cyber.GRAY)
            status_str = color("ERRO", Cyber.GRAY)
        else:
            icon = color("[+]", Cyber.GREEN)
            status_str = color("SAFE", Cyber.GREEN)

        print(f"  {icon} {color(att.technique, Cyber.CYAN)}: {status_str}")
        print(f"    Real: {att.url_real}")
        print(f"    Display: {_make_display(att.url_real)}")
        if att.details:
            print(f"    Detalhes: {att.details}")
    print()

    if result.overall_status == "vulnerable":
        print(color("[!] Status: VULNERAVEL - Servidor nao filtra caracteres RTL", Cyber.RED, Cyber.BOLD))
    elif result.overall_status == "blocked":
        print(color("[+] Status: BLOQUEADO - Servidor filtra caracteres RTL", Cyber.GREEN, Cyber.BOLD))
    else:
        print(color("[*] Status: SEGURO - Nenhuma differenca detectada", Cyber.CYAN, Cyber.BOLD))


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="RTL Override Bypass — detecta bypass via caracteres Unicode de direcao."
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: https://target.com")
    parser.add_argument(
        "-m", "--mode",
        choices=["gen", "detect", "scan"],
        default="scan",
        help="Modo: gen (gera variantes), detect (detecta RTL), scan (testa servidor). Padrao: scan",
    )
    parser.add_argument(
        "-T", "--techniques",
        nargs="*",
        choices=list(_RTL_CHARS.keys()),
        help="Tecnicas especificas para testar. Padrao: todas",
    )
    parser.set_defaults(user_agent="Mozilla/5.0 (X11; Linux x86_64) RTLOverride/1.0")
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)
    url = args.url
    mode = args.mode

    if mode == "detect":
        detected = detect_rtl(url)
        if detected:
            print(color("[!] Caracteres RTL detectados:", Cyber.RED, Cyber.BOLD))
            for name, char, pos in detected:
                print(f"  - {name} (U+{ord(char):04X}) na posicao {pos}")
        else:
            print(color("[+] Nenhum caractere RTL detectado.", Cyber.GREEN))
        return 0

    if mode == "gen":
        variants = _generate_variants(url)
        print(color(f"[*] {len(variants)} variantes geradas:", Cyber.CYAN, Cyber.BOLD))
        for label, _rtl_char, position, modified in variants:
            print(f"\n  {color(label, Cyber.CYAN)} - {color(position, Cyber.YELLOW)}")
            print(f"    Real:     {modified}")
            print(f"    Display:  {_make_display(modified)}")
        return 0

    client = create_async_client(user_agent=args.user_agent)
    try:
        try:
            b_status, _, b_content, _ = await fetch(client, url, timeout=args.timeout)
        except FetchError as exc:
            print(color(f"[-] Erro no baseline: {exc}", Cyber.RED))
            return 1

        b_size = len(b_content)
        tls = url.startswith("https://")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Baseline: {color(str(b_status), Cyber.YELLOW)} ({b_size}B)")

        variants = _generate_variants(url)
        techniques = args.techniques or list(_RTL_CHARS.keys())

        attempts: list[RTLAttempt] = []
        for label, rtl_char, position, modified in variants:
            key = next((k for k, v in _RTL_LABELS.items() if v == label), "")
            if key not in techniques:
                continue

            try:
                t_status, _, t_content, _ = await fetch(client, modified, timeout=args.timeout)
            except FetchError:
                t_status = 0
                t_content = b""

            t_size = len(t_content)
            status_changed = t_status != b_status
            size_changed = abs(t_size - b_size) > 10
            vulnerable = status_changed or size_changed

            details = ""
            if status_changed:
                details = f"status {b_status} -> {t_status}"
            elif size_changed:
                details = f"size {b_size} -> {t_size}"

            attempts.append(RTLAttempt(
                technique=key,
                label=label,
                url_display=_make_display(modified),
                url_real=modified,
                rtl_char=rtl_char,
                position=position,
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=size_changed,
                vulnerable=vulnerable,
                details=details,
                error="",
            ))

        vuln_techs = sorted({a.technique for a in attempts if a.vulnerable})
        blocked_techs = sorted({a.technique for a in attempts if not a.vulnerable and not a.error})

        if vuln_techs:
            overall = "vulnerable"
            issues = [f"{len(vuln_techs)} tecnicas vulneraveis"]
        else:
            overall = "blocked"
            issues = []

        result = RTLResult(
            target=url,
            baseline_status=b_status,
            baseline_size=b_size,
            tls=tls,
            attempts=attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked_techs,
            issues=issues,
            overall_status=overall,
        )

        if not quiet:
            print_results(result)

        if args.output:
            write_output(args.output, [asdict(a) for a in attempts], quiet=quiet)

        return 0
    finally:
        await client.aclose()


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do RTL Override."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=lambda: print(color(
            "RTL Override Bypass — detecta bypass via Unicode RTL",
            Cyber.RED, Cyber.BOLD,
        )),
        run_fn=run_once,
        has_target=lambda a: bool(a.url),
        prompt="rtlo> ",
        description="RTL Override interativo.",
        example="https://target.com -m scan",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -m gen\n"
            "  https://target.com -m detect\n"
            "  https://target.com -m scan -T rlo rle"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
