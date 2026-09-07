#!/usr/bin/env python3
"""Modulo de deteccao de Command Injection (OS Command Injection).

Testa se o servidor e vulneravel a command injection via parametros:

  OS Command Injection:
    - Semicolon: ; id
    - Pipe: | id
    - Or: || id
    - And: && id
    - Backtick: `id`
    - Dollar: $(id)

  Blind (time-based):
    - ; sleep 5
    - | sleep 5
    - $(sleep 5)
    - ; ping -c 5 127.0.0.1
    - | ping -c 5 127.0.0.1

  Bypass:
    - Newline: %0a id
    - IFS: ${IFS}id
    - Backslash: \\; id
    - Double encode: %3B%20id

  Deteccao:
    - Content signature matching (uid=, www-data, sh:, Linux)
    - Timing comparison (elapsed > baseline * 2 AND > 1.0s)
    - Status code comparison
"""

import argparse
import logging
import time
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

logger = logging.getLogger("mytools.cmdinject")

# ---------------------------------------------------------------------------
# Content signatures
# ---------------------------------------------------------------------------

_CONTENT_SIGNATURES: dict[str, list[bytes]] = {
    "uid": [b"uid=", b"gid="],
    "whoami": [b"root", b"www-data", b"nginx", b"apache", b"nobody"],
    "uname": [b"Linux", b"GNU/", b"Darwin"],
    "windows": [b"Microsoft Windows", b"C:\\Windows"],
    "error": [b"sh:", b"bash:", b"Permission denied", b"not found"],
}


def _check_content(body: bytes) -> tuple[bool, str]:
    """Verifica se body contem assinatura de execucao de comando."""
    for sig_type, signatures in _CONTENT_SIGNATURES.items():
        for sig in signatures:
            if sig in body:
                return True, sig_type
    return False, "none"


def _check_timing(time_baseline: float, time_test: float) -> bool:
    """Verifica se timing indica execucao de comando (blind injection)."""
    return time_test > time_baseline * 2 and time_test > 1.0


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

_CMD_PARAMS_DEFAULT: list[str] = [
    "cmd",
    "exec",
    "command",
    "query",
    "input",
    "ping",
    "host",
    "ip",
    "file",
    "path",
    "name",
    "data",
    "run",
    "execute",
    "shell",
]

_OS_COMMAND_PAYLOADS_DEFAULT: list[tuple[str, str]] = [
    ("semicolon", "; id"),
    ("pipe", "| id"),
    ("or", "|| id"),
    ("and", "&& id"),
    ("backtick", "`id`"),
    ("dollar", "$(id)"),
    ("whoami", "; whoami"),
    ("uname", "; uname -a"),
]

_BLIND_PAYLOADS_DEFAULT: list[tuple[str, str]] = [
    ("sleep_semicolon", "; sleep 5"),
    ("sleep_pipe", "| sleep 5"),
    ("sleep_dollar", "$(sleep 5)"),
    ("ping_semicolon", "; ping -c 5 127.0.0.1"),
    ("ping_pipe", "| ping -c 5 127.0.0.1"),
]

_BYPASS_PAYLOADS_DEFAULT: list[tuple[str, str]] = [
    ("newline", "%0a id"),
    ("ifs", "${IFS}id"),
    ("ifs_tab", "$IFS$id"),
    ("backslash", "\\; id"),
    ("double_encode", "%3B%20id"),
]


def _load_cmd_params() -> list[str]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "cmdinject", default={"cmd_params": _CMD_PARAMS_DEFAULT}
    )
    return data.get("cmd_params", _CMD_PARAMS_DEFAULT)


def _load_os_payloads() -> list[tuple[str, str]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "cmdinject",
        default={"os_command_payloads": _OS_COMMAND_PAYLOADS_DEFAULT},
    )
    raw = data.get("os_command_payloads", _OS_COMMAND_PAYLOADS_DEFAULT)
    return [tuple(item) for item in raw]


def _load_blind_payloads() -> list[tuple[str, str]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "cmdinject", default={"blind_payloads": _BLIND_PAYLOADS_DEFAULT}
    )
    raw = data.get("blind_payloads", _BLIND_PAYLOADS_DEFAULT)
    return [tuple(item) for item in raw]


def _load_bypass_payloads() -> list[tuple[str, str]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "cmdinject", default={"bypass_payloads": _BYPASS_PAYLOADS_DEFAULT}
    )
    raw = data.get("bypass_payloads", _BYPASS_PAYLOADS_DEFAULT)
    return [tuple(item) for item in raw]


_CMD_PARAMS = _load_cmd_params()
_OS_COMMAND_PAYLOADS = _load_os_payloads()
_BLIND_PAYLOADS = _load_blind_payloads()
_BYPASS_PAYLOADS = _load_bypass_payloads()


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CmdInjectAttempt:
    """Tentativa individual de command injection."""

    technique: str
    category: str
    injection_point: str
    url: str
    payload: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    time_baseline: float
    time_test: float
    content_match: bool
    content_type: str
    timing_match: bool
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class CmdInjectResult:
    """Resultado consolidado do scan de command injection."""

    target: str
    baseline_status: int
    tls: bool
    attempts: list[CmdInjectAttempt]
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
) -> tuple[int, int, bytes, float]:
    """Envia requisicao baseline para obter resposta de referencia."""
    start = time.monotonic()
    try:
        resp = await client.get(url, follow_redirects=False)
        elapsed = time.monotonic() - start
        return resp.status_code, len(resp.content), resp.content, elapsed
    except httpx.RequestError:
        return 0, 0, b"", 0.0


# ---------------------------------------------------------------------------
# Param detection
# ---------------------------------------------------------------------------


def _find_cmd_params(url: str) -> list[str]:
    """Auto-detecta parametros na URL que podem ser vulneraveis a cmd injection."""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    params = parse_qs(parsed.query, keep_blank_values=True)
    return [p for p in params if p.lower() in _CMD_PARAMS]


def _make_inject_url(base_url: str, param: str, payload: str) -> str:
    """Constroi URL com payload injetado no parametro."""
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _make_attempt(
    technique: str,
    category: str,
    injection_point: str,
    url: str,
    payload: str,
    b_status: int,
    t_status: int,
    b_size: int,
    t_size: int,
    t_time: float,
    b_time: float,
    content_match: bool,
    content_type: str,
    timing_match: bool,
    vulnerable: bool,
    details: str,
    error: str,
) -> CmdInjectAttempt:
    """Cria CmdInjectAttempt com exploit preenchido se vulneravel."""
    exploit = ""
    tool = ""
    if vulnerable:
        exploit = f"curl '{url}'"
        tool = "curl"
    return CmdInjectAttempt(
        technique=technique,
        category=category,
        injection_point=injection_point,
        url=url,
        payload=payload,
        status_baseline=b_status,
        status_test=t_status,
        size_baseline=b_size,
        size_test=t_size,
        time_baseline=b_time,
        time_test=t_time,
        content_match=content_match,
        content_type=content_type,
        timing_match=timing_match,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit=exploit,
        tool=tool,
    )


# ---------------------------------------------------------------------------
# OS command testing
# ---------------------------------------------------------------------------


async def _test_os_command(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: tuple[int, int, bytes, float],
) -> list[CmdInjectAttempt]:
    """Testa payloads de OS command injection em cada parametro."""
    attempts: list[CmdInjectAttempt] = []
    b_status, b_size, _b_body, b_time = baseline

    for param in params:
        for technique, payload in _OS_COMMAND_PAYLOADS:
            test_url = _make_inject_url(url, param, payload)
            start = time.monotonic()
            try:
                resp = await client.get(test_url, follow_redirects=False)
                t_time = time.monotonic() - start
                t_status = resp.status_code
                t_size = len(resp.content)
                content_match, content_type = _check_content(resp.content)
                timing_match = _check_timing(b_time, t_time)

                status_changed = t_status != b_status
                vulnerable = content_match

                details = (
                    f"Content: {content_type}"
                    if content_match
                    else f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca"
                )

                # Second-order verification for content-based detection
                if content_match:
                    verify = get_verify_payload("cmdinject", "os_command")
                    if verify:
                        v_payload, v_indicators = verify
                        v_url = _make_inject_url(url, param, v_payload)
                        confirmed, v_found = await verify_positive(
                            client, v_url, v_indicators
                        )
                        if not confirmed:
                            content_match = False
                            content_type = "none"
                            vulnerable = False
                            details += f" [2nd-order failed: {v_found or 'no match'}]"
                        else:
                            details += f" [2nd-order confirmed: {v_found}]"

                attempts.append(
                    _make_attempt(
                        technique=technique,
                        category="os_command",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        b_status=b_status,
                        t_status=t_status,
                        b_size=b_size,
                        t_size=t_size,
                        t_time=t_time,
                        b_time=b_time,
                        content_match=content_match,
                        content_type=content_type,
                        timing_match=timing_match,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    _make_attempt(
                        technique=technique,
                        category="os_command",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        b_status=b_status,
                        t_status=0,
                        b_size=b_size,
                        t_size=0,
                        t_time=0.0,
                        b_time=b_time,
                        content_match=False,
                        content_type="none",
                        timing_match=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


# ---------------------------------------------------------------------------
# Blind testing (time-based)
# ---------------------------------------------------------------------------


async def _test_blind(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: tuple[int, int, bytes, float],
) -> list[CmdInjectAttempt]:
    """Testa payloads blind (time-based) de command injection."""
    attempts: list[CmdInjectAttempt] = []
    b_status, b_size, _b_body, b_time = baseline

    for param in params:
        for technique, payload in _BLIND_PAYLOADS:
            test_url = _make_inject_url(url, param, payload)
            start = time.monotonic()
            try:
                resp = await client.get(test_url, follow_redirects=False)
                t_time = time.monotonic() - start
                t_status = resp.status_code
                t_size = len(resp.content)
                content_match, content_type = _check_content(resp.content)
                timing_match = _check_timing(b_time, t_time)

                vulnerable = timing_match

                details = (
                    f"Timing: {b_time:.1f}s->{t_time:.1f}s"
                    if timing_match
                    else "Sem delay"
                )

                attempts.append(
                    _make_attempt(
                        technique=technique,
                        category="blind",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        b_status=b_status,
                        t_status=t_status,
                        b_size=b_size,
                        t_size=t_size,
                        t_time=t_time,
                        b_time=b_time,
                        content_match=content_match,
                        content_type=content_type,
                        timing_match=timing_match,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    _make_attempt(
                        technique=technique,
                        category="blind",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        b_status=b_status,
                        t_status=0,
                        b_size=b_size,
                        t_size=0,
                        t_time=0.0,
                        b_time=b_time,
                        content_match=False,
                        content_type="none",
                        timing_match=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


# ---------------------------------------------------------------------------
# Bypass testing
# ---------------------------------------------------------------------------


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: tuple[int, int, bytes, float],
) -> list[CmdInjectAttempt]:
    """Testa payloads de bypass de command injection."""
    attempts: list[CmdInjectAttempt] = []
    b_status, b_size, _b_body, b_time = baseline

    for param in params:
        for technique, payload in _BYPASS_PAYLOADS:
            test_url = _make_inject_url(url, param, payload)
            start = time.monotonic()
            try:
                resp = await client.get(test_url, follow_redirects=False)
                t_time = time.monotonic() - start
                t_status = resp.status_code
                t_size = len(resp.content)
                content_match, content_type = _check_content(resp.content)
                timing_match = _check_timing(b_time, t_time)

                vulnerable = content_match

                details = f"Content: {content_type}" if content_match else "Sem mudanca"

                # Second-order verification for content-based detection
                if content_match:
                    verify = get_verify_payload("cmdinject", "bypass")
                    if verify:
                        v_payload, v_indicators = verify
                        v_url = _make_inject_url(url, param, v_payload)
                        confirmed, v_found = await verify_positive(
                            client, v_url, v_indicators
                        )
                        if not confirmed:
                            content_match = False
                            content_type = "none"
                            vulnerable = False
                            details += f" [2nd-order failed: {v_found or 'no match'}]"
                        else:
                            details += f" [2nd-order confirmed: {v_found}]"

                attempts.append(
                    _make_attempt(
                        technique=technique,
                        category="bypass",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        b_status=b_status,
                        t_status=t_status,
                        b_size=b_size,
                        t_size=t_size,
                        t_time=t_time,
                        b_time=b_time,
                        content_match=content_match,
                        content_type=content_type,
                        timing_match=timing_match,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    _make_attempt(
                        technique=technique,
                        category="bypass",
                        injection_point=f"param:{param}",
                        url=test_url,
                        payload=payload,
                        b_status=b_status,
                        t_status=0,
                        b_size=b_size,
                        t_size=0,
                        t_time=0.0,
                        b_time=b_time,
                        content_match=False,
                        content_type="none",
                        timing_match=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


# ---------------------------------------------------------------------------
# run_scan — main scan function
# ---------------------------------------------------------------------------


async def run_scan(
    url: str,
    category: str = "all",
    timeout: float = 10.0,
    concurrency: int = 5,
    output_file: str | None = None,
) -> CmdInjectResult:
    """Executa o scan de command injection contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent="MyTools/cmdinject",
        timeout=timeout,
    ) as client:
        b_status, b_size, b_body, b_time = await _test_baseline(client, url)
        baseline = (b_status, b_size, b_body, b_time)

        if b_status == 0:
            return CmdInjectResult(
                target=url,
                baseline_status=0,
                tls=tls,
                attempts=[],
                vulnerable_techniques=[],
                blocked_techniques=[],
                issues=["Falha ao conectar no alvo"],
                overall_status="error",
            )

        logger.info("Baseline: %d (%d bytes, %.2fs)", b_status, b_size, b_time)

        params = _find_cmd_params(url)
        if not params:
            logger.info("Nenhum parametro cmd detectado, testando com 'cmd'")
            params = ["cmd"]

        coros = []

        if category in ("all", "os_command"):
            coros.append(_test_os_command(client, url, params, baseline))
        if category in ("all", "blind"):
            coros.append(_test_blind(client, url, params, baseline))
        if category in ("all", "bypass"):
            coros.append(_test_bypass(client, url, params, baseline))

        if category not in ("all", "os_command", "blind", "bypass"):
            return CmdInjectResult(
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

        all_attempts: list[CmdInjectAttempt] = []
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
        issues.append(f"{len(vulnerable)} tecnicas de command injection vulneraveis")
    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return CmdInjectResult(
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


def print_results(result: CmdInjectResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  OS COMMAND INJECTION SCAN", Cyber.CYAN))
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
                if a.content_match:
                    print(color(f"      Content: {a.content_type}", Cyber.GRAY))
                if a.timing_match:
                    print(
                        color(
                            f"      Timing: {a.time_baseline:.1f}s->{a.time_test:.1f}s",
                            Cyber.GRAY,
                        )
                    )
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
   _____ __  __ ____    __  __  ______   ___  _   _ _____ _____
  / ____|  \/  |  _ \  |  \/  |/ __ \ \ / / \| | | |_   _| ____|
 | |    | \  / | |_) | | \  / | |  | \ V /|  \| | | | | | |  _
 | |    | |\/| |  __/  | |\/| | |  | | > < | . ` | | | | | | | |
 | |____| |  | | |     | |  | | |__| / ___ \| |\  | |_| | |___| |
  \_____|_|  |_|_|     |_|  |_|\____/_/   \_\_| \_|_____|______|
    """,
    "Command Injection — detecta OS command injection em web apps",
)


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta parser CLI para mytools-cmd."""
    parser = argparse.ArgumentParser(
        prog="mytools-cmd",
        description="Command Injection Scanner — detecta OS command injection.",
    )
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c",
        "--category",
        choices=["os_command", "blind", "bypass", "all"],
        default="all",
        help="Categoria de testes (default: all)",
    )
    parser.add_argument(
        "--param",
        help="Param name para forcar (override auto-detect)",
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
    """Executa um scan de command injection a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("Command injection scan iniciado para %s", args.url)

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
        prompt="cmd> ",
        description="Command Injection interativo.",
        example="https://target.com/?cmd=ls",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com/?cmd=ls\n"
            "  https://target.com/ -c os_command\n"
            "  https://target.com/ -c blind\n"
            "  https://target.com/ -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
