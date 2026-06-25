#!/usr/bin/env python3
"""Modulo de deteccao de controle de versao (.git, .svn, .hg) exposto em servidores web.

Busca diretorios e arquivos de VCS que estao acidentalmente acessiveis
via HTTP, validando o conteudo para confirmar se e um leak real.

Fluxo:
  1. Sonda paths comuns de .git, .svn, .hg no alvo
  2. Valida o conteudo retornado para confirmar leak real
  3. Exibe resumo colorido e salva output detalhado
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass
from urllib.parse import urljoin

import httpx

from utils import (
    Cyber,
    FetchError,
    RateLimiter,
    add_base_args,
    add_http_args,
    color,
    create_async_client,
    create_banner,
    extract_hostname,
    fetch,
    header_get,
    init_scanner,
    normalize_url,
    print_table,
    resolve_target_urls,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.vcsleak")

STATUS_OK = frozenset({200})

GIT_PATHS: list[str] = [
    ".git/HEAD",
    ".git/config",
    ".gitignore",
    ".git/description",
    ".git/index",
    ".git/COMMIT_EDITMSG",
    ".git/info/refs",
    ".git/packed-refs",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
    ".git/logs/HEAD",
    ".git/logs/refs/heads/main",
    ".git/refs/heads/main.lock",
]

SVN_PATHS: list[str] = [
    ".svn/entries",
    ".svn/wc.db",
    ".svn/dir-prop-base",
    ".svn/all-wcprops",
    ".svn/props/base/",
    ".svn/pristine/",
]

HG_PATHS: list[str] = [
    ".hg/store/00manifest.i",
    ".hgignore",
    ".hg/store/00manifest.d",
    ".hg/store/00log.i",
    ".hg/store/00phasesfiles.i",
    ".hg/store/undo",
    ".hg/dirstate",
    ".hg/branch",
]

ALL_PATHS = GIT_PATHS + SVN_PATHS + HG_PATHS

GIT_VALIDATORS: dict[str, re.Pattern[str]] = {
    ".git/HEAD": re.compile(r"^ref:\s*refs/"),
    ".git/config": re.compile(r"\[core\]|\[remote\s"),
    ".git/COMMIT_EDITMSG": re.compile(r"^#"),
    ".git/info/refs": re.compile(r"^[a-f0-9]{40}\s"),
    ".git/packed-refs": re.compile(r"^[a-f0-9]{40}\s"),
    ".git/logs/HEAD": re.compile(r"[0-9a-f]{40}"),
    ".git/logs/refs/heads/main": re.compile(r"[0-9a-f]{40}"),
}

SVN_VALIDATORS: dict[str, re.Pattern[str]] = {
    ".svn/entries": re.compile(r"^(\d+\n|dir|file)"),
}

HG_VALIDATORS: dict[str, re.Pattern[str]] = {
    ".hg/store/00manifest.i": re.compile(r"^[a-f0-9]{40}\s"),
    ".hg/dirstate": re.compile(r"[a-z]{4}"),
}

SQLITE_MAGIC = b"SQLite format 3"

banner = create_banner(
    r"""
 __     __         _       __     ______
 \ \   / /_ _ _ __(_) ___  \ \   / /___ \
  \ \ / / _` | '__| |/ _ \  \ \ / /  __) |
   \ V / (_| | |  | | (_) |  \ V /  / __/
    \_/ \__,_|_|  |_|\___/    \_/  |_____|

 """,
    "VCS Leak Detection | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class VCSLeak:
    """Representa um leak de controle de versao descoberto."""

    vcs_type: str
    url: str
    path: str
    status: int = 0
    detail: str = ""
    raw_size: int = 0


def _classify_path(path: str) -> str:
    """Classifica o path em git, svn ou hg."""
    if path.startswith(".git"):
        return "git"
    if path.startswith(".svn"):
        return "svn"
    if path.startswith(".hg"):
        return "hg"
    return "unknown"


def _validate_content(path: str, content: bytes) -> tuple[bool, str]:
    """Valida se o conteudo indica leak real. Retorna (e_leak, detalhe)."""
    if not content:
        return False, ""

    vcs_type = _classify_path(path)

    if vcs_type == "git":
        validator = GIT_VALIDATORS.get(path)
        if validator:
            text = content.decode("utf-8", errors="replace").strip()
            if validator.search(text):
                snippet = text[:80].replace("\n", " ")
                return True, snippet
            return False, ""

        if path == ".git/config":
            text = content.decode("utf-8", errors="replace")
            if "[remote" in text or "[core" in text:
                return True, text[:80].strip()
            return False, ""

        if path == ".git/index":
            if content[:4] == b"DIRC":
                return True, "Git index file"
            return False, ""

        if path == ".git/description":
            text = content.decode("utf-8", errors="replace").strip()
            if text and text != "Unnamed repository; edit this file 'description' to name the repository.":
                return True, text[:80]
            return False, ""

        return True, content[:80].decode("utf-8", errors="replace").strip()

    if vcs_type == "svn":
        if path == ".svn/wc.db":
            if content[:len(SQLITE_MAGIC)] == SQLITE_MAGIC:
                return True, "SQLite working copy database"
            return False, ""
        validator = SVN_VALIDATORS.get(path)
        if validator:
            text = content.decode("utf-8", errors="replace").strip()
            if validator.search(text):
                first_line = text.split("\n")[0].strip()
                return True, first_line[:80]
            return False, ""
        return True, content[:80].decode("utf-8", errors="replace").strip()

    if vcs_type == "hg":
        validator = HG_VALIDATORS.get(path)
        if validator:
            text = content.decode("utf-8", errors="replace").strip()
            if validator.search(text):
                first_line = text.split("\n")[0].strip()
                return True, first_line[:80]
            return False, ""
        return True, content[:80].decode("utf-8", errors="replace").strip()

    return True, content[:80].decode("utf-8", errors="replace").strip()


async def _probe_path(
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    base_url: str,
    path: str,
    timeout: float,
    retries: int = 2,
) -> VCSLeak | None:
    """Sonda um unico path e retorna VCSLeak se encontrar leak confirmado."""
    full_url = urljoin(base_url, path)
    await rate_limiter.wait()

    try:
        head_status, head_headers, _, _ = await fetch(
            client, full_url, timeout=timeout, method="HEAD",
            max_retries=1, rate_limiter=rate_limiter,
        )
    except FetchError:
        return None

    if head_status == 405:
        pass
    elif head_status not in STATUS_OK:
        return None
    else:
        cl = header_get(head_headers, "content-length")
        if cl:
            try:
                if int(cl) > 5 * 1024 * 1024:
                    return None
            except ValueError:
                pass

    await rate_limiter.wait()
    try:
        status, _headers, content, _ = await fetch(
            client, full_url, timeout=timeout, method="GET",
            max_retries=retries, rate_limiter=rate_limiter,
        )
    except FetchError:
        return None

    if status not in STATUS_OK:
        return None

    is_leak, detail = _validate_content(path, content)
    if not is_leak:
        return None

    vcs_type = _classify_path(path)
    return VCSLeak(
        vcs_type=vcs_type,
        url=full_url,
        path=path,
        status=status,
        detail=detail,
        raw_size=len(content),
    )


async def scan_vcs(
    base_url: str,
    timeout: float,
    concurrency: int,
    user_agent: str,
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 0.0,
    retries: int = 2,
    custom_paths: list[str] | None = None,
) -> list[VCSLeak]:
    """Busca leaks de VCS no alvo por probe assincrono."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)

    logger.info("scan vcs leak iniciado: %s", base_url)

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(base_url, Cyber.WHITE, Cyber.BOLD)}")

    paths = custom_paths or ALL_PATHS
    total = len(paths)

    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Paths: {color(str(total), Cyber.WHITE, Cyber.BOLD)} | "
        f"Concurrency: {color(str(concurrency), Cyber.YELLOW)}",
    )

    sem = asyncio.Semaphore(concurrency)
    completed = 0
    completed_lock = asyncio.Lock()

    async def _limited_probe(path: str) -> VCSLeak | None:
        nonlocal completed
        async with sem:
            result = await _probe_path(client, rate_limiter, base_url, path, timeout, retries)
            async with completed_lock:
                completed += 1
                if completed % 20 == 0 or completed == total:
                    sys.stdout.write(f"\r  Progresso: {completed}/{total} paths testados...")
                    sys.stdout.flush()
            return result

    try:
        tasks = [_limited_probe(p) for p in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

        leaks: list[VCSLeak] = []
        for r in results:
            if isinstance(r, VCSLeak):
                leaks.append(r)
                logger.info("VCS leak encontrado: [%s] %s — %s", r.vcs_type, r.path, r.detail)
                print(
                    f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                    f"{color(f'[{r.vcs_type.upper()}]', Cyber.YELLOW, Cyber.BOLD)} "
                    f"{color(r.path, Cyber.WHITE)} "
                    f"{color(r.detail, Cyber.GRAY)}"
                )
    finally:
        await client.aclose()

    elapsed = time.monotonic() - started
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}. "
        f"VCS leaks encontrados: {color(str(len(leaks)), Cyber.GREEN, Cyber.BOLD)}",
    )
    return leaks


def print_results(leaks: list[VCSLeak]) -> None:
    """Imprime tabela resumo dos leaks de VCS encontrados."""
    if not leaks:
        print(color("Nenhum VCS leak encontrado.", Cyber.RED))
        return

    print(color("\n  VCS Leaks Encontrados", Cyber.CYAN, Cyber.BOLD))

    hdrs = ("VCS", "STATUS", "TAMANHO", "DETALHE", "URL")
    rows = []
    for leak in leaks:
        rows.append((
            leak.vcs_type.upper(),
            str(leak.status),
            str(leak.raw_size),
            leak.detail[:60],
            leak.url,
        ))

    def _row_styles(row: tuple[str, ...]) -> list[tuple[str, ...]]:
        vcs = row[0].lower()
        vcs_color = {"git": Cyber.RED, "svn": Cyber.YELLOW, "hg": Cyber.GREEN}.get(vcs, Cyber.WHITE)
        return [
            (vcs_color, Cyber.BOLD),
            (Cyber.WHITE,),
            (Cyber.YELLOW,),
            (Cyber.GRAY,),
            (Cyber.CYAN,),
        ]

    print_table(
        headers=hdrs,
        rows=rows,
        empty_message="Nenhum VCS leak encontrado.",
        alignments=["left", "right", "right", "left", "left"],
        row_styles_fn=_row_styles,
    )


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Deteccao de controle de versao (.git, .svn, .hg) exposto em servidores web.",
    )
    add_base_args(parser)
    add_http_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: http://example.com")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com URLs alvo (uma por linha).")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=30,
        help="Concorrencia assincrona. Padrao: 30",
    )
    parser.add_argument(
        "--git-only",
        action="store_true",
        dest="git_only",
        help="Apenas paths de .git.",
    )
    parser.add_argument(
        "--svn-only",
        action="store_true",
        dest="svn_only",
        help="Apenas paths de .svn.",
    )
    parser.add_argument(
        "--hg-only",
        action="store_true",
        dest="hg_only",
        help="Apenas paths de .hg.",
    )
    return parser


def _load_paths_from_args(args: argparse.Namespace) -> list[str] | None:
    """Retorna lista de paths customizada baseada nos flags --git-only, --svn-only, --hg-only."""
    git_only = getattr(args, "git_only", False)
    svn_only = getattr(args, "svn_only", False)
    hg_only = getattr(args, "hg_only", False)

    if git_only:
        return GIT_PATHS
    if svn_only:
        return SVN_PATHS
    if hg_only:
        return HG_PATHS
    return None


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)
    urls = resolve_target_urls(args)

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma requisicao HTTP sera enviada.")
        for url in urls:
            base_url = normalize_url(url, default_scheme="https", ensure_trailing_slash=True)
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(base_url, Cyber.WHITE, Cyber.BOLD)}")
        return 0

    all_leaks: list[VCSLeak] = []
    for url in urls:
        base_url = normalize_url(url, default_scheme="https", ensure_trailing_slash=True)
        custom_paths = _load_paths_from_args(args)

        leaks = await scan_vcs(
            base_url=base_url,
            timeout=args.timeout,
            concurrency=args.concurrency,
            user_agent=args.user_agent,
            proxy=args.proxy,
            verify=getattr(args, "verify", False),
            requests_per_second=args.delay,
            retries=args.retries,
            custom_paths=custom_paths,
        )

        if not quiet:
            print_results(leaks)

        all_leaks.extend(leaks)

        if getattr(args, "output_dir", None):
            hostname = extract_hostname(url)
            out_path = f"{args.output_dir}/{hostname}.json"
            write_output(
                out_path,
                [asdict(leak) for leak in leaks],
                ["vcs_type", "url", "path", "status", "detail", "raw_size"],
                quiet=quiet,
            )

    if args.output:
        write_output(
            args.output,
            [asdict(leak) for leak in all_leaks],
            ["vcs_type", "url", "path", "status", "detail", "raw_size"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do VCS Leak Detection."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.url or getattr(a, "target_list", None)),
        prompt="vcs> ",
        description="VCS Leak Detection interativo.",
        example="http://target.com --git-only",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --git-only\n"
            "  http://target.com --svn-only\n"
            "  -l urls.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
