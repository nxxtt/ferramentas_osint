#!/usr/bin/env python3
"""Modulo de deteccao de arquivos de backup expostos em servidores web.

Busca arquivos de backup (.bak, .old, .save, ~, .swp, .sql, .zip, etc.)
que estao acidentalmente acessiveis via HTTP, validando o conteudo para
confirmar se e um backup real.

Fluxo:
  1. Sonda paths comuns de backup no alvo
  2. Valida o conteudo retornado para confirmar backup real
  3. Exibe resumo colorido e salva output detalhado
"""

import argparse
import asyncio
import logging
import sys
import time
from dataclasses import asdict, dataclass
from urllib.parse import urljoin

import httpx
from tqdm import tqdm

from mytools.core.utils import (
    Cyber,
    FetchError,
    RateLimiter,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    extract_hostname,
    fetch,
    header_get,
    init_scanner,
    normalize_url,
    print_exploit_info,
    print_json,
    print_table,
    resolve_target_urls,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.backupfiledetect")

STATUS_OK = frozenset({200})

# ── Path constants por tipo (fallbacks) ──────────────────────────────────────

_BAK_PATHS_DEFAULT: list[str] = [
    "config.php.bak",
    "wp-config.php.bak",
    ".env.bak",
    "index.php.bak",
    "config.json.bak",
    "database.yml.bak",
    "settings.py.bak",
    "web.config.bak",
    "config.yaml.bak",
    "config.php.old",
    "wp-config.php.old",
    ".env.old",
    "index.php.old",
    "wp-config.php.save",
    "config.php.backup",
    ".env.backup",
    "settings.py.backup",
    "index.php.backup",
]

_SWP_PATHS_DEFAULT: list[str] = [
    ".config.php.swp",
    ".wp-config.php.swp",
    ".index.php.swp",
    ".settings.py.swp",
    ".env.swp",
    ".config.json.swp",
    ".config.yaml.swp",
    ".config.php.swo",
    ".wp-config.php.swo",
]

_TILDE_PATHS_DEFAULT: list[str] = [
    "config.php~",
    "wp-config.php~",
    "index.php~",
    ".env~",
    "settings.py~",
    "config.json~",
    "config.yaml~",
    "index.html~",
    "style.css~",
    "app.js~",
]

_SQL_DUMP_PATHS_DEFAULT: list[str] = [
    "dump.sql",
    "backup.sql",
    "database.sql",
    "db.sql",
    "export.sql",
    "data.sql",
    "mysql.sql",
    "tables.sql",
    "dump.sql.gz",
    "backup.sql.gz",
    "database.sql.gz",
    "db.sql.gz",
    "sql-dump.sql",
]

_ARCHIVE_PATHS_DEFAULT: list[str] = [
    "backup.zip",
    "site.tar.gz",
    "www.zip",
    "public_html.zip",
    "backup.tar.gz",
    "site.zip",
    "www.tar.gz",
    "backup.tgz",
    "website.zip",
    "html.zip",
    "src.zip",
    "code.zip",
]

_ORIG_TMP_PATHS_DEFAULT: list[str] = [
    "index.php.orig",
    "config.php.orig",
    "index.php.tmp",
    "config.php.tmp",
    "index.php.save",
    "config.php.save",
    "style.css.bak",
    "app.js.bak",
    "style.css.orig",
    "app.js.orig",
]

_SQL_KEYWORDS_DEFAULT: frozenset[str] = frozenset(
    {
        "CREATE TABLE",
        "INSERT INTO",
        "DROP TABLE",
        "ALTER TABLE",
        "CREATE DATABASE",
        "USE ",
        "VALUES",
        "SET NAMES",
        "PRIMARY KEY",
        "FOREIGN KEY",
        "AUTO_INCREMENT",
    }
)


def _load_backup_paths() -> None:
    """Carrega backup paths de YAML com fallback e atualiza variáveis globais."""
    from mytools.data import load_payloads

    global BAK_PATHS, SWP_PATHS, TILDE_PATHS, SQL_DUMP_PATHS
    global ARCHIVE_PATHS, ORIG_TMP_PATHS, ALL_TYPES, ALL_PATHS
    global SQL_KEYWORDS

    data = load_payloads(
        "config",
        "backup_file_detect",
        default={
            "bak": _BAK_PATHS_DEFAULT,
            "swp": _SWP_PATHS_DEFAULT,
            "tilde": _TILDE_PATHS_DEFAULT,
            "sql": _SQL_DUMP_PATHS_DEFAULT,
            "archive": _ARCHIVE_PATHS_DEFAULT,
            "orig_tmp": _ORIG_TMP_PATHS_DEFAULT,
            "sql_keywords": list(_SQL_KEYWORDS_DEFAULT),
        },
    )

    BAK_PATHS = data.get("bak", _BAK_PATHS_DEFAULT)
    SWP_PATHS = data.get("swp", _SWP_PATHS_DEFAULT)
    TILDE_PATHS = data.get("tilde", _TILDE_PATHS_DEFAULT)
    SQL_DUMP_PATHS = data.get("sql", _SQL_DUMP_PATHS_DEFAULT)
    ARCHIVE_PATHS = data.get("archive", _ARCHIVE_PATHS_DEFAULT)
    ORIG_TMP_PATHS = data.get("orig_tmp", _ORIG_TMP_PATHS_DEFAULT)
    SQL_KEYWORDS = frozenset(data.get("sql_keywords", _SQL_KEYWORDS_DEFAULT))

    ALL_TYPES = {
        "bak": BAK_PATHS,
        "swp": SWP_PATHS,
        "tilde": TILDE_PATHS,
        "sql": SQL_DUMP_PATHS,
        "archive": ARCHIVE_PATHS,
        "orig_tmp": ORIG_TMP_PATHS,
    }
    ALL_PATHS = list(dict.fromkeys(p for paths in ALL_TYPES.values() for p in paths))


_load_backup_paths()

ZIP_MAGIC = b"PK"
GZIP_MAGIC = b"\x1f\x8b"
COMPRESS_MAGIC = b"\x1f\x9d"
LZMA_MAGIC = b"]\x00\x00\x04"


banner = create_banner(
    r"""
 ____            _             ____                _
|  _ \  _____   _(_)______ _  | __ )  ___  __ _  (_)____
| | | |/ _ \ \ / / |_  / _` | |  _ \ / _ \/ _` | | |_  /
| |_| |  __/\ V /| |/ (_| | | |_) |  __/ (_| | | / /
|____/ \___| \_/ |_|\__,_|_| |____/ \___|\__,_|_|/_|_

""",
    "Backup File Detection | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class BackupFile:
    """Representa um arquivo de backup exposto descoberto."""

    backup_type: str
    url: str
    path: str
    status: int = 0
    detail: str = ""
    raw_size: int = 0
    exploit: str = ""
    tool: str = ""


def _classify_backup(path: str) -> str:
    """Classifica o backup pelo tipo."""
    for btype, paths in ALL_TYPES.items():
        if path in paths:
            return btype
    # Fallback por extensao
    if path.endswith((".bak", ".old", ".backup")):
        return "bak"
    if path.endswith((".swp", ".swo", ".swn")):
        return "swp"
    if path.endswith("~"):
        return "tilde"
    if path.endswith((".sql", ".sql.gz")):
        return "sql"
    if path.endswith((".zip", ".tar.gz", ".tgz", ".tar.bz2")):
        return "archive"
    if path.endswith((".orig", ".tmp", ".save")):
        return "orig_tmp"
    return "bak"


def _validate_content(path: str, content: bytes) -> tuple[bool, str]:
    """Valida se o conteudo indica backup real."""
    if not content:
        return False, ""

    backup_type = _classify_backup(path)

    # SQL dumps — checar keywords SQL
    if backup_type == "sql":
        # GZIP compressed SQL
        if content[:2] == GZIP_MAGIC:
            return True, "GZIP compressed SQL dump"
        text = content.decode("utf-8", errors="replace")
        found = [kw for kw in SQL_KEYWORDS if kw in text[:4096].upper()]
        if found:
            return True, f"SQL dump ({found[0].lower()})"
        return False, ""

    # Archives — checar magic bytes
    if backup_type == "archive":
        if content[:2] == ZIP_MAGIC:
            return True, "ZIP archive"
        if content[:2] == GZIP_MAGIC:
            return True, "GZIP archive"
        if content[:3] == b"BZh":
            return True, "BZIP2 archive"
        if content[:4] == LZMA_MAGIC or content[:6] == b"7z\xbc\xaf\x27\x1c":
            return True, "7z/LZMA archive"
        return False, ""

    # SWP — checar magic byte do vim
    if backup_type == "swp":
        if content[0:1] == b"\x0b":
            return True, "Vim swap file"
        if len(content) > 100:
            return True, "Swap file (non-standard)"
        return False, ""

    # bak, tilde, orig_tmp, save — qualquer conteudo nao vazio
    snippet = content[:80].decode("utf-8", errors="replace").strip().replace("\n", " ")
    return True, snippet


async def _probe_path(
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    base_url: str,
    path: str,
    timeout: float,
    retries: int = 2,
) -> BackupFile | None:
    """Sonda um unico path e retorna BackupFile se encontrar backup confirmado."""
    full_url = urljoin(base_url, path)
    backup_type = _classify_backup(path)
    await rate_limiter.wait()

    # HEAD pre-check
    try:
        head_status, head_headers, _, _ = await fetch(
            client,
            full_url,
            timeout=timeout,
            method="HEAD",
            max_retries=1,
            rate_limiter=rate_limiter,
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
                size = int(cl)
                # Archives podem ser grandes
                if backup_type == "archive":
                    if size > 50 * 1024 * 1024:
                        return None
                elif size > 10 * 1024 * 1024:
                    return None
            except ValueError:
                pass

    # GET
    await rate_limiter.wait()
    try:
        status, _headers, content, _ = await fetch(
            client,
            full_url,
            timeout=timeout,
            method="GET",
            max_retries=retries,
            rate_limiter=rate_limiter,
        )
    except FetchError:
        return None

    if status not in STATUS_OK:
        return None

    is_backup, detail = _validate_content(path, content)
    if not is_backup:
        return None

    return BackupFile(
        backup_type=backup_type,
        url=full_url,
        path=path,
        status=status,
        detail=detail,
        raw_size=len(content),
        exploit=f"curl {full_url}",
        tool="curl",
    )


async def scan_backups(
    base_url: str,
    timeout: float,
    concurrency: int,
    user_agent: str,
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 0.0,
    retries: int = 2,
    custom_paths: list[str] | None = None,
) -> list[BackupFile]:
    """Busca arquivos de backup expostos no alvo por probe assincrono."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)

    logger.info("scan backup file detect iniciado: %s", base_url)

    logger.info("Alvo: %s", base_url)

    paths = custom_paths or ALL_PATHS
    total = len(paths)

    logger.info(
        "Paths: %d | Concurrency: %d",
        total,
        concurrency,
    )

    sem = asyncio.Semaphore(concurrency)

    async def _limited_probe(path: str) -> BackupFile | None:
        async with sem:
            result = await _probe_path(
                client, rate_limiter, base_url, path, timeout, retries
            )
            pbar.update(1)
            return result

    pbar = tqdm(total=total, desc="  Paths testados", leave=False, file=sys.stderr)
    try:
        async with asyncio.TaskGroup() as tg:
            futures = [tg.create_task(_limited_probe(p)) for p in paths]
        results = [f.result() for f in futures]

        backups: list[BackupFile] = []
        for r in results:
            if isinstance(r, BackupFile):
                backups.append(r)
                logger.info("[+] [%s] %s — %s", r.backup_type.upper(), r.path, r.detail)
    finally:
        pbar.close()
        await client.aclose()

    elapsed = time.monotonic() - started
    logger.info("Finalizado em %.2fs. Backups encontrados: %d", elapsed, len(backups))
    return backups


def print_results(backups: list[BackupFile]) -> None:
    """Imprime tabela resumo dos backups encontrados."""
    if not backups:
        print(color("Nenhum arquivo de backup encontrado.", Cyber.RED))
        return

    print(color("\n  Backup Files Encontrados", Cyber.CYAN, Cyber.BOLD))

    hdrs = ("TIPO", "STATUS", "TAMANHO", "DETALHE", "URL")
    rows = [
        (
            b.backup_type.upper(),
            str(b.status),
            str(b.raw_size),
            b.detail[:60],
            b.url,
        )
        for b in backups
    ]

    def _row_styles(row: tuple[str, ...]) -> list[tuple[str, ...]]:
        t = row[0].lower()
        type_color = {
            "sql": Cyber.RED,
            "archive": Cyber.RED,
            "swp": Cyber.YELLOW,
            "bak": Cyber.YELLOW,
            "tilde": Cyber.GREEN,
            "orig_tmp": Cyber.CYAN,
        }.get(t, Cyber.WHITE)
        return [
            (type_color, Cyber.BOLD),
            (Cyber.WHITE,),
            (Cyber.YELLOW,),
            (Cyber.GRAY,),
            (Cyber.CYAN,),
        ]

    print_table(
        headers=hdrs,
        rows=rows,
        empty_message="Nenhum arquivo de backup encontrado.",
        alignments=["left", "right", "right", "left", "left"],
        row_styles_fn=_row_styles,
    )

    if backups:  # pragma: no cover - backups sempre nao-vazio apos guarda acima
        print(color("\n  Exploits disponíveis:", Cyber.CYAN))
        for b in backups:
            if b.exploit:
                print(color(f"    {b.path}: {b.exploit}", Cyber.YELLOW))
                print_exploit_info(b.exploit, b.tool)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Deteccao de arquivos de backup expostos em servidores web.",
    )
    add_common_args(parser, "config")
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: http://example.com")
    parser.add_argument(
        "-l",
        "--list",
        dest="target_list",
        help="Arquivo com URLs alvo (uma por linha).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=30,
        help="Concorrencia assincrona. Padrao: 30",
    )
    parser.add_argument(
        "--type",
        choices=["bak", "swp", "tilde", "sql", "archive", "orig_tmp", "all"],
        default="all",
        dest="backup_type",
        help="Tipo de backup para buscar. Padrao: all",
    )
    return parser


def _load_paths_from_args(args: argparse.Namespace) -> list[str] | None:
    """Retorna lista de paths customizada baseada no flag --type."""
    backup_type = getattr(args, "backup_type", "all")
    if backup_type == "all":
        return None
    return ALL_TYPES.get(backup_type)


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)
    urls = resolve_target_urls(args)

    if getattr(args, "dry_run", False):
        logger.warning("Nenhuma requisicao HTTP sera enviada.")
        for url in urls:
            base_url = normalize_url(
                url, default_scheme="https", ensure_trailing_slash=True
            )
            logger.info("Alvo: %s", base_url)
        return 0

    all_backups: list[BackupFile] = []
    for url in urls:
        base_url = normalize_url(
            url, default_scheme="https", ensure_trailing_slash=True
        )
        custom_paths = _load_paths_from_args(args)

        backups = await scan_backups(
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

        if not quiet and not getattr(args, "json_output", False):
            print_results(backups)

        all_backups.extend(backups)

        if getattr(args, "output_dir", None):
            hostname = extract_hostname(url)
            out_path = f"{args.output_dir}/{hostname}.json"
            write_output(
                out_path,
                [asdict(b) for b in backups],
                ["backup_type", "url", "path", "status", "detail", "raw_size"],
                quiet=quiet,
            )

    if getattr(args, "json_output", False):
        print_json([asdict(b) for b in all_backups])
    if args.output:
        write_output(
            args.output,
            [asdict(b) for b in all_backups],
            ["backup_type", "url", "path", "status", "detail", "raw_size"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Backup File Detection."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.url or getattr(a, "target_list", None)),
        prompt="bak> ",
        description="Backup File Detection interativo.",
        example="http://target.com --type sql",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --type sql\n"
            "  http://target.com --type archive\n"
            "  -l urls.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
