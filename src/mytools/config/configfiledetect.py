#!/usr/bin/env python3
"""Modulo de deteccao de arquivos de configuracao expostos em servidores web.

Busca arquivos de configuracao (.env, config.json, settings.py, web.config, etc.)
que estao acidentalmente acessiveis via HTTP, validando o conteudo para
confirmar se e um leak real de configuracao sensivel.

Fluxo:
  1. Sonda paths comuns de configuracao no alvo
  2. Valida o conteudo retornado para confirmar leak real
  3. Exibe resumo colorido e salva output detalhado
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
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

logger = logging.getLogger("mytools.configfiledetect")

STATUS_OK = frozenset({200})

# ── Path constants por categoria (fallbacks) ─────────────────────────────────

_ENV_PATHS_DEFAULT: list[str] = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.test",
    ".env.dev",
    ".env.prod",
    ".env.live",
    ".env.bak",
    ".env.old",
    ".env.backup",
    ".env.example",
    ".env.mysql",
    ".env.www",
]

_CONFIG_PATHS_DEFAULT: list[str] = [
    "config.json",
    "config.yaml",
    "config.yml",
    "config.xml",
    "config.php",
    "config.ini",
    "config.conf",
    "config.toml",
    "config.js",
    "config.py",
    "settings.py",
    "settings.json",
    "settings.yaml",
    "settings.yml",
    "application.properties",
    "application.yml",
    "application.yaml",
    "appsettings.json",
    "config/settings.json",
    "config/config.json",
    "config/config.js",
    "config/config.php",
]

_FRAMEWORK_PATHS_DEFAULT: list[str] = [
    "wp-config.php",
    "config/database.yml",
    "config/secrets.yml",
    "web.config",
    ".htaccess",
    "app/etc/local.xml",
    "config/autoload/global.php",
    "config/autoload/local.php",
    "app/config/config.yml",
    "app/config/parameters.yml",
    "app/config/parameters.yml.dist",
]

_DATABASE_PATHS_DEFAULT: list[str] = [
    "database.yml",
    "db.conf",
    "my.cnf",
    "my.ini",
    "pg_hba.conf",
    "postgresql.conf",
    "mongod.conf",
    "redis.conf",
    "config/database.php",
    "db.php",
    "application.conf",
    "application.ini",
    "application.yml",
]

_DOCKER_PATHS_DEFAULT: list[str] = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.override.yml",
    ".dockerignore",
    ".env.docker",
    "Dockerfile",
    "helm/values.yaml",
    "k8s/deployment.yaml",
    "k8s/configmap.yaml",
    "kubernetes/deployment.yaml",
]

_CREDENTIALS_PATHS_DEFAULT: list[str] = [
    "credentials.json",
    "credentials.xml",
    "secrets.json",
    "secrets.yml",
    "secrets.yaml",
    ".htpasswd",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".ssh/config",
    "aws/credentials",
    ".aws/credentials",
    "service-account.json",
    "keyfile.json",
]

_SENSITIVE_BASENAMES_DEFAULT: frozenset[str] = frozenset(
    {
        "credentials.json",
        "secrets.json",
        "secrets.yml",
        "secrets.yaml",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".htpasswd",
        "wp-config.php",
        "config/database.yml",
        "config/secrets.yml",
        "service-account.json",
        "keyfile.json",
        "aws/credentials",
        ".aws/credentials",
    }
)

_SENSITIVE_PATTERNS_DEFAULT: dict[str, list[str]] = {
    "env": [
        "=",
        "DB_",
        "API_KEY",
        "SECRET",
        "PASSWORD",
        "TOKEN",
        "MYSQL",
        "POSTGRES",
        "REDIS",
    ],
    "config": ["config", "setting", "database", "host", "port", "password"],
    "framework": [
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
        "wp_",
        "APP_KEY",
        "SECRET_KEY",
        "database",
        "password",
        "<configuration",
        "system.web",
    ],
    "database": [
        "mysql",
        "postgres",
        "host",
        "port",
        "database",
        "user",
        "password",
        "mongodb",
        "redis",
    ],
    "docker": [
        "services:",
        "version:",
        "image:",
        "container_name:",
        "build:",
        "volumes:",
        "FROM",
    ],
    "credentials": [
        "private_key",
        "client_email",
        "project_id",
        "key:",
        "secret:",
        "token:",
        "password:",
        "$apr1$",
        "$2b$",
        "$2a$",
    ],
}


def _load_config_paths() -> None:
    """Carrega config paths de YAML com fallback e atualiza variáveis globais."""
    from mytools.data import load_payloads

    global ENV_PATHS, CONFIG_PATHS, FRAMEWORK_PATHS, DATABASE_PATHS
    global DOCKER_PATHS, CREDENTIALS_PATHS, ALL_CATEGORIES, ALL_PATHS
    global SENSITIVE_BASENAMES, _SENSITIVE_PATTERNS

    data = load_payloads(
        "config",
        "config_file_detect",
        default={
            "env": _ENV_PATHS_DEFAULT,
            "config": _CONFIG_PATHS_DEFAULT,
            "framework": _FRAMEWORK_PATHS_DEFAULT,
            "database": _DATABASE_PATHS_DEFAULT,
            "docker": _DOCKER_PATHS_DEFAULT,
            "credentials": _CREDENTIALS_PATHS_DEFAULT,
            "sensitive_basenames": list(_SENSITIVE_BASENAMES_DEFAULT),
            "sensitive_patterns": _SENSITIVE_PATTERNS_DEFAULT,
        },
    )

    ENV_PATHS = data.get("env", _ENV_PATHS_DEFAULT)
    CONFIG_PATHS = data.get("config", _CONFIG_PATHS_DEFAULT)
    FRAMEWORK_PATHS = data.get("framework", _FRAMEWORK_PATHS_DEFAULT)
    DATABASE_PATHS = data.get("database", _DATABASE_PATHS_DEFAULT)
    DOCKER_PATHS = data.get("docker", _DOCKER_PATHS_DEFAULT)
    CREDENTIALS_PATHS = data.get("credentials", _CREDENTIALS_PATHS_DEFAULT)
    SENSITIVE_BASENAMES = frozenset(
        data.get("sensitive_basenames", _SENSITIVE_BASENAMES_DEFAULT)
    )
    _SENSITIVE_PATTERNS = data.get("sensitive_patterns", _SENSITIVE_PATTERNS_DEFAULT)

    ALL_CATEGORIES = {
        "env": ENV_PATHS,
        "config": CONFIG_PATHS,
        "framework": FRAMEWORK_PATHS,
        "database": DATABASE_PATHS,
        "docker": DOCKER_PATHS,
        "credentials": CREDENTIALS_PATHS,
    }
    ALL_PATHS = list(
        dict.fromkeys(p for paths in ALL_CATEGORIES.values() for p in paths)
    )


_load_config_paths()

SENSITIVE_EXTENSIONS = frozenset({".env", ".bak", ".old", ".backup"})


banner = create_banner(
    r"""
   ______                __      ______
  / ____/___  _________ _/ /__   / ____/___  _________ ___
 / /   / __ \/ ___/ __ `/ / _ \ / /   / __ \/ ___/ __ `__ \
/ /___/ /_/ / /  / /_/ / /  __// /___/ /_/ / /  / / / / / /
\____/\____/_/   \__,_/_/\___/ \____/\____/_/  /_/ /_/ /_/
""",
    "Config File Detection | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class ConfigLeak:
    """Representa um arquivo de configuracao exposto descoberto."""

    category: str
    url: str
    path: str
    status: int = 0
    detail: str = ""
    raw_size: int = 0
    exploit: str = ""
    tool: str = ""


def _classify_path(path: str) -> str:
    """Classifica o path na categoria correspondente."""
    for cat, paths in ALL_CATEGORIES.items():
        if path in paths:
            return cat
    return "config"


def _is_sensitive(path: str) -> bool:
    """Verifica se o arquivo e potencialmente sensivel."""
    basename = Path(path).name

    if path in SENSITIVE_BASENAMES or basename in SENSITIVE_BASENAMES:
        return True
    if basename.startswith(".env"):
        return True
    ext = Path(basename).suffix
    if ext in SENSITIVE_EXTENSIONS:
        return True
    return ext in {".bak", ".old", ".save"} or basename.endswith("~")


def _validate_content(path: str, content: bytes) -> tuple[bool, str]:
    """Valida se o conteudo indica arquivo de configuracao real."""
    if not content:
        return False, ""

    category = _classify_path(path)
    text = content.decode("utf-8", errors="replace").strip()

    if not text:
        return False, ""

    # Validação específica por categoria
    if category == "env":
        lines = text.splitlines()
        has_assignment = any(
            "=" in line and not line.startswith("#") for line in lines[:50]
        )
        if has_assignment:
            snippet = text[:100].replace("\n", " ")
            return True, snippet
        return False, ""

    if category == "config":
        # JSON
        if path.endswith((".json",)):
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    return True, f"JSON config ({len(data)} keys)"
            except json.JSONDecodeError, ValueError:
                pass
        # YAML-like (checar por chaves comuns)
        patterns = _SENSITIVE_PATTERNS["config"]
        if any(p in text.lower() for p in patterns):
            snippet = text[:100].replace("\n", " ")
            return True, snippet
        return False, ""

    if category == "framework":
        patterns = _SENSITIVE_PATTERNS["framework"]
        if any(p.lower() in text.lower() for p in patterns):
            snippet = text[:100].replace("\n", " ")
            return True, snippet
        return False, ""

    if category == "database":
        patterns = _SENSITIVE_PATTERNS["database"]
        if any(p in text.lower() for p in patterns):
            snippet = text[:100].replace("\n", " ")
            return True, snippet
        return False, ""

    if category == "docker":
        patterns = _SENSITIVE_PATTERNS["docker"]
        if any(p in text for p in patterns):
            snippet = text[:100].replace("\n", " ")
            return True, snippet
        return False, ""

    if category == "credentials":
        patterns = _SENSITIVE_PATTERNS["credentials"]
        if any(p in text.lower() for p in patterns):
            snippet = text[:100].replace("\n", " ")
            return True, snippet
        return False, ""

    # Fallback: qualquer conteudo nao vazio
    if text:  # pragma: no cover
        snippet = text[:100].replace("\n", " ")
        return True, snippet

    return False, ""  # pragma: no cover


async def _probe_path(
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    base_url: str,
    path: str,
    timeout: float,
    retries: int = 2,
) -> ConfigLeak | None:
    """Sonda um unico path e retorna ConfigLeak se encontrar config exposta."""
    full_url = urljoin(base_url, path)
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
                if int(cl) > 5 * 1024 * 1024:
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

    is_config, detail = _validate_content(path, content)
    if not is_config:
        return None

    category = _classify_path(path)
    return ConfigLeak(
        category=category,
        url=full_url,
        path=path,
        status=status,
        detail=detail,
        raw_size=len(content),
        exploit=f"curl {full_url}",
        tool="curl",
    )


async def scan_configs(
    base_url: str,
    timeout: float,
    concurrency: int,
    user_agent: str,
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 0.0,
    retries: int = 2,
    custom_paths: list[str] | None = None,
    sensitive_only: bool = False,
) -> list[ConfigLeak]:
    """Busca arquivos de configuracao expostos no alvo por probe assincrono."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)

    logger.info("scan config file detect iniciado: %s", base_url)

    logger.info("Alvo: %s", base_url)

    paths = custom_paths or ALL_PATHS
    if sensitive_only:
        paths = [p for p in paths if _is_sensitive(p)]
    total = len(paths)

    logger.info(
        "Paths: %d | Concurrency: %d",
        total,
        concurrency,
    )

    sem = asyncio.Semaphore(concurrency)

    async def _limited_probe(path: str) -> ConfigLeak | None:
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

        leaks: list[ConfigLeak] = []
        for r in results:
            if isinstance(r, ConfigLeak):
                leaks.append(r)
                logger.info("[+] [%s] %s — %s", r.category.upper(), r.path, r.detail)
    finally:
        pbar.close()
        await client.aclose()

    elapsed = time.monotonic() - started
    logger.info("Finalizado em %.2fs. Configs encontrados: %d", elapsed, len(leaks))
    return leaks


def print_results(leaks: list[ConfigLeak]) -> None:
    """Imprime tabela resumo dos arquivos de configuracao encontrados."""
    if not leaks:
        print(color("Nenhum arquivo de configuracao encontrado.", Cyber.RED))
        return

    print(color("\n  Config Files Encontrados", Cyber.CYAN, Cyber.BOLD))

    hdrs = ("CATEGORIA", "STATUS", "TAMANHO", "DETALHE", "URL")
    rows = [
        (
            leak.category.upper(),
            str(leak.status),
            str(leak.raw_size),
            leak.detail[:60],
            leak.url,
        )
        for leak in leaks
    ]

    def _row_styles(row: tuple[str, ...]) -> list[tuple[str, ...]]:
        cat = row[0].lower()
        cat_color = {
            "env": Cyber.RED,
            "credentials": Cyber.RED,
            "config": Cyber.YELLOW,
            "framework": Cyber.YELLOW,
            "database": Cyber.GREEN,
            "docker": Cyber.CYAN,
        }.get(cat, Cyber.WHITE)
        return [
            (cat_color, Cyber.BOLD),
            (Cyber.WHITE,),
            (Cyber.YELLOW,),
            (Cyber.GRAY,),
            (Cyber.CYAN,),
        ]

    print_table(
        headers=hdrs,
        rows=rows,
        empty_message="Nenhum arquivo de configuracao encontrado.",
        alignments=["left", "right", "right", "left", "left"],
        row_styles_fn=_row_styles,
    )

    if leaks:  # pragma: no cover - leaks sempre nao-vazio apos guarda acima
        print(color("\n  Exploits disponíveis:", Cyber.CYAN))
        for leak in leaks:
            if leak.exploit:
                print(color(f"    {leak.path}: {leak.exploit}", Cyber.YELLOW))
                print_exploit_info(leak.exploit, leak.tool)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Deteccao de arquivos de configuracao expostos em servidores web.",
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
        "--category",
        choices=[
            "env",
            "config",
            "framework",
            "database",
            "docker",
            "credentials",
            "all",
        ],
        default="all",
        help="Categoria de configs para buscar. Padrao: all",
    )
    parser.add_argument(
        "--sensitive-only",
        action="store_true",
        dest="sensitive_only",
        help="Apenas arquivos potencialmente sensiveis (.env, credentials, etc).",
    )
    return parser


def _load_paths_from_args(args: argparse.Namespace) -> list[str] | None:
    """Retorna lista de paths customizada baseada no flag --category."""
    category = getattr(args, "category", "all")
    if category == "all":
        return None
    return ALL_CATEGORIES.get(category)


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

    all_leaks: list[ConfigLeak] = []
    for url in urls:
        base_url = normalize_url(
            url, default_scheme="https", ensure_trailing_slash=True
        )
        custom_paths = _load_paths_from_args(args)

        leaks = await scan_configs(
            base_url=base_url,
            timeout=args.timeout,
            concurrency=args.concurrency,
            user_agent=args.user_agent,
            proxy=args.proxy,
            verify=getattr(args, "verify", False),
            requests_per_second=args.delay,
            retries=args.retries,
            custom_paths=custom_paths,
            sensitive_only=getattr(args, "sensitive_only", False),
        )

        if not quiet and not getattr(args, "json_output", False):
            print_results(leaks)

        all_leaks.extend(leaks)

        if getattr(args, "output_dir", None):
            hostname = extract_hostname(url)
            out_path = f"{args.output_dir}/{hostname}.json"
            write_output(
                out_path,
                [asdict(leak) for leak in leaks],
                ["category", "url", "path", "status", "detail", "raw_size"],
                quiet=quiet,
            )

    if getattr(args, "json_output", False):
        print_json([asdict(leak) for leak in all_leaks])
    if args.output:
        write_output(
            args.output,
            [asdict(leak) for leak in all_leaks],
            ["category", "url", "path", "status", "detail", "raw_size"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Config File Detection."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.url or getattr(a, "target_list", None)),
        prompt="cfg> ",
        description="Config File Detection interativo.",
        example="http://target.com --category env",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  http://target.com\n"
            "  http://target.com --category env\n"
            "  http://target.com --sensitive-only\n"
            "  -l urls.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
