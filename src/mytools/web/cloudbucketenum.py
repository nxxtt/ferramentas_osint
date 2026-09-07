#!/usr/bin/env python3
"""Modulo de enumeracao de cloud buckets (S3, GCP, Azure).

Detecta buckets abertos, existentes ou inexistentes em provedores de nuvem:

  s3:
    - Testa {bucket}.s3.amazonaws.com
    - Detecta listagem publica (ListBucketResult, <Key>)
    - Detecta AccessDenied (bucket existe mas fechado)
    - Detecta NoSuchBucket (nao existe)

  gcp:
    - Testa storage.googleapis.com/storage/v1/b/{bucket}/o
    - Detecta listagem publica (items, kind, storage#objects)
    - Detecta 404 (bucket nao existe)

  azure:
    - Testa {bucket}.blob.core.windows.net/?comp=list
    - Detecta listagem publica (EnumerationResults, <Blobs>)
    - Detecta BlobNotFound (bucket nao existe)

Fluxo:
  1. Recebe dominio (ex: example.com)
  2. Gera nomes de bucket a partir do dominio (example, example-backup, etc.)
  3. Testa cada nome em cada provedor
  4. Reporta buckets abertos, existentes ou inexistentes

NOTA: Enumeracao de buckets abertos pode gerar falsos positivos.
Valide manualmente antes de assumir que um bucket e acessivel.
"""

import argparse
import logging
import time
from dataclasses import asdict, dataclass
from urllib.parse import quote

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    init_scanner,
    print_json,
    run_concurrent,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.cloudbucketenum")

# ---------------------------------------------------------------------------
# Payload loading
# ---------------------------------------------------------------------------

_SUFFIXES_DEFAULT: list[str] = [
    "",
    "-backup",
    "-logs",
    "-dev",
    "-staging",
    "-prod",
    "-test",
    "-data",
    "-assets",
    "-media",
    "-static",
    "-config",
    "-db",
    "-archive",
]

_PREFIXES_DEFAULT: list[str] = [
    "",
    "backup-",
    "logs-",
    "dev-",
    "staging-",
    "prod-",
    "test-",
    "data-",
    "assets-",
    "media-",
]

_S3_OPEN_DEFAULT: list[str] = [
    "ListBucketResult",
    "<Key>",
    "<Prefix>",
    "<Delimiter>",
    "<MaxKeys>",
]

_S3_EXISTS_DEFAULT: list[str] = ["NoSuchBucket"]

_S3_DENIED_DEFAULT: list[str] = ["AccessDenied", "AllAccessDisabled"]

_GCP_OPEN_DEFAULT: list[str] = [
    "items",
    "kind",
    "storage#buckets",
    "storage#objects",
]

_GCP_NOT_FOUND_DEFAULT: list[str] = [
    "NoSuchBucket",
    "Not Found",
    "The specified bucket does not exist",
]

_AZURE_OPEN_DEFAULT: list[str] = [
    "EnumerationResults",
    "<Blobs>",
    "<Blob>",
    "<Name>",
    "<Url>",
]

_AZURE_NOT_FOUND_DEFAULT: list[str] = [
    "BlobNotFound",
    "NotFound",
    "The specified container does not exist",
]


def _load_payloads() -> dict[str, object]:
    from mytools.data import load_payloads

    return load_payloads(
        "web",
        "cloud_bucket_enum",
        default={
            "suffixes": _SUFFIXES_DEFAULT,
            "prefixes": _PREFIXES_DEFAULT,
            "s3_indicators": {
                "open": _S3_OPEN_DEFAULT,
                "exists": _S3_EXISTS_DEFAULT,
                "access_denied": _S3_DENIED_DEFAULT,
            },
            "gcp_indicators": {
                "open": _GCP_OPEN_DEFAULT,
                "not_found": _GCP_NOT_FOUND_DEFAULT,
            },
            "azure_indicators": {
                "open": _AZURE_OPEN_DEFAULT,
                "not_found": _AZURE_NOT_FOUND_DEFAULT,
            },
        },
    )


def _get_suffixes() -> list[str]:
    data = _load_payloads()
    raw = data.get("suffixes", _SUFFIXES_DEFAULT)
    return list(raw) if isinstance(raw, list) else _SUFFIXES_DEFAULT


def _get_prefixes() -> list[str]:
    data = _load_payloads()
    raw = data.get("prefixes", _PREFIXES_DEFAULT)
    return list(raw) if isinstance(raw, list) else _PREFIXES_DEFAULT


def _get_s3_indicators() -> dict[str, list[str]]:
    data = _load_payloads()
    raw = data.get("s3_indicators", {})
    if isinstance(raw, dict):
        return {k: list(v) if isinstance(v, list) else [] for k, v in raw.items()}
    return {
        "open": _S3_OPEN_DEFAULT,
        "exists": _S3_EXISTS_DEFAULT,
        "access_denied": _S3_DENIED_DEFAULT,
    }


def _get_gcp_indicators() -> dict[str, list[str]]:
    data = _load_payloads()
    raw = data.get("gcp_indicators", {})
    if isinstance(raw, dict):
        return {k: list(v) if isinstance(v, list) else [] for k, v in raw.items()}
    return {"open": _GCP_OPEN_DEFAULT, "not_found": _GCP_NOT_FOUND_DEFAULT}


def _get_azure_indicators() -> dict[str, list[str]]:
    data = _load_payloads()
    raw = data.get("azure_indicators", {})
    if isinstance(raw, dict):
        return {k: list(v) if isinstance(v, list) else [] for k, v in raw.items()}
    return {"open": _AZURE_OPEN_DEFAULT, "not_found": _AZURE_NOT_FOUND_DEFAULT}


# ---------------------------------------------------------------------------
# Bucket name generation
# ---------------------------------------------------------------------------


def _generate_bucket_names(domain: str) -> list[str]:
    """Gera nomes de bucket a partir do dominio.

    example.com -> example, example-backup, example-logs, ...
    """
    base = domain.split(".")[0] if "." in domain else domain
    base = base.lower().strip()

    names: list[str] = []
    suffixes = _get_suffixes()
    prefixes = _get_prefixes()

    for prefix in prefixes:
        for suffix in suffixes:
            candidate = f"{prefix}{base}{suffix}"
            if candidate and candidate not in names:
                names.append(candidate)

    return names


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _check_s3_response(
    status: int,
    body: str,
    indicators: dict[str, list[str]],
) -> tuple[bool, bool, str]:
    """Verifica response S3. Retorna (open, exists, detail)."""
    if status == 404:
        for ind in indicators.get("exists", []):
            if ind in body:
                return False, False, "Bucket nao existe (NoSuchBucket)"
        return False, False, "HTTP 404"

    if status == 403:
        for ind in indicators.get("access_denied", []):
            if ind in body:
                return False, True, "Bucket existe mas acesso negado (AccessDenied)"
        return False, True, "HTTP 403"

    if status == 200:
        for ind in indicators.get("open", []):
            if ind in body:
                return True, True, "Bucket ABERTO — listagem publica detectada"
        return False, True, "HTTP 200 sem indicadores de listagem"

    return False, False, f"HTTP {status}"


def _check_gcp_response(
    status: int,
    body: str,
    indicators: dict[str, list[str]],
) -> tuple[bool, bool, str]:
    """Verifica response GCP. Retorna (open, exists, detail)."""
    if status == 404:
        for ind in indicators.get("not_found", []):
            if ind in body:
                return False, False, "Bucket nao existe"
        return False, False, "HTTP 404"

    if status == 403:
        return False, True, "Bucket existe mas acesso negado"

    if status == 200:
        for ind in indicators.get("open", []):
            if ind in body:
                return True, True, "Bucket ABERTO — listagem publica detectada"
        return False, True, "HTTP 200 sem indicadores de listagem"

    return False, False, f"HTTP {status}"


def _check_azure_response(
    status: int,
    body: str,
    indicators: dict[str, list[str]],
) -> tuple[bool, bool, str]:
    """Verifica response Azure. Retorna (open, exists, detail)."""
    if status in (404, 400):
        for ind in indicators.get("not_found", []):
            if ind in body:
                return False, False, "Container nao existe"
        if status == 404:
            return False, False, "HTTP 404"

    if status == 403:
        return False, True, "Container existe mas acesso negado"

    if status == 200:
        for ind in indicators.get("open", []):
            if ind in body:
                return True, True, "Container ABERTO — listagem publica detectada"
        return False, True, "HTTP 200 sem indicadores de listagem"

    return False, False, f"HTTP {status}"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BucketAttempt:
    """Tentativa individual de enumeracao de bucket."""

    provider: str
    bucket_name: str
    url: str
    status_code: int
    response_size: int
    response_time: float
    open_bucket: bool
    exists: bool
    details: str
    error: str = ""


@dataclass(frozen=True, slots=True)
class BucketResult:
    """Resultado consolidado do scan de cloud buckets."""

    domain: str
    attempts: list[BucketAttempt]
    open_buckets: list[str]
    existing_buckets: list[str]
    issues: list[str]
    overall_status: str


# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------


async def _test_s3(
    client: httpx.AsyncClient,
    bucket_name: str,
    timeout: float,
) -> list[BucketAttempt]:
    """Testa bucket S3."""
    attempts: list[BucketAttempt] = []
    indicators = _get_s3_indicators()
    encoded = quote(bucket_name, safe="")

    urls = [
        f"https://{encoded}.s3.amazonaws.com/",
        f"https://{encoded}.s3.amazonaws.com/?list-type=2&max-keys=1",
    ]

    for url in urls:
        start = time.monotonic()
        try:
            resp = await client.get(url, follow_redirects=False)
            elapsed = time.monotonic() - start
            body = resp.text[:5000]

            open_b, exists, detail = _check_s3_response(
                resp.status_code, body, indicators
            )

            attempts.append(
                BucketAttempt(
                    provider="s3",
                    bucket_name=bucket_name,
                    url=url,
                    status_code=resp.status_code,
                    response_size=len(resp.content),
                    response_time=round(elapsed, 3),
                    open_bucket=open_b,
                    exists=exists,
                    details=detail,
                )
            )

        except httpx.RequestError as exc:
            elapsed = time.monotonic() - start
            attempts.append(
                BucketAttempt(
                    provider="s3",
                    bucket_name=bucket_name,
                    url=url,
                    status_code=0,
                    response_size=0,
                    response_time=round(elapsed, 3),
                    open_bucket=False,
                    exists=False,
                    details="",
                    error=str(exc),
                )
            )

    return attempts


async def _test_gcp(
    client: httpx.AsyncClient,
    bucket_name: str,
    timeout: float,
) -> list[BucketAttempt]:
    """Testa bucket GCP."""
    attempts: list[BucketAttempt] = []
    indicators = _get_gcp_indicators()
    encoded = quote(bucket_name, safe="")

    url = f"https://storage.googleapis.com/storage/v1/b/{encoded}/o?maxResults=1"

    start = time.monotonic()
    try:
        resp = await client.get(url, follow_redirects=False)
        elapsed = time.monotonic() - start
        body = resp.text[:5000]

        open_b, exists, detail = _check_gcp_response(resp.status_code, body, indicators)

        attempts.append(
            BucketAttempt(
                provider="gcp",
                bucket_name=bucket_name,
                url=url,
                status_code=resp.status_code,
                response_size=len(resp.content),
                response_time=round(elapsed, 3),
                open_bucket=open_b,
                exists=exists,
                details=detail,
            )
        )

    except httpx.RequestError as exc:
        elapsed = time.monotonic() - start
        attempts.append(
            BucketAttempt(
                provider="gcp",
                bucket_name=bucket_name,
                url=url,
                status_code=0,
                response_size=0,
                response_time=round(elapsed, 3),
                open_bucket=False,
                exists=False,
                details="",
                error=str(exc),
            )
        )

    return attempts


async def _test_azure(
    client: httpx.AsyncClient,
    bucket_name: str,
    timeout: float,
) -> list[BucketAttempt]:
    """Testa container Azure."""
    attempts: list[BucketAttempt] = []
    indicators = _get_azure_indicators()
    encoded = quote(bucket_name, safe="")

    url = f"https://{encoded}.blob.core.windows.net/?comp=list&maxresults=1"

    start = time.monotonic()
    try:
        resp = await client.get(url, follow_redirects=False)
        elapsed = time.monotonic() - start
        body = resp.text[:5000]

        open_b, exists, detail = _check_azure_response(
            resp.status_code, body, indicators
        )

        attempts.append(
            BucketAttempt(
                provider="azure",
                bucket_name=bucket_name,
                url=url,
                status_code=resp.status_code,
                response_size=len(resp.content),
                response_time=round(elapsed, 3),
                open_bucket=open_b,
                exists=exists,
                details=detail,
            )
        )

    except httpx.RequestError as exc:
        elapsed = time.monotonic() - start
        attempts.append(
            BucketAttempt(
                provider="azure",
                bucket_name=bucket_name,
                url=url,
                status_code=0,
                response_size=0,
                response_time=round(elapsed, 3),
                open_bucket=False,
                exists=False,
                details="",
                error=str(exc),
            )
        )

    return attempts


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------


async def run_scan(
    domain: str,
    providers: str = "all",
    timeout: float = 10.0,
    concurrency: int = 5,
    output_file: str | None = None,
    json_output: bool = False,
) -> BucketResult:
    """Executa o scan de Cloud Bucket Enumeration contra o dominio alvo."""
    base = domain.split(".")[0] if "." in domain else domain
    base = base.lower().strip()

    bucket_names = _generate_bucket_names(domain)
    logger.info("Nomes gerados: %d (base: %s)", len(bucket_names), base)

    valid_providers = {"s3", "gcp", "azure", "all"}
    if providers not in valid_providers:
        return BucketResult(
            domain=domain,
            attempts=[],
            open_buckets=[],
            existing_buckets=[],
            issues=[f"Provider desconhecido: {providers}"],
            overall_status="error",
        )

    async with create_async_client(
        user_agent="MyTools/cloudbucketenum",
        timeout=timeout,
    ) as client:
        all_attempts: list[BucketAttempt] = []

        for name in bucket_names:
            coros = []

            if providers in ("all", "s3"):
                coros.append(_test_s3(client, name, timeout))
            if providers in ("all", "gcp"):
                coros.append(_test_gcp(client, name, timeout))
            if providers in ("all", "azure"):
                coros.append(_test_azure(client, name, timeout))

            if coros:  # pragma: no cover - providers validado apos gerar >=1 task
                results = await run_concurrent(coros, concurrency)
                for r in results:
                    if isinstance(r, list):
                        all_attempts.extend(r)

        open_buckets: list[str] = []
        existing_buckets: list[str] = []
        issues: list[str] = []

        for a in all_attempts:
            if a.open_bucket:
                key = f"{a.provider}:{a.bucket_name}"
                if key not in open_buckets:
                    open_buckets.append(key)
            if a.exists and not a.open_bucket:
                key = f"{a.provider}:{a.bucket_name}"
                if key not in existing_buckets:
                    existing_buckets.append(key)

        if open_buckets:
            issues.append(f"Buckets ABERTOS encontrados: {len(open_buckets)}")
        if existing_buckets:
            issues.append(f"Buckets existentes (fechados): {len(existing_buckets)}")
        if not open_buckets and not existing_buckets:
            issues.append("Nenhum bucket aberto ou existente encontrado")

        overall = "vulnerable" if open_buckets else "secure"

        return BucketResult(
            domain=domain,
            attempts=all_attempts,
            open_buckets=open_buckets,
            existing_buckets=existing_buckets,
            issues=issues,
            overall_status=overall,
        )


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


def print_results(result: BucketResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  CLOUD BUCKET ENUMERATION", Cyber.CYAN))
    print(color("=" * 60, Cyber.CYAN))
    print(color(f"  Domain: {result.domain}", Cyber.WHITE))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN
    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    if result.open_buckets:
        print(color("\n  [BUCKETS ABERTOS]", Cyber.RED))
        for b in result.open_buckets:
            print(color(f"    - {b}", Cyber.RED))

    if result.existing_buckets:
        print(color("\n  [BUCKETS EXISTENTES (fechados)]", Cyber.YELLOW))
        for b in result.existing_buckets:
            print(color(f"    - {b}", Cyber.YELLOW))

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
    ____          _        __     ___    ____
   / ___/_ _____ (_)_____ / /_   / _ |  / __ \
  / /__/ // / _ \/ //_/ _ \ /  / __ | / / / /
  \___/\_,_/_//_/\__/_//_//_/ /_/ |_|/_/ /_/
    """,
    "Cloud Bucket Enumeration — S3, GCP, Azure open bucket detection",
)


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta parser CLI para mytools-bucket."""
    parser = argparse.ArgumentParser(
        prog="mytools-bucket",
        description="Cloud Bucket Enumeration — detecta buckets abertos em S3, GCP, Azure.",
    )
    parser.add_argument("domain", nargs="?", help="Dominio alvo (ex: example.com)")
    parser.add_argument(
        "-p",
        "--providers",
        choices=["s3", "gcp", "azure", "all"],
        default="all",
        help="Provedores para testar (default: all)",
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
    """Executa um scan Cloud Bucket Enumeration a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("Cloud Bucket Enumeration iniciado para %s", args.domain)

    result = safe_asyncio_run(
        run_scan(
            domain=args.domain,
            providers=getattr(args, "providers", "all"),
            timeout=getattr(args, "timeout", 10.0),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
            json_output=getattr(args, "json_output", False),
        ),
    )

    if getattr(args, "json_output", False):
        print_json(asdict(result))
    else:
        print_results(result)

    if getattr(args, "output", None):
        write_output(args.output, asdict(result))

    return 1 if result.overall_status != "secure" else 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "domain", None)),
        prompt="bucket> ",
        description="Cloud Bucket Enumeration interativo.",
        example="example.com",
        contextual_help=(
            "Uso: <domain> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com -p s3\n"
            "  example.com -p gcp --timeout 15\n"
            "  example.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
