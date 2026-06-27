#!/usr/bin/env python3
"""Modulo de Social Engineering Recon — coleta informacoes de funcionarios.

Coleta emails, nomes, cargos de funcionarios do alvo usando fontes OSINT:
  - GitHub API — contributors + user profiles (gratis, 60 req/h)
  - Hunter.io — email finder com nomes e cargos (API key, 50 free/mes)
  - Web Scraping — paginas /about, /team do dominio (gratis)

Fluxo:
  1. GitHub: busca repos da org → contributors → perfis de usuarios
  2. Hunter.io: domain search retorna emails com nomes e cargos
  3. Web: busca paginas /about, /team e parseia com BeautifulSoup
  4. Mescla resultados sem duplicatas
"""
import argparse
import json
import logging
import time
from dataclasses import asdict, dataclass
from urllib.parse import quote, urljoin

import httpx
from bs4 import BeautifulSoup

from utils import (
    Cyber,
    FetchError,
    RateLimiter,
    add_base_args,
    add_http_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    init_scanner,
    print_table,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.socialengrecon")

STATUS_OK = frozenset({200})

GITHUB_API = "https://api.github.com"
HUNTER_API = "https://api.hunter.io/v2"

TEAM_PATHS: list[str] = [
    "/about", "/about-us", "/team", "/our-team", "/people",
    "/company", "/company/about", "/about/team",
]

DEFAULT_SOURCES = ["github"]

banner = create_banner(
    r"""
    ____                ___                 __
   / __ \____ _____   / (_)___ _____   ____/ /
  / /_/ / __ `/ __ \ / / / __ `/ __ \ / __  /
 / _, _/ /_/ / / / / / / / /_/ / /_/ / /_/ /
/_/ |_|\__,_/_/ /_/_/_/_/\__, /\____/\__,_/
                         /____/
""",
    "Social Engineering Recon | use apenas em alvos autorizados",
)


@dataclass(frozen=True, slots=True)
class EmployeeInfo:
    """Representa um funcionario descoberto."""

    domain: str
    name: str = ""
    email: str = ""
    position: str = ""
    seniority: str = ""
    department: str = ""
    source: str = ""
    profile_url: str = ""


def _extract_domain_name(domain: str) -> str:
    """Extrai nome da empresa do dominio (ex: example.com -> example)."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain


async def _query_github(
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
    rate_limiter: RateLimiter,
    max_results: int = 50,
) -> list[EmployeeInfo]:
    """Consulta GitHub API — org repos + contributors + user profiles."""
    org_name = _extract_domain_name(domain)
    employees: list[EmployeeInfo] = []
    seen_users: set[str] = set()

    await rate_limiter.wait()
    try:
        status, _headers, body, _ = await fetch(
            client, f"{GITHUB_API}/orgs/{quote(org_name)}/repos?per_page=30&sort=updated",
            timeout=timeout, max_retries=1, rate_limiter=rate_limiter,
        )
    except FetchError:
        return []

    if status != 200:
        return []

    try:
        repos = json.loads(body)
    except Exception:
        return []

    if not isinstance(repos, list):
        return []

    repo_names: list[str] = []
    for repo in repos[:10]:
        if isinstance(repo, dict):
            name = repo.get("full_name", "")
            if name:
                repo_names.append(name)

    for repo_name in repo_names:
        if len(employees) >= max_results:
            break

        await rate_limiter.wait()
        try:
            status, _headers, body, _ = await fetch(
                client, f"{GITHUB_API}/repos/{repo_name}/contributors?per_page=30",
                timeout=timeout, max_retries=1, rate_limiter=rate_limiter,
            )
        except FetchError:
            continue

        if status != 200:
            continue

        try:
            contributors = json.loads(body)
        except Exception:
            continue

        if not isinstance(contributors, list):
            continue

        for contrib in contributors:
            if len(employees) >= max_results:
                break
            if not isinstance(contrib, dict):
                continue
            login = contrib.get("login", "")
            if not login or login in seen_users:
                continue
            seen_users.add(login)

            await rate_limiter.wait()
            try:
                status, _headers, body, _ = await fetch(
                    client, f"{GITHUB_API}/users/{quote(login)}",
                    timeout=timeout, max_retries=1, rate_limiter=rate_limiter,
                )
            except FetchError:
                continue

            if status != 200:
                continue

            try:
                user = json.loads(body)
            except Exception:
                continue

            if not isinstance(user, dict):
                continue

            name = user.get("name") or ""
            email = user.get("email") or ""
            bio = user.get("bio") or ""
            profile = user.get("html_url") or ""

            position = ""
            if bio:
                for sep in [" at ", " @ ", " @"]:
                    if sep in bio.lower():
                        parts = bio.lower().split(sep, 1)
                        if len(parts) > 1:
                            position = parts[1].strip()[:50]
                            break

            if name or email:
                employees.append(EmployeeInfo(
                    domain=domain,
                    name=name,
                    email=email,
                    position=position,
                    source="github",
                    profile_url=profile,
                ))

    return employees


async def _query_hunter(
    client: httpx.AsyncClient,
    domain: str,
    api_key: str,
    timeout: float,
    rate_limiter: RateLimiter,
    max_results: int = 50,
) -> list[EmployeeInfo]:
    """Consulta Hunter.io domain search."""
    if not api_key:
        return []

    await rate_limiter.wait()
    url = f"{HUNTER_API}/domain-search?domain={quote(domain)}&api_key={api_key}&limit={max_results}"

    try:
        status, _headers, body, _ = await fetch(
            client, url, timeout=timeout, max_retries=1, rate_limiter=rate_limiter,
        )
    except FetchError:
        return []

    if status != 200:
        return []

    try:
        data = json.loads(body)
    except Exception:
        return []

    emails_data = data.get("data", {}).get("emails", [])
    if not isinstance(emails_data, list):
        return []

    employees: list[EmployeeInfo] = []
    for item in emails_data:
        if not isinstance(item, dict):
            continue
        employees.append(EmployeeInfo(
            domain=domain,
            name=f"{item.get('first_name', '')} {item.get('last_name', '')}".strip(),
            email=item.get("value", ""),
            position=item.get("position", ""),
            seniority=item.get("seniority", ""),
            department=item.get("department", ""),
            source="hunter",
        ))

    return employees


async def _query_webpages(
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
    rate_limiter: RateLimiter,
    max_results: int = 30,
) -> list[EmployeeInfo]:
    """Busca paginas /about, /team do dominio e extrai nomes."""
    employees: list[EmployeeInfo] = []
    base_url = f"https://{domain}"

    for path in TEAM_PATHS:
        if len(employees) >= max_results:
            break

        url = urljoin(base_url, path)
        await rate_limiter.wait()

        try:
            status, _headers, body, _ = await fetch(
                client, url, timeout=timeout, max_retries=1, rate_limiter=rate_limiter,
            )
        except FetchError:
            continue

        if status != 200:
            continue

        try:
            html = body.decode("utf-8", errors="replace")
        except Exception:
            continue

        soup = BeautifulSoup(html, "html.parser")

        for tag in soup.find_all(["h2", "h3", "h4", "strong", "b"]):
            text = tag.get_text(strip=True)
            if not text or len(text) < 3 or len(text) > 60:
                continue
            if any(c.isdigit() for c in text):
                continue
            words = text.split()
            if len(words) < 2 or len(words) > 5:
                continue
            if all(w[0].isupper() for w in words if w and w[0].isalpha()):
                position_tag = tag.find_next(["p", "span", "div", "em"])
                position = ""
                if position_tag:
                    pos_text = position_tag.get_text(strip=True)
                    if len(pos_text) < 60 and any(kw in pos_text.lower() for kw in [
                        "engineer", "manager", "director", "ceo", "cto", "cfo",
                        "lead", "developer", "designer", "analyst", "architect",
                        "head", "vp", "president", "founder", "co-founder",
                    ]):
                        position = pos_text

                employees.append(EmployeeInfo(
                    domain=domain,
                    name=text,
                    position=position,
                    source="web",
                    profile_url=url,
                ))

    return employees


def _dedup_employees(employees: list[EmployeeInfo]) -> list[EmployeeInfo]:
    """Remove duplicatas por email (se disponivel) ou nome+dominio."""
    seen_emails: set[str] = set()
    seen_names: set[tuple[str, str]] = set()
    result: list[EmployeeInfo] = []

    for e in employees:
        if e.email:
            key = e.email.lower()
            if key in seen_emails:
                continue
            seen_emails.add(key)
            result.append(e)
        elif e.name:
            key = (e.name.lower(), e.domain.lower())
            if key in seen_names:
                continue
            seen_names.add(key)
            result.append(e)
        else:
            result.append(e)

    return result


async def scan_employees(
    domain: str,
    sources: list[str],
    api_keys: dict[str, str | None],
    timeout: float,
    concurrency: int,
    user_agent: str,
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 0.0,
    max_results: int = 50,
) -> list[EmployeeInfo]:
    """Coleta informacoes de funcionarios do dominio."""
    started = time.monotonic()
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(user_agent=user_agent, proxy=proxy, verify=verify)

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(domain, Cyber.WHITE, Cyber.BOLD)}")
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Fontes: {color(', '.join(sources), Cyber.WHITE, Cyber.BOLD)}")

    all_employees: list[EmployeeInfo] = []

    for source in sources:
        if source == "github":
            emps = await _query_github(client, domain, timeout, rate_limiter, max_results)
            all_employees.extend(emps)
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"GitHub: {color(str(len(emps)), Cyber.GREEN)} funcionarios encontrados")
        elif source == "hunter":
            key = api_keys.get("hunter") or ""
            emps = await _query_hunter(client, domain, key, timeout, rate_limiter, max_results)
            all_employees.extend(emps)
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Hunter: {color(str(len(emps)), Cyber.GREEN)} funcionarios encontrados")
        elif source == "web":
            emps = await _query_webpages(client, domain, timeout, rate_limiter, max_results)
            all_employees.extend(emps)
            print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Web: {color(str(len(emps)), Cyber.GREEN)} funcionarios encontrados")

    await client.aclose()

    all_employees = _dedup_employees(all_employees)

    elapsed = time.monotonic() - started
    print(
        color("[*]", Cyber.CYAN, Cyber.BOLD),
        f"Finalizado em {color(f'{elapsed:.2f}s', Cyber.YELLOW)}. "
        f"Funcionarios unicos: {color(str(len(all_employees)), Cyber.GREEN, Cyber.BOLD)}",
    )

    return all_employees


def print_results(employees: list[EmployeeInfo]) -> None:
    """Imprime tabela resumo dos funcionarios encontrados."""
    if not employees:
        print(color("\nNenhum funcionario encontrado.", Cyber.YELLOW))
        return

    print(color("\n  Funcionarios Encontrados", Cyber.CYAN, Cyber.BOLD))

    hdrs = ("NOME", "EMAIL", "CARGO", "SENIORIDADE", "FONTE")
    rows: list[tuple[str, ...]] = []
    for e in employees:
        rows.append((
            e.name or "-",
            e.email or "-",
            (e.position or "-")[:30],
            e.seniority or "-",
            e.source,
        ))

    def _row_styles(_row: tuple[str, ...]) -> list[tuple[str, ...]]:
        return [
            (Cyber.WHITE, Cyber.BOLD),
            (Cyber.CYAN,),
            (Cyber.YELLOW,),
            (Cyber.GREEN,),
            (Cyber.MAGENTA,),
        ]

    print_table(
        headers=hdrs,
        rows=rows,
        empty_message="Nenhum funcionario encontrado.",
        alignments=["left", "left", "left", "left", "left"],
        row_styles_fn=_row_styles,
    )


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Social Engineering Recon — coleta informacoes de funcionarios do alvo.",
    )
    add_base_args(parser)
    add_http_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo. Ex: example.com")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com dominios (um por linha).")
    parser.add_argument(
        "--source",
        action="append",
        choices=["github", "hunter", "web"],
        dest="sources",
        help="Fonte para consulta (pode repetir). Padrao: github.",
    )
    parser.add_argument(
        "--hunter-api-key",
        dest="hunter_api_key",
        help="API key do Hunter.io (obrigatoria para --source hunter).",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=50,
        dest="max_results",
        help="Max resultados por fonte. Padrao: 50",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma requisicao HTTP sera enviada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(args.domain, Cyber.WHITE, Cyber.BOLD)}")
        return 0

    sources = args.sources or list(DEFAULT_SOURCES)
    api_keys: dict[str, str | None] = {
        "hunter": getattr(args, "hunter_api_key", None),
    }

    for s in sources:
        if s == "hunter" and not api_keys.get(s):
            print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "hunter requer API key (use --hunter-api-key)")

    employees = await scan_employees(
        domain=args.domain,
        sources=sources,
        api_keys=api_keys,
        timeout=args.timeout,
        concurrency=getattr(args, "concurrency", 5),
        user_agent=args.user_agent,
        proxy=args.proxy,
        verify=getattr(args, "verify", False),
        requests_per_second=args.delay,
        max_results=getattr(args, "max_results", 50),
    )

    if not quiet:
        print_results(employees)

    if args.output:
        write_output(
            args.output,
            [asdict(e) for e in employees],
            ["domain", "name", "email", "position", "seniority", "department", "source", "profile_url"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Social Engineering Recon."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain or getattr(a, "target_list", None)),
        prompt="soceng> ",
        description="Social Engineering Recon interativo.",
        example="example.com --source github",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --source github --source hunter\n"
            "  example.com --hunter-api-key KEY\n"
            "  -l domains.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
