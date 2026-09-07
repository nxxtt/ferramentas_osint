#!/usr/bin/env python3

"""Docker Attack Testing — Docker Registry security probing.



Testa seguranca de Docker Registries:

  - Docker: registry_exposed

"""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_banner,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.dockerattack")

_BANNER_LINES: str = (
    "  ___  ___  ___   ___  _      _              \n"
    " / __|/ _ \\|   \\ / _ \\| |___| |_ ___ _ __  \n"
    " \\__ \\ (_) | |) | (_) |  _/  __/ _ \\ '_ \\ \n"
    " |___/\\___/|___/ \\___/ \\__|\\__|\\___/ .__/ \n"
    "                                     |_|    \n"
)


_REGISTRY_V2_PATHS: list[dict[str, Any]] = [
    {"path": "/v2/", "desc": "V2 API root"},
    {"path": "/v2/_catalog", "desc": "Repository catalog"},
    {"path": "/v2/_catalog?n=100", "desc": "Catalog (extended)"},
]


_REGISTRY_AUTH_HEADERS: list[dict[str, str]] = [
    {},
    {"Authorization": "Basic "},
    {"Authorization": "Bearer "},
    {"X-Registry-Auth": ""},
]


_COMMON_REPO_NAMES_DEFAULT: list[str] = [
    "library",
    "alpine",
    "nginx",
    "ubuntu",
    "debian",
    "node",
    "python",
    "redis",
    "postgres",
    "mysql",
    "mongo",
    "jenkins",
    "ubuntu",
    "centos",
    "grafana",
    "prometheus",
    "kibana",
    "elasticsearch",
    "rabbitmq",
]

_COMMON_TAGS_DEFAULT: list[str] = ["latest", "stable", "dev", "main", "production"]


def _load_docker_data() -> tuple[list[str], list[str]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "docker_attack",
        default={
            "common_repo_names": _COMMON_REPO_NAMES_DEFAULT,
            "common_tags": _COMMON_TAGS_DEFAULT,
        },
    )
    return (
        data.get("common_repo_names", _COMMON_REPO_NAMES_DEFAULT),
        data.get("common_tags", _COMMON_TAGS_DEFAULT),
    )


_COMMON_REPO_NAMES, _COMMON_TAGS = _load_docker_data()


@dataclass(frozen=True, slots=True)
class DockerAttackAttempt:
    technique: str

    category: str

    description: str

    vulnerable: bool

    details: str

    error: str

    endpoint: str

    registry_url: str

    repositories: list[str]

    response_code: int

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class DockerAttackResult:
    target: str

    host: str

    port: int

    tls: bool

    endpoint: str

    registry_detected: bool

    repositories: list[str]

    attempts: list[DockerAttackAttempt]

    vulnerable_techniques: list[str]

    issues: list[str]

    overall_status: str


_CATEGORY_MAP: dict[str, list[str]] = {
    "docker": ["registry_exposed"],
}


def _parse_url(target: str) -> tuple[str, str, int, bool]:

    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    host = parsed.hostname or ""

    path = parsed.path or ""

    tls = parsed.scheme in ("https", "grpcs")

    default_port = 443 if tls else 80

    port = parsed.port or default_port

    return host, path, port, tls


def _make_attempt(
    tech: str,
    cat: str,
    desc: str,
    vuln: bool,
    details: str,
    error: str,
    endpoint: str,
    registry_url: str,
    repos: list[str] | None,
    code: int,
) -> DockerAttackAttempt:

    return DockerAttackAttempt(
        technique=tech,
        category=cat,
        description=desc,
        vulnerable=vuln,
        details=details,
        error=error,
        exploit="curl <TARGET>:5000/v2/_catalog" if vuln else "",
        tool="curl",
        endpoint=endpoint,
        registry_url=registry_url,
        repositories=repos or [],
        response_code=code,
    )


async def _test_registry_exposed(
    url: str,
    timeout: float,
    client: httpx.AsyncClient,
) -> DockerAttackAttempt:

    repos_found: list[str] = []

    last_code = 0

    registry_detected = False

    for path_info in _REGISTRY_V2_PATHS:
        for auth_headers in _REGISTRY_AUTH_HEADERS:
            try:
                full_url = url.rstrip("/") + path_info["path"]

                resp = await client.get(full_url, headers=auth_headers)

                last_code = resp.status_code

                if resp.status_code == 200:
                    registry_detected = True

                    if path_info["path"] == "/v2/" or path_info["path"].startswith(
                        "/v2/_catalog"
                    ):
                        try:
                            data = resp.json()

                            if "repositories" in data:
                                repos_found.extend(data["repositories"])

                        except json.JSONDecodeError, ValueError:
                            pass

                elif resp.status_code == 401:
                    www_auth = resp.headers.get("www-authenticate", "")

                    if "bearer" in www_auth.lower() or "basic" in www_auth.lower():
                        registry_detected = True

            except Exception:
                pass

    if not repos_found and registry_detected:
        for repo_name in _COMMON_REPO_NAMES:
            for auth_headers in _REGISTRY_AUTH_HEADERS:
                try:
                    tag_url = f"{url.rstrip('/')}/v2/{repo_name}/tags/list"

                    resp = await client.get(tag_url, headers=auth_headers)

                    if resp.status_code == 200:
                        try:
                            data = resp.json()

                            if "tags" in data:
                                repos_found.append(repo_name)

                        except json.JSONDecodeError, ValueError:
                            pass

                except Exception:
                    pass

    unique_repos = list(set(repos_found))

    vuln = registry_detected and len(unique_repos) > 0

    details = f"Registry: {'accessible' if registry_detected else 'not found'}"

    if unique_repos:
        details += f", {len(unique_repos)} repos ({', '.join(unique_repos[:5])})"

    return _make_attempt(
        "registry_exposed",
        "docker",
        "Docker Registry exposure",
        vuln,
        details,
        "",
        url,
        url,
        unique_repos,
        last_code,
    )


async def _test_docker(
    host: str,
    port: int,
    path: str,
    timeout: float,
    tls: bool,
    endpoint: str,
) -> list[DockerAttackAttempt]:

    results: list[DockerAttackAttempt] = []

    async with httpx.AsyncClient(
        timeout=timeout, verify=False, follow_redirects=True
    ) as client:
        for tech, fn in [
            ("registry_exposed", _test_registry_exposed),
        ]:
            try:
                result = await fn(endpoint, timeout, client)

                results.append(result)

            except Exception as exc:
                results.append(
                    _make_attempt(
                        tech,
                        "docker",
                        "",
                        False,
                        "",
                        str(exc)[:100],
                        endpoint,
                        endpoint,
                        [],
                        0,
                    )
                )

    return results


_CATEGORY_DISPATCH: dict[
    str, Callable[..., Coroutine[Any, Any, list[DockerAttackAttempt]]]
] = {
    "docker": _test_docker,
}


def print_results(result: DockerAttackResult) -> None:

    print()

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Docker Attack Testing")

    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")

    print(
        color("[*]", Cyber.CYAN),
        f"Host: {result.host}:{result.port} (TLS: {result.tls})",
    )

    print(color("[*]", Cyber.CYAN), f"Endpoint: {result.endpoint}")

    print(
        color("[*]", Cyber.CYAN),
        f"Registry detected: {'yes' if result.registry_detected else 'no'}",
    )

    if result.repositories:
        print(
            color("[*]", Cyber.CYAN),
            f"Repositories: {', '.join(result.repositories[:5])}",
        )

    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")

        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)

        print()

    categories: dict[str, list[DockerAttackAttempt]] = {}

    for attempt in result.attempts:
        categories.setdefault(attempt.category, []).append(attempt)

    for cat, attempts in categories.items():
        vuln_in_cat = [a for a in attempts if a.vulnerable]

        if vuln_in_cat:
            print(
                color("[!]", Cyber.RED, Cyber.BOLD),
                f"{cat}: {len(vuln_in_cat)} vulnerable(s)",
            )

            for a in vuln_in_cat:
                print(color("    [-]", Cyber.RED), f"{a.technique}: {a.details}")

                print_exploit_info(a.exploit, a.tool)

        else:
            print(color("[+]", Cyber.GREEN), f"{cat}: secure")

    print()

    if result.overall_status == "vulnerable":
        print(
            color("[!]", Cyber.RED, Cyber.BOLD),
            "VULNERABLE — Docker Registry weaknesses detected!",
        )

    else:
        print(
            color("[+]", Cyber.GREEN, Cyber.BOLD),
            "SECURE — Docker Registry configuration looks good",
        )

    print()


async def run_scan(
    target: str,
    categories: list[str] | None,
    timeout: float,
    output_file: str | None,
) -> DockerAttackResult:

    host, path, port, tls = _parse_url(target)

    scheme = "https" if tls else "http"

    endpoint = (
        f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
    )

    if path:
        endpoint = endpoint.rstrip("/") + path

    registry_detected = False

    all_repos: list[str] = []

    all_attempts: list[DockerAttackAttempt] = []

    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    for cat in cats:
        tester = _CATEGORY_DISPATCH.get(cat)

        if tester is None:
            continue

        try:
            raw = await tester(host, port, path, timeout, tls, endpoint)

            all_attempts.extend(raw)

            for a in raw:
                if a.vulnerable:
                    registry_detected = True

                all_repos.extend(a.repositories)

        except Exception as e:
            all_attempts.append(
                _make_attempt(
                    f"{cat}_error",
                    cat,
                    "",
                    False,
                    "",
                    str(e)[:100],
                    endpoint,
                    endpoint,
                    [],
                    0,
                )
            )

    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]

    issue_techs = [a.technique for a in all_attempts if a.error and not a.vulnerable]

    issues = [f"Errors: {', '.join(issue_techs)}"] if issue_techs else []

    overall = "vulnerable" if vuln_techs else "secure"

    result = DockerAttackResult(
        target=target,
        host=host,
        port=port,
        tls=tls,
        endpoint=endpoint,
        registry_detected=registry_detected,
        repositories=list(set(all_repos)),
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        issues=issues,
        overall_status=overall,
    )

    print_results(result)

    if output_file:
        write_output(output_file, [asdict(a) for a in all_attempts])

    return result


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="mytools-docker",
        description="Docker Attack Testing — Docker Registry security probing",
    )

    parser.add_argument("url", help="URL alvo (https://registry.target.com)")

    parser.add_argument(
        "-c",
        "--categories",
        nargs="+",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categorias para testar",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:

    result = safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=getattr(args, "categories", None),
            timeout=getattr(args, "timeout", 5.0),
            output_file=getattr(args, "output", None),
        )
    )

    return 1 if result.overall_status == "vulnerable" else 0


def main() -> int:

    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(_BANNER_LINES, "Docker Attack Testing"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="docker> ",
        description="Docker Attack Testing — Docker Registry security probing",
        example="mytools-docker https://registry.target.com",
        contextual_help="docker: registry_exposed",
    )


if __name__ == "__main__":
    raise SystemExit(main())
