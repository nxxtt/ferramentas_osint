from __future__ import annotations

import argparse
import re

import httpx
import pytest
import respx

from attackaudit import (
    CSRF_FIELD_NAMES_LOWER,
    METHODS_TO_TEST,
    SQL_ERROR_PATTERNS,
    SQLI_PAYLOADS,
    AuditResult,
    Finding,
    MethodResult,
    PageParser,
    Probe,
    RISK_WEIGHTS,
    SECURITY_HEADERS_RECS,
    TLSVersionResult,
    build_findings,
    build_parser,
    check_sqli_errors,
    check_tls_versions,
    check_xss_reflection,
    normalize_url,
    risk_score,
    severity_color,
)
from utils import Cyber


class TestNormalizeUrl:
    def test_with_scheme(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_without_scheme_adds_https(self):
        result = normalize_url("example.com")
        assert result == "https://example.com"

    def test_strips_trailing_slash(self):
        assert normalize_url("https://example.com/") == "https://example.com"

    def test_strips_whitespace(self):
        assert normalize_url("  https://example.com  ") == "https://example.com"

    def test_empty_raises(self):
        try:
            normalize_url("")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_invalid_scheme_raises(self):
        try:
            normalize_url("ftp://example.com")
            assert False, "Should have raised"
        except ValueError:
            pass


class TestRiskScore:
    def test_empty_findings(self):
        assert risk_score([]) == 0

    def test_single_critical(self):
        findings = [Finding("critical", "cat", "item", "evidence", "rec")]
        assert risk_score(findings) == RISK_WEIGHTS["critical"]

    def test_mixed_severities(self):
        findings = [
            Finding("critical", "cat", "item", "evidence", "rec"),
            Finding("low", "cat", "item", "evidence", "rec"),
            Finding("info", "cat", "item", "evidence", "rec"),
        ]
        expected = RISK_WEIGHTS["critical"] + RISK_WEIGHTS["low"] + RISK_WEIGHTS["info"]
        assert risk_score(findings) == expected


class TestSeverityColor:
    def test_critical_is_red(self):
        assert severity_color("critical") == Cyber.RED

    def test_high_is_red(self):
        assert severity_color("high") == Cyber.RED

    def test_medium_is_yellow(self):
        assert severity_color("medium") == Cyber.YELLOW

    def test_low_is_blue(self):
        assert severity_color("low") == Cyber.BLUE

    def test_info_is_gray(self):
        assert severity_color("info") == Cyber.GRAY

    def test_unknown_is_white(self):
        assert severity_color("unknown") == Cyber.WHITE

    def test_all_severities_return_strings(self):
        for sev in ("critical", "high", "medium", "low", "info", "unknown"):
            result = severity_color(sev)
            assert isinstance(result, str)
            assert len(result) > 0


class TestPageParser:
    def test_title(self):
        parser = PageParser()
        parser.feed("<html><title>My Title</title></html>")
        assert parser.title == "My Title"

    def test_forms_count(self):
        parser = PageParser()
        parser.feed("<form><input type='text'></form><form></form>")
        assert parser.forms == 2

    def test_password_inputs(self):
        parser = PageParser()
        parser.feed("<input type='password'><input type='text'><input type='password'>")
        assert parser.password_inputs == 2

    def test_external_scripts(self):
        parser = PageParser()
        parser.feed("<script src='app.js'></script><script src='lib.js'></script>")
        assert len(parser.external_scripts) == 2

    def test_comments(self):
        parser = PageParser()
        parser.feed("<!-- TODO: fix this -->")
        assert len(parser.comments) == 1
        assert "TODO" in parser.comments[0]

    def test_no_title(self):
        parser = PageParser()
        parser.feed("<html><body>no title</body></html>")
        assert parser.title == ""


class TestPageParserCSRF:
    def test_form_with_csrf_token(self):
        parser = PageParser()
        parser.feed('<form method="POST"><input type="hidden" name="csrf_token" value="abc123"><input type="text" name="user"></form>')
        assert parser.forms == 1
        assert parser.forms_missing_csrf == 0

    def test_form_without_csrf_token(self):
        parser = PageParser()
        parser.feed('<form method="POST"><input type="text" name="user"></form>')
        assert parser.forms == 1
        assert parser.forms_missing_csrf == 1

    def test_multiple_forms_mixed(self):
        parser = PageParser()
        parser.feed('<form method="POST"><input type="hidden" name="_token" value="x"></form>')
        parser.feed('<form method="POST"><input type="text" name="data"></form>')
        assert parser.forms == 2
        assert parser.forms_missing_csrf == 1

    def test_csrf_field_names_detected(self):
        for field_name in ["csrf_token", "_csrf", "_token", "authenticity_token", "csrfmiddlewaretoken"]:
            parser = PageParser()
            parser.feed(f'<form><input type="hidden" name="{field_name}" value="x"></form>')
            assert parser.forms_missing_csrf == 0, f"Failed for {field_name}"


class TestProbeDataclass:
    def test_creation(self):
        p = Probe(url="http://x.com/.env", status=200, size=50, location="")
        assert p.status == 200

    def test_frozen(self):
        p = Probe(url="http://x.com/.env", status=200, size=50, location="")
        try:
            p.status = 404
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestFindingDataclass:
    def test_creation(self):
        f = Finding("high", "transport", "item", "evidence", "rec")
        assert f.severity == "high"

    def test_frozen(self):
        f = Finding("high", "transport", "item", "evidence", "rec")
        try:
            f.severity = "low"
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestTLSVersionResult:
    def test_creation(self):
        r = TLSVersionResult(protocol="TLS 1.2", supported=True)
        assert r.protocol == "TLS 1.2"
        assert r.supported is True
        assert r.reason == ""

    def test_unsupported(self):
        r = TLSVersionResult(protocol="SSLv3", supported=False, reason="disabled")
        assert r.supported is False
        assert r.reason == "disabled"

    def test_frozen(self):
        r = TLSVersionResult(protocol="TLS 1.3", supported=True)
        try:
            r.supported = False
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestAuditResultDataclass:
    def test_creation(self):
        r = AuditResult(
            target="https://example.com", final_url="https://example.com", status=200,
            title="", ip="1.2.3.4", tls_subject="example.com", tls_issuer="Let's Encrypt",
            tls_not_after="Dec 31", allowed_methods=["GET"], forms=0, password_inputs=0,
            probes=[], findings=[], risk_score=0, elapsed=1.0,
        )
        assert r.status == 200
        assert r.risk_score == 0

    def test_optional_tls_versions(self):
        r = AuditResult(
            target="https://example.com", final_url="https://example.com", status=200,
            title="", ip="", tls_subject="", tls_issuer="",
            tls_not_after="", allowed_methods=[], forms=0, password_inputs=0,
            probes=[], findings=[], risk_score=0, elapsed=1.0,
        )
        assert r.tls_versions == []
        assert r.xss_reflected is False
        assert r.sqli_errors == []
        assert r.csrf_missing == 0


class TestBuildFindings:
    def test_http_finds_high(self):
        parser = PageParser()
        findings = build_findings("http://example.com", 200, {}, parser, [], [], "")
        severities = [f.severity for f in findings]
        assert "high" in severities

    def test_missing_security_headers(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com")
        headers_findings = [f for f in findings if f.category == "headers"]
        assert len(headers_findings) == len(SECURITY_HEADERS_RECS)

    def test_cors_wildcard(self):
        parser = PageParser()
        headers = {"access-control-allow-origin": "*"}
        findings = build_findings("https://example.com", 200, headers, parser, [], [], "example.com")
        cors_findings = [f for f in findings if f.category == "cors"]
        assert len(cors_findings) == 1

    def test_dangerous_methods(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 200, {}, parser, ["GET", "PUT", "DELETE"], [], "example.com")
        methods_findings = [f for f in findings if f.category == "methods"]
        assert len(methods_findings) == 1

    def test_password_on_http_critical(self):
        parser = PageParser()
        parser.feed("<input type='password'>")
        findings = build_findings("http://example.com", 200, {}, parser, [], [], "")
        auth_findings = [f for f in findings if f.category == "auth"]
        assert len(auth_findings) == 1
        assert auth_findings[0].severity == "critical"

    def test_5xx_error(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 500, {}, parser, [], [], "example.com")
        stability = [f for f in findings if f.category == "stability"]
        assert len(stability) == 1

    def test_sensitive_probe_200_high(self):
        parser = PageParser()
        probes = [Probe(url="https://example.com/.env", status=200, size=50, location="")]
        findings = build_findings("https://example.com", 200, {}, parser, [], probes, "example.com")
        exposure = [f for f in findings if f.category == "exposure"]
        assert len(exposure) == 1
        assert exposure[0].severity == "high"

    def test_sensitive_probe_403_medium(self):
        parser = PageParser()
        probes = [Probe(url="https://example.com/.git/HEAD", status=403, size=50, location="")]
        findings = build_findings("https://example.com", 200, {}, parser, [], probes, "example.com")
        exposure = [f for f in findings if f.category == "exposure"]
        assert len(exposure) == 1
        assert exposure[0].severity == "medium"

    def test_server_exposed(self):
        parser = PageParser()
        headers = {"server": "nginx/1.20"}
        findings = build_findings("https://example.com", 200, headers, parser, [], [], "example.com")
        fp = [f for f in findings if f.category == "fingerprint"]
        assert any("Server" in f.item for f in fp)

    def test_cookie_missing_flags(self):
        parser = PageParser()
        headers = {"Set-Cookie": "session=abc123"}
        raw_headers = {"set-cookie": ["session=abc123"]}
        findings = build_findings("https://example.com", 200, headers, parser, [], [], "example.com", raw_headers=raw_headers)
        cookie_findings = [f for f in findings if f.category == "cookies"]
        assert len(cookie_findings) == 1
        assert "httponly" in cookie_findings[0].evidence.lower()

    def test_cookie_all_flags_present(self):
        parser = PageParser()
        headers = {"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"}
        raw_headers = {"set-cookie": ["session=abc123; Secure; HttpOnly; SameSite=Strict"]}
        findings = build_findings("https://example.com", 200, headers, parser, [], [], "example.com", raw_headers=raw_headers)
        cookie_findings = [f for f in findings if f.category == "cookies"]
        assert len(cookie_findings) == 0

    def test_cookie_multiple_set_cookie(self):
        parser = PageParser()
        headers = {"Set-Cookie": "session=abc123"}
        raw_headers = {"set-cookie": ["session=abc123", "analytics=xyz"]}
        findings = build_findings("https://example.com", 200, headers, parser, [], [], "example.com", raw_headers=raw_headers)
        cookie_findings = [f for f in findings if f.category == "cookies"]
        assert len(cookie_findings) == 2

    def test_no_tls_subject(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "")
        transport = [f for f in findings if f.category == "transport"]
        assert any("TLS nao validado" in f.item for f in transport)

    def test_html_comments(self):
        parser = PageParser()
        parser.feed("<!-- secret config -->")
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com")
        content = [f for f in findings if f.category == "content"]
        assert len(content) == 1
        assert "comentario" in content[0].item.lower()


class TestBuildFindingsPhase7:
    def test_weak_tls_version(self):
        parser = PageParser()
        tls_versions = [
            TLSVersionResult(protocol="TLS 1.2", supported=True),
            TLSVersionResult(protocol="TLS 1.1", supported=True),
        ]
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com", tls_versions=tls_versions)
        transport = [f for f in findings if f.category == "transport"]
        assert any("TLS 1.1" in f.item for f in transport)

    def test_all_strong_tls(self):
        parser = PageParser()
        tls_versions = [
            TLSVersionResult(protocol="TLS 1.2", supported=True),
            TLSVersionResult(protocol="TLS 1.3", supported=True),
        ]
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com", tls_versions=tls_versions)
        transport = [f for f in findings if f.category == "transport" and "obsoleta" in f.item]
        assert len(transport) == 0

    def test_xss_reflected_finding(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com",
                                  xss_reflected=True, xss_evidence="refletido em html_body")
        xss = [f for f in findings if f.category == "xss"]
        assert len(xss) == 1
        assert xss[0].severity == "high"

    def test_no_xss_no_finding(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com",
                                  xss_reflected=False)
        xss = [f for f in findings if f.category == "xss"]
        assert len(xss) == 0

    def test_sqli_error_finding(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com",
                                  sqli_databases=["mysql"])
        sqli = [f for f in findings if f.category == "sqli"]
        assert len(sqli) == 1
        assert sqli[0].severity == "critical"
        assert "mysql" in sqli[0].evidence

    def test_sqli_multiple_databases(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com",
                                  sqli_databases=["mysql", "postgresql"])
        sqli = [f for f in findings if f.category == "sqli"]
        assert len(sqli) == 1
        assert "mysql" in sqli[0].evidence
        assert "postgresql" in sqli[0].evidence

    def test_csrf_missing_finding(self):
        parser = PageParser()
        parser.feed('<form method="POST"><input type="text" name="data"></form>')
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com")
        csrf = [f for f in findings if f.category == "csrf"]
        assert len(csrf) == 1
        assert "1" in csrf[0].evidence


class TestSQLiPatterns:
    def test_mysql_patterns_exist(self):
        assert "mysql" in SQL_ERROR_PATTERNS
        assert len(SQL_ERROR_PATTERNS["mysql"]) > 0

    def test_postgresql_patterns_exist(self):
        assert "postgresql" in SQL_ERROR_PATTERNS

    def test_mssql_patterns_exist(self):
        assert "mssql" in SQL_ERROR_PATTERNS

    def test_oracle_patterns_exist(self):
        assert "oracle" in SQL_ERROR_PATTERNS

    def test_sqlite_patterns_exist(self):
        assert "sqlite" in SQL_ERROR_PATTERNS

    def test_patterns_are_regex(self):
        for db, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                assert isinstance(pattern, re.Pattern)


class TestSQLIPayloads:
    def test_not_empty(self):
        assert len(SQLI_PAYLOADS) > 0

    def test_contains_single_quote(self):
        assert "'" in SQLI_PAYLOADS


class TestCSIFFieldNames:
    def test_not_empty(self):
        assert len(CSRF_FIELD_NAMES_LOWER) > 0

    def test_contains_common_names(self):
        for name in ["csrf_token", "_csrf", "_token", "authenticity_token", "csrfmiddlewaretoken"]:
            assert name in CSRF_FIELD_NAMES_LOWER


class TestCheckTLSVersions:
    @pytest.mark.asyncio
    async def test_http_url_returns_empty(self):
        result = await check_tls_versions("http://example.com", 5.0)
        assert result == []

    @pytest.mark.asyncio
    async def test_https_returns_list(self):
        result = await check_tls_versions("https://example.com", 2.0)
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, TLSVersionResult)


class TestCheckXSSReflection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_marker_reflected(self, async_client):
        def handler(request):
            url = str(request.url)
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            marker = params.get("q", [""])[0]
            return httpx.Response(200, text=f"<html><body>Search results for: {marker}</body></html>")

        respx.route(url__regex=r"https://example\.com/search.*").mock(side_effect=handler)
        client = async_client
        reflected, evidence = await check_xss_reflection(client, "https://example.com/search", 5.0)
        assert reflected is True
        assert "refletido" in evidence

    @respx.mock
    @pytest.mark.asyncio
    async def test_marker_not_reflected(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(return_value=httpx.Response(200, text="<html><body>Hello World</body></html>"))
        client = async_client
        reflected, evidence = await check_xss_reflection(client, "https://example.com/search", 5.0)
        assert reflected is False


class TestCheckSQLiErrors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_mysql_error_detected(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(return_value=httpx.Response(200, text="You have an error in your SQL syntax near ''"))
        client = async_client
        result = await check_sqli_errors(client, "https://example.com/page?id=1", 5.0)
        assert "mysql" in result

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_error_detected(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(return_value=httpx.Response(200, text="<html>Normal page</html>"))
        client = async_client
        result = await check_sqli_errors(client, "https://example.com/page?id=1", 5.0)
        assert result == []


class TestBuildParser:
    def test_returns_argparse(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_url_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_deep_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--deep"])
        assert args.deep is True

    def test_has_test_vulns_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--test-vulns"])
        assert args.test_vulns is True

    def test_default_test_vulns_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.test_vulns is False

    def test_default_threads(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.threads == 20

    def test_has_proxy_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--proxy", "http://proxy:8080"])
        assert args.proxy == "http://proxy:8080"

    def test_has_delay_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--delay", "5"])
        assert args.delay == 5.0

    def test_has_verbose_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-v"])
        assert args.verbose is True

    def test_default_verbose_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.verbose is False

    def test_has_log_file_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--log-file", "audit.log"])
        assert args.log_file == "audit.log"


class TestSecurityHeadersConstant:
    def test_has_all_expected(self):
        expected = {"strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy"}
        assert set(SECURITY_HEADERS_RECS.keys()) == expected

    def test_values_are_strings(self):
        for header, rec in SECURITY_HEADERS_RECS.items():
            assert isinstance(rec, str)
            assert len(rec) > 0


class TestRiskWeightsConstant:
    def test_has_all_severities(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in RISK_WEIGHTS

    def test_ordering(self):
        assert RISK_WEIGHTS["critical"] > RISK_WEIGHTS["high"] > RISK_WEIGHTS["medium"] > RISK_WEIGHTS["low"] > RISK_WEIGHTS["info"]


class TestBuildParserV3:
    def test_has_list_argument(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "targets.txt"])
        assert args.target_list == "targets.txt"

    def test_has_output_dir_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--output-dir", "results/"])
        assert args.output_dir == "results/"

    def test_has_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-q"])
        assert args.quiet is True

    def test_default_quiet_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.quiet is False

    def test_has_auth_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--auth", "admin:secret"])
        assert args.auth is not None
        assert "Authorization" in args.auth

    def test_has_bearer_token_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--bearer-token", "tok123"])
        assert args.bearer_token == "tok123"

    def test_has_cookie_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--cookie", "session=abc"])
        assert args.cookie == "session=abc"

    def test_has_header_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--header", "X-Token: abc"])
        assert args.header == ["X-Token: abc"]

    def test_has_test_methods_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--test-methods"])
        assert args.test_methods is True

    def test_default_test_methods_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.test_methods is False


class TestMethodResultDataclass:
    def test_creation(self):
        r = MethodResult(url="https://example.com/api", method="PUT", status=200, size=150)
        assert r.method == "PUT"
        assert r.status == 200

    def test_frozen(self):
        r = MethodResult(url="https://example.com/api", method="DELETE", status=204, size=0)
        try:
            r.status = 404
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestMethodsToTest:
    def test_contains_dangerous_methods(self):
        assert "PUT" in METHODS_TO_TEST
        assert "DELETE" in METHODS_TO_TEST
        assert "TRACE" in METHODS_TO_TEST

    def test_contains_standard_methods(self):
        assert "OPTIONS" in METHODS_TO_TEST
        assert "HEAD" in METHODS_TO_TEST
        assert "PATCH" in METHODS_TO_TEST

    def test_all_strings(self):
        assert all(isinstance(m, str) for m in METHODS_TO_TEST)


class TestBuildFindingsMethodResults:
    def test_put_200_high_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/upload", "PUT", 200, 500)]
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com", method_results=mr)
        method_findings = [f for f in findings if f.category == "methods" and "PUT" in f.item]
        assert len(method_findings) == 1
        assert method_findings[0].severity == "high"

    def test_delete_200_high_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/api", "DELETE", 200, 0)]
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com", method_results=mr)
        method_findings = [f for f in findings if f.category == "methods" and "DELETE" in f.item]
        assert len(method_findings) == 1
        assert method_findings[0].severity == "high"

    def test_trace_200_high_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/", "TRACE", 200, 100)]
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com", method_results=mr)
        method_findings = [f for f in findings if f.category == "methods" and "TRACE" in f.item]
        assert len(method_findings) == 1

    def test_patch_200_medium_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/api", "PATCH", 200, 200)]
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com", method_results=mr)
        method_findings = [f for f in findings if f.category == "methods" and "PATCH" in f.item]
        assert len(method_findings) == 1
        assert method_findings[0].severity == "medium"

    def test_no_method_results_no_findings(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com")
        method_findings = [f for f in findings if f.category == "methods" and "aceito" in f.item]
        assert len(method_findings) == 0

    def test_method_403_no_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/admin", "PUT", 403, 0)]
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com", method_results=mr)
        method_findings = [f for f in findings if f.category == "methods" and "PUT" in f.item]
        assert len(method_findings) == 0

    def test_multiple_method_results(self):
        parser = PageParser()
        mr = [
            MethodResult("https://example.com/api", "PUT", 200, 500),
            MethodResult("https://example.com/api", "DELETE", 200, 0),
            MethodResult("https://example.com/api", "TRACE", 200, 100),
        ]
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "example.com", method_results=mr)
        method_findings = [f for f in findings if f.category == "methods"]
        assert len(method_findings) == 3


class TestAuditResultMethodResults:
    def test_default_none(self):
        r = AuditResult(
            target="https://example.com", final_url="https://example.com", status=200,
            title="", ip="", tls_subject="", tls_issuer="",
            tls_not_after="", allowed_methods=[], forms=0, password_inputs=0,
            probes=[], findings=[], risk_score=0, elapsed=1.0,
        )
        assert r.method_results == []

    def test_with_method_results(self):
        mr = [MethodResult("https://example.com/api", "PUT", 200, 500)]
        r = AuditResult(
            target="https://example.com", final_url="https://example.com", status=200,
            title="", ip="", tls_subject="", tls_issuer="",
            tls_not_after="", allowed_methods=[], forms=0, password_inputs=0,
            probes=[], findings=[], risk_score=0, elapsed=1.0,
            method_results=mr,
        )
        assert r.method_results is not None
        assert len(r.method_results) == 1
