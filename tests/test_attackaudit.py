from __future__ import annotations

import argparse

import responses

from attackaudit import (
    AuditResult,
    Finding,
    PageParser,
    Probe,
    RISK_WEIGHTS,
    SECURITY_HEADERS,
    build_findings,
    build_parser,
    normalize_url,
    risk_score,
    severity_color,
)
from utils import Cyber, create_session


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
        assert len(headers_findings) == len(SECURITY_HEADERS)

    def test_cors_wildcard(self):
        parser = PageParser()
        headers = {"Access-Control-Allow-Origin": "*"}
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
        headers = {"Server": "nginx/1.20"}
        findings = build_findings("https://example.com", 200, headers, parser, [], [], "example.com")
        fp = [f for f in findings if f.category == "fingerprint"]
        assert any("Server" in f.item for f in fp)

    def test_cookie_missing_flags(self):
        parser = PageParser()
        headers = {"Set-Cookie": "session=abc123"}
        findings = build_findings("https://example.com", 200, headers, parser, [], [], "example.com")
        cookie_findings = [f for f in findings if f.category == "cookies"]
        assert len(cookie_findings) == 1
        assert "httponly" in cookie_findings[0].evidence.lower()

    def test_cookie_all_flags_present(self):
        parser = PageParser()
        headers = {"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"}
        findings = build_findings("https://example.com", 200, headers, parser, [], [], "example.com")
        cookie_findings = [f for f in findings if f.category == "cookies"]
        assert len(cookie_findings) == 0

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


class TestSecurityHeadersConstant:
    def test_has_all_expected(self):
        expected = {"strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy"}
        assert set(SECURITY_HEADERS.keys()) == expected

    def test_values_are_strings(self):
        for header, rec in SECURITY_HEADERS.items():
            assert isinstance(rec, str)
            assert len(rec) > 0


class TestRiskWeightsConstant:
    def test_has_all_severities(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in RISK_WEIGHTS

    def test_ordering(self):
        assert RISK_WEIGHTS["critical"] > RISK_WEIGHTS["high"] > RISK_WEIGHTS["medium"] > RISK_WEIGHTS["low"] > RISK_WEIGHTS["info"]


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
