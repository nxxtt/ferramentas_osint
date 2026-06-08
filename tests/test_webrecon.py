from __future__ import annotations

import argparse

import responses

from utils import Cyber, create_session
from webrecon import (
    ReconResult,
    build_parser,
    candidate_urls,
    normalize_url,
    probe_status,
    status_text,
)


class TestNormalizeUrl:
    def test_valid_https(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_valid_http(self):
        assert normalize_url("http://example.com") == "http://example.com"

    def test_no_scheme_raises(self):
        try:
            normalize_url("example.com")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_ftp_scheme_raises(self):
        try:
            normalize_url("ftp://example.com")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_no_netloc_raises(self):
        try:
            normalize_url("http://")
            assert False, "Should have raised"
        except ValueError:
            pass


class TestCandidateUrls:
    def test_with_scheme_returns_single(self):
        result = candidate_urls("https://example.com")
        assert len(result) == 1
        assert result[0] == "https://example.com"

    def test_without_scheme_returns_two(self):
        result = candidate_urls("example.com")
        assert len(result) == 2
        assert result[0].startswith("https://")
        assert result[1].startswith("http://")

    def test_empty_raises(self):
        try:
            candidate_urls("")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_strips_whitespace(self):
        result = candidate_urls("  example.com  ")
        assert len(result) == 2

    def test_with_port_no_scheme(self):
        try:
            candidate_urls("example.com:8080")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_with_path_no_scheme(self):
        result = candidate_urls("example.com/app")
        assert len(result) == 2
        assert "/app" in result[0]


class TestStatusText:
    def test_none_returns_no_response(self):
        result = status_text(None)
        assert "sem resposta" in result

    def test_200_contains_status(self):
        result = status_text(200)
        assert "200" in result

    def test_404_contains_status(self):
        result = status_text(404)
        assert "404" in result

    def test_returns_string(self):
        assert isinstance(status_text(200), str)


class TestProbeStatus:
    @responses.activate
    def test_returns_status_on_success(self):
        responses.add(responses.GET, "http://example.com/robots.txt", body=b"User-agent: *", status=200)
        session = create_session(user_agent="TestAgent/1.0")
        result = probe_status(session, "http://example.com/robots.txt", 5.0)
        assert result == 200

    @responses.activate
    def test_returns_none_on_error(self):
        import requests as _requests
        responses.add(responses.GET, "http://example.com/robots.txt", body=_requests.exceptions.ConnectionError("refused"))
        session = create_session(user_agent="TestAgent/1.0")
        result = probe_status(session, "http://example.com/robots.txt", 5.0)
        assert result is None


class TestReconResultDataclass:
    def test_creation(self):
        r = ReconResult(
            url="https://example.com", status=200, final_url="https://example.com",
            title="Test", server="nginx", powered_by="", content_type="text/html",
            content_length=100, redirect="", security_headers_present=["x-frame-options"],
            security_headers_missing=["content-security-policy"], robots_status=200,
            sitemap_status=404, elapsed=1.0,
        )
        assert r.status == 200
        assert len(r.security_headers_present) == 1

    def test_frozen(self):
        r = ReconResult(
            url="https://example.com", status=200, final_url="https://example.com",
            title="", server="", powered_by="", content_type="text/html",
            content_length=0, redirect="", security_headers_present=[],
            security_headers_missing=[], robots_status=None, sitemap_status=None,
            elapsed=0.0,
        )
        try:
            r.status = 404
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestBuildParser:
    def test_returns_argparse(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_url_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_default_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.timeout == 5.0

    def test_has_output_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-o", "out.json"])
        assert args.output == "out.json"

    def test_has_proxy_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--proxy", "http://proxy:8080"])
        assert args.proxy == "http://proxy:8080"
