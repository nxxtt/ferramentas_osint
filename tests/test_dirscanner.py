from __future__ import annotations

import argparse

import responses

from dirscanner import (
    DEFAULT_PATHS,
    DEFAULT_STATUSES,
    Finding,
    build_parser,
    load_paths,
    normalize_base_url,
    parse_extensions,
    parse_statuses,
    scan_path,
)
from utils import RateLimiter, create_session


class TestNormalizeBaseUrl:
    def test_adds_http_scheme(self):
        assert normalize_base_url("example.com") == "http://example.com/"

    def test_keeps_https(self):
        assert normalize_base_url("https://example.com") == "https://example.com/"

    def test_strips_trailing_slash_then_adds(self):
        assert normalize_base_url("https://example.com/") == "https://example.com/"

    def test_preserves_path(self):
        assert normalize_base_url("https://example.com/app") == "https://example.com/app/"

    def test_invalid_scheme_raises(self):
        try:
            normalize_base_url("ftp://example.com")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_empty_netloc_raises(self):
        try:
            normalize_base_url("http://")
            assert False, "Should have raised"
        except ValueError:
            pass


class TestParseStatuses:
    def test_default(self):
        assert parse_statuses("default") == DEFAULT_STATUSES

    def test_all(self):
        result = parse_statuses("all")
        assert result == set(range(100, 600))

    def test_single(self):
        assert parse_statuses("200") == {200}

    def test_comma_separated(self):
        assert parse_statuses("200,403") == {200, 403}

    def test_range(self):
        assert parse_statuses("200-202") == {200, 201, 202}

    def test_reversed_range(self):
        assert parse_statuses("202-200") == {200, 201, 202}

    def test_invalid_status_raises(self):
        try:
            parse_statuses("99")
            assert False, "Should have raised"
        except argparse.ArgumentTypeError:
            pass

    def test_non_numeric_raises(self):
        try:
            parse_statuses("abc")
            assert False, "Should have raised"
        except argparse.ArgumentTypeError as e:
            assert "abc" in str(e)

    def test_non_numeric_in_range_raises(self):
        try:
            parse_statuses("abc-200")
            assert False, "Should have raised"
        except argparse.ArgumentTypeError as e:
            assert "abc-200" in str(e)

    def test_trailing_comma(self):
        assert parse_statuses("200,403,") == {200, 403}

    def test_whitespace_parts(self):
        assert parse_statuses(" 200 , 403 ") == {200, 403}

    def test_overlapping_ranges(self):
        result = parse_statuses("200-202,201-203")
        assert result == {200, 201, 202, 203}


class TestParseExtensions:
    def test_simple(self):
        assert parse_extensions("php,txt") == ["php", "txt"]

    def test_with_dots(self):
        assert parse_extensions(".php,.bak") == ["php", "bak"]

    def test_empty(self):
        assert parse_extensions("") == []

    def test_whitespace(self):
        assert parse_extensions(" php , txt ") == ["php", "txt"]


class TestLoadPaths:
    def test_default_paths_no_extensions(self):
        paths = load_paths(None, [])
        assert len(paths) > 0
        assert "admin" in paths
        assert "robots.txt" in paths

    def test_default_paths_with_extensions(self):
        paths = load_paths(None, ["php", "txt"])
        assert "admin" in paths
        assert "admin.php" in paths
        assert "admin.txt" in paths

    def test_default_paths_deduplicates(self):
        paths = load_paths(None, [])
        assert len(paths) == len(set(paths))

    def test_custom_wordlist(self, tmp_path):
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("admin\nlogin\n# comment\n\ntest\n")
        paths = load_paths(str(wordlist), [])
        assert "admin" in paths
        assert "login" in paths
        assert "test" in paths
        assert "# comment" not in paths

    def test_extensions_not_applied_to_dotted_files(self):
        paths = load_paths(None, ["php"])
        assert ".env" in paths
        assert ".env.php" not in paths

    def test_sorted_output(self):
        paths = load_paths(None, [])
        assert paths == sorted(paths)

    def test_missing_wordlist_raises(self):
        try:
            load_paths("/nonexistent/wordlist.txt", [])
            assert False, "Should have raised"
        except ValueError as e:
            assert "nao encontrada" in str(e)


class TestDefaultPaths:
    def test_not_empty(self):
        assert len(DEFAULT_PATHS) > 0

    def test_has_common_paths(self):
        assert "admin" in DEFAULT_PATHS
        assert "robots.txt" in DEFAULT_PATHS
        assert ".env" in DEFAULT_PATHS


class TestDefaultStatuses:
    def test_has_200(self):
        assert 200 in DEFAULT_STATUSES

    def test_has_403(self):
        assert 403 in DEFAULT_STATUSES


class TestFindingDataclass:
    def test_creation(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=100, words=5, title="T")
        assert f.status == 200
        assert f.location == ""

    def test_frozen(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=100, words=5, title="T")
        try:
            f.status = 404
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestScanPath:
    @responses.activate
    def test_returns_finding_on_match(self):
        responses.add(responses.GET, "http://example.com/admin", body=b"<title>Admin</title>", status=200, headers={"Content-Type": "text/html"})
        session = create_session(user_agent="TestAgent/1.0")
        limiter = RateLimiter()
        result = scan_path(session, limiter, "http://example.com/", "admin", 5.0, {200})
        assert result is not None
        assert result.status == 200
        assert result.path == "/admin"

    @responses.activate
    def test_returns_none_on_status_mismatch(self):
        responses.add(responses.GET, "http://example.com/admin", body=b"not found", status=404)
        session = create_session(user_agent="TestAgent/1.0")
        limiter = RateLimiter()
        result = scan_path(session, limiter, "http://example.com/", "admin", 5.0, {200})
        assert result is None

    @responses.activate
    def test_returns_none_on_connection_error(self):
        import requests as _requests
        responses.add(responses.GET, "http://example.com/admin", body=_requests.exceptions.ConnectionError("refused"))
        session = create_session(user_agent="TestAgent/1.0")
        limiter = RateLimiter()
        result = scan_path(session, limiter, "http://example.com/", "admin", 5.0, {200})
        assert result is None


class TestBuildParser:
    def test_returns_argparse(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_url_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.url == "http://example.com"

    def test_has_extensions_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "-x", "php,txt"])
        assert args.extensions == ["php", "txt"]

    def test_default_threads(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.threads == 40

    def test_has_proxy_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--proxy", "http://proxy:8080"])
        assert args.proxy == "http://proxy:8080"

    def test_has_delay_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--delay", "10"])
        assert args.delay == 10.0
