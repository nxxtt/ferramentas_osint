from __future__ import annotations

import argparse
import asyncio

import httpx
import pytest
import respx

from dirscanner import (
    DEFAULT_PATHS,
    DEFAULT_STATUSES,
    Finding,
    _async_run_once,
    build_parser,
    load_paths,
    matches_filter,
    parse_extensions,
    parse_range,
    parse_statuses,
    scan_path,
)
from utils import RateLimiter, normalize_url, parse_auth, parse_extra_headers


class TestNormalizeBaseUrl:
    def test_adds_http_scheme(self):
        assert normalize_url("example.com", default_scheme="http", ensure_trailing_slash=True) == "http://example.com/"

    def test_keeps_https(self):
        assert normalize_url("https://example.com", default_scheme="http", ensure_trailing_slash=True) == "https://example.com/"

    def test_strips_trailing_slash_then_adds(self):
        assert normalize_url("https://example.com/", default_scheme="http", ensure_trailing_slash=True) == "https://example.com/"

    def test_preserves_path(self):
        assert normalize_url("https://example.com/app", default_scheme="http", ensure_trailing_slash=True) == "https://example.com/app/"

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError):
            normalize_url("ftp://example.com", default_scheme="http", ensure_trailing_slash=True)

    def test_empty_netloc_raises(self):
        with pytest.raises(ValueError):
            normalize_url("http://", default_scheme="http", ensure_trailing_slash=True)


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
        with pytest.raises(argparse.ArgumentTypeError):
            parse_statuses("99")

    def test_non_numeric_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="abc"):
            parse_statuses("abc")

    def test_non_numeric_in_range_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="abc-200"):
            parse_statuses("abc-200")

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


class TestParseRange:
    def test_valid_range(self):
        assert parse_range("100-5000") == (100, 5000)

    def test_reversed_range(self):
        assert parse_range("5000-100") == (100, 5000)

    def test_empty_returns_none(self):
        assert parse_range("") is None

    def test_none_returns_none(self):
        assert parse_range(None) is None

    def test_invalid_format_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_range("abc")

    def test_non_numeric_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_range("abc-200")


class TestParseAuth:
    def test_valid_auth(self):
        result = parse_auth("admin:secret")
        assert "Authorization" in result
        assert result["Authorization"].startswith("Basic ")

    def test_password_with_colon(self):
        result = parse_auth("user:pass:word")
        assert "Authorization" in result

    def test_no_colon_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_auth("nocolon")


class TestParseExtraHeaders:
    def test_single_header(self):
        result = parse_extra_headers(["X-Token: abc123"])
        assert result == {"X-Token": "abc123"}

    def test_multiple_headers(self):
        result = parse_extra_headers(["X-Token: abc", "X-Custom: xyz"])
        assert len(result) == 2
        assert result["X-Token"] == "abc"
        assert result["X-Custom"] == "xyz"

    def test_no_colon_raises(self):
        with pytest.raises(ValueError):
            parse_extra_headers(["InvalidHeader"])


class TestMatchesFilter:
    def test_no_filter_passes(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=100, words=10, title="")
        assert matches_filter(f, None, None) is True

    def test_size_within_range(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=500, words=10, title="")
        assert matches_filter(f, (100, 1000), None) is True

    def test_size_outside_range(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=50, words=10, title="")
        assert matches_filter(f, (100, 1000), None) is False

    def test_words_within_range(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=100, words=50, title="")
        assert matches_filter(f, None, (10, 100)) is True

    def test_words_outside_range(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=100, words=5, title="")
        assert matches_filter(f, None, (10, 100)) is False

    def test_both_filters(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=500, words=50, title="")
        assert matches_filter(f, (100, 1000), (10, 100)) is True
        assert matches_filter(f, (100, 1000), (60, 100)) is False


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
        with pytest.raises(ValueError, match="nao encontrada"):
            load_paths("/nonexistent/wordlist.txt", [])


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
        assert f.method == "GET"

    def test_frozen(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=100, words=5, title="T")
        with pytest.raises(AttributeError):
            f.status = 404

    def test_custom_method(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=100, words=5, title="T", method="POST")
        assert f.method == "POST"


class TestScanPath:
    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_finding_on_match(self, async_client):
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(200, content=b"<title>Admin</title>", headers={"Content-Type": "text/html"})
        )
        client = async_client
        limiter = RateLimiter()
        result = await scan_path(client, limiter, "http://example.com/", "admin", 5.0, {200})
        assert result is not None
        assert result.status == 200
        assert result.path == "/admin"

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_none_on_status_mismatch(self, async_client):
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(404, text="not found")
        )
        client = async_client
        limiter = RateLimiter()
        result = await scan_path(client, limiter, "http://example.com/", "admin", 5.0, {200})
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_none_on_connection_error(self, async_client):
        respx.get("http://example.com/admin").mock(side_effect=httpx.ConnectError("refused"))
        client = async_client
        limiter = RateLimiter()
        result = await scan_path(client, limiter, "http://example.com/", "admin", 5.0, {200})
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_custom_method(self, async_client):
        respx.post("http://example.com/api").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        client = async_client
        limiter = RateLimiter()
        result = await scan_path(client, limiter, "http://example.com/", "api", 5.0, {200}, method="POST")
        assert result is not None
        assert result.method == "POST"


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

    def test_default_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.concurrency == 40

    def test_has_proxy_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--proxy", "http://proxy:8080"])
        assert args.proxy == "http://proxy:8080"

    def test_has_delay_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--delay", "10"])
        assert args.delay == 10.0

    def test_has_method_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "-M", "POST"])
        assert args.method == "POST"

    def test_default_method_is_get(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.method == "GET"

    def test_has_auth_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--auth", "admin:secret"])
        assert args.auth is not None
        assert "Authorization" in args.auth

    def test_has_cookie_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--cookie", "session=abc"])
        assert args.cookie == "session=abc"

    def test_has_header_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--header", "X-Token: abc", "--header", "X-Custom: xyz"])
        assert args.header == ["X-Token: abc", "X-Custom: xyz"]

    def test_has_filter_size_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--filter-size", "100-5000"])
        assert args.filter_size == (100, 5000)

    def test_has_filter_words_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--filter-words", "10-100"])
        assert args.filter_words == (10, 100)

    def test_has_verbose_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "-v"])
        assert args.verbose is True

    def test_default_verbose_false(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.verbose is False

    def test_has_log_file_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--log-file", "scan.log"])
        assert args.log_file == "scan.log"


class TestScanPathEdgeCases:
    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_refused_returns_none(self, async_client):
        respx.get("https://example.com/secret").mock(side_effect=httpx.ConnectError("refused"))
        rl = RateLimiter(0)
        result = await scan_path(async_client, rl, "https://example.com/", "/secret", 1.0, {200, 301})
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_returns_none(self, async_client):
        def handler(request):
            raise httpx.TimeoutException("timeout")

        respx.get("https://example.com/slow").mock(side_effect=handler)
        rl = RateLimiter(0)
        result = await scan_path(async_client, rl, "https://example.com/", "/slow", 0.1, {200})
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_path_probes_root(self, async_client):
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="root"))
        rl = RateLimiter(0)
        result = await scan_path(async_client, rl, "https://example.com", "", 1.0, {200})
        assert result is None or result.path == "/"

    @respx.mock
    @pytest.mark.asyncio
    async def test_403_returns_finding_when_in_statuses(self, async_client):
        respx.get("https://example.com/admin").mock(return_value=httpx.Response(403, text="forbidden"))
        rl = RateLimiter(0)
        result = await scan_path(async_client, rl, "https://example.com/", "/admin", 1.0, {200, 403})
        assert result is not None
        assert result.status == 403

    @respx.mock
    @pytest.mark.asyncio
    async def test_large_body_handled(self, async_client):
        body = "x" * 500_000
        respx.get("https://example.com/big").mock(return_value=httpx.Response(200, text=body))
        rl = RateLimiter(0)
        result = await scan_path(async_client, rl, "https://example.com/", "/big", 5.0, {200})
        assert result is not None
        assert result.size >= 500_000


class TestDryRun:
    def test_dry_run_flag_exists_in_parser(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--dry-run"])
        assert args.dry_run is True

    def test_dry_run_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.dry_run is False

    def test_dry_run_returns_zero(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--dry-run"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_dry_run_outputs_info(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--dry-run"])
        asyncio.run(_async_run_once(args))
        captured = capsys.readouterr()
        assert "DRY-RUN" in captured.out
        assert "Nenhuma requisicao" in captured.out

