from __future__ import annotations

import argparse
import logging
import os
import time

import httpx
import pytest
import respx

from utils import (
    Cyber,
    FetchError,
    RateLimiter,
    __version__,
    add_base_args,
    add_common_args,
    apply_session_auth,
    color,
    create_async_client,
    ensure_output_dir,
    extract_hostname,
    extract_title,
    header_get,
    normalize_url,
    parse_auth,
    parse_extra_headers,
    parse_int_range,
    print_table,
    query_nvd,
    resolve_target_urls,
    set_color,
    setup_logging,
    status_color,
)


class TestCyberConstants:
    def test_all_colors_are_ansi_strings(self):
        for attr in ("RESET", "BOLD", "DIM", "RED", "GREEN", "CYAN", "BLUE", "MAGENTA", "YELLOW", "WHITE", "GRAY"):
            value = getattr(Cyber, attr)
            assert isinstance(value, str)
            assert value.startswith("\033[")

    def test_reset_ends_with_zero(self):
        assert Cyber.RESET == "\033[0m"


class TestColor:
    def test_returns_plain_text_when_no_color(self, monkeypatch):
        monkeypatch.setattr("utils._USE_COLOR", False)
        assert color("hello", Cyber.RED) == "hello"

    def test_wraps_with_ansi_when_color(self, monkeypatch):
        monkeypatch.setattr("utils._USE_COLOR", True)
        result = color("hello", Cyber.RED)
        assert result == f"{Cyber.RED}hello{Cyber.RESET}"

    def test_multiple_styles(self, monkeypatch):
        monkeypatch.setattr("utils._USE_COLOR", True)
        result = color("hello", Cyber.RED, Cyber.BOLD)
        assert result == f"{Cyber.RED}{Cyber.BOLD}hello{Cyber.RESET}"

    def test_no_styles(self, monkeypatch):
        monkeypatch.setattr("utils._USE_COLOR", True)
        result = color("hello")
        assert result == f"hello{Cyber.RESET}"


class TestStatusColor:
    def test_200_is_green(self):
        assert status_color(200) == Cyber.GREEN

    def test_301_is_yellow(self):
        assert status_color(301) == Cyber.YELLOW

    def test_401_is_magenta(self):
        assert status_color(401) == Cyber.MAGENTA

    def test_403_is_magenta(self):
        assert status_color(403) == Cyber.MAGENTA

    def test_500_is_gray(self):
        assert status_color(500) == Cyber.GRAY

    def test_503_is_gray(self):
        assert status_color(503) == Cyber.GRAY

    def test_unknown_is_gray(self):
        assert status_color(999) == Cyber.GRAY


class TestHeaderGet:
    def test_exact_match(self):
        assert header_get({"Content-Type": "text/html"}, "Content-Type") == "text/html"

    def test_missing_returns_empty(self):
        assert header_get({"Content-Type": "text/html"}, "X-Custom") == ""

    def test_empty_headers(self):
        assert header_get({}, "anything") == ""

    def test_case_insensitive(self):
        assert header_get({"Content-Type": "text/html"}, "content-type") == "text/html"

    def test_case_insensitive_mixed(self):
        assert header_get({"X-Custom": "val"}, "x-custom") == "val"


class TestExtractTitle:
    def test_simple_title(self):
        assert extract_title("<html><title>Hello</title></html>") == "Hello"

    def test_no_title(self):
        assert extract_title("<html><body>No title here</body></html>") == ""

    def test_case_insensitive(self):
        assert extract_title("<TITLE>Mixed</TITLE>") == "Mixed"

    def test_extra_whitespace(self):
        assert extract_title("<title>  Hello   World  </title>") == "Hello World"

    def test_truncation_at_100(self):
        long_title = "A" * 150
        result = extract_title(f"<title>{long_title}</title>")
        assert len(result) == 100

    def test_empty_title(self):
        assert extract_title("<title></title>") == ""


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_zero_delay_does_not_block(self):
        limiter = RateLimiter(0.0)
        start = time.monotonic()
        await limiter.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

    @pytest.mark.asyncio
    @pytest.mark.real_sleep
    async def test_rate_limit_enforces_delay(self):
        limiter = RateLimiter(20.0)
        timestamps: list[float] = []

        await limiter.wait()
        timestamps.append(time.monotonic())

        await limiter.wait()
        timestamps.append(time.monotonic())

        assert timestamps[1] - timestamps[0] >= 0.04

    @pytest.mark.asyncio
    async def test_notify_429_doubles_backoff(self):
        limiter = RateLimiter(10.0)
        assert limiter._backoff_multiplier == 1.0
        limiter.notify_429()
        assert limiter._backoff_multiplier == 2.0
        limiter.notify_429()
        assert limiter._backoff_multiplier == 4.0

    @pytest.mark.asyncio
    async def test_notify_429_caps_at_16(self):
        limiter = RateLimiter(10.0)
        for _ in range(10):
            limiter.notify_429()
        assert limiter._backoff_multiplier == 16.0

    @pytest.mark.asyncio
    async def test_reset_backoff(self):
        limiter = RateLimiter(10.0)
        limiter.notify_429()
        limiter.notify_429()
        assert limiter._backoff_multiplier == 4.0
        limiter.reset_backoff()
        assert limiter._backoff_multiplier == 1.0

    @pytest.mark.asyncio
    @pytest.mark.real_sleep
    async def test_backoff_increases_sleep_time(self):
        limiter = RateLimiter(20.0)
        await limiter.wait()
        t1 = time.monotonic()
        await limiter.wait()
        gap_no_backoff = time.monotonic() - t1

        limiter.reset_backoff()
        limiter.notify_429()
        limiter.notify_429()
        await limiter.wait()
        t2 = time.monotonic()
        await limiter.wait()
        gap_with_backoff = time.monotonic() - t2

        assert gap_with_backoff > gap_no_backoff


class TestFetch429:
    @respx.mock
    @pytest.mark.asyncio
    async def test_429_triggers_backoff_and_retries(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        limiter = RateLimiter(100.0)
        url = "https://example.com/rate"
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(429, headers={"Retry-After": "0"})
            return httpx.Response(200, text="ok")

        respx.get(url).mock(side_effect=side_effect)
        status, _, _body, _ = await fetch(client, url, rate_limiter=limiter, max_retries=3)
        assert status == 200
        assert call_count == 2
        assert limiter._backoff_multiplier == 2.0
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_429_exhausts_retries(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        limiter = RateLimiter(100.0)
        url = "https://example.com/rate"

        respx.get(url).mock(return_value=httpx.Response(429, headers={"Retry-After": "0"}))
        with pytest.raises(FetchError, match="falha ao acessar"):
            await fetch(client, url, rate_limiter=limiter, max_retries=2)
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_429_error_does_not_trigger_backoff(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        limiter = RateLimiter(100.0)
        url = "https://example.com/ok"

        respx.get(url).mock(return_value=httpx.Response(200, text="ok"))
        status, _, _body, _ = await fetch(client, url, rate_limiter=limiter)
        assert status == 200
        assert limiter._backoff_multiplier == 1.0
        await client.aclose()


class TestCreateAsyncClient:
    def test_returns_client(self):
        client = create_async_client()
        assert client is not None
        assert "User-Agent" in client.headers

    def test_custom_user_agent(self):
        client = create_async_client(user_agent="TestAgent/1.0")
        assert client.headers["User-Agent"] == "TestAgent/1.0"

    def test_no_proxy(self):
        client = create_async_client()
        assert client._mounts is not None


class TestSetupLogging:
    def test_verbose_sets_debug_level(self):
        setup_logging(verbose=True)
        root = logging.getLogger("mytools")
        assert root.level == logging.DEBUG

    def test_default_sets_warning_level(self):
        setup_logging()
        root = logging.getLogger("mytools")
        assert root.level == logging.WARNING

    def test_log_file_creates_file(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        setup_logging(log_file=log_file)
        logger = logging.getLogger("mytools.test")
        logger.info("test message")
        for handler in logging.getLogger("mytools").handlers:
            handler.flush()
        assert os.path.exists(log_file)

    def test_log_file_sets_info_level(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        setup_logging(log_file=log_file)
        root = logging.getLogger("mytools")
        assert root.level == logging.INFO

    def test_verbose_and_log_file(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        setup_logging(verbose=True, log_file=log_file)
        root = logging.getLogger("mytools")
        assert root.level == logging.DEBUG


class TestVersion:
    def test_version_is_string(self):
        assert isinstance(__version__, str)

    def test_version_format(self):
        parts = __version__.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_version_matches_pyproject(self):
        from pathlib import Path
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        for line in pyproject.read_text(encoding="utf-8").splitlines():
            if line.startswith("version"):
                expected = line.split("=", 1)[1].strip().strip('"')
                break
        else:
            expected = "0.0.0"
        assert __version__ == expected


class TestParseAuthUtils:
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


class TestParseExtraHeadersUtils:
    def test_single_header(self):
        result = parse_extra_headers(["X-Token: abc123"])
        assert result == {"X-Token": "abc123"}

    def test_multiple_headers(self):
        result = parse_extra_headers(["X-Token: abc", "X-Custom: xyz"])
        assert len(result) == 2

    def test_no_colon_raises(self):
        with pytest.raises(ValueError):
            parse_extra_headers(["InvalidHeader"])


class TestAddCommonArgs:
    def test_adds_timeout(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["-t", "10"])
        assert args.timeout == 10.0

    def test_adds_output(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["-o", "out.json"])
        assert args.output == "out.json"

    def test_adds_verbose(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["-v"])
        assert args.verbose is True

    def test_adds_quiet(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["-q"])
        assert args.quiet is True

    def test_adds_auth(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["--auth", "user:pass"])
        assert args.auth is not None
        assert "Authorization" in args.auth

    def test_adds_bearer_token(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["--bearer-token", "tok123"])
        assert args.bearer_token == "tok123"

    def test_adds_cookie(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["--cookie", "session=abc"])
        assert args.cookie == "session=abc"

    def test_adds_header(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["--header", "X-Token: abc", "--header", "X-Custom: xyz"])
        assert args.header == ["X-Token: abc", "X-Custom: xyz"]

    def test_adds_proxy(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["--proxy", "http://proxy:8080"])
        assert args.proxy == "http://proxy:8080"

    def test_adds_delay(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["--delay", "5"])
        assert args.delay == 5.0

    def test_adds_log_file(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args(["--log-file", "test.log"])
        assert args.log_file == "test.log"

    def test_default_timeout(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args([])
        assert args.timeout == 5.0

    def test_default_quiet_false(self):
        import argparse
        parser = argparse.ArgumentParser()
        add_common_args(parser)
        args = parser.parse_args([])
        assert args.quiet is False


class TestApplySessionAuth:
    def test_auth_applied(self):
        client = create_async_client(user_agent="Test/1.0")
        apply_session_auth(client, auth={"Authorization": "Basic abc"})
        assert client.headers["Authorization"] == "Basic abc"

    def test_bearer_token_applied(self):
        client = create_async_client(user_agent="Test/1.0")
        apply_session_auth(client, bearer_token="tok123")
        assert client.headers["Authorization"] == "Bearer tok123"

    def test_cookie_applied(self):
        client = create_async_client(user_agent="Test/1.0")
        apply_session_auth(client, cookie="session=abc")
        assert client.headers["Cookie"] == "session=abc"

    def test_extra_headers_applied(self):
        client = create_async_client(user_agent="Test/1.0")
        apply_session_auth(client, extra_headers=["X-Token: abc"])
        assert client.headers["X-Token"] == "abc"

    def test_no_auth_no_change(self):
        client = create_async_client(user_agent="Test/1.0")
        apply_session_auth(client)
        assert "Authorization" not in client.headers
        assert "Cookie" not in client.headers


class TestExtractHostname:
    def test_simple_url(self):
        assert extract_hostname("https://example.com") == "example.com"

    def test_with_port(self):
        assert extract_hostname("https://example.com:8080") == "example.com"

    def test_with_path(self):
        assert extract_hostname("https://example.com/path/to/page") == "example.com"

    def test_http(self):
        assert extract_hostname("http://test.example.com") == "test.example.com"


class TestCreateAsyncClientDefaultUA:
    def test_default_user_agent(self):
        client = create_async_client()
        assert client.headers["User-Agent"] == f"MyTools/{__version__}"


class TestQueryNvd:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_parsed_results(self):
        mock_response = {
            "resultsPerPage": 10,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Apache Log4j2 RCE"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                            ]
                        },
                    }
                }
            ],
        }
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(200, json=mock_response)
        )
        results = await query_nvd("Log4j 2.14")
        assert len(results) == 1
        assert results[0]["id"] == "CVE-2021-44228"
        assert results[0]["score"] == 10.0
        assert results[0]["severity"] == "CRITICAL"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_on_rate_limit(self):
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(403)
        )
        results = await query_nvd("test")
        assert results == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_empty_on_error(self):
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(500)
        )
        results = await query_nvd("test")
        assert results == []


class TestNormalizeUrl:
    def test_with_scheme(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_without_scheme_adds_https(self):
        assert normalize_url("example.com") == "https://example.com"

    def test_strips_trailing_slash(self):
        assert normalize_url("https://example.com/") == "https://example.com"

    def test_strips_whitespace(self):
        assert normalize_url("  https://example.com  ") == "https://example.com"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            normalize_url("")

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError):
            normalize_url("ftp://example.com")

    def test_no_netloc_raises(self):
        with pytest.raises(ValueError):
            normalize_url("http://")


class TestSetColor:
    def test_disables_color(self, monkeypatch):
        monkeypatch.setattr("utils._USE_COLOR", True)
        set_color(False)
        import utils
        assert utils._USE_COLOR is False
        set_color(True)

    def test_enables_color(self, monkeypatch):
        monkeypatch.setattr("utils._USE_COLOR", False)
        set_color(True)
        import utils
        assert utils._USE_COLOR is True
        set_color(False)


class TestPrintTable:
    def test_empty_rows(self, capsys):
        print_table(("A", "B"), [], [(Cyber.WHITE,)], empty_message="nothing")
        captured = capsys.readouterr()
        assert "nothing" in captured.out

    def test_prints_header_and_rows(self, capsys, monkeypatch):
        monkeypatch.setattr("utils._USE_COLOR", False)
        print_table(
            ("NAME", "VALUE"),
            [("foo", "bar"), ("baz", "qux")],
            [(Cyber.WHITE,), (Cyber.CYAN,)],
        )
        captured = capsys.readouterr()
        assert "NAME" in captured.out
        assert "foo" in captured.out
        assert "bar" in captured.out

    def test_alignments(self, capsys, monkeypatch):
        monkeypatch.setattr("utils._USE_COLOR", False)
        print_table(
            ("LEFT", "RIGHT"),
            [("a", "1")],
            [(Cyber.WHITE,), (Cyber.WHITE,)],
            alignments=["left", "right"],
        )
        captured = capsys.readouterr()
        assert "a" in captured.out
        assert "1" in captured.out


class TestParseIntRange:
    def test_single_value(self):
        assert parse_int_range("80", 1, 65535, "porta") == [80]

    def test_comma_separated(self):
        assert parse_int_range("80,443", 1, 65535, "porta") == [80, 443]

    def test_range(self):
        result = parse_int_range("80-83", 1, 65535, "porta")
        assert result == [80, 81, 82, 83]

    def test_reversed_range(self):
        result = parse_int_range("83-80", 1, 65535, "porta")
        assert result == [80, 81, 82, 83]

    def test_mixed(self):
        result = parse_int_range("22,80-82,443", 1, 65535, "porta")
        assert result == [22, 80, 81, 82, 443]

    def test_aliases(self):
        aliases = {"default": [80, 443]}
        assert parse_int_range("default", 1, 65535, "porta", aliases) == [80, 443]

    def test_out_of_range_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="invalidos"):
            parse_int_range("0", 1, 65535, "porta")

    def test_invalid_value_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="invalido"):
            parse_int_range("abc", 1, 65535, "porta")

    def test_empty_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="pelo menos um"):
            parse_int_range("", 1, 65535, "porta")

    def test_deduplication(self):
        result = parse_int_range("80,80,80", 1, 65535, "porta")
        assert result == [80]


class TestWriteOutput:
    """Testa write_output com validacao de extensao."""

    def test_json_extension(self, tmp_path):
        from utils import write_output
        path = str(tmp_path / "result.json")
        write_output(path, {"key": "value"}, quiet=True)
        assert os.path.exists(path)

    def test_csv_extension(self, tmp_path):
        from utils import write_output
        path = str(tmp_path / "result.csv")
        write_output(path, [{"a": "1"}], fieldnames=["a"], quiet=True)
        assert os.path.exists(path)

    def test_invalid_extension_raises(self, tmp_path):
        from utils import write_output
        path = str(tmp_path / "result.xml")
        with pytest.raises(ValueError, match="extensao nao suportada"):
            write_output(path, {"key": "value"}, quiet=True)

    def test_txt_extension_raises(self, tmp_path):
        from utils import write_output
        path = str(tmp_path / "result.txt")
        with pytest.raises(ValueError, match="extensao nao suportada"):
            write_output(path, [{"a": "1"}], fieldnames=["a"], quiet=True)


class TestResolveTargetUrls:
    def test_url_only(self):
        args = argparse.Namespace(target_list=None, url="http://example.com")
        assert resolve_target_urls(args) == ["http://example.com"]

    def test_list_only(self, tmp_path):
        lst = tmp_path / "targets.txt"
        lst.write_text("http://a.com\nhttp://b.com\n", encoding="utf-8")
        args = argparse.Namespace(target_list=str(lst), url=None)
        assert resolve_target_urls(args) == ["http://a.com", "http://b.com"]

    def test_both_combined(self, tmp_path):
        lst = tmp_path / "targets.txt"
        lst.write_text("http://a.com\n", encoding="utf-8")
        args = argparse.Namespace(target_list=str(lst), url="http://b.com")
        assert resolve_target_urls(args) == ["http://a.com", "http://b.com"]

    def test_skips_blank_and_comments(self, tmp_path):
        lst = tmp_path / "targets.txt"
        lst.write_text("http://a.com\n\n# comment\n  \nhttp://b.com\n", encoding="utf-8")
        args = argparse.Namespace(target_list=str(lst), url=None)
        assert resolve_target_urls(args) == ["http://a.com", "http://b.com"]

    def test_no_targets_raises(self):
        args = argparse.Namespace(target_list=None, url=None)
        with pytest.raises(ValueError, match="informe uma URL"):
            resolve_target_urls(args)

    def test_missing_file_raises(self):
        args = argparse.Namespace(target_list="/nonexistent/file.txt", url=None)
        with pytest.raises(ValueError, match="arquivo nao encontrado"):
            resolve_target_urls(args)


class TestEnsureOutputDir:
    def test_creates_dir(self, tmp_path):
        new_dir = str(tmp_path / "output")
        ensure_output_dir(new_dir)
        assert os.path.isdir(new_dir)

    def test_none_is_noop(self):
        ensure_output_dir(None)

    def test_existing_dir_is_noop(self, tmp_path):
        ensure_output_dir(str(tmp_path))


class TestFetchRetry:
    @respx.mock
    @pytest.mark.asyncio
    async def test_retries_on_connection_error(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        url = "https://example.com/test"
        attempt = 0

        def side_effect(request):
            nonlocal attempt
            attempt += 1
            raise httpx.ConnectError("connection refused")

        respx.get(url).mock(side_effect=side_effect)
        with pytest.raises(FetchError, match="falha ao acessar"):
            await fetch(client, url, max_retries=2)
        assert attempt == 2
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_success_after_retry(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        url = "https://example.com/test"
        attempt = 0

        def side_effect(request):
            nonlocal attempt
            attempt += 1
            if attempt == 1:
                raise httpx.ConnectError("refused")
            return httpx.Response(200, text="ok")

        respx.get(url).mock(side_effect=side_effect)
        status, _, body, _ = await fetch(client, url, max_retries=3)
        assert status == 200
        assert body == b"ok"
        assert attempt == 2
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_raises_after_retries(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        url = "https://example.com/test"

        def side_effect(request):
            raise httpx.TimeoutException("timeout")

        respx.get(url).mock(side_effect=side_effect)
        with pytest.raises(FetchError, match="falha ao acessar"):
            await fetch(client, url, timeout=0.1, max_retries=1)
        await client.aclose()


class TestFetchErrorAttrs:
    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_error_has_url_and_attempts(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        url = "https://example.com/fail"

        def side_effect(request):
            raise httpx.ConnectError("refused")

        respx.get(url).mock(side_effect=side_effect)
        with pytest.raises(FetchError) as exc_info:
            await fetch(client, url, max_retries=3)
        err = exc_info.value
        assert err.url == url
        assert err.attempts == 3
        assert isinstance(err.last_error, httpx.ConnectError)
        assert "falha ao acessar" in str(err)
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_error_preserves_original_exception(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        url = "https://example.com/timeout"

        def side_effect(request):
            raise httpx.TimeoutException("timed out")

        respx.get(url).mock(side_effect=side_effect)
        with pytest.raises(FetchError) as exc_info:
            await fetch(client, url, max_retries=2)
        assert isinstance(exc_info.value.last_error, httpx.TimeoutException)
        assert exc_info.value.attempts == 2
        await client.aclose()


class TestRateLimiterEdgeCases:
    @pytest.mark.asyncio
    async def test_large_rps_very_fast(self):
        limiter = RateLimiter(1000.0)
        start = time.monotonic()
        for _ in range(10):
            await limiter.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 0.5

    @pytest.mark.asyncio
    @pytest.mark.real_sleep
    async def test_consecutive_waits_maintain_interval(self):
        limiter = RateLimiter(10.0)
        timestamps = []
        for _ in range(5):
            await limiter.wait()
            timestamps.append(time.monotonic())
        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i - 1]
            assert gap >= 0.09


class TestWriteOutputMalformed:
    def test_json_with_unserializable_data(self, tmp_path):
        from utils import write_output

        path = str(tmp_path / "bad.json")
        with pytest.raises((TypeError, ValueError, OverflowError)):
            write_output(path, {"key": set([1, 2])}, quiet=True)

    def test_csv_empty_data(self, tmp_path):
        from utils import write_output

        path = str(tmp_path / "empty.csv")
        write_output(path, [], fieldnames=["a", "b"], quiet=True)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "a,b" in content


class TestDryRunFlag:
    def test_add_base_args_includes_dry_run(self):
        parser = argparse.ArgumentParser()
        add_base_args(parser)
        args = parser.parse_args(["--dry-run"])
        assert args.dry_run is True

    def test_dry_run_default_false(self):
        parser = argparse.ArgumentParser()
        add_base_args(parser)
        args = parser.parse_args([])
        assert args.dry_run is False


class TestSafeAsyncioRun:
    def test_runs_coroutine_without_loop(self):
        from utils import safe_asyncio_run

        async def coro():
            return 42

        result = safe_asyncio_run(coro())
        assert result == 42

    def test_returns_none_for_none_coroutine(self):
        from utils import safe_asyncio_run

        async def coro():
            return None

        result = safe_asyncio_run(coro())
        assert result is None

    def test_propagates_exception(self):
        from utils import safe_asyncio_run

        async def coro():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            safe_asyncio_run(coro())

    def test_works_with_existing_event_loop(self):
        import asyncio

        from utils import safe_asyncio_run

        async def coro():
            return 99

        async def caller():
            return safe_asyncio_run(coro())

        result = asyncio.run(caller())
        assert result == 99


class TestRetryAfterEdgeCases:
    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.real_sleep
    async def test_429_http_date_does_not_crash(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        limiter = RateLimiter(100.0)
        url = "https://example.com/date-retry"
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(429, headers={"Retry-After": "Fri, 31 Dec 1999 23:59:59 GMT"})
            return httpx.Response(200, text="ok")

        respx.get(url).mock(side_effect=side_effect)
        status, _, _body, _ = await fetch(client, url, rate_limiter=limiter, max_retries=3)
        assert status == 200
        assert call_count == 2
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    @pytest.mark.real_sleep
    async def test_429_invalid_retry_after_uses_default(self):
        from utils import create_async_client, fetch

        client = create_async_client()
        limiter = RateLimiter(100.0)
        url = "https://example.com/bad-retry"
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(429, headers={"Retry-After": "not-a-number"})
            return httpx.Response(200, text="ok")

        respx.get(url).mock(side_effect=side_effect)
        status, _, _body, _ = await fetch(client, url, rate_limiter=limiter, max_retries=3)
        assert status == 200
        assert call_count == 2
        await client.aclose()
