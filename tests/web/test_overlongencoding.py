#!/usr/bin/env python3
"""Testes unitarios do modulo de Overlong UTF-8 Encoding Bypass."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.overlongencoding import (
    _CATEGORY_MAP,
    _OVERLONG_ENCODINGS,
    _SENSITIVE_CHARS,
    OverlongAttempt,
    OverlongResult,
    _build_overlong_url,
    _overlong_2byte,
    _overlong_3byte,
    _overlong_4byte,
    _test_baseline,
    _test_overlong_headers,
    _test_overlong_params,
    _test_overlong_url,
    _test_overlong_waf,
    build_parser,
    main,
    print_results,
)


class TestOverlong2Byte:
    """Testes para _overlong_2byte."""

    def test_slash(self) -> None:
        assert _overlong_2byte("/") == "%c0%af"

    def test_backslash(self) -> None:
        assert _overlong_2byte("\\") == "%c1%9c"

    def test_less_than(self) -> None:
        assert _overlong_2byte("<") == "%c0%bc"

    def test_greater_than(self) -> None:
        assert _overlong_2byte(">") == "%c0%be"

    def test_single_quote(self) -> None:
        assert _overlong_2byte("'") == "%c0%a7"

    def test_double_quote(self) -> None:
        assert _overlong_2byte('"') == "%c0%a2"

    def test_space(self) -> None:
        assert _overlong_2byte(" ") == "%c0%a0"

    def test_semicolon(self) -> None:
        assert _overlong_2byte(";") == "%c0%bb"

    def test_equals(self) -> None:
        assert _overlong_2byte("=") == "%c0%bd"

    def test_ampersand(self) -> None:
        assert _overlong_2byte("&") == "%c0%a6"

    def test_open_paren(self) -> None:
        assert _overlong_2byte("(") == "%c0%a8"

    def test_close_paren(self) -> None:
        assert _overlong_2byte(")") == "%c0%a9"


class TestOverlong3Byte:
    """Testes para _overlong_3byte."""

    def test_slash(self) -> None:
        assert _overlong_3byte("/") == "%e0%80%af"

    def test_less_than(self) -> None:
        assert _overlong_3byte("<") == "%e0%80%bc"

    def test_greater_than(self) -> None:
        assert _overlong_3byte(">") == "%e0%80%be"

    def test_single_quote(self) -> None:
        assert _overlong_3byte("'") == "%e0%80%a7"

    def test_space(self) -> None:
        assert _overlong_3byte(" ") == "%e0%80%a0"

    def test_backslash(self) -> None:
        assert _overlong_3byte("\\") == "%e0%81%9c"


class TestOverlong4Byte:
    """Testes para _overlong_4byte."""

    def test_slash(self) -> None:
        assert _overlong_4byte("/") == "%f0%80%80%af"

    def test_less_than(self) -> None:
        assert _overlong_4byte("<") == "%f0%80%80%bc"

    def test_space(self) -> None:
        assert _overlong_4byte(" ") == "%f0%80%80%a0"


class TestEncodingConsistency:
    """Testes de consistencia entre encodings."""

    def test_2byte_len(self) -> None:
        result = _overlong_2byte("/")
        assert len(result) == 6

    def test_3byte_len(self) -> None:
        result = _overlong_3byte("/")
        assert len(result) == 9

    def test_4byte_len(self) -> None:
        result = _overlong_4byte("/")
        assert len(result) == 12

    def test_all_chars_have_2byte(self) -> None:
        for char in _SENSITIVE_CHARS:
            result = _overlong_2byte(char)
            assert result.startswith("%")
            assert "%" in result[1:]

    def test_all_chars_have_3byte(self) -> None:
        for char in _SENSITIVE_CHARS:
            result = _overlong_3byte(char)
            assert result.startswith("%")
            assert result.count("%") == 3

    def test_all_chars_have_4byte(self) -> None:
        for char in _SENSITIVE_CHARS:
            result = _overlong_4byte(char)
            assert result.startswith("%")
            assert result.count("%") == 4


class TestBuildOverlongUrl:
    """Testes para _build_overlong_url."""

    def test_path_position(self) -> None:
        result = _build_overlong_url("https://example.com/admin", "%c0%af", "path")
        assert "%c0%af" in result
        assert "admin" in result

    def test_query_position(self) -> None:
        result = _build_overlong_url("https://example.com", "%c0%af", "query")
        assert "test=%c0%af" in result

    def test_fragment_position(self) -> None:
        result = _build_overlong_url("https://example.com", "%c0%af", "fragment")
        assert "#" in result
        assert "%c0%af" in result

    def test_no_scheme(self) -> None:
        result = _build_overlong_url("example.com/admin", "%c0%af", "path")
        assert "%c0%af" in result
        assert "admin" in result

    def test_unknown_position(self) -> None:
        result = _build_overlong_url("https://example.com", "%c0%af", "unknown")
        assert result == "https://example.com"


class TestSensitiveChars:
    """Testes para _SENSITIVE_CHARS."""

    def test_has_all_critical(self) -> None:
        assert "/" in _SENSITIVE_CHARS
        assert "<" in _SENSITIVE_CHARS
        assert ">" in _SENSITIVE_CHARS
        assert "'" in _SENSITIVE_CHARS
        assert '"' in _SENSITIVE_CHARS

    def test_has_injection_chars(self) -> None:
        assert ";" in _SENSITIVE_CHARS
        assert "\r" in _SENSITIVE_CHARS
        assert "\n" in _SENSITIVE_CHARS
        assert "=" in _SENSITIVE_CHARS
        assert "&" in _SENSITIVE_CHARS

    def test_count(self) -> None:
        assert len(_SENSITIVE_CHARS) == 14


class TestOverlongEncodings:
    """Testes para _OVERLONG_ENCODINGS."""

    def test_has_all(self) -> None:
        assert "2byte" in _OVERLONG_ENCODINGS
        assert "3byte" in _OVERLONG_ENCODINGS
        assert "4byte" in _OVERLONG_ENCODINGS

    def test_count(self) -> None:
        assert len(_OVERLONG_ENCODINGS) == 3


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_url(self) -> None:
        assert "url" in _CATEGORY_MAP

    def test_has_param(self) -> None:
        assert "param" in _CATEGORY_MAP

    def test_has_header(self) -> None:
        assert "header" in _CATEGORY_MAP

    def test_has_waf(self) -> None:
        assert "waf" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 4


class TestOverlongAttempt:
    """Testes para OverlongAttempt dataclass."""

    def test_creation(self) -> None:
        att = OverlongAttempt(
            technique="overlong_2byte_path",
            category="url",
            url="https://example.com/test",
            payload="/=%c0%af",
            status_baseline=200,
            status_test=404,
            size_baseline=1000,
            size_test=500,
            status_changed=True,
            size_changed=True,
            vulnerable=False,
            details="Status 200->404",
            error="",
        )
        assert att.technique == "overlong_2byte_path"
        assert att.status_changed is True
        assert att.vulnerable is False

    def test_frozen(self) -> None:
        att = OverlongAttempt(
            technique="t",
            category="c",
            url="u",
            payload="p",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=100,
            status_changed=False,
            size_changed=False,
            vulnerable=False,
            details="d",
            error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "new"  # type: ignore[misc]


class TestOverlongResult:
    """Testes para OverlongResult dataclass."""

    def test_creation(self) -> None:
        result = OverlongResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert result.target == "https://example.com"
        assert result.overall_status == "secure"


class TestTestBaseline:
    """Testes para _test_baseline."""

    @pytest.mark.asyncio
    async def test_success(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"hello"
        client.get = AsyncMock(return_value=resp)

        status, size, body = await _test_baseline(client, "https://example.com")
        assert status == 200
        assert size == 5
        assert body == b"hello"

    @pytest.mark.asyncio
    async def test_error(self) -> None:
        import httpx
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        status, size, body = await _test_baseline(client, "https://example.com")
        assert status == 0
        assert size == 0
        assert body == b""


class TestTestOverlongUrl:
    """Testes para _test_overlong_url."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 404
        resp.content = b"not found"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_overlong_url(
            client, "https://example.com/admin", (200, 1000, b""),
        )
        assert len(attempts) > 0
        assert all(isinstance(a, OverlongAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_vulnerability_detected(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"admin panel"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_overlong_url(
            client, "https://example.com/admin", (404, 100, b""),
        )
        vulnerable = [a for a in attempts if a.vulnerable]
        assert len(vulnerable) > 0


class TestTestOverlongParams:
    """Testes para _test_overlong_params."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_overlong_params(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 3


class TestTestOverlongHeaders:
    """Testes para _test_overlong_headers."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_overlong_headers(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 3


class TestTestOverlongWaf:
    """Testes para _test_overlong_waf."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_overlong_waf(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 3


class TestBuildParser:
    """Testes para build_parser."""

    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "url"])
        assert args.category == "url"

    def test_has_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--concurrency", "10"])
        assert args.concurrency == 10

    def test_category_choices(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "waf"])
        assert args.category == "waf"


class TestPrintResults:
    """Testes para print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = OverlongResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "OVERLONG" in captured.out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = OverlongResult(
            target="https://example.com",
            baseline_status=404,
            baseline_size=100,
            tls=False,
            attempts=[],
            vulnerable_techniques=["overlong_2byte_path"],
            blocked_techniques=[],
            issues=["1 tecnicas vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out


class TestMain:
    """Testes para main."""

    def test_no_url(self) -> None:
        with patch("sys.argv", ["mytools-overlong"]), \
             patch("mytools.web.overlongencoding.run_main_loop", return_value=1) as mock_loop:
            result = main()
            assert result == 1
            mock_loop.assert_called_once()
