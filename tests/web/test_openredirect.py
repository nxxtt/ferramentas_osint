#!/usr/bin/env python3
"""Testes unitarios do modulo de Open Redirect."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.openredirect import (
    _BYPASS_TECHNIQUES,
    _CATEGORY_MAP,
    _EVIL_DOMAIN,
    _REDIRECT_PARAMS,
    _REDIRECT_PATHS,
    OpenRedirectAttempt,
    OpenRedirectResult,
    _is_external_redirect,
    _test_baseline,
    _test_bypass_redirect,
    _test_fragment_redirect,
    _test_header_redirect,
    _test_param_redirect,
    _test_path_redirect,
    build_parser,
    main,
    print_results,
)


class TestRedirectParams:
    """Testes para _REDIRECT_PARAMS."""

    def test_has_url(self) -> None:
        assert "url" in _REDIRECT_PARAMS

    def test_has_next(self) -> None:
        assert "next" in _REDIRECT_PARAMS

    def test_has_redirect(self) -> None:
        assert "redirect" in _REDIRECT_PARAMS

    def test_has_return(self) -> None:
        assert "return" in _REDIRECT_PARAMS

    def test_count(self) -> None:
        assert len(_REDIRECT_PARAMS) == 12


class TestRedirectPaths:
    """Testes para _REDIRECT_PATHS."""

    def test_has_redirect(self) -> None:
        assert "/redirect" in _REDIRECT_PATHS

    def test_has_login(self) -> None:
        assert "/login" in _REDIRECT_PATHS

    def test_has_go(self) -> None:
        assert "/go" in _REDIRECT_PATHS

    def test_count(self) -> None:
        assert len(_REDIRECT_PATHS) == 6


class TestEvilDomain:
    """Testes para _EVIL_DOMAIN."""

    def test_value(self) -> None:
        assert _EVIL_DOMAIN == "evil.com"


class TestBypassTechniques:
    """Testes para _BYPASS_TECHNIQUES."""

    def test_has_protocol(self) -> None:
        assert any(t[0] == "bypass_protocol" for t in _BYPASS_TECHNIQUES)

    def test_has_nullbyte(self) -> None:
        assert any(t[0] == "bypass_nullbyte" for t in _BYPASS_TECHNIQUES)

    def test_hasuserinfo(self) -> None:
        assert any(t[0] == "bypass userinfo" for t in _BYPASS_TECHNIQUES)

    def test_has_fragment(self) -> None:
        assert any(t[0] == "bypass_fragment" for t in _BYPASS_TECHNIQUES)

    def test_has_backslash(self) -> None:
        assert any(t[0] == "bypass_backslash" for t in _BYPASS_TECHNIQUES)

    def test_count(self) -> None:
        assert len(_BYPASS_TECHNIQUES) == 8


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_param(self) -> None:
        assert "param" in _CATEGORY_MAP

    def test_has_path(self) -> None:
        assert "path" in _CATEGORY_MAP

    def test_has_header(self) -> None:
        assert "header" in _CATEGORY_MAP

    def test_has_fragment(self) -> None:
        assert "fragment" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestIsExternalRedirect:
    """Testes para _is_external_redirect."""

    def test_external_domain(self) -> None:
        assert _is_external_redirect("http://evil.com", "example.com") is True

    def test_same_domain(self) -> None:
        assert _is_external_redirect("http://example.com/path", "example.com") is False

    def test_empty_location(self) -> None:
        assert _is_external_redirect("", "example.com") is False

    def test_protocol_relative(self) -> None:
        assert _is_external_redirect("//evil.com", "example.com") is True

    def test_protocol_relative_same(self) -> None:
        assert _is_external_redirect("//example.com", "example.com") is False

    def test_no_location(self) -> None:
        assert _is_external_redirect("", "example.com") is False


class TestOpenRedirectAttempt:
    """Testes para OpenRedirectAttempt dataclass."""

    def test_creation(self) -> None:
        att = OpenRedirectAttempt(
            technique="param_url",
            category="param",
            url="https://example.com?url=evil.com",
            payload="url=evil.com",
            status_baseline=200,
            status_test=302,
            size_baseline=1000,
            size_test=0,
            status_changed=True,
            size_changed=True,
            redirect_location="http://evil.com",
            vulnerable=True,
            details="Redirect -> http://evil.com",
            error="",
        )
        assert att.technique == "param_url"
        assert att.vulnerable is True
        assert att.redirect_location == "http://evil.com"

    def test_frozen(self) -> None:
        att = OpenRedirectAttempt(
            technique="t", category="c", url="u", payload="p",
            status_baseline=200, status_test=200,
            size_baseline=100, size_test=100,
            status_changed=False, size_changed=False,
            redirect_location="", vulnerable=False,
            details="d", error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "new"  # type: ignore[misc]


class TestOpenRedirectResult:
    """Testes para OpenRedirectResult dataclass."""

    def test_creation(self) -> None:
        result = OpenRedirectResult(
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


class TestTestParamRedirect:
    """Testes para _test_param_redirect."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 302
        resp.content = b""
        resp.headers = {"location": "http://evil.com"}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_param_redirect(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) > 0
        assert all(isinstance(a, OpenRedirectAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_vulnerability_detected(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 302
        resp.content = b""
        resp.headers = {"location": "http://evil.com"}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_param_redirect(
            client, "https://example.com", (200, 1000, b""),
        )
        vulnerable = [a for a in attempts if a.vulnerable]
        assert len(vulnerable) > 0


class TestTestPathRedirect:
    """Testes para _test_path_redirect."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_path_redirect(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 6


class TestTestHeaderRedirect:
    """Testes para _test_header_redirect."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_header_redirect(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 2


class TestTestFragmentRedirect:
    """Testes para _test_fragment_redirect."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_fragment_redirect(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 1


class TestTestBypassRedirect:
    """Testes para _test_bypass_redirect."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_bypass_redirect(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 8


class TestBuildParser:
    """Testes para build_parser."""

    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "param"])
        assert args.category == "param"

    def test_has_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--concurrency", "10"])
        assert args.concurrency == 10

    def test_category_choices(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "bypass"])
        assert args.category == "bypass"


class TestPrintResults:
    """Testes para print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = OpenRedirectResult(
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
        assert "OPEN REDIRECT" in captured.out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = OpenRedirectResult(
            target="https://example.com",
            baseline_status=302,
            baseline_size=0,
            tls=False,
            attempts=[],
            vulnerable_techniques=["param_url"],
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
        with patch("sys.argv", ["mytools-openredirect"]), \
             patch("mytools.web.openredirect.run_main_loop", return_value=1) as mock_loop:
            result = main()
            assert result == 1
            mock_loop.assert_called_once()
