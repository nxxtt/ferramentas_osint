#!/usr/bin/env python3
"""Testes unitarios do modulo de Charset Detection Bypass."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.charsetbypass import (
    _BOM_BYTES,
    _CATEGORY_MAP,
    _CHARSETS,
    _SQLI_PAYLOADS,
    _XSS_PAYLOADS,
    CharsetBypassAttempt,
    CharsetBypassResult,
    _build_meta_body,
    _build_meta_http_equiv,
    _build_xml_body,
    _test_baseline,
    _test_bom_charset,
    _test_content_type_charset,
    _test_meta_charset,
    _test_mixed_charset,
    _test_xml_charset,
    build_parser,
    main,
    print_results,
)


class TestCharsets:
    """Testes para _CHARSETS."""

    def test_has_utf7(self) -> None:
        assert "utf-7" in _CHARSETS
        assert _CHARSETS["utf-7"] == "utf-7"

    def test_has_utf16_le(self) -> None:
        assert "utf-16-le" in _CHARSETS

    def test_has_iso8859(self) -> None:
        assert "iso-8859-1" in _CHARSETS

    def test_has_windows_1252(self) -> None:
        assert "windows-1252" in _CHARSETS

    def test_has_koi8(self) -> None:
        assert "koi8-r" in _CHARSETS

    def test_count(self) -> None:
        assert len(_CHARSETS) == 12


class TestBomBytes:
    """Testes para _BOM_BYTES."""

    def test_has_utf7(self) -> None:
        assert "utf-7" in _BOM_BYTES
        assert _BOM_BYTES["utf-7"] == b"+/v8"

    def test_has_utf16_le(self) -> None:
        assert "utf-16-le" in _BOM_BYTES
        assert _BOM_BYTES["utf-16-le"] == b"\xff\xfe"

    def test_has_utf16_be(self) -> None:
        assert "utf-16-be" in _BOM_BYTES
        assert _BOM_BYTES["utf-16-be"] == b"\xfe\xff"

    def test_has_utf32_le(self) -> None:
        assert "utf-32-le" in _BOM_BYTES

    def test_has_utf32_be(self) -> None:
        assert "utf-32-be" in _BOM_BYTES

    def test_has_utf8(self) -> None:
        assert "utf-8" in _BOM_BYTES
        assert _BOM_BYTES["utf-8"] == b"\xef\xbb\xbf"


class TestXssPayloads:
    """Testes para _XSS_PAYLOADS."""

    def test_has_script(self) -> None:
        assert any("<script>" in p for p in _XSS_PAYLOADS)

    def test_has_img(self) -> None:
        assert any("<img" in p for p in _XSS_PAYLOADS)

    def test_has_svg(self) -> None:
        assert any("<svg" in p for p in _XSS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_XSS_PAYLOADS) >= 4


class TestSqliPayloads:
    """Testes para _SQLI_PAYLOADS."""

    def test_has_or_1(self) -> None:
        assert any("OR 1=1" in p for p in _SQLI_PAYLOADS)

    def test_has_union(self) -> None:
        assert any("UNION" in p for p in _SQLI_PAYLOADS)

    def test_count(self) -> None:
        assert len(_SQLI_PAYLOADS) >= 4


class TestBuildMetaBody:
    """Testes para _build_meta_body."""

    def test_contains_charset(self) -> None:
        body = _build_meta_body("utf-7", "test")
        assert 'charset="utf-7"' in body

    def test_contains_payload(self) -> None:
        body = _build_meta_body("utf-7", "hello")
        assert "hello" in body

    def test_is_html(self) -> None:
        body = _build_meta_body("utf-7", "test")
        assert "<!DOCTYPE html>" in body
        assert "<html>" in body


class TestBuildMetaHttpEquiv:
    """Testes para _build_meta_http_equiv."""

    def test_contains_charset(self) -> None:
        body = _build_meta_http_equiv("utf-7", "test")
        assert "charset=utf-7" in body

    def test_contains_http_equiv(self) -> None:
        body = _build_meta_http_equiv("utf-7", "test")
        assert 'http-equiv="Content-Type"' in body


class TestBuildXmlBody:
    """Testes para _build_xml_body."""

    def test_contains_encoding(self) -> None:
        body = _build_xml_body("utf-7", "<root>test</root>")
        assert 'encoding="utf-7"' in body

    def test_is_xml(self) -> None:
        body = _build_xml_body("utf-7", "<root>test</root>")
        assert "<?xml" in body
        assert "<root>" in body


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_meta(self) -> None:
        assert "meta" in _CATEGORY_MAP

    def test_has_content_type(self) -> None:
        assert "content_type" in _CATEGORY_MAP

    def test_has_bom(self) -> None:
        assert "bom" in _CATEGORY_MAP

    def test_has_xml(self) -> None:
        assert "xml" in _CATEGORY_MAP

    def test_has_mixed(self) -> None:
        assert "mixed" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestCharsetBypassAttempt:
    """Testes para CharsetBypassAttempt dataclass."""

    def test_creation(self) -> None:
        att = CharsetBypassAttempt(
            technique="meta_charset_utf7",
            category="meta",
            url="https://example.com",
            payload="charset=utf-7",
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
        assert att.technique == "meta_charset_utf7"
        assert att.status_changed is True
        assert att.vulnerable is False

    def test_frozen(self) -> None:
        att = CharsetBypassAttempt(
            technique="t", category="c", url="u", payload="p",
            status_baseline=200, status_test=200,
            size_baseline=100, size_test=100,
            status_changed=False, size_changed=False,
            vulnerable=False, details="d", error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "new"  # type: ignore[misc]


class TestCharsetBypassResult:
    """Testes para CharsetBypassResult dataclass."""

    def test_creation(self) -> None:
        result = CharsetBypassResult(
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


class TestTestMetaCharset:
    """Testes para _test_meta_charset."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_meta_charset(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) > 0
        assert all(isinstance(a, CharsetBypassAttempt) for a in attempts)


class TestTestContentTypeCharset:
    """Testes para _test_content_type_charset."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_content_type_charset(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 4


class TestTestBomCharset:
    """Testes para _test_bom_charset."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_bom_charset(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 3


class TestTestXmlCharset:
    """Testes para _test_xml_charset."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_xml_charset(
            client, "https://example.com", (200, 1000, b""),
        )
        assert len(attempts) == 3


class TestTestMixedCharset:
    """Testes para _test_mixed_charset."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_mixed_charset(
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
        args = parser.parse_args(["https://example.com", "-c", "meta"])
        assert args.category == "meta"

    def test_has_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--concurrency", "10"])
        assert args.concurrency == 10

    def test_category_choices(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "mixed"])
        assert args.category == "mixed"


class TestPrintResults:
    """Testes para print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CharsetBypassResult(
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
        assert "CHARSET" in captured.out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CharsetBypassResult(
            target="https://example.com",
            baseline_status=404,
            baseline_size=100,
            tls=False,
            attempts=[],
            vulnerable_techniques=["meta_charset_utf7"],
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
        with patch("sys.argv", ["mytools-charsetbypass"]), \
             patch("mytools.web.charsetbypass.run_main_loop", return_value=1) as mock_loop:
            result = main()
            assert result == 1
            mock_loop.assert_called_once()
