#!/usr/bin/env python3
"""Testes unitarios do modulo de Case Variation Bypass."""
import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.casevariationbypass import (
    _CATEGORY_MAP,
    CaseVariationAttempt,
    CaseVariationResult,
    _test_baseline,
    _test_cookie_case,
    _test_extension_case,
    _test_header_case,
    _test_param_case,
    _test_path_case,
    build_parser,
    main,
    print_results,
    scan_case_variation,
)


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_all_categories_present(self) -> None:
        expected = {"path", "param", "header", "extension", "cookie"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_categories_have_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) > 0, f"Categoria {cat} vazia"

    def test_all_techniques_unique(self) -> None:
        all_techs: list[str] = []
        for techs in _CATEGORY_MAP.values():
            all_techs.extend(techs)
        assert len(all_techs) == len(set(all_techs))


class TestBuildParser:
    """Testes para build_parser."""

    def test_returns_parser(self) -> None:
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_url_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_category_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "path"])
        assert args.category == "path"

    def test_has_concurrency_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--concurrency", "10"])
        assert args.concurrency == 10

    def test_invalid_category_rejected(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["https://example.com", "-c", "invalid"])


class TestTestBaseline:
    """Testes para _test_baseline."""

    @pytest.mark.asyncio
    async def test_baseline_success(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        status, size, body = await _test_baseline(mock_client, "https://example.com")
        assert status == 200
        assert size == 15
        assert body == b"<html>OK</html>"

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        status, size, body = await _test_baseline(mock_client, "https://example.com")
        assert status == 0
        assert size == 0
        assert body == b""


class TestTestPathCase:
    """Testes para _test_path_case."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b"Not Found"
        mock_client.get.return_value = mock_resp

        attempts = await _test_path_case(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) == 9
        assert all(isinstance(a, CaseVariationAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_all_path_category(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b"Not Found"
        mock_client.get.return_value = mock_resp

        attempts = await _test_path_case(mock_client, "https://example.com", (200, 15, b""))
        assert all(a.category == "path" for a in attempts)


class TestTestParamCase:
    """Testes para _test_param_case."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_param_case(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) == 6
        assert all(a.category == "param" for a in attempts)


class TestTestHeaderCase:
    """Testes para _test_header_case."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_header_case(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) == 4
        assert all(a.category == "header" for a in attempts)


class TestTestExtensionCase:
    """Testes para _test_extension_case."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b"Not Found"
        mock_client.get.return_value = mock_resp

        attempts = await _test_extension_case(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) == 8
        assert all(a.category == "extension" for a in attempts)


class TestTestCookieCase:
    """Testes para _test_cookie_case."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_cookie_case(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) == 6
        assert all(a.category == "cookie" for a in attempts)


class TestScanCaseVariation:
    """Testes para scan_case_variation."""

    @pytest.mark.asyncio
    async def test_invalid_category(self) -> None:
        result = await scan_case_variation("https://example.com", category="invalid")
        assert result.overall_status == "error"
        assert any("Categoria desconhecida" in i for i in result.issues)

    @pytest.mark.asyncio
    async def test_returns_result(self) -> None:
        result = await scan_case_variation("https://example.com", category="path")
        assert isinstance(result, CaseVariationResult)
        assert result.target == "https://example.com"

    @pytest.mark.asyncio
    async def test_tls_detected(self) -> None:
        result = await scan_case_variation("https://example.com", category="path")
        assert result.tls is True

    @pytest.mark.asyncio
    async def test_no_tls(self) -> None:
        result = await scan_case_variation("http://example.com", category="path")
        assert result.tls is False


class TestCaseVariationAttempt:
    """Testes para CaseVariationAttempt dataclass."""

    def test_frozen(self) -> None:
        att = CaseVariationAttempt(
            technique="test", category="path", url="http://x.com",
            payload="/Admin", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "changed"  # type: ignore[misc]

    def test_slots(self) -> None:
        att = CaseVariationAttempt(
            technique="test", category="path", url="http://x.com",
            payload="/Admin", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        assert not hasattr(att, "__dict__")


class TestCaseVariationResult:
    """Testes para CaseVariationResult dataclass."""

    def test_frozen(self) -> None:
        result = CaseVariationResult(
            target="http://x.com", baseline_status=200, baseline_size=100,
            tls=False, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]

    def test_overall_status_values(self) -> None:
        for status in ["vulnerable", "blocked", "secure", "error"]:
            result = CaseVariationResult(
                target="http://x.com", baseline_status=200, baseline_size=100,
                tls=False, attempts=[], vulnerable_techniques=[],
                blocked_techniques=[], issues=[], overall_status=status,
            )
            assert result.overall_status == status


class TestPrintResults:
    """Testes para print_results."""

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CaseVariationResult(
            target="https://example.com", baseline_status=200, baseline_size=100,
            tls=True,
            attempts=[CaseVariationAttempt(
                technique="path_upper", category="path", url="https://example.com/ADMIN",
                payload="/ADMIN", status_baseline=200, status_test=200,
                size_baseline=100, size_test=200, status_changed=True,
                size_changed=True, vulnerable=True, details="Mudanca detectada", error="",
            )],
            vulnerable_techniques=["path_upper"],
            blocked_techniques=[],
            issues=["1 tecnicas vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "CASE VARIATION" in captured.out
        assert "VULNERAVEL" in captured.out

    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CaseVariationResult(
            target="https://example.com", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "SECURE" in captured.out


class TestMain:
    """Testes para main()."""

    def test_main_no_url(self) -> None:
        with patch("sys.argv", ["mytools-casevar"]), patch("builtins.input", side_effect=EOFError("exit")):
            result = main()
            assert result == 0
