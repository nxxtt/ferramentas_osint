#!/usr/bin/env python3
"""Testes unitarios do modulo de RTL Override."""
import argparse
from unittest.mock import patch

import pytest

from mytools.web.rtloverride import (
    _RTL_CHARS,
    RTLAttempt,
    RTLResult,
    _generate_variants,
    _insert_rtl,
    _make_display,
    build_parser,
    detect_rtl,
    main,
    print_results,
)


class TestRTLChars:
    """Testes para _RTL_CHARS."""

    def test_has_rlo(self) -> None:
        assert "rlo" in _RTL_CHARS
        assert _RTL_CHARS["rlo"] == "\u202e"

    def test_has_rle(self) -> None:
        assert "rle" in _RTL_CHARS

    def test_all_values_are_rtl(self) -> None:
        for key, char in _RTL_CHARS.items():
            code = ord(char)
            assert code in (0x202E, 0x202B, 0x202D, 0x2066, 0x2067, 0x2068, 0x2069), f"{key} nao e RTL"


class TestInsertRTL:
    """Testes para _insert_rtl."""

    def test_before_domain(self) -> None:
        result = _insert_rtl("https://evil.com/path", "\u202e", "before_domain")
        assert "\u202e" in result
        assert result.startswith("https://")

    def test_in_path(self) -> None:
        result = _insert_rtl("https://evil.com/a/b/c", "\u202e", "in_path")
        assert "\u202e" in result

    def test_before_path(self) -> None:
        result = _insert_rtl("https://evil.com/admin", "\u202e", "before_path")
        assert "\u202e" in result
        assert result.startswith("https://evil.com\u202e")

    def test_in_query(self) -> None:
        result = _insert_rtl("https://evil.com/path?q=test", "\u202e", "in_query")
        assert result.endswith("\u202e")


class TestGenerateVariants:
    """Testes para _generate_variants."""

    def test_generates_variants(self) -> None:
        variants = _generate_variants("https://example.com")
        assert len(variants) > 0

    def test_all_variants_different(self) -> None:
        variants = _generate_variants("https://example.com/a/b/c")
        urls = [v[3] for v in variants]
        assert len(urls) == len(set(urls))

    def test_variants_contain_rtl(self) -> None:
        variants = _generate_variants("https://example.com")
        for _label, rtl_char, _position, url in variants:
            assert rtl_char in url


class TestDetectRTL:
    """Testes para detect_rtl."""

    def test_detects_rlo(self) -> None:
        text = "hello\u202eworld"
        found = detect_rtl(text)
        assert len(found) == 1
        assert "RIGHT-TO-LEFT OVERRIDE" in found[0][0]

    def test_detects_multiple(self) -> None:
        text = "\u202e\u202btest"
        found = detect_rtl(text)
        assert len(found) == 2

    def test_no_rtl(self) -> None:
        found = detect_rtl("normal text")
        assert len(found) == 0

    def test_empty(self) -> None:
        found = detect_rtl("")
        assert len(found) == 0


class TestMakeDisplay:
    """Testes para _make_display."""

    def test_removes_rlo(self) -> None:
        result = _make_display("hello\u202eworld")
        assert result == "helloworld"

    def test_removes_all_rtl(self) -> None:
        result = _make_display("a\u202eb\u202bc\u202d")
        assert result == "abc"

    def test_no_rtl_unchanged(self) -> None:
        result = _make_display("normal text")
        assert result == "normal text"


class TestBuildParser:
    """Testes para build_parser."""

    def test_returns_parser(self) -> None:
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_url_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_mode_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-m", "gen"])
        assert args.mode == "gen"

    def test_default_mode_scan(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.mode == "scan"


class TestRTLAttempt:
    """Testes para RTLAttempt dataclass."""

    def test_frozen(self) -> None:
        att = RTLAttempt(
            technique="rlo", label="RTL Override", url_display="http://x.com",
            url_real="http://x.com", rtl_char="\u202e", position="before_domain",
            status_baseline=200, status_test=200, size_baseline=100, size_test=100,
            status_changed=False, size_changed=False, vulnerable=False,
            details="", error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "changed"  # type: ignore[misc]


class TestRTLResult:
    """Testes para RTLResult dataclass."""

    def test_frozen(self) -> None:
        result = RTLResult(
            target="http://x.com", baseline_status=200, baseline_size=100,
            tls=False, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="safe",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestPrintResults:
    """Testes para print_results."""

    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = RTLResult(
            target="https://example.com", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="blocked",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "BLOQUEADO" in captured.out

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = RTLResult(
            target="https://example.com", baseline_status=200, baseline_size=100,
            tls=True,
            attempts=[RTLAttempt(
                technique="rlo", label="RTL Override", url_display="https://example.com",
                url_real="https://example.com\u202eadmin", rtl_char="\u202e",
                position="before_domain", status_baseline=200, status_test=200,
                size_baseline=100, size_test=200, status_changed=False,
                size_changed=True, vulnerable=True, details="size changed", error="",
            )],
            vulnerable_techniques=["rlo"],
            blocked_techniques=[],
            issues=["1 tecnicas vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out


class TestMain:
    """Testes para main()."""

    def test_main_no_url(self) -> None:
        with patch("sys.argv", ["mytools-rtlo"]), patch("builtins.input", side_effect=EOFError("exit")):
            result = main()
            assert result == 0
