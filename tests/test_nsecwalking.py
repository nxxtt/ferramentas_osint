#!/usr/bin/env python3
"""Testes unitarios do modulo de NSEC Walking."""
from unittest.mock import MagicMock, patch

import pytest

from nsecwalking import (
    NsecEntry,
    NsecResult,
    _parse_nsec_types,
    _random_label,
    build_parser,
    print_results,
    scan_nsec,
)


class TestNsecEntry:
    """Testes do dataclass NsecEntry."""

    def test_frozen(self) -> None:
        e = NsecEntry(name="a", next_name="b", record_types=["A"])
        with pytest.raises(AttributeError):
            e.name = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(NsecEntry, "__slots__")


class TestNsecResult:
    """Testes do dataclass NsecResult."""

    def test_frozen(self) -> None:
        r = NsecResult(
            domain="a", names_found=[], total_names=0,
            has_nsec3=False, zone_enumerated=False,
            entries=[], max_hops=0, hops_used=0,
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(NsecResult, "__slots__")


class TestRandomLabel:
    """Testes da funcao _random_label."""

    def test_length(self) -> None:
        label = _random_label(10)
        assert len(label) == 10

    def test_alphabetic(self) -> None:
        label = _random_label(20)
        assert label.isalpha()

    def test_lowercase(self) -> None:
        label = _random_label(20)
        assert label == label.lower()


class TestParseNsecTypes:
    """Testes da funcao _parse_nsec_types."""

    def test_empty(self) -> None:
        assert _parse_nsec_types("") == []

    def test_known_types(self) -> None:
        result = _parse_nsec_types("A NS SOA MX")
        assert "A" in result
        assert "NS" in result

    def test_unknown_types(self) -> None:
        result = _parse_nsec_types("TYPE255 TYPE256")
        assert len(result) == 2


class TestParser:
    """Testes do build_parser."""

    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_nameserver(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--nameserver", "1.1.1.1"])
        assert args.nameserver == "1.1.1.1"

    def test_max_hops(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--max-hops", "100"])
        assert args.max_hops == 100

    def test_query_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "5.0"])
        assert args.query_timeout == 5.0


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_enumerated(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NsecResult(
            domain="example.com",
            names_found=["a.example.com", "b.example.com"],
            total_names=2,
            has_nsec3=False,
            zone_enumerated=True,
            entries=[
                NsecEntry("x.example.com", "a.example.com", ["A"]),
                NsecEntry("a.example.com", "b.example.com", ["A", "MX"]),
            ],
            max_hops=500, hops_used=2,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "NSEC Walking" in out
        assert "Enumerado: SIM" in out

    def test_nsec3(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NsecResult(
            domain="test.com", names_found=[], total_names=0,
            has_nsec3=True, zone_enumerated=False,
            entries=[], max_hops=500, hops_used=0,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "NSEC3 detectado" in out

    def test_empty(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NsecResult(
            domain="empty.com", names_found=[], total_names=0,
            has_nsec3=False, zone_enumerated=False,
            entries=[], max_hops=500, hops_used=0,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Nenhum registro NSEC" in out


class TestScanNsec:
    """Testes da funcao scan_nsec com mocks."""

    @patch("nsecwalking._query_nsec")
    def test_basic(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("x.example.com", "a.example.com", ["A"], False)
        result = scan_nsec("example.com", max_hops=3)
        assert result.total_names >= 0

    @patch("nsecwalking._query_nsec")
    def test_nsec3_detected(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("x.test.com", "", ["NSEC3"], True)
        result = scan_nsec("test.com")
        assert result.has_nsec3 is True
        assert result.zone_enumerated is False

    @patch("nsecwalking._query_nsec")
    def test_max_hops(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("x.example.com", "a.example.com", ["A"], False)
        result = scan_nsec("example.com", max_hops=2)
        assert result.hops_used <= 2

    @patch("nsecwalking._query_nsec")
    def test_empty_response(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("", "", [], False)
        result = scan_nsec("example.com")
        assert result.total_names == 0
