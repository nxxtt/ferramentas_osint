#!/usr/bin/env python3
"""Testes unitarios do modulo de CAA Record Check."""
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from caacheck import (
    CaaRecord,
    CaaResult,
    _identify_ca,
    _parse_caa_rdata,
    build_parser,
    print_results,
    scan_caa,
)


class TestCaaRecord:
    """Testes do dataclass CaaRecord."""

    def test_frozen(self) -> None:
        r = CaaRecord(tag="issue", value="letsencrypt.org", flags=0)
        with pytest.raises(AttributeError):
            r.tag = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(CaaRecord, "__slots__")


class TestCaaResult:
    """Testes do dataclass CaaResult."""

    def test_frozen(self) -> None:
        r = CaaResult(
            domain="a", records=[], has_caa=False,
            authorized_cas=[], has_iodef=False, policy_status="none",
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(CaaResult, "__slots__")


class TestIdentifyCa:
    """Testes da funcao _identify_ca."""

    def test_letsencrypt(self) -> None:
        assert _identify_ca("letsencrypt.org") == "Let's Encrypt"

    def test_digicert(self) -> None:
        assert _identify_ca("digicert.com") == "DigiCert"

    def test_unknown(self) -> None:
        assert _identify_ca("unknown-ca.com") == "unknown-ca.com"

    def test_with_dot(self) -> None:
        assert _identify_ca("letsencrypt.org.") == "Let's Encrypt"


class TestParseCaaRdata:
    """Testes da funcao _parse_caa_rdata."""

    def test_valid(self) -> None:
        result = _parse_caa_rdata('0 issue "letsencrypt.org"')
        assert result is not None
        assert result.tag == "issue"
        assert result.value == "letsencrypt.org"
        assert result.flags == 0

    def test_issuewild(self) -> None:
        result = _parse_caa_rdata('0 issuewild "digicert.com"')
        assert result is not None
        assert result.tag == "issuewild"

    def test_iodef(self) -> None:
        result = _parse_caa_rdata('0 iodef "mailto:admin@example.com"')
        assert result is not None
        assert result.tag == "iodef"

    def test_critical(self) -> None:
        result = _parse_caa_rdata('128 issue "letsencrypt.org"')
        assert result is not None
        assert result.flags == 128

    def test_invalid(self) -> None:
        result = _parse_caa_rdata("invalid")
        assert result is None


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

    def test_query_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "10.0"])
        assert args.query_timeout == 10.0


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_no_caa(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CaaResult(
            domain="test.com", records=[], has_caa=False,
            authorized_cas=[], has_iodef=False, policy_status="none",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "CAA Record Check" in out
        assert "NAO" in out

    def test_restrictive(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CaaResult(
            domain="secure.com",
            records=[CaaRecord("issue", "letsencrypt.org", 0)],
            has_caa=True, authorized_cas=["Let's Encrypt"],
            has_iodef=False, policy_status="restrictive",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "RESTRITIVA" in out or "restrictive" in out.lower()

    def test_permissive(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CaaResult(
            domain="open.com",
            records=[
                CaaRecord("issue", "letsencrypt.org", 0),
                CaaRecord("issue", "digicert.com", 0),
                CaaRecord("issue", "globalsign.com", 0),
            ],
            has_caa=True, authorized_cas=["DigiCert", "GlobalSign", "Let's Encrypt"],
            has_iodef=True, policy_status="permissive",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "PERMISSIVA" in out or "permissive" in out.lower()


class TestScanCaa:
    """Testes da funcao scan_caa com mocks."""

    @patch("caacheck.dns.resolver.Resolver")
    def test_no_caa(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        result = scan_caa("test.com")
        assert result.has_caa is False
        assert result.policy_status == "none"

    def test_empty_domain(self) -> None:
        result = scan_caa("")
        assert result.has_caa is False
