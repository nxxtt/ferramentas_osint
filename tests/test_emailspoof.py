#!/usr/bin/env python3
"""Testes unitarios do modulo de Email Spoofing."""
from unittest.mock import MagicMock, patch

import pytest

from emailsecurity import DmarcRecord, EmailSecurityResult, SpfRecord
from emailspoof import (
    SpoofResult,
    SpoofVector,
    _max_severity,
    analyze_spoofing,
    build_parser,
    print_results,
)


class TestSpoofVector:
    def test_frozen(self) -> None:
        v = SpoofVector(name="test", severity="high", description="d", remediation="r")
        with pytest.raises(AttributeError):
            v.name = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(SpoofVector, "__slots__")


class TestSpoofResult:
    def test_frozen(self) -> None:
        r = SpoofResult(domain="a", risk_score="none", vectors=[], issues=[],
                        spf_status="strict", dmarc_status="reject",
                        dkim_status="present", overall_protection="protected")
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(SpoofResult, "__slots__")


class TestMaxSeverity:
    def test_empty(self) -> None:
        assert _max_severity([]) == "none"

    def test_critical_wins(self) -> None:
        vectors = [
            SpoofVector("a", "low", "d", "r"),
            SpoofVector("b", "critical", "d", "r"),
            SpoofVector("c", "medium", "d", "r"),
        ]
        assert _max_severity(vectors) == "critical"

    def test_high_wins(self) -> None:
        vectors = [
            SpoofVector("a", "low", "d", "r"),
            SpoofVector("b", "high", "d", "r"),
        ]
        assert _max_severity(vectors) == "high"


class TestParser:
    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_nameserver(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--nameserver", "1.1.1.1"])
        assert args.nameserver == "1.1.1.1"

    def test_selectors(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--selectors", "a,b"])
        assert args.selectors == "a,b"

    def test_query_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "10.0"])
        assert args.query_timeout == 10.0


class TestAnalyzeSpoofing:
    """Testes da funcao analyze_spoofing com mocks."""

    @patch("emailspoof.scan_email_security")
    def test_no_records(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="bad.com", spf=None, dkim_selectors=[], dmarc=None,
            overall_status="critical", issues=[],
        )
        result = analyze_spoofing("bad.com")
        assert result.risk_score == "critical"
        assert result.overall_protection == "vulnerable"
        assert len(result.vectors) >= 2

    @patch("emailspoof.scan_email_security")
    def test_full_protection(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="good.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject; rua=mailto:d@example.com",
                              "reject", "reject", "mailto:d@example.com", 100),
            overall_status="secure",
            issues=[],
        )
        result = analyze_spoofing("good.com")
        assert result.risk_score == "none"
        assert result.overall_protection == "protected"
        assert len(result.vectors) == 0

    @patch("emailspoof.scan_email_security")
    def test_spf_plus_all(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="open.com",
            spf=SpfRecord("v=spf1 +all", "spf1", [], True, "+", []),
            dkim_selectors=[],
            dmarc=None,
            overall_status="critical",
            issues=[],
        )
        result = analyze_spoofing("open.com")
        assert result.risk_score == "critical"
        assert result.spf_status == "critical"
        assert any("SPF +all" in v.name for v in result.vectors)

    @patch("emailspoof.scan_email_security")
    def test_dmarc_none(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="weak.com",
            spf=SpfRecord("v=spf1 ~all", "spf1", [], True, "~", []),
            dkim_selectors=[],
            dmarc=DmarcRecord("v=DMARC1; p=none", "none", "none", "", 100),
            overall_status="warning",
            issues=[],
        )
        result = analyze_spoofing("weak.com")
        assert result.dmarc_status == "monitor_only"
        assert any("DMARC p=none" in v.name for v in result.vectors)

    @patch("emailspoof.scan_email_security")
    def test_dmarc_pct_low(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="partial.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject; pct=50", "reject", "reject", "", 50),
            overall_status="good",
            issues=[],
        )
        result = analyze_spoofing("partial.com")
        assert any("pct=50" in v.name for v in result.vectors)

    @patch("emailspoof.scan_email_security")
    def test_subdomain_sp_none(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="sub.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject; sp=none", "reject", "none", "", 100),
            overall_status="good",
            issues=[],
        )
        result = analyze_spoofing("sub.com")
        assert any("sp=none" in v.name for v in result.vectors)

    @patch("emailspoof.scan_email_security")
    def test_spf_softfail(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="soft.com",
            spf=SpfRecord("v=spf1 ~all", "spf1", [], True, "~", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject", "reject", "reject", "", 100),
            overall_status="good",
            issues=[],
        )
        result = analyze_spoofing("soft.com")
        assert result.spf_status == "softfail"

    @patch("emailspoof.scan_email_security")
    def test_dmarc_quarantine(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="q.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=quarantine", "quarantine", "quarantine", "", 100),
            overall_status="good",
            issues=[],
        )
        result = analyze_spoofing("q.com")
        assert result.dmarc_status == "quarantine"
        assert result.risk_score in ("none", "low")

    @patch("emailspoof.scan_email_security")
    def test_no_rua(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="nrua.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject", "reject", "reject", "", 100),
            overall_status="secure",
            issues=[],
        )
        result = analyze_spoofing("nrua.com")
        assert any("relatorio" in v.name.lower() for v in result.vectors)


class TestPrintResults:
    def test_protected(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SpoofResult(
            domain="ok.com", risk_score="none", vectors=[], issues=[],
            spf_status="strict", dmarc_status="reject",
            dkim_status="present", overall_protection="protected",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "PROTECTED" in out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SpoofResult(
            domain="bad.com", risk_score="critical",
            vectors=[SpoofVector("SPF +all", "critical", "desc", "fix")],
            issues=[], spf_status="critical", dmarc_status="missing",
            dkim_status="missing", overall_protection="vulnerable",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "VULNERAVEL" in out
        assert "SPF +all" in out


class TestEmailSecurityResult:
    """Verificar que emailsecurity dataclasses sao usadas corretamente."""
    def test_spoof_uses_base_result(self) -> None:
        from emailsecurity import EmailSecurityResult as ESR
        r = ESR(domain="x", spf=None, dkim_selectors=[], dmarc=None,
                overall_status="critical", issues=[])
        assert r.domain == "x"
