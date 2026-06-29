#!/usr/bin/env python3
"""Testes unitarios do modulo de DNS Rebinding Detection."""
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from dnsrebinding import (
    RebindingResult,
    _check_private_ips,
    _check_ttl,
    _is_cloud_metadata,
    _is_private_ip,
    build_parser,
    print_results,
    scan_rebinding,
)


class TestRebindingResult:
    """Testes do dataclass RebindingResult."""

    def test_frozen(self) -> None:
        r = RebindingResult(domain="a", check="b", severity="c", detail="d")
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(RebindingResult, "__slots__")

    def test_default_records(self) -> None:
        r = RebindingResult(domain="a", check="b", severity="c", detail="d")
        assert r.records == []


class TestIsPrivateIp:
    """Testes da funcao _is_private_ip."""

    def test_private_10(self) -> None:
        assert _is_private_ip("10.0.0.1")

    def test_private_172(self) -> None:
        assert _is_private_ip("172.16.0.1")

    def test_private_192(self) -> None:
        assert _is_private_ip("192.168.1.1")

    def test_loopback(self) -> None:
        assert _is_private_ip("127.0.0.1")

    def test_link_local(self) -> None:
        assert _is_private_ip("169.254.169.254")

    def test_carrier_grade(self) -> None:
        assert _is_private_ip("100.64.0.1")

    def test_public(self) -> None:
        assert not _is_private_ip("8.8.8.8")

    def test_public_2(self) -> None:
        assert not _is_private_ip("1.1.1.1")

    def test_invalid(self) -> None:
        assert not _is_private_ip("not-an-ip")


class TestIsCloudMetadata:
    """Testes da funcao _is_cloud_metadata."""

    def test_aws(self) -> None:
        assert _is_cloud_metadata("169.254.169.254")

    def test_alibaba(self) -> None:
        assert _is_cloud_metadata("100.100.100.200")

    def test_not_metadata(self) -> None:
        assert not _is_cloud_metadata("8.8.8.8")


class TestCheckTtl:
    """Testes da funcao _check_ttl."""

    def _make_answers(self, ttl: int) -> MagicMock:
        mock_answers = MagicMock()
        mock_answers.rrset.ttl = ttl
        return mock_answers

    def test_ttl_zero(self) -> None:
        result = _check_ttl("example.com", self._make_answers(0))
        assert result is not None
        assert result.severity == "critical"

    def test_ttl_one(self) -> None:
        result = _check_ttl("example.com", self._make_answers(1))
        assert result is not None
        assert result.severity == "high"

    def test_ttl_three(self) -> None:
        result = _check_ttl("example.com", self._make_answers(3))
        assert result is not None
        assert result.severity == "medium"

    def test_ttl_ten(self) -> None:
        result = _check_ttl("example.com", self._make_answers(10))
        assert result is not None
        assert result.severity == "low"

    def test_ttl_normal(self) -> None:
        result = _check_ttl("example.com", self._make_answers(3600))
        assert result is None


class TestCheckPrivateIps:
    """Testes da funcao _check_private_ips."""

    def _make_answers(self, ips: list[str]) -> MagicMock:
        mock_answers = MagicMock()
        rdatas = []
        for ip in ips:
            rdata = MagicMock()
            rdata.address = ip
            rdatas.append(rdata)
        mock_answers.__iter__ = MagicMock(return_value=iter(rdatas))
        return mock_answers

    def test_private_ip(self) -> None:
        results = _check_private_ips("example.com", self._make_answers(["192.168.1.1"]))
        assert len(results) == 1
        assert results[0].severity == "critical"

    def test_cloud_metadata(self) -> None:
        results = _check_private_ips("example.com", self._make_answers(["169.254.169.254"]))
        assert len(results) == 1
        assert results[0].severity == "critical"
        assert "cloud" in results[0].detail.lower()

    def test_public_ip(self) -> None:
        results = _check_private_ips("example.com", self._make_answers(["8.8.8.8"]))
        assert results == []

    def test_mixed(self) -> None:
        results = _check_private_ips("example.com", self._make_answers(["8.8.8.8", "192.168.1.1"]))
        assert len(results) == 1


class TestParser:
    """Testes do build_parser."""

    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_queries(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--queries", "10"])
        assert args.queries == 10

    def test_list_file(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-l", "domains.txt"])
        assert args.target_list == "domains.txt"


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_empty(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade" in out

    def test_with_vulns(self, capsys: pytest.CaptureFixture[str]) -> None:
        results = [
            RebindingResult(
                domain="example.com", check="ttl", severity="critical",
                detail="TTL=0", records=["TTL=0"],
            ),
        ]
        print_results(results)
        out = capsys.readouterr().out
        assert "1 vulnerabilidade" in out
        assert "CRITICAL" in out

    def test_with_info(self, capsys: pytest.CaptureFixture[str]) -> None:
        results = [
            RebindingResult(
                domain="example.com", check="resolve", severity="info",
                detail="Dominio nao existe",
            ),
        ]
        print_results(results)
        out = capsys.readouterr().out
        assert "1 info" in out


class TestScanRebinding:
    """Testes da funcao scan_rebinding com mocks DNS."""

    @patch("dnsrebinding.dns.resolver.Resolver")
    def test_nxdomain(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        results = scan_rebinding("nonexistent.example.com")
        assert len(results) == 1
        assert results[0].check == "resolve"
        assert results[0].severity == "info"

    @patch("dnsrebinding.dns.resolver.Resolver")
    def test_timeout(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()

        results = scan_rebinding("timeout.example.com")
        assert len(results) == 1
        assert results[0].check == "resolve"

    @patch("dnsrebinding._check_ip_flip")
    @patch("dnsrebinding._check_wildcard")
    @patch("dnsrebinding._check_cname_chain")
    @patch("dnsrebinding._check_private_ips")
    @patch("dnsrebinding._check_ttl")
    @patch("dnsrebinding.dns.resolver.Resolver")
    def test_normal_domain(
        self,
        mock_resolver_cls: MagicMock,
        mock_ttl: MagicMock,
        mock_private: MagicMock,
        mock_cname: MagicMock,
        mock_wildcard: MagicMock,
        mock_flip: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_answers = MagicMock()
        mock_answers.rrset.ttl = 3600
        mock_answers.__iter__ = MagicMock(return_value=iter([]))
        mock_resolver.resolve.return_value = mock_answers

        mock_ttl.return_value = None
        mock_private.return_value = []
        mock_cname.return_value = None
        mock_wildcard.return_value = None
        mock_flip.return_value = None

        results = scan_rebinding("example.com")
        assert results == []

    @patch("dnsrebinding._check_ip_flip")
    @patch("dnsrebinding._check_wildcard")
    @patch("dnsrebinding._check_cname_chain")
    @patch("dnsrebinding._check_private_ips")
    @patch("dnsrebinding._check_ttl")
    @patch("dnsrebinding.dns.resolver.Resolver")
    def test_vulnerable_domain(
        self,
        mock_resolver_cls: MagicMock,
        mock_ttl: MagicMock,
        mock_private: MagicMock,
        mock_cname: MagicMock,
        mock_wildcard: MagicMock,
        mock_flip: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_answers = MagicMock()
        mock_answers.rrset.ttl = 0
        mock_answers.__iter__ = MagicMock(return_value=iter([]))
        mock_resolver.resolve.return_value = mock_answers

        mock_ttl.return_value = RebindingResult(
            domain="example.com", check="ttl", severity="critical",
            detail="TTL=0", records=["TTL=0"],
        )
        mock_private.return_value = []
        mock_cname.return_value = None
        mock_wildcard.return_value = None
        mock_flip.return_value = None

        results = scan_rebinding("example.com")
        assert len(results) == 1
        assert results[0].severity == "critical"
