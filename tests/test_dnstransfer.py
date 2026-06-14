from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.zone

from dnstransfer import (
    AXFR_TIMEOUT,
    BANNER_ART,
    DNS_PORT,
    XfrResult,
    build_parser,
    get_nameservers,
    resolve_ns_to_ip,
    run_once,
    run_xfr_scan,
    try_zone_transfer,
)


class TestXfrResult:
    def test_frozen(self):
        result = XfrResult(domain="example.com", nameserver="ns1.example.com", ns_ip="1.2.3.4", zone_transferred=False)
        try:
            result.domain = "other.com"
            assert False, "Should be frozen"
        except AttributeError:
            pass

    def test_default_values(self):
        result = XfrResult(domain="example.com", nameserver="ns1.example.com", ns_ip="1.2.3.4", zone_transferred=False)
        assert result.record_count == 0
        assert result.records == []
        assert result.error == ""
        assert result.elapsed == 0.0

    def test_vulnerable_result(self):
        result = XfrResult(
            domain="example.com",
            nameserver="ns1.example.com",
            ns_ip="1.2.3.4",
            zone_transferred=True,
            record_count=50,
            records=["example.com. A 1.2.3.4", "www.example.com. A 1.2.3.5"],
            elapsed=0.5,
        )
        assert result.zone_transferred is True
        assert result.record_count == 50
        assert len(result.records) == 2

    def test_error_result(self):
        result = XfrResult(
            domain="example.com",
            nameserver="ns1.example.com",
            ns_ip="1.2.3.4",
            zone_transferred=False,
            error="AXFR recusado",
            elapsed=1.0,
        )
        assert result.zone_transferred is False
        assert result.error == "AXFR recusado"

    def test_records_default_factory(self):
        r1 = XfrResult(domain="a.com", nameserver="ns.a.com", ns_ip="1.1.1.1", zone_transferred=False)
        r2 = XfrResult(domain="b.com", nameserver="ns.b.com", ns_ip="2.2.2.2", zone_transferred=False)
        assert r1.records is not r2.records


class TestGetNameservers:
    @patch("dnstransfer.dns.resolver.resolve")
    def test_returns_sorted_ns_list(self, mock_resolve):
        rr1 = MagicMock()
        rr1.target = "ns2.example.com."
        rr2 = MagicMock()
        rr2.target = "ns1.example.com."
        mock_resolve.return_value = [rr1, rr2]

        result = get_nameservers("example.com")
        assert result == ["ns1.example.com", "ns2.example.com"]
        mock_resolve.assert_called_once_with("example.com", "NS")

    @patch("dnstransfer.dns.resolver.resolve")
    def test_strips_trailing_dot(self, mock_resolve):
        rr = MagicMock()
        rr.target = "ns.example.com."
        mock_resolve.return_value = [rr]

        result = get_nameservers("example.com")
        assert result == ["ns.example.com"]

    @patch("dnstransfer.dns.resolver.resolve", side_effect=dns.resolver.NoAnswer())
    def test_returns_empty_on_noanswer(self, mock_resolve):
        result = get_nameservers("example.com")
        assert result == []

    @patch("dnstransfer.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN())
    def test_returns_empty_on_nxdomain(self, mock_resolve):
        result = get_nameservers("nonexistent.com")
        assert result == []

    @patch("dnstransfer.dns.resolver.resolve", side_effect=dns.exception.DNSException("fail"))
    def test_returns_empty_on_dns_exception(self, mock_resolve):
        result = get_nameservers("example.com")
        assert result == []

    @patch("dnstransfer.dns.resolver.resolve")
    def test_multiple_ns(self, mock_resolve):
        rrs = [MagicMock(target=f"ns{i}.example.com.") for i in range(1, 5)]
        mock_resolve.return_value = rrs

        result = get_nameservers("example.com")
        assert len(result) == 4
        assert result == sorted(result)


class TestResolveNsToIp:
    @patch("dnstransfer.dns.resolver.resolve")
    def test_resolves_ip(self, mock_resolve):
        rr = MagicMock()
        rr.__str__ = lambda self: "1.2.3.4"
        mock_resolve.return_value = [rr]

        ip = resolve_ns_to_ip("ns1.example.com")
        assert ip == "1.2.3.4"
        mock_resolve.assert_called_once_with("ns1.example.com", "A")

    @patch("dnstransfer.dns.resolver.resolve", side_effect=dns.exception.DNSException("fail"))
    def test_raises_on_failure(self, mock_resolve):
        try:
            resolve_ns_to_ip("ns1.example.com")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "ns1.example.com" in str(e)


class TestTryZoneTransfer:
    @patch("dnstransfer.dns.query.inbound_xfr")
    def test_successful_transfer(self, mock_axfr):
        mock_zone = MagicMock()
        mock_zone.nodes = {}
        mock_axfr.return_value = mock_zone

        result = try_zone_transfer("example.com", "ns1.example.com", "1.2.3.4", timeout=5)
        assert result.zone_transferred is True
        assert result.record_count == 0
        assert result.elapsed >= 0

    @patch("dnstransfer.dns.query.inbound_xfr")
    def test_successful_transfer_with_records(self, mock_axfr):
        import dns.rdataset
        import dns.rdata

        mock_zone = MagicMock()
        mock_node = MagicMock()

        mock_rdataset = MagicMock()
        mock_rdataset.rdtype = dns.rdatatype.A
        mock_rdataset.__iter__ = lambda self: iter([MagicMock(__str__=lambda s: "1.2.3.4")])

        mock_node.rdatasets = [mock_rdataset]
        mock_zone.nodes = {dns.name.from_text("example.com."): mock_node}
        mock_axfr.return_value = mock_zone

        result = try_zone_transfer("example.com", "ns1.example.com", "1.2.3.4", timeout=5)
        assert result.zone_transferred is True
        assert result.record_count >= 1

    @patch("dnstransfer.dns.query.inbound_xfr", return_value=None)
    def test_empty_zone_returns_not_transferred(self, mock_axfr):
        result = try_zone_transfer("example.com", "ns1.example.com", "1.2.3.4", timeout=5)
        assert result.zone_transferred is False
        assert "vazia" in result.error

    @patch("dnstransfer.dns.query.inbound_xfr", side_effect=dns.exception.FormError("refused"))
    def test_form_error_means_refused(self, mock_axfr):
        result = try_zone_transfer("example.com", "ns1.example.com", "1.2.3.4", timeout=5)
        assert result.zone_transferred is False
        assert "recusado" in result.error

    @patch("dnstransfer.dns.query.inbound_xfr", side_effect=dns.exception.Timeout())
    def test_timeout_error(self, mock_axfr):
        result = try_zone_transfer("example.com", "ns1.example.com", "1.2.3.4", timeout=1)
        assert result.zone_transferred is False
        assert "timeout" in result.error.lower()

    @patch("dnstransfer.dns.query.inbound_xfr", side_effect=dns.exception.DNSException("generic"))
    def test_dns_exception(self, mock_axfr):
        result = try_zone_transfer("example.com", "ns1.example.com", "1.2.3.4", timeout=5)
        assert result.zone_transferred is False
        assert "DNS" in result.error

    @patch("dnstransfer.dns.query.inbound_xfr", side_effect=RuntimeError("unexpected"))
    def test_generic_exception(self, mock_axfr):
        result = try_zone_transfer("example.com", "ns1.example.com", "1.2.3.4", timeout=5)
        assert result.zone_transferred is False
        assert "inesperado" in result.error

    @patch("dnstransfer.dns.query.inbound_xfr")
    def test_elapsed_time_tracked(self, mock_axfr):
        mock_zone = MagicMock()
        mock_zone.nodes = {}
        mock_axfr.return_value = mock_zone

        result = try_zone_transfer("example.com", "ns1.example.com", "1.2.3.4", timeout=5)
        assert result.elapsed >= 0.0

    @patch("dnstransfer.dns.query.inbound_xfr")
    def test_stores_domain_and_ns(self, mock_axfr):
        mock_zone = MagicMock()
        mock_zone.nodes = {}
        mock_axfr.return_value = mock_zone

        result = try_zone_transfer("test.com", "ns2.test.com", "5.6.7.8", timeout=5)
        assert result.domain == "test.com"
        assert result.nameserver == "ns2.test.com"
        assert result.ns_ip == "5.6.7.8"


class TestRunXfrScan:
    @patch("dnstransfer.get_nameservers", return_value=[])
    def test_empty_ns_list(self, mock_ns):
        results = run_xfr_scan("example.com")
        assert results == []

    @patch("dnstransfer.resolve_ns_to_ip", side_effect=ValueError("fail"))
    @patch("dnstransfer.get_nameservers", return_value=["ns1.example.com"])
    def test_ns_resolution_failure(self, mock_ns, mock_ip):
        results = run_xfr_scan("example.com")
        assert len(results) == 1
        assert results[0].zone_transferred is False
        assert "fail" in results[0].error

    @patch("dnstransfer.try_zone_transfer")
    @patch("dnstransfer.resolve_ns_to_ip", return_value="1.2.3.4")
    @patch("dnstransfer.get_nameservers", return_value=["ns1.example.com", "ns2.example.com"])
    def test_multiple_ns(self, mock_ns, mock_ip, mock_xfr):
        mock_xfr.return_value = XfrResult(
            domain="example.com", nameserver="ns1.example.com", ns_ip="1.2.3.4", zone_transferred=False,
        )
        results = run_xfr_scan("example.com")
        assert len(results) == 2
        assert mock_xfr.call_count == 2

    @patch("dnstransfer.try_zone_transfer")
    @patch("dnstransfer.resolve_ns_to_ip", return_value="1.2.3.4")
    @patch("dnstransfer.get_nameservers", return_value=["ns1.example.com"])
    def test_vulnerable_detected(self, mock_ns, mock_ip, mock_xfr):
        mock_xfr.return_value = XfrResult(
            domain="example.com", nameserver="ns1.example.com", ns_ip="1.2.3.4",
            zone_transferred=True, record_count=10, records=["a A 1.2.3.4"],
        )
        results = run_xfr_scan("example.com")
        assert results[0].zone_transferred is True
        assert results[0].record_count == 10

    def test_raises_on_empty_domain(self):
        try:
            run_xfr_scan("  ")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass


class TestBuildParser:
    def test_has_domain_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_timeout_default(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.timeout == AXFR_TIMEOUT

    def test_timeout_custom(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "-t", "20"])
        assert args.timeout == 20.0

    def test_output_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "-o", "result.json"])
        assert args.output == "result.json"

    def test_verbose_flag(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "-v"])
        assert args.verbose is True

    def test_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "-q"])
        assert args.quiet is True

    def test_color_flags(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--color"])
        assert args.color is True
        args2 = parser.parse_args(["example.com", "--no-color"])
        assert args2.color is False

    def test_version_flag(self):
        parser = build_parser()
        try:
            parser.parse_args(["--version"])
            assert False, "Should have raised SystemExit"
        except SystemExit:
            pass

    def test_no_args_domain_is_none(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.domain is None


class TestRunOnce:
    @patch("dnstransfer.run_xfr_scan")
    def test_returns_0_when_not_vulnerable(self, mock_scan):
        mock_scan.return_value = [
            XfrResult(domain="example.com", nameserver="ns1.example.com", ns_ip="1.2.3.4", zone_transferred=False),
        ]
        args = build_parser().parse_args(["example.com"])
        result = run_once(args)
        assert result == 0

    @patch("dnstransfer.run_xfr_scan")
    def test_returns_1_when_vulnerable(self, mock_scan):
        mock_scan.return_value = [
            XfrResult(domain="example.com", nameserver="ns1.example.com", ns_ip="1.2.3.4", zone_transferred=True, record_count=5),
        ]
        args = build_parser().parse_args(["example.com"])
        result = run_once(args)
        assert result == 1

    @patch("dnstransfer.write_output")
    @patch("dnstransfer.run_xfr_scan")
    def test_saves_output(self, mock_scan, mock_write):
        mock_scan.return_value = [
            XfrResult(domain="example.com", nameserver="ns1.example.com", ns_ip="1.2.3.4", zone_transferred=False),
        ]
        args = build_parser().parse_args(["example.com", "-o", "out.json"])
        run_once(args)
        mock_write.assert_called_once()

    @patch("dnstransfer.run_xfr_scan")
    def test_negative_timeout_raises(self, mock_scan):
        args = build_parser().parse_args(["example.com", "-t", "-1"])
        try:
            run_once(args)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    @patch("dnstransfer.run_xfr_scan")
    def test_quiet_mode(self, mock_scan, capsys):
        mock_scan.return_value = [
            XfrResult(domain="example.com", nameserver="ns1.example.com", ns_ip="1.2.3.4", zone_transferred=False),
        ]
        args = build_parser().parse_args(["example.com", "-q", "-o", "out.json"])
        run_once(args)
        captured = capsys.readouterr()
        assert captured.out == ""


class TestBannerAndConstants:
    def test_banner_art_exists(self):
        assert isinstance(BANNER_ART, str)
        assert len(BANNER_ART) > 10

    def test_axfr_timeout_positive(self):
        assert AXFR_TIMEOUT > 0

    def test_dns_port_is_53(self):
        assert DNS_PORT == 53
