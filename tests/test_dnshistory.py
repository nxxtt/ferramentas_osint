import argparse
import json
from unittest.mock import MagicMock, patch

import pytest

from dnshistory import (
    BANNER_ART,
    DEFAULT_TIMEOUT,
    RECORD_TYPES,
    DnsHistoryRecord,
    _parse_dnslytics,
    _parse_securitytrails,
    _parse_viewdns,
    build_parser,
    run_history,
    run_once,
)


class TestDnsHistoryRecord:
    def test_frozen(self):
        r = DnsHistoryRecord(record_type="a", value="1.2.3.4", source="dnslytics")
        with pytest.raises(AttributeError):
            r.value = "5.6.7.8"

    def test_defaults(self):
        r = DnsHistoryRecord(record_type="a", value="1.2.3.4")
        assert r.first_seen is None
        assert r.last_seen is None
        assert r.location is None
        assert r.owner is None
        assert r.source == ""

    def test_all_fields(self):
        r = DnsHistoryRecord(
            record_type="mx",
            value="mail.example.com",
            first_seen="2020-01-01",
            last_seen="2024-12-31",
            location="US",
            owner="Cloudflare",
            source="viewdns",
        )
        assert r.first_seen == "2020-01-01"
        assert r.last_seen == "2024-12-31"


class TestParseDnslytics:
    def test_extracts_ipv4(self):
        data = {
            "status": "succeed",
            "data": {
                "ipv4": [{"ip": "1.2.3.4", "updatedate": "2023-06-15"}],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "a"
        assert result[0].value == "1.2.3.4"
        assert result[0].last_seen == "2023-06-15"

    def test_extracts_ipv6(self):
        data = {
            "status": "succeed",
            "data": {
                "ipv6": [{"ip": "2001:db8::1", "updatedate": "2023-01-01"}],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "aaaa"

    def test_extracts_ns(self):
        data = {
            "status": "succeed",
            "data": {
                "dns": [{"dns": "ns1.example.com", "updatedate": "2022-05-10"}],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "ns"
        assert result[0].value == "ns1.example.com"

    def test_extracts_mx(self):
        data = {
            "status": "succeed",
            "data": {
                "mx": [{"mx": "mx1.example.com", "updatedate": "2023-03-01"}],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "mx"

    def test_extracts_spf(self):
        data = {
            "status": "succeed",
            "data": {
                "spf": [{"record": "v=spf1 include:_spf.example.com ~all", "updatedate": "2023-07-01"}],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "txt"

    def test_failed_status_returns_empty(self):
        data = {"status": "failed", "data": {}}
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert result == []

    def test_invalid_json_returns_empty(self):
        result = _parse_dnslytics(b"not json", "example.com")
        assert result == []

    def test_empty_data_returns_empty(self):
        data = {"status": "succeed", "data": {}}
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert result == []


class TestParseSecuritytrails:
    def test_extracts_records(self):
        data = {
            "type": "a/ipv4",
            "records": [
                {
                    "first_seen": "2020-01-01",
                    "last_seen": "2024-06-01",
                    "organizations": ["Amazon"],
                    "values": [{"ip": "52.1.2.3"}],
                },
            ],
        }
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "a"
        assert result[0].value == "52.1.2.3"
        assert result[0].first_seen == "2020-01-01"
        assert result[0].owner == "Amazon"

    def test_multiple_values(self):
        data = {
            "type": "ns",
            "records": [
                {
                    "first_seen": "2021-01-01",
                    "last_seen": None,
                    "organizations": [],
                    "values": [{"host": "ns1.example.com"}, {"host": "ns2.example.com"}],
                },
            ],
        }
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert len(result) == 2
        assert result[0].value == "ns1.example.com"
        assert result[1].value == "ns2.example.com"

    def test_invalid_json_returns_empty(self):
        result = _parse_securitytrails(b"bad", "example.com")
        assert result == []

    def test_empty_records(self):
        data = {"type": "a/ipv4", "records": []}
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert result == []


class TestParseViewdns:
    def test_extracts_records(self):
        data = {
            "response": {
                "records": [
                    {"ip": "104.18.42.197", "lastseen": "2024-09-20", "owner": "Cloudflare", "location": "US"},
                ],
            },
        }
        result = _parse_viewdns(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "a"
        assert result[0].value == "104.18.42.197"
        assert result[0].owner == "Cloudflare"
        assert result[0].location == "US"

    def test_invalid_json_returns_empty(self):
        result = _parse_viewdns(b"bad", "example.com")
        assert result == []

    def test_empty_records(self):
        data = {"response": {"records": []}}
        result = _parse_viewdns(json.dumps(data).encode(), "example.com")
        assert result == []


class TestBuildParser:
    def test_returns_parser(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_domain_positional(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_has_source_flag(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--source", "dnslytics"])
        assert args.source == ["dnslytics"]

    def test_has_source_multiple(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--source", "dnslytics", "--source", "securitytrails"])
        assert args.source == ["dnslytics", "securitytrails"]

    def test_has_st_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--st-api-key", "abc123"])
        assert args.st_api_key == "abc123"

    def test_has_viewdns_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--viewdns-api-key", "xyz789"])
        assert args.viewdns_key == "xyz789"

    def test_has_record_types(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--record-types", "a,mx,ns"])
        assert args.record_types == "a,mx,ns"

    def test_default_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.timeout == DEFAULT_TIMEOUT


class TestRunOnce:
    def test_returns_zero(self, capsys):
        args = argparse.Namespace(
            domain="example.com", source=None, dnslytics_key=None,
            st_api_key=None, viewdns_key=None, record_types=None,
            timeout=5.0, dry_run=False, output=None, verbose=False,
            quiet=False, color=None, log_file=None,
        )
        with patch("dnshistory.run_history", return_value=[]):
            result = run_once(args)
        assert result == 0

    def test_dry_run(self, capsys):
        args = argparse.Namespace(
            domain="example.com", source=["dnslytics"], dnslytics_key=None,
            st_api_key=None, viewdns_key=None, record_types=None,
            timeout=5.0, dry_run=True, output=None, verbose=False,
            quiet=False, color=None, log_file=None,
        )
        result = run_once(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "DRY-RUN" in captured.out
        assert "example.com" in captured.out

    def test_saves_output(self, capsys, tmp_path):
        out_file = str(tmp_path / "history.json")
        args = argparse.Namespace(
            domain="example.com", source=None, dnslytics_key=None,
            st_api_key=None, viewdns_key=None, record_types=None,
            timeout=5.0, dry_run=False, output=out_file, verbose=False,
            quiet=False, color=None, log_file=None,
        )
        with patch("dnshistory.run_history", return_value=[
            DnsHistoryRecord(record_type="a", value="1.2.3.4", source="test"),
        ]):
            result = run_once(args)
        assert result == 0

    def test_with_records_prints_table(self, capsys):
        args = argparse.Namespace(
            domain="example.com", source=None, dnslytics_key=None,
            st_api_key=None, viewdns_key=None, record_types=None,
            timeout=5.0, dry_run=False, output=None, verbose=False,
            quiet=False, color=None, log_file=None,
        )
        records = [
            DnsHistoryRecord(record_type="a", value="1.2.3.4", last_seen="2024-01-01", source="dnslytics"),
            DnsHistoryRecord(record_type="ns", value="ns1.example.com", source="dnslytics"),
        ]
        with patch("dnshistory.run_history", return_value=records):
            result = run_once(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "1.2.3.4" in captured.out
        assert "ns1.example.com" in captured.out


class TestRunHistory:
    def test_empty_sources_returns_empty(self):
        result = run_history("example.com", sources=[])
        assert result == []

    @patch("dnshistory._query_all_sources", new_callable=MagicMock)
    @patch("utils.safe_asyncio_run")
    def test_calls_with_correct_sources(self, mock_run, mock_async):
        mock_run.return_value = [
            DnsHistoryRecord(record_type="a", value="1.2.3.4", source="test"),
        ]
        result = run_history("example.com", sources=["dnslytics"])
        assert len(result) == 1
        assert result[0].value == "1.2.3.4"


class TestConstants:
    def test_banner_not_empty(self):
        assert len(BANNER_ART) > 0

    def test_record_types(self):
        assert "a" in RECORD_TYPES
        assert "mx" in RECORD_TYPES
        assert "ns" in RECORD_TYPES

    def test_default_timeout_positive(self):
        assert DEFAULT_TIMEOUT > 0


class TestMain:
    def test_no_domain_shells_interactive(self):
        with patch("dnshistory.run_main_loop", return_value=0) as mock_loop:
            from dnshistory import main
            with patch("sys.argv", ["mytools-dnshistory"]):
                result = main()
            assert result == 0
            mock_loop.assert_called_once()

    def test_valid_domain_calls_run_once(self):
        with patch("dnshistory.run_main_loop"):
            with patch("dnshistory.run_once", return_value=0) as mock_run:
                from dnshistory import main
                with patch("sys.argv", ["mytools-dnshistory", "example.com"]):
                    result = main()
            assert result == 0
            mock_run.assert_called_once()
