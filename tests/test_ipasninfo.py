import argparse
import json
from unittest.mock import patch

import pytest

from ipasninfo import (
    BANNER_ART,
    DEFAULT_TIMEOUT,
    IpAsnInfo,
    _parse_ipapi,
    _parse_ipapi_batch,
    _parse_ipwhois,
    build_parser,
    lookup_ip_asn,
    run_once,
)


class TestIpAsnInfo:
    def test_frozen(self):
        r = IpAsnInfo(ip="8.8.8.8", asn="AS15169")
        with pytest.raises(AttributeError):
            r.asn = "AS0000"

    def test_defaults(self):
        r = IpAsnInfo(ip="1.1.1.1")
        assert r.asn == ""
        assert r.org == ""
        assert r.isp == ""
        assert r.country == ""
        assert r.country_code == ""
        assert r.city == ""
        assert r.is_hosting is False
        assert r.is_proxy is False
        assert r.source == ""

    def test_all_fields(self):
        r = IpAsnInfo(
            ip="8.8.8.8",
            asn="AS15169",
            org="Google LLC",
            isp="Google LLC",
            country="United States",
            country_code="US",
            city="Mountain View",
            is_hosting=True,
            is_proxy=False,
            source="ipwhois",
        )
        assert r.asn == "AS15169"
        assert r.is_hosting is True


class TestParseIpwhois:
    def test_extracts_fields(self):
        data = {
            "ip": "8.8.8.8",
            "success": True,
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "connection": {
                "asn": 15169,
                "org": "Google LLC",
                "isp": "Google LLC",
            },
        }
        result = _parse_ipwhois(json.dumps(data).encode())
        assert result is not None
        assert result.ip == "8.8.8.8"
        assert result.asn == "AS15169"
        assert result.org == "Google LLC"
        assert result.isp == "Google LLC"
        assert result.country == "United States"
        assert result.city == "Mountain View"
        assert result.source == "ipwhois"

    def test_failure_returns_none(self):
        data = {"ip": "1.2.3.4", "success": False}
        result = _parse_ipwhois(json.dumps(data).encode())
        assert result is None

    def test_invalid_json(self):
        result = _parse_ipwhois(b"not json")
        assert result is None

    def test_missing_connection(self):
        data = {"ip": "8.8.8.8", "success": True}
        result = _parse_ipwhois(json.dumps(data).encode())
        assert result is not None
        assert result.asn == ""

    def test_asn_string(self):
        data = {
            "ip": "8.8.8.8",
            "success": True,
            "connection": {"asn": "AS15169"},
        }
        result = _parse_ipwhois(json.dumps(data).encode())
        assert result is not None
        assert result.asn == "AS15169"


class TestParseIpapi:
    def test_extracts_fields(self):
        data = {
            "query": "8.8.8.8",
            "status": "success",
            "as": "AS15169 Google LLC",
            "org": "Google LLC",
            "isp": "Google LLC",
            "country": "United States",
            "countryCode": "US",
            "city": "Mountain View",
            "hosting": True,
            "proxy": False,
        }
        result = _parse_ipapi(json.dumps(data).encode())
        assert result is not None
        assert result.ip == "8.8.8.8"
        assert result.asn == "AS15169"
        assert result.is_hosting is True
        assert result.source == "ipapi"

    def test_failure_returns_none(self):
        data = {"query": "1.2.3.4", "status": "fail"}
        result = _parse_ipapi(json.dumps(data).encode())
        assert result is None

    def test_invalid_json(self):
        result = _parse_ipapi(b"bad")
        assert result is None


class TestParseIpapiBatch:
    def test_extracts_multiple(self):
        items = [
            {
                "query": "8.8.8.8",
                "status": "success",
                "as": "AS15169 Google LLC",
                "isp": "Google LLC",
                "country": "United States",
                "countryCode": "US",
            },
            {
                "query": "1.1.1.1",
                "status": "success",
                "as": "AS13335 Cloudflare Inc.",
                "isp": "Cloudflare Inc.",
                "country": "Australia",
                "countryCode": "AU",
            },
        ]
        result = _parse_ipapi_batch(json.dumps(items).encode())
        assert len(result) == 2
        assert result[0].ip == "8.8.8.8"
        assert result[1].ip == "1.1.1.1"

    def test_filters_failed(self):
        items = [
            {"query": "8.8.8.8", "status": "success", "as": "AS15169"},
            {"query": "9.9.9.9", "status": "fail"},
        ]
        result = _parse_ipapi_batch(json.dumps(items).encode())
        assert len(result) == 1

    def test_empty_array(self):
        result = _parse_ipapi_batch(json.dumps([]).encode())
        assert result == []

    def test_invalid_json(self):
        result = _parse_ipapi_batch(b"bad")
        assert result == []

    def test_non_list(self):
        result = _parse_ipapi_batch(json.dumps({"status": "success"}).encode())
        assert result == []


class TestLookupIpAsn:
    def test_empty_returns_empty(self):
        result = lookup_ip_asn([])
        assert result == []

    def test_single_ip_calls_async(self):
        with patch("utils.safe_asyncio_run") as mock_run:
            mock_run.return_value = [IpAsnInfo(ip="8.8.8.8", asn="AS15169", source="ipwhois")]
            result = lookup_ip_asn(["8.8.8.8"])
            assert len(result) == 1
            mock_run.assert_called_once()


class TestBuildParser:
    def test_has_ips(self):
        parser = build_parser()
        args = parser.parse_args(["8.8.8.8"])
        assert args.ips == ["8.8.8.8"]

    def test_has_multiple_ips(self):
        parser = build_parser()
        args = parser.parse_args(["8.8.8.8", "1.1.1.1"])
        assert args.ips == ["8.8.8.8", "1.1.1.1"]

    def test_has_file(self):
        parser = build_parser()
        args = parser.parse_args(["-f", "ips.txt"])
        assert args.ip_file == "ips.txt"

    def test_has_batch_flag(self):
        parser = build_parser()
        args = parser.parse_args(["8.8.8.8", "--batch"])
        assert args.batch is True

    def test_ips_optional(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.ips == []

    def test_timeout_default(self):
        parser = build_parser()
        args = parser.parse_args(["8.8.8.8"])
        assert args.timeout == DEFAULT_TIMEOUT


class TestRunOnce:
    def _make_args(self, **overrides):
        parser = build_parser()
        defaults = vars(parser.parse_args(["8.8.8.8"]))
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_dry_run(self, capsys):
        args = self._make_args(dry_run=True)
        result = run_once(args)
        assert result == 0
        output = capsys.readouterr().out
        assert "DRY-RUN" in output

    def test_no_ips_returns_1(self, capsys):
        parser = build_parser()
        args = parser.parse_args([])
        # Force no file either
        args.ip_file = None
        result = run_once(args)
        assert result == 1

    def test_calls_lookup(self):
        args = self._make_args()
        with patch("ipasninfo.lookup_ip_asn", return_value=[]) as mock_lookup:
            with patch("ipasninfo.init_scanner"):
                run_once(args)
            mock_lookup.assert_called_once()


class TestBannerArt:
    def test_not_empty(self):
        assert len(BANNER_ART) > 0
