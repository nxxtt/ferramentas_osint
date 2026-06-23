from __future__ import annotations

import argparse
from unittest.mock import patch

from reconall import (
    ALL_MODULES,
    _extract_domain,
    _is_url,
    _make_args,
    build_parser,
    run_all,
)


class TestIsUrl:
    def test_http(self):
        assert _is_url("http://example.com") is True

    def test_https(self):
        assert _is_url("https://example.com") is True

    def test_domain(self):
        assert _is_url("example.com") is False

    def test_ip(self):
        assert _is_url("192.168.1.1") is False


class TestExtractDomain:
    def test_from_url(self):
        assert _extract_domain("https://example.com") == "example.com"

    def test_from_url_with_port(self):
        assert _extract_domain("https://example.com:8080") == "example.com"

    def test_from_domain(self):
        assert _extract_domain("example.com") == "example.com"

    def test_from_ip(self):
        assert _extract_domain("192.168.1.1") == "192.168.1.1"


class TestMakeArgs:
    def test_merges_base_and_extra(self):
        base = argparse.Namespace(timeout=5.0, verbose=False)
        result = _make_args("target", {"url": "http://example.com", "deep": True}, base)
        assert result.url == "http://example.com"
        assert result.deep is True
        assert result.timeout == 5.0
        assert result.verbose is False


class TestBuildParser:
    def test_has_target(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.target == "example.com"

    def test_deep_flag(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--deep"])
        assert args.deep is True

    def test_test_vulns_flag(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--test-vulns"])
        assert args.test_vulns is True

    def test_skip_module(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum"])
        assert "dnstransfer" in args.skip
        assert "subenum" in args.skip

    def test_skip_invalid_module_rejected(self):
        import pytest
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["example.com", "--skip", "invalidmodule"])

    def test_dry_run(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--dry-run"])
        assert args.dry_run is True

    def test_output_dir(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "-o", "results/"])
        assert args.output_dir == "results/"

    def test_cve_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--cve"])
        assert args.cve is True

    def test_dnshistory_in_all_modules(self):
        assert "dnshistory" in ALL_MODULES

    def test_skip_dnshistory(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnshistory"])
        assert "dnshistory" in args.skip


class TestRunAll:
    def test_runs_portscanner_for_domain(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum"])
        with patch("reconall.portscanner.run_once", return_value=0) as mock_fn:
            result = run_all(args)
            assert result == 0
            mock_fn.assert_called_once()

    def test_runs_all_http_for_url(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner"])
        with (
            patch("reconall.dirscanner.run_once", return_value=0),
            patch("reconall.webrecon.run_once", return_value=0),
            patch("reconall.attackaudit.run_once", return_value=0),
        ):
            result = run_all(args)
            assert result == 0

    def test_skips_specified_modules(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "dirscanner", "--skip", "webrecon"])
        with (
            patch("reconall.portscanner.run_once", return_value=0),
            patch("reconall.attackaudit.run_once", return_value=0),
            patch("reconall.dirscanner.run_once") as mock_dir,
            patch("reconall.webrecon.run_once") as mock_web,
        ):
            result = run_all(args)
            assert result == 0
            mock_dir.assert_not_called()
            mock_web.assert_not_called()

    def test_counts_errors(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum"])
        with patch("reconall.portscanner.run_once", return_value=1):
            result = run_all(args)
            assert result == 1

    def test_passes_deep_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner", "--deep"])
        with (
            patch("reconall.dirscanner.run_once", return_value=0),
            patch("reconall.webrecon.run_once", return_value=0) as mock_web,
            patch("reconall.attackaudit.run_once", return_value=0),
        ):
            run_all(args)
            call_args = mock_web.call_args[0][0]
            assert call_args.deep is True


class TestNamespaceConstruction:
    def test_portscanner_has_threads(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum"])
        with patch("reconall.portscanner.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            assert hasattr(ns, "threads")
            assert ns.threads is None

    def test_portscanner_has_workers(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum"])
        with patch("reconall.portscanner.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            assert hasattr(ns, "workers")
            assert ns.workers == 200

    def test_dirscanner_has_required_attrs(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner", "--skip", "webrecon", "--skip", "attackaudit"])
        with patch("reconall.dirscanner.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            for attr in ("user_agent", "proxy", "delay", "auth", "header", "cookie",
                         "concurrency", "status", "method", "wordlist", "extensions",
                         "filter_size", "filter_words", "retries"):
                assert hasattr(ns, attr), f"dirscanner missing attribute: {attr}"

    def test_dirscanner_extensions_is_list(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner", "--skip", "webrecon", "--skip", "attackaudit"])
        with patch("reconall.dirscanner.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            assert isinstance(ns.extensions, list)
            assert ns.extensions == ["php", "txt", "bak", "html"]

    def test_webrecon_has_required_attrs(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner", "--skip", "dirscanner", "--skip", "attackaudit"])
        with patch("reconall.webrecon.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            for attr in ("user_agent", "proxy", "cve", "deep", "crawl_limit", "nvd_api_key"):
                assert hasattr(ns, attr), f"webrecon missing attribute: {attr}"

    def test_attackaudit_has_required_attrs(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner", "--skip", "dirscanner", "--skip", "webrecon"])
        with patch("reconall.attackaudit.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            for attr in ("user_agent", "proxy", "delay", "concurrency", "deep",
                         "test_vulns", "test_methods", "paths_file", "params"):
                assert hasattr(ns, attr), f"attackaudit missing attribute: {attr}"

    def test_subenum_has_threads(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "portscanner"])
        with patch("reconall.subdomainenum.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            assert hasattr(ns, "threads")
            assert ns.threads is None or isinstance(ns.threads, int)

    def test_portscanner_ports_is_list(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum"])
        with patch("reconall.portscanner.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            assert isinstance(ns.ports, list)
            assert all(isinstance(p, int) for p in ns.ports)

    def test_portscanner_default_ports_count(self):
        from portscanner import TOP_100_PORTS
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum"])
        with patch("reconall.portscanner.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            assert len(ns.ports) == len(TOP_100_PORTS)

    def test_portscanner_custom_ports(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "-p", "22,80,443", "--skip", "dnstransfer", "--skip", "subenum"])
        with patch("reconall.portscanner.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            assert ns.ports == [22, 80, 443]

    def test_http_modules_user_agent_not_none(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner"])
        with (
            patch("reconall.dirscanner.run_once", return_value=0) as mock_dir,
            patch("reconall.webrecon.run_once", return_value=0) as mock_web,
            patch("reconall.attackaudit.run_once", return_value=0) as mock_audit,
        ):
            run_all(args)
            for mock_fn in (mock_dir, mock_web, mock_audit):
                ns = mock_fn.call_args[0][0]
                assert ns.user_agent is not None
                assert "MyTools/" in ns.user_agent

    def test_portscanner_has_output(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "-o", "/tmp/results", "--skip", "dnstransfer", "--skip", "subenum"])
        with patch("reconall.portscanner.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            assert ns.output is not None
            assert "portscanner" in ns.output

    def test_dnshistory_runs_for_domain(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum", "--skip", "portscanner"])
        with patch("reconall.dnshistory.run_once", return_value=0) as mock_fn:
            result = run_all(args)
            assert result == 0
            mock_fn.assert_called_once()
            ns = mock_fn.call_args[0][0]
            assert ns.domain == "example.com"

    def test_dnshistory_runs_for_url(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner", "--skip", "dirscanner", "--skip", "webrecon", "--skip", "attackaudit"])
        with patch("reconall.dnshistory.run_once", return_value=0) as mock_fn:
            result = run_all(args)
            assert result == 0
            mock_fn.assert_called_once()
            ns = mock_fn.call_args[0][0]
            assert ns.domain == "example.com"

    def test_dnshistory_has_required_attrs(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum", "--skip", "portscanner"])
        with patch("reconall.dnshistory.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            for attr in ("source", "record_types", "dnslytics_key", "st_api_key", "viewdns_key"):
                assert hasattr(ns, attr), f"dnshistory missing attribute: {attr}"

    def test_whoishistory_in_all_modules(self):
        assert "whoishistory" in ALL_MODULES

    def test_skip_whoishistory(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "whoishistory"])
        assert "whoishistory" in args.skip

    def test_whoishistory_runs_for_domain(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum", "--skip", "portscanner", "--skip", "dnshistory"])
        with patch("reconall.whoishistory.run_once", return_value=0) as mock_fn:
            result = run_all(args)
            assert result == 0
            mock_fn.assert_called_once()
            ns = mock_fn.call_args[0][0]
            assert ns.domain == "example.com"

    def test_whoishistory_runs_for_url(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner", "--skip", "dirscanner", "--skip", "webrecon", "--skip", "attackaudit", "--skip", "dnshistory"])
        with patch("reconall.whoishistory.run_once", return_value=0) as mock_fn:
            result = run_all(args)
            assert result == 0
            mock_fn.assert_called_once()
            ns = mock_fn.call_args[0][0]
            assert ns.domain == "example.com"

    def test_whoishistory_has_required_attrs(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--skip", "dnstransfer", "--skip", "subenum", "--skip", "portscanner", "--skip", "dnshistory"])
        with patch("reconall.whoishistory.run_once", return_value=0) as mock_fn:
            run_all(args)
            ns = mock_fn.call_args[0][0]
            for attr in ("st_api_key", "whoisxml_key", "source"):
                assert hasattr(ns, attr), f"whoishistory missing attribute: {attr}"


class TestAuthArgs:
    """Testes para argumentos de auth no reconall."""

    def test_has_auth_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--auth", "user:pass"])
        assert args.auth == {"Authorization": "Basic dXNlcjpwYXNz"}

    def test_has_bearer_token_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--bearer-token", "tok123"])
        assert args.bearer_token == "tok123"

    def test_has_cookie_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--cookie", "session=abc"])
        assert args.cookie == "session=abc"

    def test_has_header_argument(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--header", "X-Token: abc"])
        assert args.header == ["X-Token: abc"]

    def test_header_multiple(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--header", "X-A: 1", "--header", "X-B: 2"])
        assert args.header == ["X-A: 1", "X-B: 2"]

    def test_auth_defaults_none(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.auth is None
        assert args.bearer_token is None
        assert args.cookie is None
        assert args.header == []


class TestAuthPropagated:
    """Testes para propagacao de auth via base_ns."""

    def test_bearer_token_propagated_to_http_modules(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--bearer-token", "tok_abc", "--skip", "portscanner"])
        with (
            patch("reconall.webrecon.run_once", return_value=0) as mock_web,
            patch("reconall.attackaudit.run_once", return_value=0) as mock_audit,
        ):
            run_all(args)
            for mock_fn in (mock_web, mock_audit):
                ns = mock_fn.call_args[0][0]
                assert ns.bearer_token == "tok_abc"

    def test_auth_propagated_to_http_modules(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--auth", "admin:s3cret", "--skip", "portscanner"])
        with (
            patch("reconall.webrecon.run_once", return_value=0) as mock_web,
            patch("reconall.attackaudit.run_once", return_value=0) as mock_audit,
        ):
            run_all(args)
            for mock_fn in (mock_web, mock_audit):
                ns = mock_fn.call_args[0][0]
                assert ns.auth is not None

    def test_cookie_propagated(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--cookie", "sid=xyz", "--skip", "portscanner"])
        with patch("reconall.webrecon.run_once", return_value=0) as mock_web:
            run_all(args)
            ns = mock_web.call_args[0][0]
            assert ns.cookie == "sid=xyz"

    def test_header_propagated(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--header", "X-Custom: val", "--skip", "portscanner"])
        with patch("reconall.attackaudit.run_once", return_value=0) as mock_audit:
            run_all(args)
            ns = mock_audit.call_args[0][0]
            assert ns.header == ["X-Custom: val"]

    def test_auth_none_does_not_override_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--skip", "portscanner"])
        with patch("reconall.webrecon.run_once", return_value=0) as mock_web:
            run_all(args)
            ns = mock_web.call_args[0][0]
            assert ns.auth is None
            assert ns.bearer_token is None
