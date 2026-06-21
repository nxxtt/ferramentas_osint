from __future__ import annotations

import argparse
from unittest.mock import patch

from reconall import (
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
