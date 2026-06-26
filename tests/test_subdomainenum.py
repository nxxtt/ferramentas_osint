import argparse
import json
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from subdomainenum import (
    _PASSIVE_SOURCES,
    BANNER_ART,
    BUILTIN_WORDLIST,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    SubdomainResult,
    _parse_crtsh,
    _parse_otx,
    _parse_securitytrails,
    _parse_shodan,
    _parse_urlscan,
    _parse_virustotal,
    _resolve_subdomain,
    build_parser,
    enumerate_subdomains,
    load_wordlist,
    main,
    passive_enumeration,
    run_enum_scan,
    run_once,
)


def _make_args(**kwargs):
    defaults = {
        "domain": "example.com",
        "threads": DEFAULT_THREADS,
        "timeout": DEFAULT_TIMEOUT,
        "wordlist": None,
        "output": None,
        "verbose": False,
        "quiet": False,
        "color": None,
        "log_file": None,
        "passive": False,
        "vt_api_key": None,
        "st_api_key": None,
        "shodan_api_key": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestSubdomainResult:
    def test_frozen(self):
        result = SubdomainResult(subdomain="www.example.com")
        with pytest.raises(AttributeError):
            result.subdomain = "other.com"

    def test_defaults(self):
        result = SubdomainResult(subdomain="www.example.com")
        assert result.ip_addresses == []
        assert result.status == "resolved"

    def test_resolved_result(self):
        result = SubdomainResult(
            subdomain="api.example.com",
            ip_addresses=["1.2.3.4", "5.6.7.8"],
            status="resolved",
        )
        assert result.subdomain == "api.example.com"
        assert len(result.ip_addresses) == 2
        assert result.status == "resolved"

    def test_equality(self):
        r1 = SubdomainResult(subdomain="a.example.com", status="nxdomain")
        r2 = SubdomainResult(subdomain="a.example.com", status="nxdomain")
        assert r1 == r2

    def test_inequality(self):
        r1 = SubdomainResult(subdomain="a.example.com")
        r2 = SubdomainResult(subdomain="b.example.com")
        assert r1 != r2


class TestBuiltinWordlist:
    def test_is_tuple(self):
        assert isinstance(BUILTIN_WORDLIST, tuple)

    def test_size(self):
        assert len(BUILTIN_WORDLIST) > 100

    def test_no_duplicates(self):
        assert len(BUILTIN_WORDLIST) == len(set(BUILTIN_WORDLIST))


class TestLoadWordlist:
    def test_none_returns_builtin(self):
        result = load_wordlist(None)
        assert isinstance(result, list)
        assert len(result) == len(BUILTIN_WORDLIST)
        assert result[0] == BUILTIN_WORDLIST[0]

    def test_none_returns_copy(self):
        result = load_wordlist(None)
        result.append("hacked")
        assert len(load_wordlist(None)) == len(BUILTIN_WORDLIST)

    def test_valid_file(self, tmp_path):
        wl = tmp_path / "wordlist.txt"
        wl.write_text("www\ntest\napi\n", encoding="utf-8")
        result = load_wordlist(str(wl))
        assert result == ["www", "test", "api"]

    def test_file_not_found(self):
        with pytest.raises(ValueError, match="arquivo nao encontrado"):
            load_wordlist("/tmp/nonexistent_wordlist_12345.txt")

    def test_empty_file(self, tmp_path):
        wl = tmp_path / "empty.txt"
        wl.write_text("\n\n\n", encoding="utf-8")
        with pytest.raises(ValueError, match="vazia"):
            load_wordlist(str(wl))

    def test_strips_and_lowercases(self, tmp_path):
        wl = tmp_path / "mixed.txt"
        wl.write_text("  WWW  \nTest\n  API\n# comment\n\n", encoding="utf-8")
        result = load_wordlist(str(wl))
        assert result == ["www", "test", "api"]

    def test_skips_comments(self, tmp_path):
        wl = tmp_path / "comments.txt"
        wl.write_text("# first\nwww\n# second\ntest\n", encoding="utf-8")
        result = load_wordlist(str(wl))
        assert result == ["www", "test"]


class TestResolveSubdomain:
    @patch("subdomainenum.dns.resolver.Resolver")
    def test_resolved(self, MockResolver):
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        rdata = MagicMock()
        rdata.__str__ = lambda self: "1.2.3.4"
        mock_resolver.resolve.return_value = [rdata]

        result = _resolve_subdomain("www", "example.com", 3.0, mock_resolver)
        assert result.status == "resolved"
        assert result.ip_addresses == ["1.2.3.4"]
        assert result.subdomain == "www.example.com"

    @patch("subdomainenum.dns.resolver.Resolver")
    def test_resolved_sorted(self, MockResolver):
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        r1 = MagicMock()
        r1.__str__ = lambda self: "5.6.7.8"
        r2 = MagicMock()
        r2.__str__ = lambda self: "1.2.3.4"
        mock_resolver.resolve.return_value = [r1, r2]

        result = _resolve_subdomain("www", "example.com", 3.0, mock_resolver)
        assert result.ip_addresses == ["1.2.3.4", "5.6.7.8"]

    @patch("subdomainenum.dns.resolver.Resolver")
    def test_nxdomain(self, MockResolver):
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        result = _resolve_subdomain("nope", "example.com", 3.0, mock_resolver)
        assert result.status == "nxdomain"
        assert result.subdomain == "nope.example.com"
        assert result.ip_addresses == []

    @patch("subdomainenum.dns.resolver.Resolver")
    def test_noanswer(self, MockResolver):
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

        result = _resolve_subdomain("mx", "example.com", 3.0, mock_resolver)
        assert result.status == "noanswer"
        assert result.ip_addresses == []

    @patch("subdomainenum.dns.resolver.Resolver")
    def test_timeout(self, MockResolver):
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.Timeout()

        result = _resolve_subdomain("slow", "example.com", 3.0, mock_resolver)
        assert result.status == "timeout"
        assert result.ip_addresses == []

    @patch("subdomainenum.dns.resolver.Resolver")
    def test_dns_exception(self, MockResolver):
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.DNSException("fail")

        result = _resolve_subdomain("err", "example.com", 3.0, mock_resolver)
        assert result.status == "error"
        assert result.ip_addresses == []

    @patch("subdomainenum.dns.resolver.Resolver")
    def test_generic_exception(self, MockResolver):
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        mock_resolver.resolve.side_effect = RuntimeError("unexpected")

        result = _resolve_subdomain("err", "example.com", 3.0, mock_resolver)
        assert result.status == "error"
        assert result.ip_addresses == []

    @patch("subdomainenum.dns.resolver.Resolver")
    def test_fqdn_format(self, MockResolver):
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        _resolve_subdomain("mail", "test.com", 3.0, mock_resolver)
        mock_resolver.resolve.assert_called_once_with("mail.test.com", "A")


class TestEnumerateSubdomains:
    def test_empty_domain(self):
        with pytest.raises(ValueError) as excinfo:
            enumerate_subdomains("", ["www"])
        assert "dominio" in str(excinfo.value).lower() or "domínio" in str(excinfo.value).lower()

    def test_whitespace_domain_stripped(self):
        with pytest.raises(ValueError):
            enumerate_subdomains("   ", ["www"])

    @patch("subdomainenum._resolve_subdomain")
    def test_returns_only_resolved(self, mock_resolve):
        r1 = SubdomainResult(subdomain="www.example.com", ip_addresses=["1.2.3.4"], status="resolved")
        r2 = SubdomainResult(subdomain="nope.example.com", status="nxdomain")
        mock_resolve.side_effect = [r1, r2]

        results = enumerate_subdomains("example.com", ["www", "nope"], threads=1)
        assert len(results) == 1
        assert results[0].subdomain == "www.example.com"

    @patch("subdomainenum._resolve_subdomain")
    def test_all_resolved(self, mock_resolve):
        r1 = SubdomainResult(subdomain="a.example.com", ip_addresses=["1.1.1.1"], status="resolved")
        r2 = SubdomainResult(subdomain="b.example.com", ip_addresses=["2.2.2.2"], status="resolved")
        mock_resolve.side_effect = [r1, r2]

        results = enumerate_subdomains("example.com", ["a", "b"], threads=1)
        assert len(results) == 2

    @patch("subdomainenum._resolve_subdomain")
    def test_none_resolved(self, mock_resolve):
        mock_resolve.return_value = SubdomainResult(subdomain="x.example.com", status="nxdomain")

        results = enumerate_subdomains("example.com", ["x"], threads=1)
        assert len(results) == 0

    @patch("subdomainenum._resolve_subdomain")
    def test_empty_wordlist(self, mock_resolve):
        results = enumerate_subdomains("example.com", [], threads=1)
        assert results == []
        mock_resolve.assert_not_called()

    @patch("subdomainenum._resolve_subdomain")
    def test_threads_passed(self, mock_resolve):
        mock_resolve.return_value = SubdomainResult(subdomain="x.example.com", status="nxdomain")

        enumerate_subdomains("example.com", ["x", "y"], threads=2)
        assert mock_resolve.call_count == 2


class TestRunEnumScan:
    @patch("subdomainenum.enumerate_subdomains")
    @patch("subdomainenum.load_wordlist")
    def test_delegates_correctly(self, mock_load, mock_enum):
        mock_load.return_value = ["www"]
        mock_enum.return_value = []

        results = run_enum_scan("example.com", wordlist_path=None, threads=10, timeout=5.0)
        mock_load.assert_called_once_with(None)
        mock_enum.assert_called_once_with("example.com", ["www"], threads=10, timeout=5.0, skip_names=None)
        assert results == []

    @patch("subdomainenum.enumerate_subdomains")
    @patch("subdomainenum.load_wordlist")
    def test_custom_wordlist_path(self, mock_load, mock_enum):
        mock_load.return_value = ["api"]
        mock_enum.return_value = []

        run_enum_scan("example.com", wordlist_path="/tmp/wl.txt")
        mock_load.assert_called_once_with("/tmp/wl.txt")

    @patch("subdomainenum.enumerate_subdomains")
    @patch("subdomainenum.load_wordlist")
    def test_returns_results(self, mock_load, mock_enum):
        mock_load.return_value = ["www"]
        expected = [SubdomainResult(subdomain="www.example.com", ip_addresses=["1.2.3.4"], status="resolved")]
        mock_enum.return_value = expected

        results = run_enum_scan("example.com")
        assert results == expected


class TestBuildParser:
    def setup_method(self):
        self.parser = build_parser()

    def test_returns_parser(self):
        assert isinstance(self.parser, argparse.ArgumentParser)

    def test_domain_positional(self):
        args = self.parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_domain_optional(self):
        args = self.parser.parse_args([])
        assert args.domain is None

    def test_wordlist_short(self):
        args = self.parser.parse_args(["example.com", "-w", "/tmp/wl.txt"])
        assert args.wordlist == "/tmp/wl.txt"

    def test_wordlist_long(self):
        args = self.parser.parse_args(["example.com", "--wordlist", "/tmp/wl.txt"])
        assert args.wordlist == "/tmp/wl.txt"

    def test_threads_short(self):
        args = self.parser.parse_args(["example.com", "-T", "50"])
        assert args.threads == 50

    def test_threads_long(self):
        args = self.parser.parse_args(["example.com", "--threads", "100"])
        assert args.threads == 100

    def test_timeout_short(self):
        args = self.parser.parse_args(["example.com", "-t", "10.0"])
        assert args.timeout == 10.0

    def test_timeout_long(self):
        args = self.parser.parse_args(["example.com", "--timeout", "5.0"])
        assert args.timeout == 5.0

    def test_output_short(self):
        args = self.parser.parse_args(["example.com", "-o", "out.json"])
        assert args.output == "out.json"

    def test_verbose(self):
        args = self.parser.parse_args(["example.com", "-v"])
        assert args.verbose is True

    def test_quiet(self):
        args = self.parser.parse_args(["example.com", "-q"])
        assert args.quiet is True

    def test_color_flag(self):
        args = self.parser.parse_args(["example.com", "--color"])
        assert args.color is True

    def test_no_color_flag(self):
        args = self.parser.parse_args(["example.com", "--no-color"])
        assert args.color is False

    def test_defaults(self):
        args = self.parser.parse_args(["example.com"])
        assert args.threads == DEFAULT_THREADS
        assert args.timeout == DEFAULT_TIMEOUT
        assert args.verbose is False
        assert args.quiet is False
        assert args.color is None
        assert args.output is None
        assert args.wordlist is None
        assert args.log_file is None


class TestRunOnce:
    @patch("subdomainenum.run_enum_scan")
    def test_returns_zero(self, mock_scan):
        mock_scan.return_value = []
        args = _make_args()
        assert run_once(args) == 0

    def test_invalid_threads(self):
        args = _make_args(threads=0)
        with pytest.raises(ValueError, match="threads"):
            run_once(args)

    def test_invalid_timeout(self):
        args = _make_args(timeout=0)
        with pytest.raises(ValueError, match="timeout"):
            run_once(args)

    @patch("subdomainenum.run_enum_scan")
    @patch("subdomainenum.write_output")
    def test_saves_output(self, mock_write, mock_scan):
        mock_scan.return_value = [SubdomainResult(subdomain="www.example.com", ip_addresses=["1.2.3.4"], status="resolved")]
        args = _make_args(output="out.json")
        run_once(args)
        mock_write.assert_called_once()

    @patch("subdomainenum.run_enum_scan")
    def test_no_output_no_write(self, mock_scan):
        mock_scan.return_value = []
        args = _make_args(output=None)
        assert run_once(args) == 0


class TestMain:
    def test_no_domain_shells_interactive(self):
        with patch("utils.run_interactive_shell") as mock_shell:
            mock_shell.return_value = 0
            args = _make_args(domain=None)
            with patch("subdomainenum.argparse.ArgumentParser.parse_args", return_value=args):
                result = main()
                assert result == 0
                mock_shell.assert_called_once()

    def test_quiet_without_output_returns_1(self):
        args = _make_args(quiet=True, output=None)
        with patch("subdomainenum.argparse.ArgumentParser.parse_args", return_value=args):
            result = main()
            assert result == 1

    @patch("subdomainenum.run_once")
    @patch("utils.show_banner")
    def test_valid_domain_calls_run_once(self, mock_banner, mock_run_once):
        mock_run_once.return_value = 0
        args = _make_args(domain="example.com")
        with patch("subdomainenum.argparse.ArgumentParser.parse_args", return_value=args):
            result = main()
            assert result == 0
            mock_run_once.assert_called_once()

    @patch("subdomainenum.run_once")
    def test_quiet_with_output_skips_banner(self, mock_run_once):
        mock_run_once.return_value = 0
        args = _make_args(quiet=True, output="out.json")
        with patch("subdomainenum.argparse.ArgumentParser.parse_args", return_value=args), patch("utils.show_banner") as mock_banner:
            result = main()
            assert result == 0
            mock_banner.assert_not_called()

    @patch("subdomainenum.run_once")
    @patch("utils.show_banner")
    def test_exception_returns_1(self, mock_banner, mock_run_once):
        mock_run_once.side_effect = RuntimeError("fail")
        args = _make_args(domain="example.com")
        with patch("subdomainenum.argparse.ArgumentParser.parse_args", return_value=args):
            result = main()
            assert result == 1


class TestBannerAndConstants:
    def test_banner_not_empty(self):
        assert len(BANNER_ART.strip()) > 0

    def test_default_threads(self):
        assert DEFAULT_THREADS == 20

    def test_default_timeout(self):
        assert DEFAULT_TIMEOUT == 3.0


class TestDryRun:
    def test_dry_run_flag_exists_in_parser(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--dry-run"])
        assert args.dry_run is True

    def test_dry_run_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.dry_run is False

    def test_dry_run_returns_zero(self, capsys):
        args = _make_args(dry_run=True)
        result = run_once(args)
        assert result == 0

    def test_dry_run_outputs_info(self, capsys):
        args = _make_args(dry_run=True)
        run_once(args)
        captured = capsys.readouterr()
        assert "DRY-RUN" in captured.out
        assert "Nenhuma consulta" in captured.out


class TestPassiveSources:
    def test_has_expected_sources(self):
        expected = {"crtsh", "otx", "urlscan", "virustotal", "securitytrails", "shodan"}
        assert set(_PASSIVE_SOURCES.keys()) == expected

    def test_all_have_url(self):
        for name, cfg in _PASSIVE_SOURCES.items():
            assert "url" in cfg, f"{name} missing url"
            assert "{domain}" in cfg["url"], f"{name} url must contain {{domain}}"

    def test_crtsh_no_auth(self):
        assert _PASSIVE_SOURCES["crtsh"]["auth_type"] == "none"

    def test_virustotal_needs_api_key(self):
        assert _PASSIVE_SOURCES["virustotal"]["auth_type"] == "api_key"
        assert _PASSIVE_SOURCES["virustotal"]["auth_header"] == "x-apikey"

    def test_shodan_uses_query_param(self):
        assert _PASSIVE_SOURCES["shodan"]["auth_type"] == "query_param"


class TestParseCrtsh:
    def test_extracts_subdomains(self):
        data = [
            {"name_value": "www.example.com\nexample.com"},
            {"name_value": "mail.example.com"},
        ]
        body = json.dumps(data).encode()
        result = _parse_crtsh(body, "example.com")
        assert "www.example.com" in result
        assert "mail.example.com" in result
        assert "example.com" not in result

    def test_strips_wildcards(self):
        data = [{"name_value": "*.example.com"}]
        body = json.dumps(data).encode()
        result = _parse_crtsh(body, "example.com")
        assert "*.example.com" not in result
        assert "example.com" not in result

    def test_invalid_json_returns_empty(self):
        result = _parse_crtsh(b"not json", "example.com")
        assert result == []

    def test_empty_array(self):
        result = _parse_crtsh(b"[]", "example.com")
        assert result == []


class TestParseOtx:
    def test_extracts_subdomains(self):
        data = {"passive_dns": [{"hostname": "www.example.com"}, {"hostname": "mail.example.com"}]}
        body = json.dumps(data).encode()
        result = _parse_otx(body, "example.com")
        assert "www.example.com" in result
        assert "mail.example.com" in result

    def test_filters_non_matching(self):
        data = {"passive_dns": [{"hostname": "www.other.com"}]}
        body = json.dumps(data).encode()
        result = _parse_otx(body, "example.com")
        assert result == []

    def test_invalid_json(self):
        result = _parse_otx(b"bad", "example.com")
        assert result == []


class TestParseUrlscan:
    def test_extracts_subdomains(self):
        data = {"results": [{"page": {"domain": "www.example.com"}}]}
        body = json.dumps(data).encode()
        result = _parse_urlscan(body, "example.com")
        assert "www.example.com" in result

    def test_empty_results(self):
        data = {"results": []}
        body = json.dumps(data).encode()
        result = _parse_urlscan(body, "example.com")
        assert result == []


class TestParseVirustotal:
    def test_extracts_subdomains(self):
        data = {"data": [{"id": "www.example.com"}, {"id": "api.example.com"}]}
        body = json.dumps(data).encode()
        result = _parse_virustotal(body, "example.com")
        assert "www.example.com" in result
        assert "api.example.com" in result


class TestParseSecuritytrails:
    def test_extracts_subdomains(self):
        data = {"subdomains": ["www", "api", "mail"]}
        body = json.dumps(data).encode()
        result = _parse_securitytrails(body, "example.com")
        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "mail.example.com" in result


class TestParseShodan:
    def test_extracts_subdomains(self):
        data = {"data": [{"subdomain": "www"}, {"subdomain": "api"}]}
        body = json.dumps(data).encode()
        result = _parse_shodan(body, "example.com")
        assert "www.example.com" in result
        assert "api.example.com" in result

    def test_empty_data(self):
        data = {"data": []}
        body = json.dumps(data).encode()
        result = _parse_shodan(body, "example.com")
        assert result == []


class TestBuildParserPassive:
    def test_has_passive_flag(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--passive"])
        assert args.passive is True

    def test_passive_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.passive is False

    def test_has_vt_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--vt-api-key", "abc123"])
        assert args.vt_api_key == "abc123"

    def test_has_st_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--st-api-key", "xyz789"])
        assert args.st_api_key == "xyz789"

    def test_has_shodan_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--shodan-api-key", "key123"])
        assert args.shodan_api_key == "key123"


class TestPassiveEnumeration:
    def test_empty_sources_returns_empty(self):
        result = passive_enumeration("example.com", [])
        assert result == []

    @patch("subdomainenum._passive_enumerate_async", new_callable=MagicMock)
    @patch("subdomainenum.safe_asyncio_run")
    def test_calls_with_correct_sources(self, mock_run, mock_async):
        mock_run.return_value = ["www.example.com"]
        results = passive_enumeration("example.com", ["crtsh"], timeout=5.0)
        assert len(results) == 1
        assert results[0].subdomain == "www.example.com"
        assert results[0].status == "passive"

    @patch("subdomainenum._passive_enumerate_async", new_callable=MagicMock)
    @patch("subdomainenum.safe_asyncio_run")
    def test_deduplicates_results(self, mock_run, mock_async):
        mock_run.return_value = ["www.example.com", "www.example.com"]
        results = passive_enumeration("example.com", ["crtsh"])
        assert len(results) == 1

    @patch("subdomainenum._passive_enumerate_async", new_callable=MagicMock)
    @patch("subdomainenum.safe_asyncio_run")
    def test_returns_sorted(self, mock_run, mock_async):
        mock_run.return_value = ["z.example.com", "a.example.com"]
        results = passive_enumeration("example.com", ["crtsh"])
        assert results[0].subdomain == "a.example.com"
        assert results[1].subdomain == "z.example.com"


class TestRunOncePassive:
    def test_passive_flag_in_dry_run(self, capsys):
        args = _make_args(passive=False, dry_run=True)
        result = run_once(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "DRY-RUN" in captured.out
