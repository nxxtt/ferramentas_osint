from __future__ import annotations

import argparse
import re
from unittest.mock import patch

import httpx
import pytest
import respx

from utils import Cyber, severity_color
from webrecon import (
    CMS_SIGNATURES,
    EMAIL_PATTERN,
    FRAMEWORK_SIGNATURES,
    LIBRARY_SIGNATURES,
    SERVER_PATTERNS,
    WAF_SIGNATURES,
    CVEFinding,
    ReconResult,
    WhoisResult,
    _async_run_once,
    _ensure_list,
    _format_date,
    build_parser,
    candidate_urls,
    crawl_internal_links,
    detect_technologies,
    detect_waf,
    extract_versions,
    harvest_emails,
    lookup_cves,
    normalize_url,
    probe_status,
    run_whois,
    status_text,
)


class TestNormalizeUrl:
    def test_valid_https(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_valid_http(self):
        assert normalize_url("http://example.com") == "http://example.com"

    def test_no_scheme_adds_https(self):
        assert normalize_url("example.com") == "https://example.com"

    def test_ftp_scheme_raises(self):
        with pytest.raises(ValueError):
            normalize_url("ftp://example.com")

    def test_no_netloc_raises(self):
        with pytest.raises(ValueError):
            normalize_url("http://")

    def test_strips_trailing_slash(self):
        assert normalize_url("https://example.com/") == "https://example.com"

    def test_strips_whitespace(self):
        assert normalize_url("  https://example.com  ") == "https://example.com"


class TestCandidateUrls:
    def test_with_scheme_returns_single(self):
        result = candidate_urls("https://example.com")
        assert len(result) == 1
        assert result[0] == "https://example.com"

    def test_without_scheme_returns_two(self):
        result = candidate_urls("example.com")
        assert len(result) == 2
        assert result[0].startswith("https://")
        assert result[1].startswith("http://")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            candidate_urls("")

    def test_strips_whitespace(self):
        result = candidate_urls("  example.com  ")
        assert len(result) == 2

    def test_with_port_no_scheme(self):
        result = candidate_urls("example.com:8080")
        assert len(result) == 2
        assert "example.com:8080" in result[0]

    def test_with_path_no_scheme(self):
        result = candidate_urls("example.com/app")
        assert len(result) == 2
        assert "/app" in result[0]


class TestStatusText:
    def test_none_returns_no_response(self):
        result = status_text(None)
        assert "sem resposta" in result

    def test_200_contains_status(self):
        result = status_text(200)
        assert "200" in result

    def test_404_contains_status(self):
        result = status_text(404)
        assert "404" in result

    def test_returns_string(self):
        assert isinstance(status_text(200), str)


class TestProbeStatus:
    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_status_on_success(self, async_client):
        respx.get("http://example.com/robots.txt").mock(
            return_value=httpx.Response(200, text="User-agent: *")
        )
        client = async_client
        result = await probe_status(client, "http://example.com/robots.txt", 5.0)
        assert result == 200

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_none_on_error(self, async_client):
        respx.get("http://example.com/robots.txt").mock(
            side_effect=httpx.ConnectError("refused")
        )
        client = async_client
        result = await probe_status(client, "http://example.com/robots.txt", 5.0)
        assert result is None


class TestReconResultDataclass:
    def test_creation(self):
        r = ReconResult(
            url="https://example.com", status=200, final_url="https://example.com",
            title="Test", server="nginx", powered_by="", content_type="text/html",
            content_length=100, redirect="", security_headers_present=["x-frame-options"],
            security_headers_missing=["content-security-policy"], robots_status=200,
            sitemap_status=404, elapsed=1.0,
        )
        assert r.status == 200
        assert len(r.security_headers_present) == 1

    def test_frozen(self):
        r = ReconResult(
            url="https://example.com", status=200, final_url="https://example.com",
            title="", server="", powered_by="", content_type="text/html",
            content_length=0, redirect="", security_headers_present=[],
            security_headers_missing=[], robots_status=None, sitemap_status=None,
            elapsed=0.0,
        )
        with pytest.raises(AttributeError):
            r.status = 404


class TestDetectTechnologies:
    def test_wordpress_by_body(self):
        tech = detect_technologies({}, '<html><link href="/wp-content/style.css">', "https://example.com")
        assert "WordPress" in tech["cms"]

    def test_wordpress_by_header(self):
        tech = detect_technologies({"X-Pingback": "https://example.com/xmlrpc.php"}, "", "https://example.com")
        assert "WordPress" in tech["cms"]

    def test_wordpress_by_cookie(self):
        tech = detect_technologies({}, "", "https://example.com", cookies=["wordpress_logged_in_abc=123"])
        assert "WordPress" in tech["cms"]

    def test_django_by_cookie(self):
        tech = detect_technologies({}, "", "https://example.com", cookies=["csrftoken=xyz"])
        assert "Django" in tech["frameworks"]

    def test_django_by_body(self):
        tech = detect_technologies({}, '<input type="hidden" name="csrfmiddlewaretoken">', "https://example.com")
        assert "Django" in tech["frameworks"]

    def test_express_by_header(self):
        tech = detect_technologies({"X-Powered-By": "Express"}, "", "https://example.com")
        assert "Express" in tech["frameworks"]

    def test_laravel_by_cookie(self):
        tech = detect_technologies({}, "", "https://example.com", cookies=["laravel_session=eyJ"])
        assert "Laravel" in tech["frameworks"]

    def test_jquery_by_body(self):
        tech = detect_technologies({}, '<script src="jquery-3.6.0.min.js">', "https://example.com")
        assert "jQuery" in tech["libraries"]

    def test_bootstrap_by_body(self):
        tech = detect_technologies({}, '<link rel="stylesheet" href="bootstrap.min.css">', "https://example.com")
        assert "Bootstrap" in tech["libraries"]

    def test_react_by_body(self):
        tech = detect_technologies({}, '<script>__REACT_DEVTOOLS_GLOBAL_HOOK__</script>', "https://example.com")
        assert "React" in tech["libraries"]

    def test_vue_by_body(self):
        tech = detect_technologies({}, '<script>Vue.__vue__</script>', "https://example.com")
        assert "Vue.js" in tech["libraries"]

    def test_angular_by_body(self):
        tech = detect_technologies({}, '<app-root ng-version="14.0.0">', "https://example.com")
        assert "Angular" in tech["libraries"]

    def test_server_nginx(self):
        tech = detect_technologies({"Server": "nginx/1.24.0"}, "", "https://example.com")
        assert "Nginx" in tech["server"]

    def test_server_apache(self):
        tech = detect_technologies({"Server": "Apache/2.4.57"}, "", "https://example.com")
        assert "Apache" in tech["server"]

    def test_server_iis(self):
        tech = detect_technologies({"Server": "Microsoft-IIS/10.0"}, "", "https://example.com")
        assert "IIS" in tech["server"]

    def test_multiple_cms(self):
        body = '<html><link href="/wp-content/style.css"><title>Joomla!</title>'
        tech = detect_technologies({}, body, "https://example.com")
        assert "WordPress" in tech["cms"]
        assert "Joomla" in tech["cms"]

    def test_empty_headers_body(self):
        tech = detect_technologies({}, "", "https://example.com")
        assert tech["cms"] == []
        assert tech["frameworks"] == []
        assert tech["libraries"] == []

    def test_no_false_positives(self):
        tech = detect_technologies({"Server": "nginx"}, "<html><body>Hello</body></html>", "https://example.com")
        assert tech["cms"] == []
        assert tech["frameworks"] == []
        assert tech["libraries"] == []

    def test_shopify_by_body(self):
        tech = detect_technologies({}, '<script>Shopify.theme</script>', "https://example.com")
        assert "Shopify" in tech["cms"]

    def test_aspnet_by_header(self):
        tech = detect_technologies({"X-AspNet-Version": "4.0.30319"}, "", "https://example.com")
        assert "ASP.NET" in tech["frameworks"]

    def test_flask_by_cookie(self):
        tech = detect_technologies({}, "", "https://example.com", cookies=["session=eyJhbGciOiJIUzI1NiJ9"])
        assert "Flask" in tech["frameworks"]


class TestSignatureDictionaries:
    def test_cms_signatures_have_required_keys(self):
        for name, sigs in CMS_SIGNATURES.items():
            assert isinstance(name, str)
            assert isinstance(sigs, dict)
            assert any(k in sigs for k in ("headers", "body", "cookies", "urls"))

    def test_framework_signatures_have_required_keys(self):
        for name, sigs in FRAMEWORK_SIGNATURES.items():
            assert isinstance(name, str)
            assert isinstance(sigs, dict)
            assert any(k in sigs for k in ("headers", "body", "cookies", "urls"))

    def test_library_signatures_have_body(self):
        for name, sigs in LIBRARY_SIGNATURES.items():
            assert isinstance(name, str)
            assert "body" in sigs
            assert len(sigs["body"]) > 0

    def test_server_patterns_are_compiled(self):
        for name, pattern in SERVER_PATTERNS.items():
            assert isinstance(name, str)
            assert isinstance(pattern, re.Pattern)


class TestBuildParser:
    def test_returns_argparse(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_url_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_default_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.timeout == 5.0

    def test_has_output_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-o", "out.json"])
        assert args.output == "out.json"

    def test_has_proxy_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--proxy", "http://proxy:8080"])
        assert args.proxy == "http://proxy:8080"

    def test_has_verbose_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-v"])
        assert args.verbose is True

    def test_default_verbose_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.verbose is False

    def test_has_log_file_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--log-file", "out.log"])
        assert args.log_file == "out.log"


class TestBuildParserV3:
    def test_has_list_argument(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "targets.txt"])
        assert args.target_list == "targets.txt"

    def test_has_output_dir_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--output-dir", "results/"])
        assert args.output_dir == "results/"

    def test_has_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-q"])
        assert args.quiet is True

    def test_default_quiet_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.quiet is False

    def test_has_auth_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--auth", "admin:secret"])
        assert args.auth is not None
        assert "Authorization" in args.auth

    def test_has_bearer_token_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--bearer-token", "tok123"])
        assert args.bearer_token == "tok123"

    def test_has_cookie_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--cookie", "session=abc"])
        assert args.cookie == "session=abc"

    def test_has_header_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--header", "X-Token: abc"])
        assert args.header == ["X-Token: abc"]

    def test_has_delay_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--delay", "5"])
        assert args.delay == 5.0

    def test_has_user_agent_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-A", "CustomAgent/1.0"])
        assert args.user_agent == "CustomAgent/1.0"

    def test_default_user_agent(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert "WebRecon/" in args.user_agent


class TestExtractVersions:
    def test_apache_from_server_header(self):
        headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
        versions = extract_versions(headers, "")
        assert ("Apache", "2.4.41") in versions

    def test_nginx_from_server_header(self):
        headers = {"Server": "nginx/1.24.0"}
        versions = extract_versions(headers, "")
        assert ("Nginx", "1.24.0") in versions

    def test_php_from_server_header(self):
        headers = {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.3"}
        versions = extract_versions(headers, "")
        assert ("PHP", "7.4.3") in versions

    def test_wordpress_from_body(self):
        body = '<meta name="generator" content="WordPress 6.2">'
        versions = extract_versions({}, body)
        assert ("WordPress", "6.2") in versions

    def test_angular_from_body(self):
        body = '<app-root ng-version="15.2.0">'
        versions = extract_versions({}, body)
        assert ("Angular", "15.2.0") in versions

    def test_jquery_from_body(self):
        body = '<script src="jquery-3.6.0.min.js"></script>'
        versions = extract_versions({}, body)
        assert ("jQuery", "3.6.0") in versions

    def test_no_versions(self):
        versions = extract_versions({}, "")
        assert versions == []

    def test_deduplicates(self):
        headers = {"Server": "Apache/2.4.41"}
        versions = extract_versions(headers, "")
        apache_count = sum(1 for name, _ in versions if name == "Apache")
        assert apache_count == 1


class TestSeverityColor:
    def test_critical_is_red(self):
        assert severity_color("CRITICAL") == Cyber.RED

    def test_high_is_orange(self):
        assert severity_color("HIGH") == Cyber.ORANGE

    def test_medium_is_yellow(self):
        assert severity_color("MEDIUM") == Cyber.YELLOW

    def test_low_is_blue(self):
        assert severity_color("LOW") == Cyber.BLUE

    def test_unknown_is_gray(self):
        assert severity_color("UNKNOWN") == Cyber.GRAY

    def test_case_insensitive(self):
        assert severity_color("critical") == Cyber.RED


class TestCVEFindingDataclass:
    def test_creation(self):
        f = CVEFinding(
            cve_id="CVE-2021-44228",
            description="Log4j RCE",
            score=10.0,
            severity="CRITICAL",
            technology="Apache",
            version="2.14",
        )
        assert f.cve_id == "CVE-2021-44228"
        assert f.score == 10.0

    def test_frozen(self):
        f = CVEFinding(
            cve_id="CVE-2021-44228", description="Log4j RCE",
            score=10.0, severity="CRITICAL", technology="Apache", version="2.14",
        )
        with pytest.raises(AttributeError):
            f.score = 5.0


class TestLookupCves:
    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_findings(self):
        mock_response = {
            "resultsPerPage": 5,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Apache Log4j2 RCE"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                            ]
                        },
                    }
                }
            ],
        }
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(200, json=mock_response)
        )
        findings = await lookup_cves([("Apache", "2.4.41")])
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2021-44228"
        assert findings[0].technology == "Apache"

    @pytest.mark.asyncio
    @respx.mock
    async def test_deduplicates_cves(self):
        mock_response = {
            "resultsPerPage": 5,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Log4j RCE"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
                    }
                }
            ],
        }
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(200, json=mock_response)
        )
        findings = await lookup_cves([("Apache", "2.4.41"), ("Apache", "2.4.41")])
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_empty_versions_returns_empty(self):
        findings = await lookup_cves([])
        assert findings == []


class TestBuildParserCVE:
    def test_has_cve_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--cve"])
        assert args.cve is True

    def test_default_cve_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.cve is False

    def test_has_nvd_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--nvd-api-key", "mykey123"])
        assert args.nvd_api_key == "mykey123"


class TestDetectWaf:
    def test_cloudflare_by_header(self):
        waf = detect_waf({"Server": "cloudflare"}, "", "https://example.com")
        assert "Cloudflare" in waf

    def test_cloudflare_by_cf_ray(self):
        waf = detect_waf({"Cf-Ray": "12345-abc"}, "", "https://example.com")
        assert "Cloudflare" in waf

    def test_cloudflare_by_cookie(self):
        waf = detect_waf({}, "", "https://example.com", cookies=["__cfduid=abc123"])
        assert "Cloudflare" in waf

    def test_akamai_by_header(self):
        waf = detect_waf({"X-Akamai-Transformed": "9 - 0 pmb=mRUM"}, "", "https://example.com")
        assert "Akamai" in waf

    def test_sucuri_by_header(self):
        waf = detect_waf({"X-Sucuri-ID": "12345"}, "", "https://example.com")
        assert "Sucuri" in waf

    def test_imperva_by_header(self):
        waf = detect_waf({"X-Iinfo": "12345"}, "", "https://example.com")
        assert "Imperva" in waf

    def test_imperva_by_cookie(self):
        waf = detect_waf({}, "", "https://example.com", cookies=["incap_ses_123=abc"])
        assert "Imperva" in waf

    def test_modsecurity_by_header(self):
        waf = detect_waf({"Server": "mod_security/2.9"}, "", "https://example.com")
        assert "ModSecurity" in waf

    def test_modsecurity_by_body(self):
        waf = detect_waf({}, '<html><body>mod_security error</body></html>', "https://example.com")
        assert "ModSecurity" in waf

    def test_fortinet_by_header(self):
        waf = detect_waf({"Server": "Fortigate"}, "", "https://example.com")
        assert "Fortinet" in waf

    def test_aws_waf_by_cookie(self):
        waf = detect_waf({}, "", "https://example.com", cookies=["aws-waf-token=abc123"])
        assert "AWS WAF" in waf

    def test_varnish_by_header(self):
        waf = detect_waf({"X-Varnish": "12345"}, "", "https://example.com")
        assert "Varnish" in waf

    def test_multiple_wafs(self):
        waf = detect_waf(
            {"Server": "cloudflare", "X-Sucuri-ID": "123"},
            "",
            "https://example.com",
        )
        assert "Cloudflare" in waf
        assert "Sucuri" in waf

    def test_no_waf(self):
        waf = detect_waf({"Server": "nginx"}, "", "https://example.com")
        assert waf == []

    def test_empty_input(self):
        waf = detect_waf({}, "", "https://example.com")
        assert waf == []


class TestWafSignatures:
    def test_waf_signatures_have_required_keys(self):
        for name, sigs in WAF_SIGNATURES.items():
            assert isinstance(name, str)
            assert isinstance(sigs, dict)
            assert any(k in sigs for k in ("headers", "body", "cookies", "urls"))


class TestEmailPattern:
    def test_pattern_is_compiled(self):
        assert isinstance(EMAIL_PATTERN, re.Pattern)

    def test_matches_basic_email(self):
        assert EMAIL_PATTERN.search("user@example.com").group() == "user@example.com"

    def test_matches_email_with_dots(self):
        assert EMAIL_PATTERN.search("first.last@example.com").group() == "first.last@example.com"

    def test_matches_email_with_plus(self):
        assert EMAIL_PATTERN.search("user+tag@example.com").group() == "user+tag@example.com"

    def test_matches_email_with_subdomain(self):
        assert EMAIL_PATTERN.search("user@mail.example.com").group() == "user@mail.example.com"

    def test_no_match_invalid(self):
        assert EMAIL_PATTERN.search("notanemail") is None

    def test_no_match_at_only(self):
        assert EMAIL_PATTERN.search("user@") is None


class TestHarvestEmails:
    def test_extracts_from_html(self):
        html = '<a href="mailto:contact@example.com">Contact</a><p>admin@test.org</p>'
        emails = harvest_emails(html)
        assert "admin@test.org" in emails
        assert "contact@example.com" in emails

    def test_deduplicates(self):
        text = "user@example.com and user@example.com"
        emails = harvest_emails(text)
        assert emails.count("user@example.com") == 1

    def test_sorted_output(self):
        text = "z@test.com a@test.com m@test.com"
        emails = harvest_emails(text)
        assert emails == sorted(emails)

    def test_empty_text(self):
        assert harvest_emails("") == []

    def test_no_emails(self):
        assert harvest_emails("<html><body>Hello world</body></html>") == []

    def test_extracts_from_robots(self):
        robots = "# Comment\nUser-agent: *\nDisallow: /admin/\nContact: admin@example.com"
        emails = harvest_emails(robots)
        assert "admin@example.com" in emails

    def test_extracts_multiple(self):
        text = "Contact: a@b.com, support@b.com, info@b.com"
        emails = harvest_emails(text)
        assert len(emails) == 3


class TestCrawlInternalLinks:
    @pytest.mark.asyncio
    @respx.mock
    async def test_crawls_internal_links(self, async_client):
        respx.get("http://example.com/contact").mock(
            return_value=httpx.Response(200, text='<html><p>Email: info@example.com</p></html>')
        )
        respx.get("http://example.com/about").mock(
            return_value=httpx.Response(200, text='<html><p>No emails here</p></html>')
        )
        client = async_client
        body = '<html><a href="/contact">Contact</a> <a href="/about">About</a></html>'
        emails = await crawl_internal_links(client, "http://example.com", body, 5.0, max_links=2)
        assert "info@example.com" in emails

    @pytest.mark.asyncio
    @respx.mock
    async def test_skips_external_links(self, async_client):
        body = '<html><a href="https://external.com/mail">Ext</a></html>'
        client = async_client
        emails = await crawl_internal_links(client, "http://example.com", body, 5.0)
        assert emails == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_respects_max_links(self, async_client):
        respx.get("http://example.com/a").mock(
            return_value=httpx.Response(200, text='<html><p>a@test.com</p></html>')
        )
        body = '<html><a href="/a">A</a> <a href="/b">B</a> <a href="/c">C</a></html>'
        client = async_client
        emails = await crawl_internal_links(client, "http://example.com", body, 5.0, max_links=1)
        assert respx.get("http://example.com/b").called is False
        assert respx.get("http://example.com/c").called is False
        assert "a@test.com" in emails

    @pytest.mark.asyncio
    @respx.mock
    async def test_handles_fetch_error(self, async_client):
        respx.get("http://example.com/broken").mock(
            side_effect=httpx.ConnectError("refused")
        )
        body = '<html><a href="/broken">Broken</a></html>'
        client = async_client
        emails = await crawl_internal_links(client, "http://example.com", body, 5.0)
        assert emails == []

    @pytest.mark.asyncio
    async def test_skips_anchors_and_javascript(self, async_client):
        body = '<html><a href="#section">S</a> <a href="javascript:void(0)">JS</a></html>'
        client = async_client
        emails = await crawl_internal_links(client, "http://example.com", body, 5.0)
        assert emails == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_deduplicates_urls(self, async_client):
        respx.get("http://example.com/page").mock(
            return_value=httpx.Response(200, text='<html><p>x@y.com</p></html>')
        )
        body = '<html><a href="/page">P1</a> <a href="/page">P2</a></html>'
        client = async_client
        emails = await crawl_internal_links(client, "http://example.com", body, 5.0)
        assert respx.get("http://example.com/page").call_count == 1
        assert "x@y.com" in emails


class TestBuildParserEmailHarvesting:
    def test_has_deep_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--deep"])
        assert args.deep is True

    def test_default_deep_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.deep is False

    def test_has_crawl_limit(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--crawl-limit", "20"])
        assert args.crawl_limit == 20

    def test_default_crawl_limit(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.crawl_limit == 10


class TestWhoisResultDataclass:
    def test_creation(self):
        w = WhoisResult(
            domain="example.com",
            registrar="GoDaddy",
            registrant_name="Jane Doe",
            registrant_organization="Example Corp",
            registrant_country="US",
            creation_date="1995-08-14T00:00:00",
            expiration_date="2025-08-13T00:00:00",
            updated_date="2024-08-14T00:00:00",
            name_servers=["ns1.example.com", "ns2.example.com"],
            emails=["admin@example.com"],
            status=["clientTransferProhibited"],
        )
        assert w.domain == "example.com"
        assert w.registrar == "GoDaddy"
        assert len(w.name_servers) == 2

    def test_frozen(self):
        w = WhoisResult(domain="example.com")
        with pytest.raises(AttributeError):
            w.domain = "other.com"

    def test_defaults_none(self):
        w = WhoisResult(domain="test.com")
        assert w.registrar is None
        assert w.creation_date is None
        assert w.name_servers is None

    def test_optional_fields(self):
        w = WhoisResult(domain="test.com", registrar="Namecheap")
        assert w.registrar == "Namecheap"
        assert w.registrant_name is None


class TestFormatDate:
    def test_none_returns_none(self):
        assert _format_date(None) is None

    def test_datetime_returns_iso(self):
        from datetime import datetime
        dt = datetime(2024, 1, 15, 10, 30, 0)
        assert _format_date(dt) == "2024-01-15T10:30:00"

    def test_string_returns_itself(self):
        assert _format_date("2024-01-15") == "2024-01-15"

    def test_list_returns_first(self):
        from datetime import datetime
        dt1 = datetime(2024, 1, 15)
        dt2 = datetime(2024, 6, 20)
        assert _format_date([dt1, dt2]) == "2024-01-15T00:00:00"

    def test_empty_list_returns_none(self):
        assert _format_date([]) is None


class TestEnsureList:
    def test_none_returns_none(self):
        assert _ensure_list(None) is None

    def test_string_returns_list(self):
        assert _ensure_list("hello") == ["hello"]

    def test_empty_string_returns_none(self):
        assert _ensure_list("") is None

    def test_list_passes_through(self):
        assert _ensure_list(["a", "b"]) == ["a", "b"]

    def test_list_with_none_filters(self):
        assert _ensure_list(["a", None, "b"]) == ["a", "b"]

    def test_empty_list_returns_none(self):
        assert _ensure_list([]) is None


class TestRunWhois:
    @pytest.mark.asyncio
    async def test_returns_none_for_ip(self):
        result = await run_whois("192.168.1.1")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_for_ipv6(self):
        result = await run_whois("::1")
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_none_on_error(self):
        import unittest.mock

        import whois as _whois
        with unittest.mock.patch.object(_whois, "whois", side_effect=Exception("connection refused")):
            result = await run_whois("nonexistent.invalid")
            assert result is None

    @pytest.mark.asyncio
    async def test_handles_url_input(self):
        result = await run_whois("https://example.com/path")
        assert result is None or result.domain == "example.com"

    @pytest.mark.asyncio
    async def test_returns_whois_result_on_success(self):
        import unittest.mock

        import whois as _whois
        mock_w = unittest.mock.MagicMock()
        mock_w.registrar = "Test Registrar"
        mock_w.name = "Test Owner"
        mock_w.org = "Test Org"
        mock_w.country = "US"
        mock_w.creation_date = "2020-01-01"
        mock_w.expiration_date = "2025-12-31"
        mock_w.updated_date = "2024-06-15"
        mock_w.name_servers = ["ns1.test.com", "ns2.test.com"]
        mock_w.emails = ["admin@test.com"]
        mock_w.status = ["active"]

        with unittest.mock.patch.object(_whois, "whois", return_value=mock_w):
            result = await run_whois("test.com")
            assert result is not None
            assert result.domain == "test.com"
            assert result.registrar == "Test Registrar"
            assert result.registrant_name == "Test Owner"
            assert result.name_servers == ["ns1.test.com", "ns2.test.com"]


class TestProbeStatusEdgeCases:
    @pytest.mark.asyncio
    @respx.mock
    async def test_timeout_returns_none(self, async_client):
        respx.get("http://example.com/robots.txt").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        result = await probe_status(async_client, "http://example.com/robots.txt", 0.1)
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_403_returns_status(self, async_client):
        respx.get("http://example.com/forbidden").mock(
            return_value=httpx.Response(403)
        )
        result = await probe_status(async_client, "http://example.com/forbidden", 5.0)
        assert result == 403

    @pytest.mark.asyncio
    @respx.mock
    async def test_500_returns_status(self, async_client):
        respx.get("http://example.com/error").mock(
            return_value=httpx.Response(500)
        )
        result = await probe_status(async_client, "http://example.com/error", 5.0)
        assert result == 500


class TestCrawlInternalLinksEdgeCases:
    @pytest.mark.asyncio
    @respx.mock
    async def test_connection_refused_returns_empty(self, async_client):
        respx.get("http://example.com/").mock(
            side_effect=httpx.ConnectError("refused")
        )
        result = await crawl_internal_links(async_client, "http://example.com", "<html></html>", timeout=1.0)
        assert result == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_timeout_returns_empty(self, async_client):
        respx.get("http://example.com/").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        result = await crawl_internal_links(async_client, "http://example.com", "<html></html>", timeout=0.1)
        assert result == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_malformed_html_handled(self, async_client):
        respx.get("http://example.com/page").mock(
            return_value=httpx.Response(200, text="Contact: admin@example.com")
        )
        body = "<html><body><a href='/page'>link</a></body></html>"
        result = await crawl_internal_links(async_client, "http://example.com", body, timeout=5.0)
        assert "admin@example.com" in result


class TestLookupCvesEdgeCases:
    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_versions_returns_empty(self):
        result = await lookup_cves([])
        assert result == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_connection_error_returns_empty(self):
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            side_effect=httpx.ConnectError("refused")
        )
        result = await lookup_cves([("nginx", "1.21.0")])
        assert result == []


class TestDryRun:
    def test_dry_run_flag_exists_in_parser(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--dry-run"])
        assert args.dry_run is True

    def test_dry_run_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.dry_run is False

    def test_dry_run_returns_zero(self, capsys):
        import asyncio as _asyncio
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--dry-run"])
        result = _asyncio.run(_async_run_once(args))
        assert result == 0

    def test_dry_run_outputs_info(self, capsys):
        import asyncio as _asyncio
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--dry-run"])
        _asyncio.run(_async_run_once(args))
        captured = capsys.readouterr()
        assert "DRY-RUN" in captured.out
        assert "Nenhuma requisicao" in captured.out


class TestMain:
    @patch("utils.run_interactive_shell")
    def test_no_target_shells_interactive(self, mock_shell):
        mock_shell.return_value = 0
        from webrecon import main
        args = argparse.Namespace(
            url=None, target_list=None, quiet=False, output=None,
            verbose=False, color=None, log_file=None, timeout=5.0,
            deep=False, cve=False, nvd_api_key=None, crawl_limit=10,
            retries=3, dry_run=False, verify=False, proxy=None,
            auth=None, bearer_token=None, cookie=None, header=[],
        )
        with patch("webrecon.argparse.ArgumentParser.parse_args", return_value=args):
            result = main()
            assert result == 0
            mock_shell.assert_called_once()

    def test_quiet_without_output_returns_1(self):
        from webrecon import main
        args = argparse.Namespace(
            url="https://example.com", target_list=None, quiet=True, output=None,
            verbose=False, color=None, log_file=None, timeout=5.0,
            deep=False, cve=False, nvd_api_key=None, crawl_limit=10,
            retries=3, dry_run=False, verify=False, proxy=None,
            auth=None, bearer_token=None, cookie=None, header=[],
        )
        with patch("webrecon.argparse.ArgumentParser.parse_args", return_value=args):
            result = main()
            assert result == 1

    @patch("webrecon.run_once")
    def test_valid_url_calls_run_once(self, mock_run_once):
        mock_run_once.return_value = 0
        from webrecon import main
        args = argparse.Namespace(
            url="https://example.com", target_list=None, quiet=False, output=None,
            verbose=False, color=None, log_file=None, timeout=5.0,
            deep=False, cve=False, nvd_api_key=None, crawl_limit=10,
            retries=3, dry_run=False, verify=False, proxy=None,
            auth=None, bearer_token=None, cookie=None, header=[],
        )
        with patch("webrecon.argparse.ArgumentParser.parse_args", return_value=args):
            result = main()
            assert result == 0
            mock_run_once.assert_called_once()

    @patch("webrecon.run_once")
    def test_exception_returns_1(self, mock_run_once):
        mock_run_once.side_effect = RuntimeError("fail")
        from webrecon import main
        args = argparse.Namespace(
            url="https://example.com", target_list=None, quiet=False, output=None,
            verbose=False, color=None, log_file=None, timeout=5.0,
            deep=False, cve=False, nvd_api_key=None, crawl_limit=10,
            retries=3, dry_run=False, verify=False, proxy=None,
            auth=None, bearer_token=None, cookie=None, header=[],
        )
        with patch("webrecon.argparse.ArgumentParser.parse_args", return_value=args):
            result = main()
            assert result == 1
