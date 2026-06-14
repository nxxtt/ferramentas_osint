from __future__ import annotations

import argparse
import re

import responses

from utils import Cyber, create_session
from webrecon import (
    CMS_SIGNATURES,
    CVEFinding,
    EMAIL_PATTERN,
    FRAMEWORK_SIGNATURES,
    LIBRARY_SIGNATURES,
    SERVER_PATTERNS,
    WAF_SIGNATURES,
    ReconResult,
    _severity_color,
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
        try:
            normalize_url("ftp://example.com")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_no_netloc_raises(self):
        try:
            normalize_url("http://")
            assert False, "Should have raised"
        except ValueError:
            pass

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
        try:
            candidate_urls("")
            assert False, "Should have raised"
        except ValueError:
            pass

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
    @responses.activate
    def test_returns_status_on_success(self):
        responses.add(responses.GET, "http://example.com/robots.txt", body=b"User-agent: *", status=200)
        session = create_session(user_agent="TestAgent/1.0")
        result = probe_status(session, "http://example.com/robots.txt", 5.0)
        assert result == 200

    @responses.activate
    def test_returns_none_on_error(self):
        import requests as _requests
        responses.add(responses.GET, "http://example.com/robots.txt", body=_requests.exceptions.ConnectionError("refused"))
        session = create_session(user_agent="TestAgent/1.0")
        result = probe_status(session, "http://example.com/robots.txt", 5.0)
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
        try:
            r.status = 404
            assert False, "Should be frozen"
        except AttributeError:
            pass


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
        assert _severity_color("CRITICAL") == Cyber.RED

    def test_high_is_magenta(self):
        assert _severity_color("HIGH") == Cyber.MAGENTA

    def test_medium_is_yellow(self):
        assert _severity_color("MEDIUM") == Cyber.YELLOW

    def test_low_is_green(self):
        assert _severity_color("LOW") == Cyber.GREEN

    def test_unknown_is_gray(self):
        assert _severity_color("UNKNOWN") == Cyber.GRAY

    def test_case_insensitive(self):
        assert _severity_color("critical") == Cyber.RED


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
        try:
            f.score = 5.0
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestLookupCves:
    @responses.activate
    def test_returns_findings(self):
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
        responses.add(responses.GET, "https://services.nvd.nist.gov/rest/json/cves/2.0", json=mock_response, status=200)
        findings = lookup_cves([("Apache", "2.4.41")])
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2021-44228"
        assert findings[0].technology == "Apache"

    @responses.activate
    def test_deduplicates_cves(self):
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
        responses.add(responses.GET, "https://services.nvd.nist.gov/rest/json/cves/2.0", json=mock_response, status=200)
        findings = lookup_cves([("Apache", "2.4.41"), ("Apache", "2.4.41")])
        assert len(findings) == 1

    def test_empty_versions_returns_empty(self):
        findings = lookup_cves([])
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
    @responses.activate
    def test_crawls_internal_links(self):
        responses.add(
            responses.GET, "http://example.com/contact",
            body=b'<html><p>Email: info@example.com</p></html>',
            status=200,
        )
        responses.add(
            responses.GET, "http://example.com/about",
            body=b'<html><p>No emails here</p></html>',
            status=200,
        )
        session = create_session(user_agent="TestAgent/1.0")
        body = '<html><a href="/contact">Contact</a> <a href="/about">About</a></html>'
        emails = crawl_internal_links(session, "http://example.com", body, 5.0, max_links=2)
        assert "info@example.com" in emails

    @responses.activate
    def test_skips_external_links(self):
        body = '<html><a href="https://external.com/mail">Ext</a></html>'
        session = create_session(user_agent="TestAgent/1.0")
        emails = crawl_internal_links(session, "http://example.com", body, 5.0)
        assert emails == []

    @responses.activate
    def test_respects_max_links(self):
        responses.add(
            responses.GET, "http://example.com/a",
            body=b'<html><p>a@test.com</p></html>',
            status=200,
        )
        body = '<html><a href="/a">A</a> <a href="/b">B</a> <a href="/c">C</a></html>'
        session = create_session(user_agent="TestAgent/1.0")
        emails = crawl_internal_links(session, "http://example.com", body, 5.0, max_links=1)
        assert len(responses.calls) == 1
        assert "a@test.com" in emails

    @responses.activate
    def test_handles_fetch_error(self):
        import requests as _requests
        responses.add(
            responses.GET, "http://example.com/broken",
            body=_requests.exceptions.ConnectionError("refused"),
        )
        body = '<html><a href="/broken">Broken</a></html>'
        session = create_session(user_agent="TestAgent/1.0")
        emails = crawl_internal_links(session, "http://example.com", body, 5.0)
        assert emails == []

    def test_skips_anchors_and_javascript(self):
        body = '<html><a href="#section">S</a> <a href="javascript:void(0)">JS</a></html>'
        session = create_session(user_agent="TestAgent/1.0")
        emails = crawl_internal_links(session, "http://example.com", body, 5.0)
        assert emails == []

    @responses.activate
    def test_deduplicates_urls(self):
        responses.add(
            responses.GET, "http://example.com/page",
            body=b'<html><p>x@y.com</p></html>',
            status=200,
        )
        body = '<html><a href="/page">P1</a> <a href="/page">P2</a></html>'
        session = create_session(user_agent="TestAgent/1.0")
        emails = crawl_internal_links(session, "http://example.com", body, 5.0)
        assert len(responses.calls) == 1
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
