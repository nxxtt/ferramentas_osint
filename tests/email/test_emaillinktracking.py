#!/usr/bin/env python3
"""Testes unitarios do modulo de Email Link Tracking."""
import smtplib
from unittest.mock import MagicMock, patch

import pytest

from mytools.email.emaillinktracking import (
    _CATEGORY_MAP,
    TrackingAttempt,
    TrackingResult,
    _build_test_email,
    _build_test_html,
    _connect_smtp,
    _detect_css_tracking,
    _detect_font_fingerprint,
    _detect_hidden_element,
    _detect_link_rewrite,
    _detect_message_id_tracking,
    _detect_pixel_1x1,
    _detect_pixel_css,
    _detect_read_receipt,
    _detect_redirect_chain,
    _detect_url_shortener,
    _detect_utm_params,
    _detect_web_beacon,
    _get_banner,
    build_parser,
    print_results,
    scan_link_tracking,
)


class TestTrackingAttempt:
    def test_frozen(self) -> None:
        a = TrackingAttempt(technique="pixel_1x1", status="detected",
                            details="found", error="")
        with pytest.raises(AttributeError):
            a.technique = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(TrackingAttempt, "__slots__")


class TestTrackingResult:
    def test_frozen(self) -> None:
        r = TrackingResult(
            target="mail.test.com", port=587, tls=False, banner="220",
            attempts=[], detected_techniques=[], clean_techniques=[],
            issues=[], overall_status="clean",
        )
        with pytest.raises(AttributeError):
            r.target = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(TrackingResult, "__slots__")


class TestBuildTestHtml:
    def test_contains_tracking_payloads(self) -> None:
        html = _build_test_html()
        assert "tracking.example.com" in html
        assert "utm_source" in html
        assert "display:none" in html
        assert "@font-face" in html

    def test_is_valid_html(self) -> None:
        html = _build_test_html()
        assert html.startswith("<html>")
        assert html.endswith("</html>")


class TestBuildTestEmail:
    def test_email_structure(self) -> None:
        msg = _build_test_email("from@test.com", "to@test.com")
        assert msg["From"] == "from@test.com"
        assert msg["To"] == "to@test.com"
        assert "Link Tracking Bypass Test" in msg["Subject"]
        assert "mytools-emaillinktracking" in msg["X-Tracking-Test"]

    def test_email_has_html_part(self) -> None:
        msg = _build_test_email("a@b.com", "c@d.com")
        payload = msg.get_payload()
        assert len(payload) == 1
        assert payload[0].get_content_type() == "text/html"


class TestCategoryMap:
    def test_all_categories(self) -> None:
        expected = {"pixel", "link", "header", "css"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_categories_cover_all_techniques(self) -> None:
        all_named = set()
        for names in _CATEGORY_MAP.values():
            all_named.update(names)
        assert len(all_named) == 12


class TestParser:
    def test_default_port(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com"])
        assert args.target == "mail.test.com"
        assert args.port == 587

    def test_custom_port(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--port", "25"])
        assert args.port == 25

    def test_from_addr(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--from-addr", "a@b.com"])
        assert args.from_addr == "a@b.com"

    def test_to_addr(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--to-addr", "c@d.com"])
        assert args.to_addr == "c@d.com"

    def test_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--category", "pixel"])
        assert args.category == "pixel"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["mail.test.com", "--category", cat])
            assert args.category == cat

    def test_dry_run(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--dry-run", "mail.test.com"])
        assert args.dry_run is True


class TestConnectSmtp:
    @patch("mytools.email.emaillinktracking.smtplib.SMTP")
    def test_connect_ok(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_smtp.return_value = mock_server
        server, tls = _connect_smtp("mail.test.com", 587, 10.0)
        mock_smtp.assert_called_once_with("mail.test.com", 587, timeout=10.0)
        assert server is not None
        assert tls is False

    @patch("mytools.email.emaillinktracking.smtplib.SMTP_SSL")
    def test_connect_ssl(self, mock_ssl: MagicMock) -> None:
        mock_server = MagicMock()
        mock_ssl.return_value = mock_server
        _server, tls = _connect_smtp("mail.test.com", 465, 10.0)
        mock_ssl.assert_called_once_with("mail.test.com", 465, timeout=10.0)
        assert tls is True

    @patch("mytools.email.emaillinktracking.smtplib.SMTP")
    def test_connect_fail(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = ConnectionError("refused")
        with pytest.raises(ConnectionError):
            _connect_smtp("bad.host", 587, 5.0)


class TestGetBanner:
    def test_banner_ok(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"250 mail.example.com")
        assert _get_banner(server) == "250 mail.example.com"

    def test_banner_exception(self) -> None:
        server = MagicMock()
        server.ehlo.side_effect = smtplib.SMTPException("fail")
        assert _get_banner(server) == ""


class TestDetectors:
    def test_pixel_1x1_detected(self) -> None:
        status, _details = _detect_pixel_1x1("", 'width="1" height="1"')
        assert status == "detected"

    def test_pixel_1x1_not_detected(self) -> None:
        status, _ = _detect_pixel_1x1("", "normal content")
        assert status == "not_detected"

    def test_pixel_css_detected(self) -> None:
        status, _ = _detect_pixel_css("", "background-image:url('https://track.example.com/bg.gif')")
        assert status == "detected"

    def test_pixel_css_not_detected(self) -> None:
        status, _ = _detect_pixel_css("", "normal content")
        assert status == "not_detected"

    def test_web_beacon_detected(self) -> None:
        status, _ = _detect_web_beacon("", 'webbeacon.example.com/beacon')
        assert status == "detected"

    def test_web_beacon_not_detected(self) -> None:
        status, _ = _detect_web_beacon("", "normal content")
        assert status == "not_detected"

    def test_link_rewrite_preserved(self) -> None:
        status, _ = _detect_link_rewrite("https://legit.com/page", "", '<a href="https://legit.com/page">')
        assert status == "not_detected"

    def test_link_rewrite_detected(self) -> None:
        status, _ = _detect_link_rewrite("https://legit.com/page", "", "redirect tracking click")
        assert status == "detected"

    def test_utm_detected(self) -> None:
        status, details = _detect_utm_params("utm_source=email&utm_medium=campaign")
        assert status == "detected"
        assert "2" in details

    def test_utm_not_detected(self) -> None:
        status, _ = _detect_utm_params("no utm params here")
        assert status == "not_detected"

    def test_redirect_detected(self) -> None:
        status, _ = _detect_redirect_chain("redirect to destination")
        assert status == "detected"

    def test_redirect_not_detected(self) -> None:
        status, _ = _detect_redirect_chain("no tracking here")
        assert status == "not_detected"

    def test_url_shortener_detected(self) -> None:
        status, details = _detect_url_shortener("visit https://bit.ly/abc123")
        assert status == "detected"
        assert "bit.ly" in details

    def test_url_shortener_not_detected(self) -> None:
        status, _ = _detect_url_shortener("https://legitimate.com/page")
        assert status == "not_detected"

    def test_read_receipt_detected(self) -> None:
        status, _ = _detect_read_receipt("Disposition-Notification-To: user@test.com")
        assert status == "detected"

    def test_read_receipt_not_detected(self) -> None:
        status, _ = _detect_read_receipt("Normal headers")
        assert status == "not_detected"

    def test_message_id_tracking_detected(self) -> None:
        status, _ = _detect_message_id_tracking("<tracking-abc@mail.test.com>")
        assert status == "detected"

    def test_message_id_tracking_not_detected(self) -> None:
        status, _ = _detect_message_id_tracking("<正常的@mail.test.com>")
        assert status == "not_detected"

    def test_hidden_element_detected(self) -> None:
        status, _ = _detect_hidden_element('style="display:none" data-track-id="123"')
        assert status == "detected"

    def test_hidden_element_not_detected(self) -> None:
        status, _ = _detect_hidden_element("visible content")
        assert status == "not_detected"

    def test_css_tracking_detected(self) -> None:
        status, _ = _detect_css_tracking('background:url("https://track.example.com/t.gif")')
        assert status == "detected"

    def test_css_tracking_not_detected(self) -> None:
        status, _ = _detect_css_tracking("no background tracking")
        assert status == "not_detected"

    def test_font_fingerprint_detected(self) -> None:
        status, _ = _detect_font_fingerprint('@font-face{src:url("https://track.example.com/f.woff")}')
        assert status == "detected"

    def test_font_fingerprint_not_detected(self) -> None:
        status, _ = _detect_font_fingerprint("no font tracking")
        assert status == "not_detected"


class TestScanLinkTracking:
    @patch("mytools.email.emaillinktracking._connect_smtp")
    def test_connection_failure(self, mock_conn: MagicMock) -> None:
        mock_conn.side_effect = ConnectionError("refused")
        result = scan_link_tracking("mail.test.com", 587)
        assert result.overall_status == "error"
        assert any("Falha de conexao" in i for i in result.issues)

    @patch("mytools.email.emaillinktracking._connect_smtp")
    def test_server_quitted(self, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_server.data.return_value = (250, b"OK")
        mock_conn.return_value = (mock_server, False)

        scan_link_tracking("mail.test.com", 587)
        mock_server.quit.assert_called()

    @patch("mytools.email.emaillinktracking._connect_smtp")
    def test_tls_detected(self, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_server.data.return_value = (250, b"OK")
        mock_conn.return_value = (mock_server, True)

        result = scan_link_tracking("mail.test.com", 587)
        assert result.tls is True

    @patch("mytools.email.emaillinktracking._connect_smtp")
    def test_result_fields(self, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_server.data.return_value = (250, b"OK")
        mock_conn.return_value = (mock_server, False)

        result = scan_link_tracking("mail.test.com", 25)
        assert result.target == "mail.test.com"
        assert result.port == 25
        assert isinstance(result.banner, str)

    @patch("mytools.email.emaillinktracking._connect_smtp")
    def test_category_filter(self, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_server.data.return_value = (250, b"OK")
        mock_conn.return_value = (mock_server, False)

        result = scan_link_tracking("mail.test.com", 587, category="pixel")
        assert len(result.attempts) == 3

    @patch("mytools.email.emaillinktracking._connect_smtp")
    def test_invalid_category(self, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_server.data.return_value = (250, b"OK")
        mock_conn.return_value = (mock_server, False)

        result = scan_link_tracking("mail.test.com", 587, category="invalid")
        assert any("Categoria desconhecida" in i for i in result.issues)

    @patch("mytools.email.emaillinktracking._connect_smtp")
    def test_smtp_data_error(self, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_server.data.side_effect = smtplib.SMTPResponseException(550, b"Rejected")
        mock_conn.return_value = (mock_server, False)

        result = scan_link_tracking("mail.test.com", 587)
        assert len(result.attempts) == 12

    @patch("mytools.email.emaillinktracking._connect_smtp")
    def test_all_techniques_present(self, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_server.data.return_value = (250, b"OK")
        mock_conn.return_value = (mock_server, False)

        result = scan_link_tracking("mail.test.com", 587)
        assert len(result.attempts) == 12


class TestPrintResults:
    def test_print_tracking_detected(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TrackingResult(
            target="mail.test.com", port=587, tls=False, banner="220",
            attempts=[TrackingAttempt(
                technique="pixel_1x1", status="detected",
                details="Pixel found", error="",
            )],
            detected_techniques=["pixel_1x1"],
            clean_techniques=[],
            issues=["1/12 tracking detected"],
            overall_status="tracking_detected",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "TRACKING" in captured.out

    def test_print_clean(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TrackingResult(
            target="mail.test.com", port=587, tls=True, banner="220",
            attempts=[TrackingAttempt(
                technique="pixel_1x1", status="not_detected",
                details="Clean", error="",
            )],
            detected_techniques=[],
            clean_techniques=["pixel_1x1"],
            issues=["No tracking"],
            overall_status="clean",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "clean" in captured.out.lower()

    def test_print_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TrackingResult(
            target="mail.test.com", port=587, tls=False, banner="",
            attempts=[], detected_techniques=[], clean_techniques=[],
            issues=["Connection failed"], overall_status="error",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "ERROR" in captured.out

    def test_print_with_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TrackingResult(
            target="mail.test.com", port=587, tls=False, banner="220",
            attempts=[TrackingAttempt(
                technique="pixel_1x1", status="error",
                details="", error="timeout",
            )],
            detected_techniques=[],
            clean_techniques=[],
            issues=[],
            overall_status="warning",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "timeout" in captured.out
