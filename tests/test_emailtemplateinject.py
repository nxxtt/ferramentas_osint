#!/usr/bin/env python3
"""Testes unitarios do modulo de Email Template Injection."""
from unittest.mock import MagicMock, patch

import pytest

import emailtemplateinject
from emailtemplateinject import (
    TemplateInjectionResult,
    TemplateProbe,
    _build_email,
    _connect_smtp,
    _detect_engine_from_response,
    _get_banner,
    _send_template_email,
    build_parser,
    print_results,
    scan_email_template_injection,
)


class TestTemplateProbe:
    def test_frozen(self) -> None:
        p = TemplateProbe(engine="jinja2", payload_name="test", payload="x",
                          response_snippet="y", detected=True, status="detected")
        with pytest.raises(AttributeError):
            p.engine = "z"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(TemplateProbe, "__slots__")


class TestTemplateInjectionResult:
    def test_frozen(self) -> None:
        r = TemplateInjectionResult(
            target="mail.test.com", port=587, banner="220",
            engines_detected=[], probes=[], issues=[], overall_status="safe",
        )
        with pytest.raises(AttributeError):
            r.target = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(TemplateInjectionResult, "__slots__")


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

    def test_dry_run(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--dry-run", "mail.test.com"])
        assert args.dry_run is True


class TestConnectSmtp:
    @patch("emailtemplateinject.smtplib.SMTP")
    def test_connect_ok(self, mock_smtp: MagicMock) -> None:
        mock_smtp.return_value = MagicMock()
        result = _connect_smtp("mail.test.com", 587, 10.0)
        mock_smtp.assert_called_once_with("mail.test.com", 587, timeout=10.0)
        assert result is not None

    @patch("emailtemplateinject.smtplib.SMTP")
    def test_connect_error(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = emailtemplateinject.smtplib.SMTPConnectError(421, b"unavail")
        with pytest.raises(ConnectionError):
            _connect_smtp("mail.test.com", 587, 10.0)

    @patch("emailtemplateinject.smtplib.SMTP")
    def test_connect_os_error(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = OSError("timeout")
        with pytest.raises(ConnectionError):
            _connect_smtp("mail.test.com", 587, 10.0)


class TestGetBanner:
    def test_ok(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"220 mail ESMTP")
        result = _get_banner(server)
        assert "220 mail ESMTP" in result

    def test_smtp_exception(self) -> None:
        server = MagicMock()
        server.ehlo.side_effect = emailtemplateinject.smtplib.SMTPException("fail")
        result = _get_banner(server)
        assert result == ""


class TestBuildEmail:
    def test_basic(self) -> None:
        msg = _build_email("a@b.com", "c@d.com", "Test Subject", "Test body")
        assert "From: a@b.com" in msg
        assert "To: c@d.com" in msg
        assert "Subject: Test Subject" in msg
        assert "Test body" in msg

    def test_multiline_body(self) -> None:
        msg = _build_email("a@b.com", "c@d.com", "Sub", "Line 1\r\nLine 2")
        assert "Line 1\r\nLine 2" in msg

    def test_special_chars(self) -> None:
        msg = _build_email("a@b.com", "c@d.com", "Sub {{7*7}}", "Body")
        assert "{{7*7}}" in msg


class TestSendTemplateEmail:
    def test_accepted(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"OK")
        server.mail.return_value = (250, b"OK")
        server.rcpt.return_value = (250, b"OK")
        server.data.return_value = (250, b"OK")
        accepted, details = _send_template_email(server, "a@b.com", "c@d.com", "test", "{{7*7}}")
        assert accepted is True
        assert "accepted" in details

    def test_rejected(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"OK")
        server.mail.return_value = (250, b"OK")
        server.rcpt.side_effect = emailtemplateinject.smtplib.SMTPResponseException(550, b"Rejected")
        accepted, details = _send_template_email(server, "a@b.com", "c@d.com", "test", "{{7*7}}")
        assert accepted is False
        assert "550" in details

    def test_smtp_exception(self) -> None:
        server = MagicMock()
        server.ehlo.side_effect = emailtemplateinject.smtplib.SMTPException("fail")
        accepted, _details = _send_template_email(server, "a@b.com", "c@d.com", "test", "{{7*7}}")
        assert accepted is False


class TestDetectEngineFromResponse:
    def test_jinja2_detected(self) -> None:
        detected, info = _detect_engine_from_response("TemplateError: undefined", "jinja2_expr")
        assert detected is True
        assert "jinja2" in info

    def test_handlebars_detected(self) -> None:
        detected, info = _detect_engine_from_response("Handlebars: helper not found", "handlebars_expr")
        assert detected is True
        assert "handlebars" in info

    def test_mako_detected(self) -> None:
        detected, info = _detect_engine_from_response("MakoSyntaxError", "mako_expr")
        assert detected is True
        assert "mako" in info

    def test_tornado_detected(self) -> None:
        detected, info = _detect_engine_from_response("Tornado template error", "tornado_expr")
        assert detected is True
        assert "tornado" in info

    def test_blocked(self) -> None:
        detected, info = _detect_engine_from_response("550 Rejected", "jinja2_expr")
        assert detected is False
        assert info == "blocked"

    def test_unknown(self) -> None:
        detected, info = _detect_engine_from_response("250 OK", "jinja2_expr")
        assert detected is False
        assert info == "unknown"

    def test_case_insensitive(self) -> None:
        detected, info = _detect_engine_from_response("JINJA Template error", "test")
        assert detected is True
        assert "jinja2" in info


class TestScanEmailTemplateInjection:
    def test_connection_failure(self) -> None:
        with patch("emailtemplateinject._connect_smtp", side_effect=ConnectionError("refused")):
            result = scan_email_template_injection("mail.test.com", 587)
            assert result.overall_status == "unknown"
            assert result.issues

    def test_all_blocked(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail")
        mock_server.mail.return_value = (250, b"OK")
        mock_server.rcpt.side_effect = emailtemplateinject.smtplib.SMTPResponseException(550, b"Rejected")

        with (
            patch("emailtemplateinject._connect_smtp", return_value=mock_server),
            patch("emailtemplateinject._get_banner", return_value="220 mail"),
        ):
            result = scan_email_template_injection("mail.test.com", 587)
            assert result.overall_status == "safe"
            assert all(p.status == "blocked" for p in result.probes)

    def test_all_accepted(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail")
        mock_server.mail.return_value = (250, b"OK")
        mock_server.rcpt.return_value = (250, b"OK")
        mock_server.data.return_value = (250, b"OK")

        with (
            patch("emailtemplateinject._connect_smtp", return_value=mock_server),
            patch("emailtemplateinject._get_banner", return_value="220 mail"),
        ):
            result = scan_email_template_injection("mail.test.com", 587)
            assert result.overall_status == "unknown"
            assert all(p.status == "not_detected" for p in result.probes)

    def test_vulnerable(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail")
        mock_server.mail.return_value = (250, b"OK")
        mock_server.rcpt.return_value = (250, b"OK")
        mock_server.data.return_value = (250, b"OK")

        with (
            patch("emailtemplateinject._connect_smtp", return_value=mock_server),
            patch("emailtemplateinject._get_banner", return_value="220 mail"),
            patch("emailtemplateinject._detect_engine_from_response", return_value=(True, "jinja2")),
        ):
            result = scan_email_template_injection("mail.test.com", 587)
            assert result.overall_status == "vulnerable"
            assert "jinja2" in result.engines_detected

    def test_custom_port(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail")
        mock_server.mail.return_value = (250, b"OK")
        mock_server.rcpt.side_effect = emailtemplateinject.smtplib.SMTPResponseException(550, b"Rejected")

        with (
            patch("emailtemplateinject._connect_smtp", return_value=mock_server),
            patch("emailtemplateinject._get_banner", return_value="220 mail"),
        ):
            result = scan_email_template_injection("mail.test.com", 25, from_addr="a@b.com")
            assert result.port == 25


class TestPrintResults:
    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = TemplateInjectionResult(
            target="mail.test.com", port=587, banner="220",
            engines_detected=["jinja2"],
            probes=[TemplateProbe("jinja2", "jinja2_expr", "{{7*7}}", "49", True, "detected")],
            issues=["Vulneravel"], overall_status="vulnerable",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "VULNERAVEL" in out

    def test_safe(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = TemplateInjectionResult(
            target="mail.test.com", port=587, banner="220",
            engines_detected=[],
            probes=[TemplateProbe("unknown", "jinja2_expr", "{{7*7}}", "550 Rejected", False, "blocked")],
            issues=["Seguro"], overall_status="safe",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "SAFE" in out

    def test_unknown(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = TemplateInjectionResult(
            target="mail.test.com", port=587, banner="220",
            engines_detected=[],
            probes=[TemplateProbe("unknown", "jinja2_expr", "{{7*7}}", "250 OK", False, "not_detected")],
            issues=["Inconclusivo"], overall_status="unknown",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "UNKNOWN" in out

    def test_with_probes(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = TemplateInjectionResult(
            target="mail.test.com", port=587, banner="220",
            engines_detected=["jinja2", "handlebars"],
            probes=[
                TemplateProbe("jinja2", "jinja2_expr", "{{7*7}}", "49", True, "detected"),
                TemplateProbe("unknown", "mako_expr", "${7*7}", "550", False, "blocked"),
                TemplateProbe("unknown", "tornado_expr", "{{7*7}}", "error", False, "error"),
            ],
            issues=[], overall_status="vulnerable",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "jinja2" in out
        assert "handlebars" in out
        assert "jinja2_expr" in out
