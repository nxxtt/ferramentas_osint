#!/usr/bin/env python3
"""Testes unitarios do modulo de SMTP Header Injection."""
from unittest.mock import MagicMock, patch

import pytest

from smtpinjection import (
    InjectionAttempt,
    InjectionResult,
    _connect_smtp,
    _test_injection,
    build_parser,
    print_results,
    scan_smtp_injection,
)


class TestInjectionAttempt:
    def test_frozen(self) -> None:
        a = InjectionAttempt(field="To", payload_name="crlf", payload="x",
                             status="blocked", server_response="501", error="")
        with pytest.raises(AttributeError):
            a.field = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(InjectionAttempt, "__slots__")


class TestInjectionResult:
    def test_frozen(self) -> None:
        r = InjectionResult(target="a", port=25, tls=False, banner="",
                            ehlo_response="", attempts=[], vulnerable_fields=[],
                            issues=[])
        with pytest.raises(AttributeError):
            r.target = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(InjectionResult, "__slots__")


class TestParser:
    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com"])
        assert args.target == "mail.example.com"

    def test_port(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--port", "25"])
        assert args.port == 25

    def test_from_addr(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--from-addr", "a@b.com"])
        assert args.from_addr == "a@b.com"

    def test_to_addr(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--to-addr", "x@y.com"])
        assert args.to_addr == "x@y.com"

    def test_no_tls(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--no-tls"])
        assert args.no_tls is True

    def test_fields(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--fields", "To,Subject"])
        assert args.fields == "To,Subject"

    def test_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--timeout", "5.0"])
        assert args.timeout == 5.0


class TestConnectSmtp:
    @patch("smtpinjection.smtplib.SMTP")
    def test_connect_ok(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"Hello")
        mock_smtp.return_value = mock_server
        server, _banner, _ehlo = _connect_smtp("mail.test.com", 587, 10.0, False)
        assert server is mock_server
        mock_smtp.assert_called_once_with("mail.test.com", 587, timeout=10.0)

    @patch("smtpinjection.smtplib.SMTP_SSL")
    def test_connect_ssl(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"Hello")
        mock_smtp.return_value = mock_server
        server, _banner, _ehlo = _connect_smtp("mail.test.com", 465, 10.0, False)
        assert server is mock_server
        mock_smtp.assert_called_once_with("mail.test.com", 465, timeout=10.0)

    @patch("smtpinjection.smtplib.SMTP")
    def test_connect_failure(self, mock_smtp: MagicMock) -> None:
        import smtplib
        mock_smtp.side_effect = smtplib.SMTPConnectError(421, b"Service unavailable")
        with pytest.raises(ConnectionError, match="Falha ao conectar"):
            _connect_smtp("bad.host", 25, 5.0, False)

    @patch("smtpinjection.smtplib.SMTP")
    def test_connect_os_error(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = OSError("Connection refused")
        with pytest.raises(ConnectionError, match="Erro de conexao"):
            _connect_smtp("bad.host", 25, 5.0, False)


class TestTestInjection:
    def _make_server(self, sendmail_exc: Exception | None = None) -> MagicMock:
        server = MagicMock()
        server.ehlo.return_value = (250, b"EHLO")
        server.mail.return_value = (250, b"OK")
        server.rcpt.return_value = (250, b"OK")
        if sendmail_exc is not None:
            server.sendmail.side_effect = sendmail_exc
        return server

    def test_injected(self) -> None:
        server = self._make_server()
        attempt = _test_injection(server, "a@b.com", "x@y.com", "To", "crlf_header",
                                  "\r\nX-Injected: test")
        assert attempt.status == "injected"

    def test_blocked(self) -> None:
        import smtplib
        exc = smtplib.SMTPDataError(501, b"Bad syntax")
        server = self._make_server(sendmail_exc=exc)
        attempt = _test_injection(server, "a@b.com", "x@y.com", "To", "crlf_header",
                                  "\r\nX-Injected: test")
        assert attempt.status == "blocked"
        assert "501" in attempt.server_response

    def test_smtp_exception(self) -> None:
        import smtplib
        server = self._make_server(sendmail_exc=smtplib.SMTPException("fail"))
        attempt = _test_injection(server, "a@b.com", "x@y.com", "Subject", "crlf_bcc",
                                  "\r\nBCC: evil@x.com")
        assert attempt.status == "error"
        assert "fail" in attempt.error

    def test_os_error_timeout(self) -> None:
        server = self._make_server(sendmail_exc=OSError("timed out"))
        attempt = _test_injection(server, "a@b.com", "x@y.com", "To", "crlf_body",
                                  "\r\n\r\nINJECTED")
        assert attempt.status == "timeout"


class TestScanSmtpInjection:
    @patch("smtpinjection._connect_smtp")
    def test_connection_failure(self, mock_connect: MagicMock) -> None:
        mock_connect.side_effect = ConnectionError("refused")
        result = scan_smtp_injection("bad.host", 25)
        assert len(result.attempts) == 0
        assert any("conexao" in i.lower() for i in result.issues)

    @patch("smtpinjection._test_injection")
    @patch("smtpinjection._connect_smtp")
    def test_all_blocked(self, mock_connect: MagicMock, mock_inject: MagicMock) -> None:
        mock_server = MagicMock()
        mock_connect.return_value = (mock_server, "banner", "ehlo")
        mock_inject.return_value = InjectionAttempt(
            field="To", payload_name="crlf", payload="x",
            status="blocked", server_response="501", error="",
        )
        result = scan_smtp_injection("safe.host", 587)
        assert len(result.vulnerable_fields) == 0
        assert "seguro" in result.issues[-1].lower()

    @patch("smtpinjection._test_injection")
    @patch("smtpinjection._connect_smtp")
    def test_some_injected(self, mock_connect: MagicMock, mock_inject: MagicMock) -> None:
        mock_server = MagicMock()
        mock_connect.return_value = (mock_server, "banner", "ehlo")

        def side_effect(server, from_a, to_a, field, pname, payload):
            if field == "To":
                return InjectionAttempt(field=field, payload_name=pname, payload=payload,
                                        status="injected", server_response="250", error="")
            return InjectionAttempt(field=field, payload_name=pname, payload=payload,
                                    status="blocked", server_response="501", error="")
        mock_inject.side_effect = side_effect
        result = scan_smtp_injection("vuln.host", 587)
        assert "To" in result.vulnerable_fields
        assert len(result.attempts) > 0

    @patch("smtpinjection._connect_smtp")
    def test_dry_run_fields(self, mock_connect: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.data.return_value = (250, b"OK")
        mock_connect.return_value = (mock_server, "banner", "ehlo")
        result = scan_smtp_injection("host.com", 587, fields=["Subject"])
        assert result.port == 587


class TestPrintResults:
    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = InjectionResult(
            target="vuln.host", port=587, tls=True, banner="ESMTP",
            ehlo_response="250-SIZE",
            attempts=[InjectionAttempt("To", "crlf", "\r\nX-Injected: t",
                                       "injected", "250", "")],
            vulnerable_fields=["To"],
            issues=["INJECAO DETECTADA"],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "VULNERAVEL" in out

    def test_safe(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = InjectionResult(
            target="safe.host", port=587, tls=True, banner="ESMTP",
            ehlo_response="250",
            attempts=[InjectionAttempt("To", "crlf", "x",
                                       "blocked", "501", "")],
            vulnerable_fields=[],
            issues=["Nenhuma injecao detectada"],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Nenhuma injecao detectada" in out
        assert "corretamente" in out.lower()
