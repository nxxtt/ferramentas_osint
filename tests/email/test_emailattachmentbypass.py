#!/usr/bin/env python3
"""Testes unitarios do modulo de Email Attachment Bypass."""
import smtplib
from unittest.mock import MagicMock, patch

import pytest

from mytools.email.emailattachmentbypass import (
    _ATTACH_BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    BypassAttempt,
    BypassResult,
    _build_attachment_email,
    _connect_smtp,
    _get_banner,
    _send_bypass_email,
    build_parser,
    print_results,
    scan_attachment_bypass,
)


class TestBypassAttempt:
    def test_frozen(self) -> None:
        a = BypassAttempt(
            technique="double_ext_php_jpg", filename="shell.php.jpg",
            content_type="application/octet-stream", status="accepted",
            server_response="250 OK", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(BypassAttempt, "__slots__")


class TestBypassResult:
    def test_frozen(self) -> None:
        r = BypassResult(
            target="mail.test.com", port=587, tls=False, banner="220",
            attempts=[], accepted_techniques=[], blocked_techniques=[],
            issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(BypassResult, "__slots__")


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

    def test_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--category", "polyglot"])
        assert args.category == "polyglot"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["mail.test.com", "--category", cat])
            assert args.category == cat


class TestPayloads:
    def test_all_payloads_have_required_fields(self) -> None:
        for _name, (filename, content_type, payload) in _ATTACH_BYPASS_PAYLOADS.items():
            assert isinstance(filename, str) and filename
            assert isinstance(content_type, str) and "/" in content_type
            assert isinstance(payload, bytes) and len(payload) > 0

    def test_categories_cover_all_payloads(self) -> None:
        all_named = set()
        for names in _CATEGORY_MAP.values():
            all_named.update(names)
        assert all_named == set(_ATTACH_BYPASS_PAYLOADS.keys())

    def test_category_map_keys(self) -> None:
        expected = {
            "double_ext", "mime_spoof", "polyglot", "null_byte",
            "case", "trailing", "semicolon", "magic_bytes",
        }
        assert set(_CATEGORY_MAP.keys()) == expected


class TestBuildAttachmentEmail:
    def test_basic_email(self) -> None:
        msg = _build_attachment_email(
            "from@test.com", "to@test.com", "test.php", "image/jpeg", b"content",
        )
        assert msg["From"] == "from@test.com"
        assert msg["To"] == "to@test.com"
        assert "Attachment Bypass Test" in msg["Subject"]
        assert len(msg.get_payload()) == 2

    def test_attachment_filename(self) -> None:
        msg = _build_attachment_email(
            "a@b.com", "c@d.com", "shell.php.jpg", "application/octet-stream", b"x",
        )
        part = msg.get_payload()[1]
        disp = part["Content-Disposition"]
        assert "shell.php.jpg" in disp

    def test_content_type_override(self) -> None:
        msg = _build_attachment_email(
            "a@b.com", "c@d.com", "test.php", "image/jpeg", b"php_code",
        )
        part = msg.get_payload()[1]
        assert "image/jpeg" in part["Content-Type"]


class TestConnectSmtp:
    @patch("mytools.email.emailattachmentbypass.smtplib.SMTP")
    def test_connect_ok(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_smtp.return_value = mock_server
        server, tls = _connect_smtp("mail.test.com", 587, 10.0)
        mock_smtp.assert_called_once_with("mail.test.com", 587, timeout=10.0)
        assert server is not None
        assert tls is False

    @patch("mytools.email.emailattachmentbypass.smtplib.SMTP_SSL")
    def test_connect_ssl(self, mock_ssl: MagicMock) -> None:
        mock_server = MagicMock()
        mock_ssl.return_value = mock_server
        _server, tls = _connect_smtp("mail.test.com", 465, 10.0)
        mock_ssl.assert_called_once_with("mail.test.com", 465, timeout=10.0)
        assert tls is True

    @patch("mytools.email.emailattachmentbypass.smtplib.SMTP")
    def test_connect_fail(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = ConnectionError("refused")
        with pytest.raises(ConnectionError):
            _connect_smtp("bad.host", 587, 5.0)

    @patch("mytools.email.emailattachmentbypass.smtplib.SMTP")
    def test_starttls_attempted(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250-mail\n250-STARTTLS")
        mock_server.starttls.return_value = (220, b"Ready")
        mock_smtp.return_value = mock_server
        _server, _tls = _connect_smtp("mail.test.com", 587, 10.0)
        mock_server.starttls.assert_called_once()


class TestGetBanner:
    def test_banner_ok(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"250 mail.example.com")
        assert _get_banner(server) == "250 mail.example.com"

    def test_banner_bytes(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"250-\xe9\xe3")
        result = _get_banner(server)
        assert isinstance(result, str)

    def test_banner_exception(self) -> None:
        server = MagicMock()
        server.ehlo.side_effect = smtplib.SMTPException("fail")
        assert _get_banner(server) == ""


class TestSendBypassEmail:
    @patch("mytools.email.emailattachmentbypass.smtplib.SMTP")
    def test_send_ok(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server
        accepted, details = _send_bypass_email(
            mock_server, "a@b.com", "c@d.com", "test.php", "image/jpeg", b"content",
        )
        assert accepted is True
        assert details == "accepted"

    @patch("mytools.email.emailattachmentbypass.smtplib.SMTP")
    def test_send_rejected(self, mock_smtp: MagicMock) -> None:
        from smtplib import SMTPResponseException
        mock_server = MagicMock()
        mock_server.data.side_effect = SMTPResponseException(550, b"Rejected")
        mock_smtp.return_value = mock_server
        accepted, details = _send_bypass_email(
            mock_server, "a@b.com", "c@d.com", "test.php", "image/jpeg", b"content",
        )
        assert accepted is False
        assert "550" in details


class TestScanAttachmentBypass:
    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    @patch("mytools.email.emailattachmentbypass._send_bypass_email")
    def test_all_accepted(self, mock_send: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_send.return_value = (True, "accepted")

        result = scan_attachment_bypass("mail.test.com", 587)
        assert result.overall_status == "vulnerable"
        assert len(result.accepted_techniques) == len(_ATTACH_BYPASS_PAYLOADS)

    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    @patch("mytools.email.emailattachmentbypass._send_bypass_email")
    def test_all_rejected(self, mock_send: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_send.return_value = (False, "550 Rejected")

        result = scan_attachment_bypass("mail.test.com", 587)
        assert result.overall_status == "secure"
        assert len(result.blocked_techniques) == len(_ATTACH_BYPASS_PAYLOADS)

    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    @patch("mytools.email.emailattachmentbypass._send_bypass_email")
    def test_partial_accepted(self, mock_send: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, True)

        call_count = 0

        def _side_effect(*args: object, **kwargs: object) -> tuple[bool, str]:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return True, "accepted"
            return False, "550 Rejected"

        mock_send.side_effect = _side_effect
        result = scan_attachment_bypass("mail.test.com", 587)
        assert result.overall_status == "vulnerable"
        assert len(result.accepted_techniques) == 2

    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    def test_connection_failure(self, mock_conn: MagicMock) -> None:
        mock_conn.side_effect = ConnectionError("refused")
        result = scan_attachment_bypass("mail.test.com", 587)
        assert result.overall_status == "error"
        assert any("Falha de conexao" in i for i in result.issues)

    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    @patch("mytools.email.emailattachmentbypass._send_bypass_email")
    def test_category_filter(self, mock_send: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_send.return_value = (True, "accepted")

        result = scan_attachment_bypass("mail.test.com", 587, category="polyglot")
        assert len(result.attempts) == 2
        assert all(a.technique.startswith("polyglot") for a in result.attempts)

    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    @patch("mytools.email.emailattachmentbypass._send_bypass_email")
    def test_tls_detected(self, mock_send: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, True)
        mock_send.return_value = (False, "550 Rejected")

        result = scan_attachment_bypass("mail.test.com", 587)
        assert result.tls is True

    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    @patch("mytools.email.emailattachmentbypass._send_bypass_email")
    def test_send_error(self, mock_send: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_send.side_effect = OSError("timeout")

        result = scan_attachment_bypass("mail.test.com", 587)
        assert any(a.status == "error" for a in result.attempts)

    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    def test_invalid_category(self, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)

        with patch("mytools.email.emailattachmentbypass._send_bypass_email", return_value=(False, "550")):
            result = scan_attachment_bypass("mail.test.com", 587, category="invalid")
            assert any("Categoria desconhecida" in i for i in result.issues)

    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    @patch("mytools.email.emailattachmentbypass._send_bypass_email")
    def test_server_quitted(self, mock_send: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_send.return_value = (False, "550 Rejected")

        scan_attachment_bypass("mail.test.com", 587)
        mock_server.quit.assert_called()

    @patch("mytools.email.emailattachmentbypass._connect_smtp")
    @patch("mytools.email.emailattachmentbypass._send_bypass_email")
    def test_result_fields(self, mock_send: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_send.return_value = (False, "550 Rejected")

        result = scan_attachment_bypass("mail.test.com", 25)
        assert result.target == "mail.test.com"
        assert result.port == 25
        assert isinstance(result.banner, str)


class TestPrintResults:
    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BypassResult(
            target="mail.test.com", port=587, tls=False, banner="220",
            attempts=[BypassAttempt(
                technique="double_ext_php_jpg", filename="shell.php.jpg",
                content_type="application/octet-stream", status="accepted",
                server_response="250 OK", error="",
            )],
            accepted_techniques=["double_ext_php_jpg"],
            blocked_techniques=[],
            issues=["1/14 bypasses aceitos"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out

    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BypassResult(
            target="mail.test.com", port=587, tls=True, banner="220",
            attempts=[BypassAttempt(
                technique="double_ext_php_jpg", filename="shell.php.jpg",
                content_type="application/octet-stream", status="rejected",
                server_response="550 Rejected", error="",
            )],
            accepted_techniques=[],
            blocked_techniques=["double_ext_php_jpg"],
            issues=["Todas as tecnicas bloqueadas"],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "seguro" in captured.out

    def test_print_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BypassResult(
            target="mail.test.com", port=587, tls=False, banner="",
            attempts=[], accepted_techniques=[], blocked_techniques=[],
            issues=["Falha de conexao"], overall_status="error",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "ERROR" in captured.out

    def test_print_with_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BypassResult(
            target="mail.test.com", port=587, tls=False, banner="220",
            attempts=[BypassAttempt(
                technique="polyglot_jpg_php", filename="polyglot.jpg",
                content_type="image/jpeg", status="error",
                server_response="", error="timeout",
            )],
            accepted_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="warning",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "timeout" in captured.out
