from __future__ import annotations

import logging
import os
import threading
import time

from utils import (
    Cyber,
    RateLimiter,
    color,
    create_session,
    extract_title,
    fetch,
    header_get,
    setup_logging,
    status_color,
)


class TestCyberConstants:
    def test_all_colors_are_ansi_strings(self):
        for attr in ("RESET", "BOLD", "DIM", "RED", "GREEN", "CYAN", "BLUE", "MAGENTA", "YELLOW", "WHITE", "GRAY"):
            value = getattr(Cyber, attr)
            assert isinstance(value, str)
            assert value.startswith("\033[")

    def test_reset_ends_with_zero(self):
        assert Cyber.RESET == "\033[0m"


class TestColor:
    def test_returns_plain_text_when_no_color(self, monkeypatch):
        monkeypatch.setattr("utils.USE_COLOR", False)
        assert color("hello", Cyber.RED) == "hello"

    def test_wraps_with_ansi_when_color(self, monkeypatch):
        monkeypatch.setattr("utils.USE_COLOR", True)
        result = color("hello", Cyber.RED)
        assert result == f"{Cyber.RED}hello{Cyber.RESET}"

    def test_multiple_styles(self, monkeypatch):
        monkeypatch.setattr("utils.USE_COLOR", True)
        result = color("hello", Cyber.RED, Cyber.BOLD)
        assert result == f"{Cyber.RED}{Cyber.BOLD}hello{Cyber.RESET}"

    def test_no_styles(self, monkeypatch):
        monkeypatch.setattr("utils.USE_COLOR", True)
        result = color("hello")
        assert result == f"hello{Cyber.RESET}"


class TestStatusColor:
    def test_200_is_green(self):
        assert status_color(200) == Cyber.GREEN

    def test_301_is_yellow(self):
        assert status_color(301) == Cyber.YELLOW

    def test_401_is_magenta(self):
        assert status_color(401) == Cyber.MAGENTA

    def test_403_is_magenta(self):
        assert status_color(403) == Cyber.MAGENTA

    def test_500_is_gray(self):
        assert status_color(500) == Cyber.GRAY

    def test_503_is_gray(self):
        assert status_color(503) == Cyber.GRAY

    def test_unknown_is_gray(self):
        assert status_color(999) == Cyber.GRAY


class TestHeaderGet:
    def test_exact_match(self):
        assert header_get({"Content-Type": "text/html"}, "Content-Type") == "text/html"

    def test_case_insensitive(self):
        assert header_get({"CONTENT-TYPE": "text/html"}, "content-type") == "text/html"

    def test_missing_returns_empty(self):
        assert header_get({"Content-Type": "text/html"}, "X-Custom") == ""

    def test_empty_headers(self):
        assert header_get({}, "anything") == ""


class TestExtractTitle:
    def test_simple_title(self):
        assert extract_title("<html><title>Hello</title></html>") == "Hello"

    def test_no_title(self):
        assert extract_title("<html><body>No title here</body></html>") == ""

    def test_case_insensitive(self):
        assert extract_title("<TITLE>Mixed</TITLE>") == "Mixed"

    def test_extra_whitespace(self):
        assert extract_title("<title>  Hello   World  </title>") == "Hello World"

    def test_truncation_at_100(self):
        long_title = "A" * 150
        result = extract_title(f"<title>{long_title}</title>")
        assert len(result) == 100

    def test_empty_title(self):
        assert extract_title("<title></title>") == ""


class TestRateLimiter:
    def test_zero_delay_does_not_block(self):
        limiter = RateLimiter(0.0)
        start = time.monotonic()
        limiter.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

    def test_rate_limit_enforces_delay(self):
        limiter = RateLimiter(10.0)
        timestamps: list[float] = []
        lock = threading.Lock()

        def record():
            limiter.wait()
            with lock:
                timestamps.append(time.monotonic())

        threads = [threading.Thread(target=record) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        timestamps.sort()
        for i in range(1, len(timestamps)):
            assert timestamps[i] - timestamps[i - 1] >= 0.08


class TestCreateSession:
    def test_returns_session(self):
        session = create_session()
        assert session is not None
        assert "User-Agent" in session.headers

    def test_custom_user_agent(self):
        session = create_session(user_agent="TestAgent/1.0")
        assert session.headers["User-Agent"] == "TestAgent/1.0"

    def test_proxy_set(self):
        session = create_session(proxy="http://proxy:8080")
        assert session.proxies.get("http") == "http://proxy:8080"
        assert session.proxies.get("https") == "http://proxy:8080"

    def test_no_proxy(self):
        session = create_session()
        assert session.proxies == {} or session.proxies is None or "http" not in session.proxies


class TestSetupLogging:
    def test_verbose_sets_debug_level(self):
        setup_logging(verbose=True)
        root = logging.getLogger("mytools")
        assert root.level == logging.DEBUG

    def test_default_sets_warning_level(self):
        setup_logging()
        root = logging.getLogger("mytools")
        assert root.level == logging.WARNING

    def test_log_file_creates_file(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        setup_logging(log_file=log_file)
        logger = logging.getLogger("mytools.test")
        logger.info("test message")
        for handler in logging.getLogger("mytools").handlers:
            handler.flush()
        assert os.path.exists(log_file)

    def test_log_file_sets_info_level(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        setup_logging(log_file=log_file)
        root = logging.getLogger("mytools")
        assert root.level == logging.INFO

    def test_verbose_and_log_file(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        setup_logging(verbose=True, log_file=log_file)
        root = logging.getLogger("mytools")
        assert root.level == logging.DEBUG
