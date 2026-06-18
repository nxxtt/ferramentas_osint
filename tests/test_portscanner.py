from __future__ import annotations

import argparse

from portscanner import (
    BANNER_PROBES,
    DEFAULT_PORTS,
    TOP_100_PORTS,
    Finding,
    _create_connection,
    build_parser,
    ip_sort_key,
    parse_ports,
    resolve_targets,
)


class TestParsePorts:
    def test_default_returns_default_ports(self):
        assert parse_ports("default") == sorted(DEFAULT_PORTS)

    def test_top100_returns_top100_ports(self):
        assert parse_ports("top100") == sorted(TOP_100_PORTS)

    def test_all_returns_full_range(self):
        result = parse_ports("all")
        assert result == list(range(1, 65536))

    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_comma_separated(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        assert parse_ports("80-83") == [80, 81, 82, 83]

    def test_reversed_range(self):
        assert parse_ports("83-80") == [80, 81, 82, 83]

    def test_mixed(self):
        result = parse_ports("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_deduplication(self):
        assert parse_ports("80,80,80") == [80]

    def test_invalid_port_raises(self):
        try:
            parse_ports("0")
            assert False, "Should have raised"
        except argparse.ArgumentTypeError:
            pass

    def test_empty_raises(self):
        try:
            parse_ports("")
            assert False, "Should have raised"
        except argparse.ArgumentTypeError:
            pass

    def test_non_numeric_raises(self):
        try:
            parse_ports("abc")
            assert False, "Should have raised"
        except argparse.ArgumentTypeError as e:
            assert "abc" in str(e)

    def test_non_numeric_in_range_raises(self):
        try:
            parse_ports("abc-100")
            assert False, "Should have raised"
        except argparse.ArgumentTypeError as e:
            assert "abc-100" in str(e)

    def test_mixed_valid_invalid_raises(self):
        try:
            parse_ports("80,abc,443")
            assert False, "Should have raised"
        except argparse.ArgumentTypeError:
            pass

    def test_trailing_comma(self):
        assert parse_ports("80,443,") == [80, 443]

    def test_whitespace_parts(self):
        assert parse_ports(" 80 , 443 ") == [80, 443]

    def test_large_port(self):
        assert parse_ports("65535") == [65535]

    def test_port_boundary_one(self):
        assert parse_ports("1") == [1]

    def test_overlapping_ranges(self):
        result = parse_ports("80-82,81-83")
        assert result == [80, 81, 82, 83]


class TestIpSortKey:
    def test_ipv4_returns_zero_version(self):
        key = ip_sort_key("192.168.0.1")
        assert key[0] == 0

    def test_ipv6_returns_one_version(self):
        key = ip_sort_key("::1")
        assert key[0] == 1

    def test_hostname_returns_two_version(self):
        key = ip_sort_key("example.com")
        assert key[0] == 2

    def test_ipv4_before_ipv6(self):
        assert ip_sort_key("10.0.0.1") < ip_sort_key("::1")

    def test_ipv4_ordering(self):
        assert ip_sort_key("10.0.0.1") < ip_sort_key("192.168.0.1")

    def test_ipv4_all_zeros(self):
        key = ip_sort_key("0.0.0.0")
        assert key[0] == 0
        assert key[2] == "00000000"


class TestBannerProbes:
    def test_contains_expected_ports(self):
        assert 80 in BANNER_PROBES
        assert 8080 in BANNER_PROBES
        assert 8000 in BANNER_PROBES
        assert 8443 in BANNER_PROBES

    def test_probes_are_bytes(self):
        for port, probe in BANNER_PROBES.items():
            assert isinstance(probe, bytes)
            assert b"HEAD" in probe


class TestFindingDataclass:
    def test_creation(self):
        f = Finding(host="localhost", address="127.0.0.1", port=80, state="open", service="http")
        assert f.host == "localhost"
        assert f.port == 80
        assert f.banner == ""

    def test_frozen(self):
        f = Finding(host="localhost", address="127.0.0.1", port=80, state="open", service="http")
        try:
            f.port = 443
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestBuildParser:
    def test_returns_argparse(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_targets_argument(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.targets == ["127.0.0.1"]

    def test_has_ports_argument(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "80,443"])
        assert args.ports == [80, 443]

    def test_has_banner_flag(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-b"])
        assert args.banner is True

    def test_default_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.timeout == 0.5

    def test_has_verbose_argument(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-v"])
        assert args.verbose is True

    def test_default_verbose_false(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.verbose is False

    def test_has_log_file_argument(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "--log-file", "scan.log"])
        assert args.log_file == "scan.log"


class TestBuildParserV3:
    def test_has_list_argument(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "targets.txt"])
        assert args.target_list == "targets.txt"

    def test_has_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-q"])
        assert args.quiet is True

    def test_default_quiet_false(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.quiet is False

    def test_has_threads_alias(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "--threads", "100"])
        assert args.threads == 100

    def test_default_threads_none(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.threads is None

    def test_default_workers(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.workers == 200


class TestResolveTargetsIPv6:
    def test_ipv4_single(self):
        targets = resolve_targets(["192.168.0.1"])
        assert len(targets) == 1
        assert targets[0][1] == "192.168.0.1"

    def test_ipv6_loopback(self):
        targets = resolve_targets(["::1"])
        assert len(targets) == 1
        assert targets[0][1] == "::1"

    def test_ipv6_full(self):
        targets = resolve_targets(["2001:db8::1"])
        assert len(targets) == 1
        assert targets[0][1] == "2001:db8::1"

    def test_ipv6_cidr(self):
        targets = resolve_targets(["::1/128"])
        assert len(targets) == 1

    def test_ipv4_cidr(self):
        targets = resolve_targets(["192.168.0.0/30"])
        assert len(targets) == 2

    def test_mixed_ipv4_ipv6(self):
        targets = resolve_targets(["192.168.0.1", "::1"])
        assert len(targets) == 2
        addresses = {t[1] for t in targets}
        assert "192.168.0.1" in addresses
        assert "::1" in addresses

    def test_hostname_resolves(self):
        targets = resolve_targets(["localhost"])
        assert len(targets) >= 1

    def test_empty_string_skipped(self):
        targets = resolve_targets(["", "  ", "192.168.0.1"])
        assert len(targets) == 1

    def test_invalid_raises(self):
        import pytest
        with pytest.raises(ValueError, match="nenhum alvo"):
            resolve_targets([])

    def test_unresolvable_hostname_raises(self):
        import pytest
        with pytest.raises(ValueError, match="nao consegui resolver"):
            resolve_targets(["thishostdoesnotexist.invalid"])


class TestCreateConnection:
    def test_ipv4_connection_refused(self):
        import pytest
        with pytest.raises((ConnectionRefusedError, TimeoutError, OSError)):
            _create_connection("192.0.2.1", 1, 0.1)

    def test_ipv6_connection_refused(self):
        import pytest
        with pytest.raises((ConnectionRefusedError, TimeoutError, OSError)):
            _create_connection("::1", 1, 0.1)
