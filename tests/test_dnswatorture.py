#!/usr/bin/env python3
"""Testes unitarios do modulo de DNS Water Torture."""
import pytest

from dnswatorture import (
    QueryResult,
    WaterTortureResult,
    _gen_random_label,
    _gen_sequential_label,
    _gen_uuid_label,
    _gen_wordlist_label,
    _generate_domains,
    build_parser,
    print_results,
)


class TestQueryResult:
    """Testes do dataclass QueryResult."""

    def test_frozen(self) -> None:
        r = QueryResult(domain="a", response_code="b", latency_ms=1.0, error="")
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(QueryResult, "__slots__")


class TestWaterTortureResult:
    """Testes do dataclass WaterTortureResult."""

    def test_frozen(self) -> None:
        r = WaterTortureResult(
            domain="a", nameserver="b", pattern="c", queries_sent=0,
            nxdomain_count=0, noerror_count=0, other_count=0,
            timeout_count=0, avg_latency_ms=0.0, p95_latency_ms=0.0,
            p99_latency_ms=0.0, loss_rate=0.0, duration_s=0.0, qps=0.0,
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(WaterTortureResult, "__slots__")


class TestGenRandomLabel:
    """Testes da funcao _gen_random_label."""

    def test_length(self) -> None:
        label = _gen_random_label(8)
        assert len(label) == 8

    def test_custom_length(self) -> None:
        label = _gen_random_label(12)
        assert len(label) == 12

    def test_alphanumeric(self) -> None:
        label = _gen_random_label(20)
        assert label.isalnum()

    def test_lowercase(self) -> None:
        label = _gen_random_label(20)
        assert label == label.lower()


class TestGenUuidLabel:
    """Testes da funcao _gen_uuid_label."""

    def test_length(self) -> None:
        label = _gen_uuid_label()
        assert len(label) == 12

    def test_alphanumeric(self) -> None:
        label = _gen_uuid_label()
        assert label.isalnum()

    def test_unique(self) -> None:
        labels = {_gen_uuid_label() for _ in range(100)}
        assert len(labels) == 100


class TestGenSequentialLabel:
    """Testes da funcao _gen_sequential_label."""

    def test_format(self) -> None:
        label = _gen_sequential_label(0)
        assert label == "000000000000"

    def test_hex(self) -> None:
        label = _gen_sequential_label(255)
        assert label == "0000000000ff"

    def test_length(self) -> None:
        label = _gen_sequential_label(12345)
        assert len(label) == 12


class TestGenWordlistLabel:
    """Testes da funcao _gen_wordlist_label."""

    def test_not_empty(self) -> None:
        label = _gen_wordlist_label()
        assert len(label) > 0

    def test_has_digits(self) -> None:
        label = _gen_wordlist_label()
        assert any(c.isdigit() for c in label)


class TestGenerateDomains:
    """Testes da funcao _generate_domains."""

    def test_random(self) -> None:
        domains = _generate_domains("example.com", 5, "random")
        assert len(domains) == 5
        for d in domains:
            assert d.endswith(".example.com")

    def test_uuid(self) -> None:
        domains = _generate_domains("test.com", 3, "uuid")
        assert len(domains) == 3
        for d in domains:
            assert d.endswith(".test.com")

    def test_sequential(self) -> None:
        domains = _generate_domains("test.com", 3, "sequential")
        assert len(domains) == 3

    def test_wordlist(self) -> None:
        domains = _generate_domains("test.com", 3, "wordlist")
        assert len(domains) == 3


class TestParser:
    """Testes do build_parser."""

    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_nameserver(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--nameserver", "1.1.1.1"])
        assert args.nameserver == "1.1.1.1"

    def test_rate(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--rate", "500"])
        assert args.rate == 500

    def test_duration(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--duration", "30"])
        assert args.duration == 30

    def test_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--concurrency", "100"])
        assert args.concurrency == 100

    def test_pattern(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--pattern", "uuid"])
        assert args.pattern == "uuid"

    def test_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "5.0"])
        assert args.query_timeout == 5.0


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = WaterTortureResult(
            domain="example.com", nameserver="8.8.8.8", pattern="random",
            queries_sent=100, nxdomain_count=90, noerror_count=5,
            other_count=3, timeout_count=2, avg_latency_ms=15.5,
            p95_latency_ms=30.0, p99_latency_ms=45.0, loss_rate=0.02,
            duration_s=10.0, qps=10.0,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "DNS Water Torture" in out
        assert "example.com" in out
        assert "100" in out
        assert "NXDOMAIN" in out

    def test_high_loss(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = WaterTortureResult(
            domain="test.com", nameserver="8.8.8.8", pattern="random",
            queries_sent=100, nxdomain_count=50, noerror_count=10,
            other_count=0, timeout_count=40, avg_latency_ms=50.0,
            p95_latency_ms=100.0, p99_latency_ms=150.0, loss_rate=0.4,
            duration_s=10.0, qps=10.0,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "sobrecarregado" in out.lower() or "rate limiting" in out.lower() or "Loss rate" in out
