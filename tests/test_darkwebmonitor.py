#!/usr/bin/env python3
"""Testes unitarios do modulo de Dark Web Monitoring."""
import httpx
import pytest
import respx

from darkwebmonitor import (
    DarkWebMention,
    _classify_severity,
    _dedup_mentions,
    build_parser,
    print_results,
    scan_darkweb,
)


class TestDarkWebMention:
    """Testes do dataclass DarkWebMention."""

    def test_frozen(self) -> None:
        r = DarkWebMention(source="a", url="b", title="c", snippet="d", date_seen="e", domain="f", severity="g")
        with pytest.raises(AttributeError):
            r.source = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DarkWebMention, "__slots__")


class TestClassifySeverity:
    """Testes da funcao _classify_severity."""

    def test_critical(self) -> None:
        assert _classify_severity("password dump leaked") == "critical"

    def test_high(self) -> None:
        assert _classify_severity("exploit attack method") == "high"

    def test_medium(self) -> None:
        assert _classify_severity("forum discussion about") == "medium"

    def test_low(self) -> None:
        assert _classify_severity("mention reference link") == "low"

    def test_info(self) -> None:
        assert _classify_severity("random unrelated text") == "info"

    def test_case_insensitive(self) -> None:
        assert _classify_severity("PASSWORD leaked") == "critical"


class TestDedupMentions:
    """Testes da funcao _dedup_mentions."""

    def test_dedup(self) -> None:
        r1 = DarkWebMention(source="a", url="b", title="c", snippet="d", date_seen="e", domain="f", severity="g")
        r2 = DarkWebMention(source="a", url="b", title="c", snippet="d", date_seen="e", domain="f", severity="g")
        result = _dedup_mentions([r1, r2])
        assert len(result) == 1

    def test_different_sources(self) -> None:
        r1 = DarkWebMention(source="a", url="b", title="c", snippet="d", date_seen="e", domain="f", severity="g")
        r2 = DarkWebMention(source="x", url="b", title="c", snippet="d", date_seen="e", domain="f", severity="g")
        result = _dedup_mentions([r1, r2])
        assert len(result) == 2

    def test_empty(self) -> None:
        assert _dedup_mentions([]) == []


class TestParser:
    """Testes do build_parser."""

    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_source(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--source", "ahmia", "--source", "darksearch"])
        assert args.sources == ["ahmia", "darksearch"]

    def test_intelx_key(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--intelx-key", "test123"])
        assert args.intelx_key == "test123"

    def test_max_results(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--max-results", "50"])
        assert args.max_results == 50

    def test_list_file(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-l", "domains.txt"])
        assert args.target_list == "domains.txt"


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_empty(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhuma mencao" in out

    def test_with_data(self, capsys: pytest.CaptureFixture[str]) -> None:
        mentions = [
            DarkWebMention(
                source="ahmia",
                url="http://example.onion",
                title="test mention",
                snippet="password dump",
                date_seen="2025-01-01T00:00:00",
                domain="example.com",
                severity="critical",
            ),
        ]
        print_results(mentions)
        out = capsys.readouterr().out
        assert "1 mencao" in out
        assert "ahmia" in out
        assert "CRITICAL" in out


class TestScanDarkweb:
    """Testes da funcao scan_darkweb com mocks HTTP."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_ahmia(self) -> None:
        html = '<div class="result"><h3><a href="http://test.onion">test password dump</a></h3></div>'
        respx.get("https://ahmia.fi/search/").mock(
            return_value=httpx.Response(200, text=html),
        )

        mentions = await scan_darkweb(
            domain="example.com",
            sources=["ahmia"],
            api_keys={},
            max_results=5,
        )
        assert any(m.source == "ahmia" for m in mentions)

    @pytest.mark.asyncio
    @respx.mock
    async def test_darksearch(self) -> None:
        api_response = {
            "data": [
                {
                    "title": "example.com password leak",
                    "description": "password dump found",
                    "link": "http://example.onion/page",
                    "date": "2025-01-01",
                },
            ],
        }
        respx.get("https://darksearch.io/api/search").mock(
            return_value=httpx.Response(200, json=api_response),
        )

        mentions = await scan_darkweb(
            domain="example.com",
            sources=["darksearch"],
            api_keys={},
            max_results=5,
        )
        assert any(m.source == "darksearch" for m in mentions)

    @pytest.mark.asyncio
    @respx.mock
    async def test_intelx_no_key(self) -> None:
        mentions = await scan_darkweb(
            domain="example.com",
            sources=["intelx"],
            api_keys={},
            max_results=5,
        )
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_results(self) -> None:
        respx.get("https://ahmia.fi/search/").mock(
            return_value=httpx.Response(200, text=""),
        )
        respx.get("https://darksearch.io/api/search").mock(
            return_value=httpx.Response(200, json={"data": []}),
        )

        mentions = await scan_darkweb(
            domain="example.com",
            sources=["ahmia", "darksearch"],
            api_keys={},
            max_results=5,
        )
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_dedup_across_sources(self) -> None:
        html = '<div class="result"><h3><a href="http://test.onion">example password</a></h3></div>'
        respx.get("https://ahmia.fi/search/").mock(
            return_value=httpx.Response(200, text=html),
        )
        api_response = {
            "data": [
                {
                    "title": "example password",
                    "description": "found",
                    "link": "http://test.onion/page",
                    "date": "2025-01-01",
                },
            ],
        }
        respx.get("https://darksearch.io/api/search").mock(
            return_value=httpx.Response(200, json=api_response),
        )

        mentions = await scan_darkweb(
            domain="example.com",
            sources=["ahmia", "darksearch"],
            api_keys={},
            max_results=5,
        )
        assert len(mentions) == 2
