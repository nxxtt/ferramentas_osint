#!/usr/bin/env python3
"""Testes unitarios do modulo de Social Engineering Recon."""
import httpx
import pytest
import respx

from socialengrecon import (
    EmployeeInfo,
    _dedup_employees,
    _extract_domain_name,
    _query_github,
    _query_hunter,
    _query_webpages,
    build_parser,
    print_results,
    scan_employees,
)
from utils import RateLimiter

# ── Dataclass ────────────────────────────────────────────────────────────────


class TestEmployeeInfo:
    def test_frozen(self):
        e = EmployeeInfo(domain="x.com", name="A", email="a@x.com")
        with pytest.raises(AttributeError):
            e.name = "B"  # type: ignore[misc]

    def test_defaults(self):
        e = EmployeeInfo(domain="x.com")
        assert e.name == ""
        assert e.email == ""
        assert e.position == ""
        assert e.seniority == ""
        assert e.department == ""
        assert e.source == ""
        assert e.profile_url == ""

    def test_all_fields(self):
        e = EmployeeInfo(
            domain="x.com", name="John Doe", email="john@x.com",
            position="Engineer", seniority="senior", department="engineering",
            source="github", profile_url="https://github.com/john",
        )
        assert e.position == "Engineer"
        assert e.source == "github"


# ── _extract_domain_name ─────────────────────────────────────────────────────


class TestExtractDomainName:
    def test_two_parts(self):
        assert _extract_domain_name("example.com") == "example"

    def test_three_parts(self):
        assert _extract_domain_name("www.example.com") == "example"

    def test_single_part(self):
        assert _extract_domain_name("com") == "com"

    def test_co_uk(self):
        assert _extract_domain_name("example.co.uk") == "co"


# ── _dedup_employees ─────────────────────────────────────────────────────────


class TestDedupEmployees:
    def test_dedup_by_email(self):
        employees = [
            EmployeeInfo(domain="x.com", email="a@x.com", name="A"),
            EmployeeInfo(domain="x.com", email="a@x.com", name="B"),
        ]
        result = _dedup_employees(employees)
        assert len(result) == 1
        assert result[0].name == "A"

    def test_dedup_by_name(self):
        employees = [
            EmployeeInfo(domain="x.com", name="John Doe"),
            EmployeeInfo(domain="x.com", name="John Doe"),
        ]
        result = _dedup_employees(employees)
        assert len(result) == 1

    def test_different_names(self):
        employees = [
            EmployeeInfo(domain="x.com", name="John Doe"),
            EmployeeInfo(domain="x.com", name="Jane Smith"),
        ]
        result = _dedup_employees(employees)
        assert len(result) == 2

    def test_empty(self):
        assert _dedup_employees([]) == []

    def test_no_email_no_name(self):
        employees = [
            EmployeeInfo(domain="x.com"),
            EmployeeInfo(domain="x.com"),
        ]
        result = _dedup_employees(employees)
        assert len(result) == 2


# ── _query_github ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_github_found():
    repos_resp = [{"full_name": "example/repo1"}, {"full_name": "example/repo2"}]
    contrib_resp = [{"login": "john"}, {"login": "jane"}]
    user_resp = {"name": "John Doe", "email": "john@example.com", "bio": "", "company": "@Example", "html_url": "https://github.com/john"}

    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=repos_resp),
        )
        respx.route(method="GET", url="https://api.github.com/repos/example/repo1/contributors?per_page=30").mock(
            return_value=httpx.Response(200, json=contrib_resp),
        )
        respx.route(method="GET", url="https://api.github.com/repos/example/repo2/contributors?per_page=30").mock(
            return_value=httpx.Response(200, json=[]),
        )
        respx.route(method="GET", url="https://api.github.com/users/john").mock(
            return_value=httpx.Response(200, json=user_resp),
        )
        respx.route(method="GET", url="https://api.github.com/users/jane").mock(
            return_value=httpx.Response(200, json={"name": "Jane Smith", "email": "", "bio": "", "company": "", "html_url": ""}),
        )

        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl, max_results=10)
        await client.aclose()
        assert len(emps) >= 1
        assert any(e.email == "john@example.com" for e in emps)


@pytest.mark.asyncio
async def test_github_org_not_found():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(404),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "nonexistent99999.com", 5.0, rl)
        await client.aclose()
        assert emps == []


@pytest.mark.asyncio
async def test_github_error():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.github.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []


# ── _query_hunter ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hunter_found():
    resp = {"data": {"emails": [
        {"first_name": "John", "last_name": "Doe", "value": "john@example.com",
         "position": "Engineer", "seniority": "senior", "department": "engineering"},
    ]}}
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.hunter.io/").mock(
            return_value=httpx.Response(200, json=resp),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "fake-key", 5.0, rl)
        await client.aclose()
        assert len(emps) == 1
        assert emps[0].email == "john@example.com"
        assert emps[0].source == "hunter"


@pytest.mark.asyncio
async def test_hunter_no_key():
    client = httpx.AsyncClient()
    rl = RateLimiter(0)
    emps = await _query_hunter(client, "example.com", "", 5.0, rl)
    await client.aclose()
    assert emps == []


@pytest.mark.asyncio
async def test_hunter_error():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.hunter.io/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "fake-key", 5.0, rl)
        await client.aclose()
        assert emps == []


@pytest.mark.asyncio
async def test_hunter_no_emails():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.hunter.io/").mock(
            return_value=httpx.Response(200, json={"data": {"emails": []}}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "fake-key", 5.0, rl)
        await client.aclose()
        assert emps == []


# ── _query_webpages ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webpages_found():
    html = """
    <html><body>
    <h2>John Doe</h2><p>CEO</p>
    <h3>Jane Smith</h3><p>CTO</p>
    </body></html>
    """
    with respx.mock:
        respx.route(method="GET", url="https://example.com/about").mock(
            return_value=httpx.Response(200, text=html),
        )
        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(404),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_webpages(client, "example.com", 5.0, rl)
        await client.aclose()
        assert len(emps) >= 1
        assert any(e.name == "John Doe" for e in emps)


@pytest.mark.asyncio
async def test_webpages_no_team():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(404),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_webpages(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []


@pytest.mark.asyncio
async def test_webpages_error():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://example.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_webpages(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []


# ── build_parser ──────────────────────────────────────────────────────────────


class TestBuildParser:
    def test_has_domain(self):
        args = build_parser().parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_has_list(self):
        args = build_parser().parse_args(["-l", "domains.txt"])
        assert args.target_list == "domains.txt"

    def test_has_source(self):
        args = build_parser().parse_args(["--source", "hunter"])
        assert args.sources == ["hunter"]

    def test_has_hunter_key(self):
        args = build_parser().parse_args(["--hunter-api-key", "abc123"])
        assert args.hunter_api_key == "abc123"

    def test_has_max_results(self):
        args = build_parser().parse_args(["--max-results", "100"])
        assert args.max_results == 100

    def test_default_sources(self):
        args = build_parser().parse_args([])
        assert args.sources is None


# ── print_results ─────────────────────────────────────────────────────────────


class TestPrintResults:
    def test_empty(self, capsys):
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhum" in out

    def test_with_results(self, capsys):
        employees = [
            EmployeeInfo(domain="x.com", name="John Doe", email="john@x.com",
                         position="Engineer", source="github"),
        ]
        print_results(employees)
        out = capsys.readouterr().out
        assert "John Doe" in out
        assert "john@x.com" in out


# ── scan_employees (mock) ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_employees_github_only():
    repos_resp = [{"full_name": "example/repo1"}]
    contrib_resp = [{"login": "john"}]
    user_resp = {"name": "John", "email": "john@example.com", "bio": "", "company": "", "html_url": ""}

    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=repos_resp),
        )
        respx.route(method="GET", url="https://api.github.com/repos/example/repo1/contributors?per_page=30").mock(
            return_value=httpx.Response(200, json=contrib_resp),
        )
        respx.route(method="GET", url="https://api.github.com/users/john").mock(
            return_value=httpx.Response(200, json=user_resp),
        )

        employees = await scan_employees(
            domain="example.com",
            sources=["github"],
            api_keys={},
            timeout=5.0,
            concurrency=3,
            user_agent="test/1.0",
        )
        assert any(e.email == "john@example.com" for e in employees)


@pytest.mark.asyncio
async def test_scan_employees_hunter_no_key():
    employees = await scan_employees(
        domain="example.com",
        sources=["hunter"],
        api_keys={},
        timeout=5.0,
        concurrency=3,
        user_agent="test/1.0",
    )
    assert employees == []
