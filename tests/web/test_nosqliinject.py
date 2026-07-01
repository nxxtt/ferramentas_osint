#!/usr/bin/env python3
"""Testes unitarios do modulo de NoSQL Injection."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.nosqliinject import (
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _COUCHDB_PAYLOADS,
    _DETECT_PAYLOADS,
    _LOGIN_PARAMS,
    _MONGODB_PAYLOADS,
    _REDIS_PAYLOADS,
    NoSQLiAttempt,
    NoSQLiResult,
    _check_nosqli_response,
    _test_baseline,
    _test_bypass,
    _test_couchdb,
    _test_detect,
    _test_mongodb,
    _test_redis,
    build_parser,
    main,
    print_results,
)


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_detect(self) -> None:
        assert "detect" in _CATEGORY_MAP

    def test_has_mongodb(self) -> None:
        assert "mongodb" in _CATEGORY_MAP

    def test_has_redis(self) -> None:
        assert "redis" in _CATEGORY_MAP

    def test_has_couchdb(self) -> None:
        assert "couchdb" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestDetectPayloads:
    """Testes para _DETECT_PAYLOADS."""

    def test_has_gt_bypass(self) -> None:
        assert any("gt_bypass" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_ne_bypass(self) -> None:
        assert any("ne_bypass" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_regex_bypass(self) -> None:
        assert any("regex_bypass" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_exists_bypass(self) -> None:
        assert any("exists_bypass" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_type_bypass(self) -> None:
        assert any("type_bypass" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 5

    def test_all_are_json(self) -> None:
        for _, _, ct, _ in _DETECT_PAYLOADS:
            assert "json" in ct


class TestMongoDBPayloads:
    """Testes para _MONGODB_PAYLOADS."""

    def test_has_gt(self) -> None:
        assert any("mongo_gt" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_ne(self) -> None:
        assert any("mongo_ne" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_where(self) -> None:
        assert any("mongo_where" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_regex(self) -> None:
        assert any("mongo_regex" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_or(self) -> None:
        assert any("mongo_or" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_nin(self) -> None:
        assert any("mongo_nin" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_and(self) -> None:
        assert any("mongo_and" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_not(self) -> None:
        assert any("mongo_not" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_mod(self) -> None:
        assert any("mongo_mod" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_exists(self) -> None:
        assert any("mongo_exists" in p[0] for p in _MONGODB_PAYLOADS)

    def test_has_type(self) -> None:
        assert any("mongo_type" in p[0] for p in _MONGODB_PAYLOADS)

    def test_count(self) -> None:
        assert len(_MONGODB_PAYLOADS) == 11


class TestRedisPayloads:
    """Testes para _REDIS_PAYLOADS."""

    def test_has_info(self) -> None:
        assert any("redis_info" in p[0] for p in _REDIS_PAYLOADS)

    def test_has_config(self) -> None:
        assert any("redis_config" in p[0] for p in _REDIS_PAYLOADS)

    def test_has_keys(self) -> None:
        assert any("redis_keys" in p[0] for p in _REDIS_PAYLOADS)

    def test_has_eval(self) -> None:
        assert any("redis_eval" in p[0] for p in _REDIS_PAYLOADS)

    def test_has_flushall(self) -> None:
        assert any("redis_flushall" in p[0] for p in _REDIS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_REDIS_PAYLOADS) == 5


class TestCouchDBPayloads:
    """Testes para _COUCHDB_PAYLOADS."""

    def test_has_alldocs(self) -> None:
        assert any("couchdb_alldocs" in p[0] for p in _COUCHDB_PAYLOADS)

    def test_has_changes(self) -> None:
        assert any("couchdb_changes" in p[0] for p in _COUCHDB_PAYLOADS)

    def test_has_show(self) -> None:
        assert any("couchdb_show" in p[0] for p in _COUCHDB_PAYLOADS)

    def test_has_utils(self) -> None:
        assert any("couchdb_utils" in p[0] for p in _COUCHDB_PAYLOADS)

    def test_has_config(self) -> None:
        assert any("couchdb_config" in p[0] for p in _COUCHDB_PAYLOADS)

    def test_count(self) -> None:
        assert len(_COUCHDB_PAYLOADS) == 5


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_unicode(self) -> None:
        assert any("unicode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_double_json(self) -> None:
        assert any("double_json" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_nested(self) -> None:
        assert any("nested" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_mixed_type(self) -> None:
        assert any("mixed_type" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_array(self) -> None:
        assert any("array" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_null_terminator(self) -> None:
        assert any("null_terminator" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 6


class TestLoginParams:
    """Testes para _LOGIN_PARAMS."""

    def test_has_user(self) -> None:
        assert "user" in _LOGIN_PARAMS

    def test_has_username(self) -> None:
        assert "username" in _LOGIN_PARAMS

    def test_has_email(self) -> None:
        assert "email" in _LOGIN_PARAMS

    def test_has_password(self) -> None:
        assert "password" in _LOGIN_PARAMS

    def test_has_pass(self) -> None:
        assert "pass" in _LOGIN_PARAMS

    def test_count(self) -> None:
        assert len(_LOGIN_PARAMS) == 11


class TestNoSQLiAttempt:
    """Testes para dataclass NoSQLiAttempt."""

    def test_create(self) -> None:
        attempt = NoSQLiAttempt(
            technique="gt_bypass",
            category="detect",
            payload="{}",
            method="json_post",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=200,
            status_changed=False,
            size_changed=True,
            vulnerable=True,
            details="bypass found",
            error="",
        )
        assert attempt.technique == "gt_bypass"
        assert attempt.vulnerable is True

    def test_immutable(self) -> None:
        attempt = NoSQLiAttempt(
            technique="test", category="detect", payload="{}",
            method="json_post", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestNoSQLiResult:
    """Testes para dataclass NoSQLiResult."""

    def test_create(self) -> None:
        result = NoSQLiResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert result.target == "https://example.com"
        assert result.overall_status == "secure"

    def test_immutable(self) -> None:
        result = NoSQLiResult(
            target="t", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestCheckNoSQLiResponse:
    """Testes para _check_nosqli_response."""

    def test_welcome_detected(self) -> None:
        assert _check_nosqli_response(b"welcome back", 200, ["welcome"])

    def test_not_detected(self) -> None:
        assert not _check_nosqli_response(b"error 404", 200, ["welcome"])

    def test_status_zero(self) -> None:
        assert not _check_nosqli_response(b"welcome", 0, ["welcome"])

    def test_case_insensitive(self) -> None:
        assert _check_nosqli_response(b"WELCOME", 200, ["welcome"])

    def test_multiple_indicators(self) -> None:
        assert _check_nosqli_response(b"success: token issued", 200, ["success", "token"])

    def test_empty_body(self) -> None:
        assert not _check_nosqli_response(b"", 200, ["welcome"])


class TestTestBaseline:
    """Testes para _test_baseline."""

    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.get.return_value = mock_resp

        status, size, body = await _test_baseline(mock_client, "https://example.com")
        assert status == 200
        assert size == 2
        assert body == b"ok"

    @pytest.mark.asyncio
    async def test_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        status, size, body = await _test_baseline(mock_client, "https://example.com")
        assert status == 0
        assert size == 0
        assert body == b""


class TestTestDetect:
    """Testes para _test_detect."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"welcome back"
        mock_client.post.return_value = mock_resp
        mock_client.get.return_value = mock_resp

        results = await _test_detect(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 10
        vulns = [r for r in results if r.vulnerable]
        assert len(vulns) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_detect(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 10
        assert all(r.error for r in results)


class TestTestMongoDB:
    """Testes para _test_mongodb."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"success token"
        mock_client.post.return_value = mock_resp

        results = await _test_mongodb(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 11

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_mongodb(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 11
        assert all(r.error for r in results)


class TestTestRedis:
    """Testes para _test_redis."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp

        results = await _test_redis(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_redis(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 5
        assert all(r.error for r in results)


class TestTestCouchDB:
    """Testes para _test_couchdb."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"total_rows"
        mock_client.post.return_value = mock_resp

        results = await _test_couchdb(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_couchdb(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 5
        assert all(r.error for r in results)


class TestTestBypass:
    """Testes para _test_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 6

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 6
        assert all(r.error for r in results)


class TestPrintResults:
    """Testes para print_results."""

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NoSQLiResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=["gt_bypass"],
            blocked_techniques=[],
            issues=["VULN: gt_bypass"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERAVEIS" in output

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NoSQLiResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhuma NoSQL Injection detectada" in output


class TestBuildParser:
    """Testes para build_parser."""

    def test_has_url(self) -> None:
        parser = build_parser()
        assert any(a.dest == "url" for a in parser._actions)

    def test_has_category(self) -> None:
        parser = build_parser()
        assert any(a.dest == "category" for a in parser._actions)

    def test_has_concurrency(self) -> None:
        parser = build_parser()
        assert any(a.dest == "concurrency" for a in parser._actions)

    def test_category_choices(self) -> None:
        parser = build_parser()
        for action in parser._actions:
            if action.dest == "category":
                assert set(action.choices) == set(_CATEGORY_MAP.keys())


class TestMain:
    """Testes para main()."""

    def test_main_returns_int(self) -> None:
        with patch("sys.argv", ["mytools-nosqli"]), \
             patch("mytools.web.nosqliinject.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with patch("sys.argv", ["mytools-nosqli", "https://example.com"]), \
             patch("mytools.web.nosqliinject.run_main_loop", return_value=0):
            result = main()
            assert result == 0


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.nosqliinject import run_scan

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not vulnerable"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        with patch("mytools.web.nosqliinject.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=[],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 0

    @pytest.mark.asyncio
    async def test_run_scan_vulnerable(self) -> None:
        from mytools.web.nosqliinject import run_scan

        mock_client = AsyncMock()
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"welcome back success token"
        mock_client.post.return_value = mock_post

        with patch("mytools.web.nosqliinject.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["detect"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_run_scan_connection_error(self) -> None:
        from mytools.web.nosqliinject import run_scan

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.content = b""
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.nosqliinject.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["detect"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_run_scan_with_output(self, tmp_path: object) -> None:
        from mytools.web.nosqliinject import run_scan

        mock_client = AsyncMock()
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"not vulnerable"
        mock_client.post.return_value = mock_post

        output_file = str(tmp_path) + "/output.json"  # type: ignore[operator]
        with patch("mytools.web.nosqliinject.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["detect"],
                timeout=10,
                concurrency=5,
                output_file=output_file,
                verbose=False,
            )
            assert result == 0

    def test_run_once(self) -> None:
        args = MagicMock()
        args.url = "https://example.com"
        args.category = "detect"
        args.timeout = 10
        args.concurrency = 5
        args.output = None
        args.verbose = False

        with patch("mytools.web.nosqliinject.safe_asyncio_run", return_value=0) as mock_run:
            from mytools.web.nosqliinject import run_once
            result = run_once(args)
            assert result == 0
            mock_run.assert_called_once()

    def test_run_once_no_category(self) -> None:
        args = MagicMock()
        args.url = "https://example.com"
        args.category = None
        args.timeout = 10
        args.concurrency = 5
        args.output = None
        args.verbose = False

        with patch("mytools.web.nosqliinject.safe_asyncio_run", return_value=0):
            from mytools.web.nosqliinject import run_once
            result = run_once(args)
            assert result == 0
