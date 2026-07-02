#!/usr/bin/env python3
"""Testes unitarios do modulo de Cache Poisoning."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.cachepoisoning import (
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _ENCODING_PAYLOADS,
    _HEADER_PAYLOADS,
    _HOST_PAYLOADS,
    _PATH_PAYLOADS,
    _SSI_PARAMS,
    CacheAttempt,
    CacheResult,
    _check_cache_response,
    _test_baseline,
    _test_bypass,
    _test_encoding,
    _test_header,
    _test_host,
    _test_path,
    build_parser,
    main,
    print_results,
)


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_host(self) -> None:
        assert "host" in _CATEGORY_MAP

    def test_has_path(self) -> None:
        assert "path" in _CATEGORY_MAP

    def test_has_header(self) -> None:
        assert "header" in _CATEGORY_MAP

    def test_has_encoding(self) -> None:
        assert "encoding" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestHostPayloads:
    """Testes para _HOST_PAYLOADS."""

    def test_has_xfwd_host(self) -> None:
        assert any("xfwd_host" in p[0] for p in _HOST_PAYLOADS)

    def test_has_xorig_host(self) -> None:
        assert any("xorig_host" in p[0] for p in _HOST_PAYLOADS)

    def test_has_xrewrite_host(self) -> None:
        assert any("xrewrite_host" in p[0] for p in _HOST_PAYLOADS)

    def test_has_xhost_bypass(self) -> None:
        assert any("xhost_bypass" in p[0] for p in _HOST_PAYLOADS)

    def test_has_host_mismatch(self) -> None:
        assert any("host_mismatch" in p[0] for p in _HOST_PAYLOADS)

    def test_count(self) -> None:
        assert len(_HOST_PAYLOADS) == 5

    def test_all_have_headers(self) -> None:
        for _, headers, _ in _HOST_PAYLOADS:
            assert isinstance(headers, dict)


class TestPathPayloads:
    """Testes para _PATH_PAYLOADS."""

    def test_has_xorig_url(self) -> None:
        assert any("xorig_url" in p[0] for p in _PATH_PAYLOADS)

    def test_has_xrewrite_url(self) -> None:
        assert any("xrewrite_url" in p[0] for p in _PATH_PAYLOADS)

    def test_has_url_path_poison(self) -> None:
        assert any("url_path_poison" in p[0] for p in _PATH_PAYLOADS)

    def test_has_path_confusion(self) -> None:
        assert any("path_confusion" in p[0] for p in _PATH_PAYLOADS)

    def test_has_double_path(self) -> None:
        assert any("double_path" in p[0] for p in _PATH_PAYLOADS)

    def test_count(self) -> None:
        assert len(_PATH_PAYLOADS) == 5


class TestHeaderPayloads:
    """Testes para _HEADER_PAYLOADS."""

    def test_has_vary_poison(self) -> None:
        assert any("vary_poison" in p[0] for p in _HEADER_PAYLOADS)

    def test_has_cache_control_bypass(self) -> None:
        assert any("cache_control_bypass" in p[0] for p in _HEADER_PAYLOADS)

    def test_has_pragma_bypass(self) -> None:
        assert any("pragma_bypass" in p[0] for p in _HEADER_PAYLOADS)

    def test_has_x_cache_test(self) -> None:
        assert any("x_cache_test" in p[0] for p in _HEADER_PAYLOADS)

    def test_has_if_modified(self) -> None:
        assert any("if_modified" in p[0] for p in _HEADER_PAYLOADS)

    def test_count(self) -> None:
        assert len(_HEADER_PAYLOADS) == 5


class TestEncodingPayloads:
    """Testes para _ENCODING_PAYLOADS."""

    def test_has_clte_bypass(self) -> None:
        assert any("clte_bypass" in p[0] for p in _ENCODING_PAYLOADS)

    def test_has_te_chunked(self) -> None:
        assert any("te_chunked" in p[0] for p in _ENCODING_PAYLOADS)

    def test_has_content_length_mismatch(self) -> None:
        assert any("content_length_mismatch" in p[0] for p in _ENCODING_PAYLOADS)

    def test_has_transfer_encoding(self) -> None:
        assert any("transfer_encoding" in p[0] for p in _ENCODING_PAYLOADS)

    def test_has_identity_poison(self) -> None:
        assert any("identity_poison" in p[0] for p in _ENCODING_PAYLOADS)

    def test_count(self) -> None:
        assert len(_ENCODING_PAYLOADS) == 5

    def test_all_have_4_elements(self) -> None:
        for item in _ENCODING_PAYLOADS:
            assert len(item) == 4


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_double_encode(self) -> None:
        assert any("double_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_null_byte(self) -> None:
        assert any("null_byte" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_case_variation(self) -> None:
        assert any("case_variation" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_unicode_path(self) -> None:
        assert any("unicode_path" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_backslash_path(self) -> None:
        assert any("backslash_path" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5


class TestSSIParams:
    """Testes para _SSI_PARAMS."""

    def test_has_data(self) -> None:
        assert "data" in _SSI_PARAMS

    def test_has_json(self) -> None:
        assert "json" in _SSI_PARAMS

    def test_has_payload(self) -> None:
        assert "payload" in _SSI_PARAMS

    def test_count(self) -> None:
        assert len(_SSI_PARAMS) == 15


class TestCacheAttempt:
    """Testes para dataclass CacheAttempt."""

    def test_create(self) -> None:
        attempt = CacheAttempt(
            technique="xfwd_host",
            category="host",
            payload='{"X-Forwarded-Host": "evil.com"}',
            param="data",
            method="get_headers",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=200,
            status_changed=False,
            size_changed=True,
            vulnerable=True,
            details="evil.com found",
            error="",
        )
        assert attempt.technique == "xfwd_host"
        assert attempt.vulnerable is True

    def test_immutable(self) -> None:
        attempt = CacheAttempt(
            technique="test", category="host", payload="p",
            param="data", method="get_headers", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestCacheResult:
    """Testes para dataclass CacheResult."""

    def test_create(self) -> None:
        result = CacheResult(
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
        result = CacheResult(
            target="t", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestCheckCacheResponse:
    """Testes para _check_cache_response."""

    def test_cache_hit_detected(self) -> None:
        assert _check_cache_response(b"ok", 200, {"x-cache": "HIT"}, ["HIT"])

    def test_not_detected(self) -> None:
        assert not _check_cache_response(b"error 404", 200, {}, ["evil.com"])

    def test_status_zero(self) -> None:
        assert not _check_cache_response(b"ok", 0, {}, ["HIT"])

    def test_case_insensitive(self) -> None:
        assert _check_cache_response(b"HIT", 200, {}, ["hit"])

    def test_header_match(self) -> None:
        assert _check_cache_response(b"", 200, {"x-cache": "HIT"}, ["x-cache"])

    def test_empty_body(self) -> None:
        assert not _check_cache_response(b"", 200, {}, ["evil.com"])


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


class TestTestHost:
    """Testes para _test_host."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"evil.com"
        mock_resp.headers = {"x-cache": "HIT"}
        mock_client.get.return_value = mock_resp

        results = await _test_host(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_host(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestPath:
    """Testes para _test_path."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_resp.headers = {}
        mock_client.get.return_value = mock_resp

        results = await _test_path(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_path(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestHeader:
    """Testes para _test_header."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"vary": "X-Forwarded-Host"}
        mock_client.get.return_value = mock_resp

        results = await _test_header(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_header(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestEncoding:
    """Testes para _test_encoding."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"transfer-encoding": "chunked"}
        mock_client.post.return_value = mock_resp

        results = await _test_encoding(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_encoding(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestBypass:
    """Testes para _test_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_resp.headers = {}
        mock_client.get.return_value = mock_resp

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestPrintResults:
    """Testes para print_results."""

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CacheResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                CacheAttempt(
                    technique="xfwd_host", category="host",
                    payload='{"X-Forwarded-Host": "evil.com"}', param="data",
                    method="get_headers", status_baseline=200, status_test=200,
                    size_baseline=100, size_test=200, status_changed=False,
                    size_changed=True, vulnerable=True, details="evil.com found",
                    error="",
                ),
            ],
            vulnerable_techniques=["xfwd_host"],
            blocked_techniques=[],
            issues=["VULN: xfwd_host via data"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERABILIDADES DETECTADAS" in output

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CacheResult(
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
        assert "Nenhuma Cache Poisoning detectada" in output


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
        with patch("sys.argv", ["mytools-cachepoison"]), \
             patch("mytools.web.cachepoisoning.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with patch("sys.argv", ["mytools-cachepoison", "https://example.com"]), \
             patch("mytools.web.cachepoisoning.run_main_loop", return_value=0):
            result = main()
            assert result == 0


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.cachepoisoning import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not vulnerable"
        mock_resp.headers = {}
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        with patch("mytools.web.cachepoisoning.create_async_client", return_value=mock_client):
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
        from mytools.web.cachepoisoning import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client

        mock_baseline = MagicMock()
        mock_baseline.status_code = 200
        mock_baseline.content = b"ok"
        mock_baseline.headers = {}

        mock_vuln = MagicMock()
        mock_vuln.status_code = 200
        mock_vuln.content = b"evil.com"
        mock_vuln.headers = {"x-cache": "HIT"}

        call_count = 0

        async def side_effect_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return mock_baseline
            return mock_vuln

        mock_client.get = AsyncMock(side_effect=side_effect_get)
        mock_client.post = AsyncMock(return_value=mock_vuln)

        with patch("mytools.web.cachepoisoning.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["host"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_run_scan_connection_error(self) -> None:
        from mytools.web.cachepoisoning import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.content = b""
        mock_resp.headers = {}
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.cachepoisoning.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["host"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_run_scan_with_output(self, tmp_path: object) -> None:
        from mytools.web.cachepoisoning import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_get.headers = {}
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"not vulnerable"
        mock_post.headers = {}
        mock_client.post.return_value = mock_post

        output_file = str(tmp_path) + "/output.json"  # type: ignore[operator]
        with patch("mytools.web.cachepoisoning.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["host"],
                timeout=10,
                concurrency=5,
                output_file=output_file,
                verbose=False,
            )
            assert result == 0

    def test_run_once(self) -> None:
        args = MagicMock()
        args.url = "https://example.com"
        args.category = "host"
        args.timeout = 10
        args.concurrency = 5
        args.output = None
        args.verbose = False

        with patch("mytools.web.cachepoisoning.safe_asyncio_run", return_value=0) as mock_run:
            from mytools.web.cachepoisoning import run_once
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

        with patch("mytools.web.cachepoisoning.safe_asyncio_run", return_value=0):
            from mytools.web.cachepoisoning import run_once
            result = run_once(args)
            assert result == 0
