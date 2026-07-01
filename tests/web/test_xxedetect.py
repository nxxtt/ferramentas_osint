#!/usr/bin/env python3
"""Testes unitarios do modulo de XXE Detection."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.xxedetect import (
    _BLIND_PAYLOADS,
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _DETECT_PAYLOADS,
    _FILE_READ_PAYLOADS,
    _SSRF_PAYLOADS,
    _XML_PARAMS,
    XXEAttempt,
    XXEResult,
    _build_xxe_body,
    _check_xxe_response,
    _test_baseline,
    _test_blind,
    _test_bypass,
    _test_detect,
    _test_file_read,
    _test_ssrf,
    build_parser,
    main,
    print_results,
)


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_detect(self) -> None:
        assert "detect" in _CATEGORY_MAP

    def test_has_file_read(self) -> None:
        assert "file_read" in _CATEGORY_MAP

    def test_has_ssrf(self) -> None:
        assert "ssrf" in _CATEGORY_MAP

    def test_has_blind(self) -> None:
        assert "blind" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestDetectPayloads:
    """Testes para _DETECT_PAYLOADS."""

    def test_has_basic_xxe(self) -> None:
        assert any("basic_xxe" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_svg_xxe(self) -> None:
        assert any("svg_xxe" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_soap_xxe(self) -> None:
        assert any("soap_xxe" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_param_entity(self) -> None:
        assert any("param_entity" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_rss_xxe(self) -> None:
        assert any("rss_xxe" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 5

    def test_all_haveDOCTYPE(self) -> None:
        for _, payload, _, _ in _DETECT_PAYLOADS:
            assert "DOCTYPE" in payload


class TestFileReadPayloads:
    """Testes para _FILE_READ_PAYLOADS."""

    def test_has_passwd(self) -> None:
        assert any("passwd" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_hosts(self) -> None:
        assert any("hosts" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_winini(self) -> None:
        assert any("winini" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_environ(self) -> None:
        assert any("environ" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_shadow(self) -> None:
        assert any("shadow" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_cmdline(self) -> None:
        assert any("cmdline" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_iis(self) -> None:
        assert any("iis" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_proc_status(self) -> None:
        assert any("proc_self_status" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_count(self) -> None:
        assert len(_FILE_READ_PAYLOADS) == 8


class TestSSRFPayloads:
    """Testes para _SSRF_PAYLOADS."""

    def test_has_localhost(self) -> None:
        assert any("localhost" in p[0] for p in _SSRF_PAYLOADS)

    def test_has_private(self) -> None:
        assert any("private" in p[0] for p in _SSRF_PAYLOADS)

    def test_has_metadata_aws(self) -> None:
        assert any("aws" in p[0] for p in _SSRF_PAYLOADS)

    def test_has_metadata_gcp(self) -> None:
        assert any("gcp" in p[0] for p in _SSRF_PAYLOADS)

    def test_has_expect(self) -> None:
        assert any("expect" in p[0] for p in _SSRF_PAYLOADS)

    def test_has_port_scan(self) -> None:
        assert any("port_scan" in p[0] for p in _SSRF_PAYLOADS)

    def test_count(self) -> None:
        assert len(_SSRF_PAYLOADS) == 6


class TestBlindPayloads:
    """Testes para _BLIND_PAYLOADS."""

    def test_has_dtd(self) -> None:
        assert any("dtd" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_length(self) -> None:
        assert any("length" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_oob(self) -> None:
        assert any("oob" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_error(self) -> None:
        assert any("error" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_parameter(self) -> None:
        assert any("parameter" in p[0] for p in _BLIND_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BLIND_PAYLOADS) == 5


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_utf16(self) -> None:
        assert any("utf16" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_utf7(self) -> None:
        assert any("utf7" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_param_entity(self) -> None:
        assert any("param_entity" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_dtd_external(self) -> None:
        assert any("dtd_external" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_cdata(self) -> None:
        assert any("cdata" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_comment(self) -> None:
        assert any("comment" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_encoding_bypass(self) -> None:
        assert any("encoding_bypass" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_double_encoding(self) -> None:
        assert any("double_encoding" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 8


class TestXMLParams:
    """Testes para _XML_PARAMS."""

    def test_has_xml(self) -> None:
        assert "xml" in _XML_PARAMS

    def test_has_data(self) -> None:
        assert "data" in _XML_PARAMS

    def test_has_body(self) -> None:
        assert "body" in _XML_PARAMS

    def test_has_content(self) -> None:
        assert "content" in _XML_PARAMS

    def test_has_svg(self) -> None:
        assert "svg" in _XML_PARAMS

    def test_has_soap_body(self) -> None:
        assert "soap_body" in _XML_PARAMS

    def test_count(self) -> None:
        assert len(_XML_PARAMS) == 16


class TestXXEAttempt:
    """Testes para dataclass XXEAttempt."""

    def test_create(self) -> None:
        attempt = XXEAttempt(
            technique="basic_xxe",
            category="detect",
            format="generic",
            payload="test",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=200,
            status_changed=False,
            size_changed=True,
            vulnerable=True,
            details="root found",
            error="",
        )
        assert attempt.technique == "basic_xxe"
        assert attempt.vulnerable is True

    def test_immutable(self) -> None:
        attempt = XXEAttempt(
            technique="test", category="detect", format="generic",
            payload="p", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestXXEResult:
    """Testes para dataclass XXEResult."""

    def test_create(self) -> None:
        result = XXEResult(
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
        result = XXEResult(
            target="t", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestCheckXXEResponse:
    """Testes para _check_xxe_response."""

    def test_passwd_detected(self) -> None:
        assert _check_xxe_response(b"root:x:0:0:root:/root:/bin/bash", 200, ["root:"])

    def test_not_detected(self) -> None:
        assert not _check_xxe_response(b"not found", 200, ["root:"])

    def test_status_zero(self) -> None:
        assert not _check_xxe_response(b"root:", 0, ["root:"])

    def test_case_insensitive(self) -> None:
        assert _check_xxe_response(b"ROOT:X:0:0", 200, ["root:"])

    def test_multiple_indicators(self) -> None:
        assert _check_xxe_response(b"error: permission denied", 200, ["error", "exception"])

    def test_empty_body(self) -> None:
        assert not _check_xxe_response(b"", 200, ["root:"])


class TestBuildXXEBody:
    """Testes para _build_xxe_body."""

    def test_generic(self) -> None:
        body, ct = _build_xxe_body("<root>test</root>")
        assert body == b"<root>test</root>"
        assert ct == "application/xml"

    def test_utf16le(self) -> None:
        body, ct = _build_xxe_body("<root>test</root>", "utf-16le")
        assert isinstance(body, bytes)
        assert "utf-16" in ct

    def test_utf7(self) -> None:
        body, ct = _build_xxe_body("<root>test</root>", "utf-7")
        assert isinstance(body, bytes)
        assert "utf-7" in ct


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
    async def test_baseline_ok(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"root:x:0:0:root:/root:/bin/bash"
        mock_client.post.return_value = mock_resp

        results = await _test_detect(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 5
        vulns = [r for r in results if r.vulnerable]
        assert len(vulns) > 0

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp

        results = await _test_detect(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_detect(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 5
        assert all(r.error for r in results)


class TestTestFileRead:
    """Testes para _test_file_read."""

    @pytest.mark.asyncio
    async def test_passwd_found(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
        mock_client.post.return_value = mock_resp

        results = await _test_file_read(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 8
        vulns = [r for r in results if r.vulnerable]
        assert len(vulns) > 0

    @pytest.mark.asyncio
    async def test_not_found(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b"Not Found"
        mock_client.post.return_value = mock_resp

        results = await _test_file_read(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 8
        vulns = [r for r in results if r.vulnerable]
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_file_read(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 8
        assert all(r.error for r in results)


class TestTestSSRF:
    """Testes para _test_ssrf."""

    @pytest.mark.asyncio
    async def test_response(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ami-id: ami-12345"
        mock_client.post.return_value = mock_resp

        results = await _test_ssrf(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 6

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_ssrf(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 6
        assert all(r.error for r in results)


class TestTestBlind:
    """Testes para _test_blind."""

    @pytest.mark.asyncio
    async def test_response(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"response"
        mock_client.post.return_value = mock_resp

        results = await _test_blind(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_blind(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 5
        assert all(r.error for r in results)


class TestTestBypass:
    """Testes para _test_bypass."""

    @pytest.mark.asyncio
    async def test_passwd_found(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"root:x:0:0:root:/root:/bin/bash"
        mock_client.post.return_value = mock_resp

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 8
        vulns = [r for r in results if r.vulnerable]
        assert len(vulns) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == 8
        assert all(r.error for r in results)


class TestPrintResults:
    """Testes para print_results."""

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = XXEResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=["basic_xxe"],
            blocked_techniques=[],
            issues=["VULN: basic_xxe"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERAVEIS" in output

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = XXEResult(
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
        assert "Nenhum XXE detectado" in output


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
        with patch("sys.argv", ["mytools-xxedetect"]), \
             patch("mytools.web.xxedetect.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with patch("sys.argv", ["mytools-xxedetect", "https://example.com"]), \
             patch("mytools.web.xxedetect.run_main_loop", return_value=0):
            result = main()
            assert result == 0


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.xxedetect import run_scan

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not vulnerable"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        with patch("mytools.web.xxedetect.create_async_client", return_value=mock_client):
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
        from mytools.web.xxedetect import run_scan

        mock_client = AsyncMock()
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"root:x:0:0:root:/root:/bin/bash"
        mock_client.post.return_value = mock_post

        with patch("mytools.web.xxedetect.create_async_client", return_value=mock_client):
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
        from mytools.web.xxedetect import run_scan

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.content = b""
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.xxedetect.create_async_client", return_value=mock_client):
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
        from mytools.web.xxedetect import run_scan

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
        with patch("mytools.web.xxedetect.create_async_client", return_value=mock_client):
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

        with patch("mytools.web.xxedetect.safe_asyncio_run", return_value=0) as mock_run:
            from mytools.web.xxedetect import run_once
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

        with patch("mytools.web.xxedetect.safe_asyncio_run", return_value=0):
            from mytools.web.xxedetect import run_once
            result = run_once(args)
            assert result == 0
