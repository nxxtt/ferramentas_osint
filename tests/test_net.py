from __future__ import annotations

import httpx
import pytest
import respx

from net import (
    Client,
    FetchError,
    classify_by_content_type,
    fetch_bytes,
    http,
    read_response_text,
)


class TestClassifyByContentType:
    def test_html(self):
        assert classify_by_content_type({"content-type": "text/html; charset=utf-8"}) == "html"

    def test_json(self):
        assert classify_by_content_type({"content-type": "application/json"}) == "json"

    def test_json_with_json_suffix(self):
        assert classify_by_content_type({"content-type": "application/vnd.api+json"}) == "json"

    def test_xml(self):
        assert classify_by_content_type({"content-type": "application/xml"}) == "xml"

    def test_text_xml(self):
        assert classify_by_content_type({"content-type": "text/xml"}) == "xml"

    def test_plain_text(self):
        assert classify_by_content_type({"content-type": "text/plain"}) == "text"

    def test_css_text(self):
        assert classify_by_content_type({"content-type": "text/css"}) == "text"

    def test_binary(self):
        assert classify_by_content_type({"content-type": "application/octet-stream"}) == "binary"

    def test_image(self):
        assert classify_by_content_type({"content-type": "image/png"}) == "binary"

    def test_empty_content_type(self):
        assert classify_by_content_type({}) == "binary"

    def test_case_insensitive_value(self):
        assert classify_by_content_type({"content-type": "Text/HTML"}) == "html"

    def test_multipart_form_data(self):
        assert classify_by_content_type({"content-type": "multipart/form-data"}) == "binary"


class TestFetchBytes:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_bytes(self, async_client):
        respx.get("http://example.com/binary").mock(
            return_value=httpx.Response(200, content=b"\x00\x01\x02")
        )
        result = await fetch_bytes(async_client, "http://example.com/binary")
        assert result == b"\x00\x01\x02"

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_body(self, async_client):
        respx.get("http://example.com/empty").mock(
            return_value=httpx.Response(200, content=b"")
        )
        result = await fetch_bytes(async_client, "http://example.com/empty")
        assert result == b""

    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_error_raises(self, async_client):
        respx.get("http://example.com/fail").mock(side_effect=httpx.ConnectError("refused"))
        with pytest.raises(FetchError):
            await fetch_bytes(async_client, "http://example.com/fail")


class TestReadResponseText:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_text(self, async_client):
        respx.get("http://example.com/page").mock(
            return_value=httpx.Response(200, text="<html>Hello</html>")
        )
        result = await read_response_text(async_client, "http://example.com/page")
        assert result == "<html>Hello</html>"

    @respx.mock
    @pytest.mark.asyncio
    async def test_custom_encoding(self, async_client):
        respx.get("http://example.com/latin").mock(
            return_value=httpx.Response(200, content="café".encode("latin-1"))
        )
        result = await read_response_text(
            async_client, "http://example.com/latin", encoding="latin-1"
        )
        assert result == "café"

    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_error_raises(self, async_client):
        respx.get("http://example.com/fail").mock(side_effect=httpx.ConnectError("refused"))
        with pytest.raises(FetchError):
            await read_response_text(async_client, "http://example.com/fail")


class TestModuleAliases:
    def test_http_is_httpx(self):
        assert http is httpx

    def test_client_is_async_client(self):
        assert Client is httpx.AsyncClient
