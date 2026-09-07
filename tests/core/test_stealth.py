import argparse
import builtins
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from mytools.core import stealth as stealth_mod
from mytools.core.stealth import (
    ProxyPool,
    TorManager,
    UserAgentRotator,
    apply_jitter,
    fragment_http_headers,
    fragment_tcp_request,
    pad_headers,
    randomize_source_port,
    waf_encode_headers,
    waf_encode_url,
)
from mytools.core.utils import (
    add_stealth_args,
    validate_stealth_args,
)


class TestProxyPool:
    def test_round_robin(self):
        pool = ProxyPool(["http://p1:8080", "http://p2:8080", "http://p3:8080"])
        results = [pool.get_sync() for _ in range(6)]
        assert results == [
            "http://p1:8080",
            "http://p2:8080",
            "http://p3:8080",
            "http://p1:8080",
            "http://p2:8080",
            "http://p3:8080",
        ]

    def test_mark_dead_removes_from_pool(self):
        pool = ProxyPool(["http://p1:8080", "http://p2:8080"])
        pool.mark_dead("http://p1:8080")
        pool.mark_dead("http://p1:8080")
        pool.mark_dead("http://p1:8080")
        assert pool.get_sync() == "http://p2:8080"
        assert pool.alive == ["http://p2:8080"]

    def test_all_dead_returns_none(self):
        pool = ProxyPool(["http://p1:8080"])
        pool.mark_dead("http://p1:8080")
        pool.mark_dead("http://p1:8080")
        pool.mark_dead("http://p1:8080")
        assert pool.get_sync() is None

    def test_mark_ok_resets_failures(self):
        pool = ProxyPool(["http://p1:8080"])
        pool.mark_dead("http://p1:8080")
        pool.mark_dead("http://p1:8080")
        pool.mark_ok("http://p1:8080")
        pool.mark_dead("http://p1:8080")
        assert pool.get_sync() == "http://p1:8080"

    def test_stats(self):
        pool = ProxyPool(["http://p1:8080", "http://p2:8080"])
        stats = pool.stats
        assert stats["total"] == "2"
        assert stats["alive"] == "2"
        assert stats["dead"] == "0"

    def test_empty_pool(self):
        pool = ProxyPool([])
        assert pool.get_sync() is None
        assert pool.alive == []

    @pytest.mark.asyncio
    async def test_get_async(self):
        pool = ProxyPool(["http://p1:8080"])
        proxy = await pool.get()
        assert proxy == "http://p1:8080"


class TestUserAgentRotator:
    def test_default_count(self):
        rotator = UserAgentRotator()
        assert rotator.count > 40

    def test_rotation(self):
        rotator = UserAgentRotator()
        seen = set()
        for _ in range(rotator.count + 5):
            seen.add(rotator.get())
        assert len(seen) > 1

    def test_category_chrome(self):
        rotator = UserAgentRotator()
        ua = rotator.get(category="chrome")
        assert "Chrome" in ua

    def test_category_firefox(self):
        rotator = UserAgentRotator()
        ua = rotator.get(category="firefox")
        assert "Firefox" in ua

    def test_category_safari(self):
        rotator = UserAgentRotator()
        ua = rotator.get(category="safari")
        assert "Safari" in ua
        assert "Chrome" not in ua

    def test_category_mobile(self):
        rotator = UserAgentRotator()
        ua = rotator.get(category="mobile")
        assert "Mobile" in ua or "Android" in ua or "iPhone" in ua

    def test_category_bot(self):
        rotator = UserAgentRotator()
        ua = rotator.get(category="bot")
        assert "bot" in ua.lower() or "Bot" in ua

    def test_custom_user_agents(self):
        custom = ["CustomAgent/1.0", "CustomAgent/2.0"]
        rotator = UserAgentRotator(user_agents=custom)
        assert rotator.count == 2
        ua = rotator.get()
        assert ua.startswith("CustomAgent")

    def test_invalid_category_fallback(self):
        rotator = UserAgentRotator()
        ua = rotator.get(category="nonexistent")
        assert ua  # should return something


class TestTorManager:
    def test_proxy_url(self):
        tor = TorManager()
        assert tor.proxy_url == "socks5://127.0.0.1:9050"

    def test_custom_port(self):
        tor = TorManager(socks_port=9150)
        assert tor.proxy_url == "socks5://127.0.0.1:9150"

    @pytest.mark.asyncio
    async def test_get_proxy(self):
        tor = TorManager()
        proxy = await tor.get_proxy()
        assert proxy.startswith("socks5://")

    @pytest.mark.asyncio
    async def test_get_ip_success(self, monkeypatch):
        fake_transport = MagicMock()

        class _FakeTransport:
            @classmethod
            def from_url(cls, url):
                fake_transport.url = url
                return fake_transport

        fake_mod = MagicMock()
        fake_mod.AsyncProxyTransport = _FakeTransport
        monkeypatch.setitem(sys.modules, "httpx_socks", fake_mod)

        class _FakeClient:
            get: Any

            def __init__(self, **kwargs):
                self.kwargs = kwargs

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        client = _FakeClient()
        resp = MagicMock()
        resp.json.return_value = {"ip": "1.2.3.4"}
        client.get = AsyncMock(return_value=resp)
        monkeypatch.setattr(
            "mytools.core.stealth.httpx.AsyncClient",
            MagicMock(return_value=client),
        )

        tor = TorManager()
        ip = await tor.get_ip()
        assert ip == "1.2.3.4"
        assert fake_transport.url == "socks5://127.0.0.1:9050"

    @pytest.mark.asyncio
    async def test_get_ip_import_error(self, monkeypatch):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "httpx_socks":
                raise ImportError
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        tor = TorManager()
        assert await tor.get_ip() == "unknown"

    @pytest.mark.asyncio
    async def test_get_ip_exception(self, monkeypatch):
        fake_mod = MagicMock()
        fake_mod.AsyncProxyTransport = MagicMock()
        monkeypatch.setitem(sys.modules, "httpx_socks", fake_mod)

        client = MagicMock()
        client.__aenter__.return_value = client
        client.__aexit__.return_value = False
        client.get.side_effect = RuntimeError("falha de rede")
        monkeypatch.setattr(
            "mytools.core.stealth.httpx.AsyncClient",
            MagicMock(return_value=client),
        )

        tor = TorManager()
        assert await tor.get_ip() == "unknown"

    @pytest.mark.asyncio
    async def test_new_circuit_success(self, monkeypatch):
        reader = AsyncMock()
        reader.read.side_effect = [b"250 OK\r\n", b"250 OK\r\n"]
        writer = MagicMock()
        writer.drain = AsyncMock()
        monkeypatch.setattr(
            "mytools.core.stealth.asyncio.open_connection",
            AsyncMock(return_value=(reader, writer)),
        )

        tor = TorManager()
        monkeypatch.setattr(tor, "get_ip", AsyncMock(return_value="9.9.9.9"))
        assert await tor.new_circuit(new_circuit_wait=0) == "9.9.9.9"
        writer.write.assert_called()
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_new_circuit_exception(self, monkeypatch):
        monkeypatch.setattr(
            "mytools.core.stealth.asyncio.open_connection",
            AsyncMock(side_effect=OSError("conexao recusada")),
        )

        tor = TorManager()
        assert await tor.new_circuit() is None

    @pytest.mark.asyncio
    async def test_new_circuit_no_auth_response(self, monkeypatch):
        reader = AsyncMock()
        reader.read.return_value = b"500 ERROR\r\n"
        writer = MagicMock()
        writer.drain = AsyncMock()
        monkeypatch.setattr(
            "mytools.core.stealth.asyncio.open_connection",
            AsyncMock(return_value=(reader, writer)),
        )

        tor = TorManager()
        monkeypatch.setattr(tor, "get_ip", AsyncMock(return_value="9.9.9.9"))
        assert await tor.new_circuit() is None

    @pytest.mark.asyncio
    async def test_new_circuit_nym_response_rejected(self, monkeypatch):
        reader = AsyncMock()
        reader.read.side_effect = [b"250 OK\r\n", b"500 ERROR\r\n"]
        writer = MagicMock()
        writer.drain = AsyncMock()
        monkeypatch.setattr(
            "mytools.core.stealth.asyncio.open_connection",
            AsyncMock(return_value=(reader, writer)),
        )

        tor = TorManager()
        monkeypatch.setattr(tor, "get_ip", AsyncMock(return_value="9.9.9.9"))
        assert await tor.new_circuit() is None

    @pytest.mark.asyncio
    async def test_new_circuit_uses_auth_cookie(self, monkeypatch, tmp_path):
        cookie_file = tmp_path / "control.authcookie"
        cookie_file.write_bytes(b"X" * 32)

        reader = AsyncMock()
        reader.read.side_effect = [b"250 OK\r\n", b"250 OK\r\n"]
        writer = MagicMock()
        writer.drain = AsyncMock()
        monkeypatch.setattr(
            "mytools.core.stealth.asyncio.open_connection",
            AsyncMock(return_value=(reader, writer)),
        )

        tor = TorManager(control_auth_cookie=str(cookie_file))
        monkeypatch.setattr(tor, "get_ip", AsyncMock(return_value="9.9.9.9"))
        assert await tor.new_circuit(new_circuit_wait=0) == "9.9.9.9"
        expected = b"AUTHENTICATE " + (b"X" * 32).hex().encode() + b"\r\n"
        writer.write.assert_any_call(expected)

    @pytest.mark.asyncio
    async def test_get_ip_recreates_closed_client(self, monkeypatch):
        # Cliente existente porem fechado -> transport/client sao recriados.
        fake_mod = MagicMock()
        fake_mod.AsyncProxyTransport = MagicMock()
        monkeypatch.setitem(sys.modules, "httpx_socks", fake_mod)

        tor = TorManager()
        tor._tor_client = MagicMock(is_closed=True)

        new_client = MagicMock()
        new_client.is_closed = False
        new_client.get = AsyncMock(
            return_value=MagicMock(json=MagicMock(return_value={"ip": "5.5.5.5"}))
        )
        monkeypatch.setattr(
            "mytools.core.stealth.httpx.AsyncClient",
            MagicMock(return_value=new_client),
        )

        assert await tor.get_ip() == "5.5.5.5"
        assert tor._tor_client is new_client

    @pytest.mark.asyncio
    async def test_get_ip_reuses_open_client(self, monkeypatch):
        # Cliente aberto e reutilizado (nao recria transport).
        fake_mod = MagicMock()
        monkeypatch.setitem(sys.modules, "httpx_socks", fake_mod)

        client = MagicMock()
        client.is_closed = False
        client.get = AsyncMock(
            return_value=MagicMock(json=MagicMock(return_value={"ip": "7.7.7.7"}))
        )
        monkeypatch.setattr(
            "mytools.core.stealth.httpx.AsyncClient",
            MagicMock(return_value=MagicMock()),
        )

        tor = TorManager()
        tor._tor_client = client
        assert await tor.get_ip() == "7.7.7.7"
        assert tor._tor_client is client

    def test_find_auth_cookie_missing_all(self, tmp_path):
        tor = TorManager(control_auth_cookie=str(tmp_path / "missing.authcookie"))
        assert tor._find_auth_cookie() is None

    def test_find_auth_cookie_empty_first_candidate_skips(self, tmp_path):
        empty = tmp_path / "empty.authcookie"
        empty.write_bytes(b"")
        tor = TorManager(control_auth_cookie=str(empty))
        assert tor._find_auth_cookie() is None

    @pytest.mark.asyncio
    async def test_read_status_loop_exhausts(self):
        # Chunks sem '\r\n' -> loop acumula ate as 8 leituras e sai por completo.
        reader = AsyncMock()
        reader.read.return_value = b"250 OK"
        assert await TorManager._read_status(reader) is True

    @pytest.mark.asyncio
    async def test_read_status_empty_chunk_breaks(self):
        reader = AsyncMock()
        reader.read.return_value = b""
        assert await TorManager._read_status(reader) is False

    @pytest.mark.asyncio
    async def test_read_status_exception_returns_false(self):
        reader = AsyncMock()
        reader.read.side_effect = RuntimeError("io")
        assert await TorManager._read_status(reader) is False

    @pytest.mark.asyncio
    async def test_tor_control_exchange_drain_error(self, monkeypatch):
        reader = AsyncMock()
        reader.read.side_effect = [b"250 OK\r\n"]
        writer = MagicMock()
        writer.drain = AsyncMock(side_effect=RuntimeError("write failed"))
        monkeypatch.setattr(
            "mytools.core.stealth.asyncio.open_connection",
            AsyncMock(return_value=(reader, writer)),
        )

        tor = TorManager()
        assert await tor._tor_control_exchange() is False

    @pytest.mark.asyncio
    async def test_new_circuit_get_ip_raises(self, monkeypatch):
        reader = AsyncMock()
        reader.read.side_effect = [b"250 OK\r\n", b"250 OK\r\n"]
        writer = MagicMock()
        writer.drain = AsyncMock()
        monkeypatch.setattr(
            "mytools.core.stealth.asyncio.open_connection",
            AsyncMock(return_value=(reader, writer)),
        )

        tor = TorManager()
        monkeypatch.setattr(tor, "get_ip", AsyncMock(side_effect=RuntimeError("boom")))
        assert await tor.new_circuit(new_circuit_wait=0) is None


class TestApplyJitter:
    def test_no_jitter(self):
        result = apply_jitter(1.0, jitter_pct=0.0)
        assert result == 1.0

    def test_zero_delay(self):
        result = apply_jitter(0.0, jitter_pct=0.5)
        assert result == 0.0

    def test_jitter_in_range(self):
        results = [apply_jitter(1.0, jitter_pct=0.2) for _ in range(100)]
        assert all(0.8 <= r <= 1.2 for r in results)

    def test_negative_delay_becomes_zero(self):
        result = apply_jitter(-1.0, jitter_pct=0.2)
        assert result >= 0.0

    def test_negative_jitter_pct(self):
        result = apply_jitter(1.0, jitter_pct=-0.5)
        assert result == 1.0


class TestFragmentHttpHeaders:
    def test_small_headers_single_chunk(self):
        headers = {"Host": "example.com"}
        result = fragment_http_headers(headers, chunk_size=100)
        assert len(result) == 1
        assert b"Host: example.com" in result[0]

    def test_large_headers_multiple_chunks(self):
        headers = {"Host": "example.com", "X-Custom": "a" * 50}
        result = fragment_http_headers(headers, chunk_size=10)
        assert len(result) > 1
        # Reassembled should match original
        full = b"".join(result)
        assert b"Host: example.com" in full

    def test_empty_headers(self):
        result = fragment_http_headers({}, chunk_size=10)
        assert result == [b""]

    def test_zero_chunk_size(self):
        headers = {"Host": "example.com"}
        result = fragment_http_headers(headers, chunk_size=0)
        assert b"".join(result) == b"Host: example.com\r\n"

    def test_negative_chunk_size(self):
        headers = {"Host": "example.com"}
        result = fragment_http_headers(headers, chunk_size=-3)
        assert b"".join(result) == b"Host: example.com\r\n"


class TestFragmentTcpRequest:
    def test_small_data_single_chunk(self):
        data = b"hello"
        result = fragment_tcp_request(data, fragment_size=100)
        assert result == [b"hello"]

    def test_large_data_multiple_chunks(self):
        data = b"x" * 30
        result = fragment_tcp_request(data, fragment_size=8)
        assert len(result) == 4
        assert b"".join(result) == data

    def test_exact_chunk_size(self):
        data = b"12345"
        result = fragment_tcp_request(data, fragment_size=5)
        assert result == [b"12345"]

    def test_zero_fragment_size(self):
        data = b"hello"
        result = fragment_tcp_request(data, fragment_size=0)
        assert b"".join(result) == data


class TestWafEncodeUrl:
    def test_preserves_scheme_and_host(self):
        url = "https://example.com/path"
        result = waf_encode_url(url)
        assert result.startswith("https://example.com")

    def test_preserves_query_and_fragment(self):
        url = "https://example.com/path?q=1#frag"
        result = waf_encode_url(url)
        assert "q=1" in result
        assert "frag" in result

    def test_may_double_encode(self):
        url = "https://example.com/test"
        # Run multiple times; at least one should differ from original
        results = [waf_encode_url(url) for _ in range(20)]
        # At least some should have encoding
        assert any(r != url for r in results)

    def test_encodes_dot_as_percent2e(self, monkeypatch):
        # randbelow(2) == 0 -> ponto vira %2e (depois %252e pelo double encode)
        monkeypatch.setattr(
            stealth_mod.secrets, "randbelow", lambda n: 0 if n == 2 else 1
        )
        result = waf_encode_url("https://example.com/a.b")
        assert "%252e" in result

    def test_encodes_space_as_percent20(self, monkeypatch):
        # randbelow(2) == 0 -> espaco vira %20 (depois %2520 pelo double encode)
        monkeypatch.setattr(
            stealth_mod.secrets, "randbelow", lambda n: 0 if n == 2 else 1
        )
        result = waf_encode_url("https://example.com/a b")
        assert "%2520" in result

    def test_double_encodes_percent_sign(self, monkeypatch):
        monkeypatch.setattr(
            stealth_mod.secrets, "randbelow", lambda n: 0 if n == 2 else 1
        )
        result = waf_encode_url("https://example.com/a.b")
        assert "%25" in result  # %2e -> %252e

    def test_non_ascii_letters_are_percent_encoded(self, monkeypatch):
        # Forca a variacao de caixa (randbelow(3)==0) para garantir que o
        # caminho bugado (char cru nao-ascii) nao ocorra.
        monkeypatch.setattr(stealth_mod.secrets, "randbelow", lambda n: 0)
        result = waf_encode_url("https://example.com/ção")
        assert not any(c.isalpha() and ord(c) > 127 for c in result)


class TestWafEncodeHeaders:
    def test_preserves_values(self):
        headers = {"Content-Type": "application/json", "Authorization": "Bearer abc"}
        result = waf_encode_headers(headers)
        assert set(result.values()) == set(headers.values())

    def test_mixed_case_names(self):
        headers = {"Content-Type": "text/html"}
        result = waf_encode_headers(headers)
        name = next(iter(result.keys()))
        # Should have mixed case
        has_upper = any(c.isupper() for c in name.replace("-", ""))
        has_lower = any(c.islower() for c in name.replace("-", ""))
        assert has_upper and has_lower

    def test_preserves_count(self):
        headers = {"A": "1", "B": "2", "C": "3"}
        result = waf_encode_headers(headers)
        assert len(result) == 3

    def test_case_collision_keeps_both(self):
        headers = {"X-Foo": "a", "x-foo": "b"}
        result = waf_encode_headers(headers)
        assert set(result.values()) == {"a", "b"}


class TestPadHeaders:
    def test_already_has_enough(self):
        headers = {f"H{i}": str(i) for i in range(15)}
        result = pad_headers(headers, target_count=10)
        assert len(result) >= 10

    def test_no_infinite_loop_when_target_exceeds_available(self):
        headers = {"Host": "example.com"}
        result = pad_headers(headers, target_count=10_000)
        assert "Host" in result
        assert len(result) < 10_000

    def test_adds_padding(self):
        headers = {"Host": "example.com"}
        result = pad_headers(headers, target_count=10)
        assert len(result) >= 10
        assert "Host" in result

    def test_preserves_originals(self):
        headers = {"X-Real": "value"}
        result = pad_headers(headers, target_count=5)
        assert "X-Real" in result
        assert result["X-Real"] == "value"


class TestRandomizeSourcePort:
    def test_in_valid_range(self):
        ports = {randomize_source_port() for _ in range(100)}
        assert all(1024 <= p <= 65535 for p in ports)

    def test_varies(self):
        ports = {randomize_source_port() for _ in range(50)}
        assert len(ports) > 1

    def test_upper_bound_reachable(self, monkeypatch):
        monkeypatch.setattr(stealth_mod.secrets, "randbelow", lambda n: n - 1)
        assert randomize_source_port() == 65535


def test_random_user_agent_returns_known_agent():
    ua = stealth_mod.random_user_agent()
    assert ua in stealth_mod._USER_AGENTS
    assert ua


class TestAddStealthArgs:
    def test_web_module_has_all_flags(self):
        parser = argparse.ArgumentParser()
        add_stealth_args(parser, module_type="web")
        args = parser.parse_args([])
        assert hasattr(args, "random_delay")
        assert hasattr(args, "jitter")
        assert hasattr(args, "user_agent_rotate")
        assert hasattr(args, "impersonate")
        assert hasattr(args, "fragment")
        assert hasattr(args, "tor")
        assert hasattr(args, "waf_evasion")
        assert hasattr(args, "pad_headers")
        assert hasattr(args, "rate_limit")

    def test_network_module_has_tcp_fragment(self):
        parser = argparse.ArgumentParser()
        add_stealth_args(parser, module_type="network")
        args = parser.parse_args([])
        assert hasattr(args, "fragment_tcp")
        assert hasattr(args, "src_port_random")

    def test_network_module_no_http_fragment(self):
        parser = argparse.ArgumentParser()
        add_stealth_args(parser, module_type="network")
        args = parser.parse_args([])
        assert not hasattr(args, "fragment")

    def test_dns_module_minimal_flags(self):
        parser = argparse.ArgumentParser()
        add_stealth_args(parser, module_type="dns")
        args = parser.parse_args([])
        assert hasattr(args, "tor")
        assert hasattr(args, "jitter")
        assert not hasattr(args, "impersonate")
        assert not hasattr(args, "waf_evasion")


class TestValidateStealthArgs:
    def test_compatible_flags_pass(self):
        args = argparse.Namespace(
            tor=True,
            jitter=0.5,
            proxy=None,
            delay=0.0,
            random_delay=False,
            user_agent_rotate=False,
            impersonate=None,
            fragment=0,
            fragment_tcp=0,
            waf_evasion=False,
            pad_headers=0,
            src_port_random=False,
            rate_limit=0.0,
        )
        validate_stealth_args(args, module_type="web")

    def test_incompatible_flag_aborts(self):
        args = argparse.Namespace(
            tor=False,
            jitter=0.0,
            proxy=None,
            delay=0.0,
            random_delay=False,
            user_agent_rotate=False,
            impersonate="chrome",
            fragment=0,
            fragment_tcp=0,
            waf_evasion=False,
            pad_headers=0,
            src_port_random=False,
            rate_limit=0.0,
        )
        with pytest.raises(SystemExit) as exc_info:
            validate_stealth_args(args, module_type="dns")
        assert exc_info.value.code == 2

    def test_no_stealth_flags_pass(self):
        args = argparse.Namespace(
            tor=False,
            jitter=0.0,
            proxy=None,
            delay=0.0,
            random_delay=False,
            user_agent_rotate=False,
            impersonate=None,
            fragment=0,
            fragment_tcp=0,
            waf_evasion=False,
            pad_headers=0,
            src_port_random=False,
            rate_limit=0.0,
        )
        validate_stealth_args(args, module_type="network")
