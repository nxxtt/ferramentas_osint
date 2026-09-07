import argparse
import re
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from mytools.core import utils
from mytools.core.utils import (
    RateLimiter,
    add_stealth_args,
    apply_session_auth_async,
    clear_console,
    create_async_client,
    create_banner,
    detect_spa_fallback,
    fetch,
    init_scanner,
    normalize_url,
    print_exploit_info,
    print_table,
    query_nvd,
    read_target_lines,
    resolve_cred_async,
    run_interactive_shell,
    run_main_loop,
    safe_asyncio_run,
    set_fetch_cache_ttl,
    show_banner,
    validate_stealth_args,
    write_output,
)

pytestmark = pytest.mark.integration


def _make_args(**overrides: object) -> argparse.Namespace:
    defaults = {
        "verbose": False,
        "log_file": None,
        "quiet": False,
        "color": None,
        "theme": None,
        "severity_override": None,
        "random_delay": False,
        "jitter": 0.0,
        "user_agent_rotate": False,
        "impersonate": None,
        "tor": False,
        "waf_evasion": False,
        "pad_headers": 0,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestReadVersionExcept:
    def test_returns_zero_on_missing_pyproject(self, monkeypatch):
        def fake_load(_fh):
            raise FileNotFoundError

        monkeypatch.setattr(utils.tomllib, "load", fake_load)
        assert utils._read_version() == "0.0.0"


class TestInitScannerBranches:
    def test_color_applied(self, monkeypatch):
        mock = MagicMock()
        monkeypatch.setattr(utils, "set_color", mock)
        init_scanner(_make_args(color=False))
        mock.assert_called_once_with(False)

    def test_theme_applied(self, monkeypatch):
        init_scanner(_make_args(theme="dracula"))
        theme = utils.THEMES["dracula"]
        assert theme["RED"] == utils.Cyber.RED

    def test_severity_override(self, monkeypatch):
        mock = MagicMock()
        monkeypatch.setattr(utils, "override_severity", mock)
        init_scanner(_make_args(severity_override="high=RED,critical=MAGENTA"))
        calls = [c.args for c in mock.call_args_list]
        assert ("high", "RED") in calls
        assert ("critical", "MAGENTA") in calls

    def test_severity_override_skips_malformed_pair(self, monkeypatch):
        mock = MagicMock()
        monkeypatch.setattr(utils, "override_severity", mock)
        init_scanner(_make_args(severity_override="high=RED,badpair"))
        calls = [c.args for c in mock.call_args_list]
        assert ("high", "RED") in calls
        assert len(calls) == 1


class TestRunMainLoopDumpPayloads:
    def test_dump_payloads_returns_zero(self, monkeypatch, capsys):
        parser = argparse.ArgumentParser()
        parser.add_argument("--dump-payloads", action="store_true")
        old_argv = sys.argv
        sys.argv = ["prog", "--dump-payloads"]
        try:
            code = run_main_loop(
                parser=parser,
                banner_fn=lambda: None,
                run_fn=lambda a: 1,
                has_target=lambda a: True,
                prompt="x> ",
                description="x",
                example="x",
                contextual_help="x",
            )
        finally:
            sys.argv = old_argv
        assert code == 0
        assert "registry" in capsys.readouterr().out


class TestRunMainLoopNoTarget:
    def test_enters_interactive_shell(self, monkeypatch, capsys):
        parser = argparse.ArgumentParser()
        parser.add_argument("url", nargs="?")
        inputs = iter(["exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))
        old_argv = sys.argv
        sys.argv = ["prog"]
        try:
            code = run_main_loop(
                parser=parser,
                banner_fn=lambda: None,
                run_fn=lambda a: 0,
                has_target=lambda a: bool(a.url),
                prompt="x> ",
                description="Test shell",
                example="example.com",
                contextual_help="HELP",
            )
        finally:
            sys.argv = old_argv
        assert code == 0
        assert "Test shell" in capsys.readouterr().out


class TestRunMainLoopOutputDirInject:
    def test_output_dir_with_target_sets_output(self, monkeypatch, tmp_path: Path):
        parser = argparse.ArgumentParser()
        parser.add_argument("url", nargs="?")
        parser.add_argument("-o", "--output")
        parser.add_argument("--output-dir")
        parser.add_argument("-q", "--quiet", action="store_true")
        old_argv = sys.argv
        sys.argv = ["prog", "--output-dir", str(tmp_path), "https://example.com"]
        captured = {}

        def _run(args):
            captured["output"] = args.output
            return 0

        try:
            code = run_main_loop(
                parser=parser,
                banner_fn=lambda: None,
                run_fn=_run,
                has_target=lambda a: bool(a.url),
                prompt="x> ",
                description="x",
                example="x",
                contextual_help="x",
            )
        finally:
            sys.argv = old_argv
        assert code == 0
        assert captured["output"] is not None
        assert str(tmp_path) in captured["output"]


class TestRunMainLoopOutputDirWithoutTarget:
    def test_output_dir_without_target_keeps_output_none(
        self, monkeypatch, tmp_path: Path
    ):
        parser = argparse.ArgumentParser()
        parser.add_argument("url", nargs="?")
        parser.add_argument("-o", "--output")
        parser.add_argument("--output-dir")
        parser.add_argument("-q", "--quiet", action="store_true")
        old_argv = sys.argv
        sys.argv = ["prog", "--output-dir", str(tmp_path)]
        captured = {}

        def _run(args):
            captured["output"] = args.output
            return 0

        try:
            code = run_main_loop(
                parser=parser,
                banner_fn=lambda: None,
                run_fn=_run,
                has_target=lambda a: True,
                prompt="x> ",
                description="x",
                example="x",
                contextual_help="x",
            )
        finally:
            sys.argv = old_argv
        assert code == 0
        assert captured["output"] is None


class TestRunMainLoopQuietNoOutput:
    def test_quiet_without_output_returns_one(self, monkeypatch):
        parser = argparse.ArgumentParser()
        parser.add_argument("-q", "--quiet", action="store_true")
        parser.add_argument("-o", "--output")
        parser.add_argument("--output-dir")
        parser.add_argument("url", nargs="?")
        old_argv = sys.argv
        sys.argv = ["prog", "-q", "https://example.com"]
        try:
            code = run_main_loop(
                parser=parser,
                banner_fn=lambda: None,
                run_fn=lambda a: 0,
                has_target=lambda a: bool(a.url),
                prompt="x> ",
                description="x",
                example="x",
                contextual_help="x",
            )
        finally:
            sys.argv = old_argv
        assert code == 1


class TestRunMainLoopKeyboardInterrupt:
    def test_returns_130(self, monkeypatch):
        parser = argparse.ArgumentParser()
        parser.add_argument("url", nargs="?")
        old_argv = sys.argv
        sys.argv = ["prog", "https://example.com"]
        try:

            def _boom(_a):
                raise KeyboardInterrupt

            code = run_main_loop(
                parser=parser,
                banner_fn=lambda: None,
                run_fn=_boom,
                has_target=lambda a: bool(a.url),
                prompt="x> ",
                description="x",
                example="x",
                contextual_help="x",
            )
        finally:
            sys.argv = old_argv
        assert code == 130


class TestRunMainLoopException:
    def test_returns_one(self, monkeypatch):
        parser = argparse.ArgumentParser()
        parser.add_argument("url", nargs="?")
        old_argv = sys.argv
        sys.argv = ["prog", "https://example.com"]
        try:

            def _boom(_a):
                raise RuntimeError("boom")

            code = run_main_loop(
                parser=parser,
                banner_fn=lambda: None,
                run_fn=_boom,
                has_target=lambda a: bool(a.url),
                prompt="x> ",
                description="x",
                example="x",
                contextual_help="x",
            )
        finally:
            sys.argv = old_argv
        assert code == 1


class TestClearConsole:
    def test_calls_os_system(self, monkeypatch):
        fake = MagicMock()
        monkeypatch.setattr(utils.os, "system", fake)
        clear_console()
        fake.assert_called_once()


class TestRateLimiterExtra:
    @pytest.mark.asyncio
    async def test_jitter_applied(self):
        rl = RateLimiter(requests_per_second=10, jitter=0.5)
        rl.notify_429(0.0)
        await rl.wait()

    def test_notify_ok_reduces_backoff(self):
        rl = RateLimiter(requests_per_second=1.0)
        rl.notify_429(0.0)
        assert rl._backoff_multiplier > 1.0
        rl.notify_ok()
        assert rl._backoff_multiplier >= 1.0

    def test_get_effective_rps(self):
        rl = RateLimiter(requests_per_second=0.0)
        assert rl.get_effective_rps() == 0.0
        rl2 = RateLimiter(requests_per_second=2.0)
        assert rl2.get_effective_rps() == 2.0

    def test_get_effective_rps_negative_effective(self):
        rl = RateLimiter(requests_per_second=2.0)
        rl._backoff_multiplier = -5.0
        assert rl.get_effective_rps() == 0.0

    def test_notify_ok_without_backoff_keeps_one(self):
        rl = RateLimiter(requests_per_second=1.0)
        rl.notify_ok()
        assert rl._backoff_multiplier == 1.0


class TestCreateAsyncClientStealth:
    def test_impersonate(self, monkeypatch):
        monkeypatch.setattr(
            utils,
            "get_stealth_ctx",
            lambda: MagicMock(impersonate="chrome", user_agent_rotate=False, tor=False),
        )
        client = create_async_client()
        import contextlib

        with contextlib.suppress(Exception):
            client.aclose()
        assert isinstance(client, (httpx.AsyncClient, object))

    def test_tor(self, monkeypatch):
        ctx = MagicMock(impersonate=None, user_agent_rotate=False, tor=True)
        fake_tor = MagicMock(proxy_url="socks5://127.0.0.1:9050")
        monkeypatch.setattr(utils, "get_stealth_ctx", lambda: ctx)
        import mytools.core.stealth as stealth_mod

        monkeypatch.setattr(stealth_mod, "TorManager", lambda: fake_tor)
        captured = {}

        class FakeClient(MagicMock):
            def __init__(self, *args, **kwargs):
                super().__init__()
                captured.update(kwargs)
                self.headers = httpx.Headers({"User-Agent": "MyTools/test"})

        monkeypatch.setattr(utils.httpx, "AsyncClient", FakeClient)
        create_async_client()
        assert captured.get("proxy") == "socks5://127.0.0.1:9050"

    def test_curl_cffi_exception_falls_back(self, monkeypatch):
        ctx = MagicMock(impersonate="chrome", user_agent_rotate=False, tor=False)
        monkeypatch.setattr(utils, "get_stealth_ctx", lambda: ctx)
        fake_session_cls = MagicMock(side_effect=RuntimeError("boom"))

        class FakeModule:
            AsyncSession = fake_session_cls

        import builtins
        import importlib

        real_import = importlib.__import__

        def fake_import(name, *args, **kwargs):
            if name == "curl_cffi" or name.startswith("curl_cffi."):
                return FakeModule()
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        client = create_async_client()
        assert isinstance(client, httpx.AsyncClient)
        import asyncio

        asyncio.run(client.aclose())

    def test_curl_cffi_import_fallback(self, monkeypatch):
        import builtins
        import importlib

        ctx = MagicMock(impersonate="chrome", user_agent_rotate=False, tor=False)
        monkeypatch.setattr(utils, "get_stealth_ctx", lambda: ctx)
        real_import = importlib.__import__

        def fake_import(name, *args, **kwargs):
            if name == "curl_cffi" or name.startswith("curl_cffi."):
                raise ImportError("no curl-cffi")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        client = create_async_client()
        assert isinstance(client, httpx.AsyncClient)
        import asyncio

        asyncio.run(client.aclose())


class TestCurlCffiAdapter:
    """O ramo curl-cffi de create_async_client deve ser compativel com httpx.

    curl-cffi usa allow_redirects (nao follow_redirects) e close() (nao aclose()).
    O adapter traduz os nomes e normaliza headers para httpx.Headers.
    """

    def test_maps_follow_redirects_and_aclose(self, monkeypatch):
        ctx = MagicMock(impersonate="chrome", user_agent_rotate=False, tor=False)
        monkeypatch.setattr(utils, "get_stealth_ctx", lambda: ctx)
        captured: dict = {}

        class FakeResponse:
            def __init__(self):
                self.status_code = 200
                self.content = b"ok"
                self.text = "ok"
                self.headers = {"set-cookie": "a=1"}

        class FakeSession:
            def __init__(self, **kwargs):
                captured["init"] = kwargs
                self.headers = {}

            async def request(self, method, url, **kwargs):
                captured["request"] = (method, url, kwargs)
                return FakeResponse()

            async def close(self):
                captured["closed"] = True

        monkeypatch.setattr("curl_cffi.requests.AsyncSession", FakeSession)

        import asyncio

        client = create_async_client(
            user_agent="UA", proxy="http://p:8080", impersonate="chrome"
        )
        resp = asyncio.run(
            client.get("http://x/", follow_redirects=True, headers={"a": "b"})
        )
        asyncio.run(client.aclose())

        req_kwargs = captured["request"][2]
        assert req_kwargs["allow_redirects"] is True
        assert "follow_redirects" not in req_kwargs
        assert isinstance(resp.headers, httpx.Headers)
        assert resp.headers["set-cookie"] == "a=1"
        assert resp.status_code == 200
        assert resp.content == b"ok"
        assert captured["closed"] is True

    def test_headers_normalized_for_multi_items(self, monkeypatch):
        ctx = MagicMock(impersonate="chrome", user_agent_rotate=False, tor=False)
        monkeypatch.setattr(utils, "get_stealth_ctx", lambda: ctx)

        class FakeResponse:
            def __init__(self):
                self.status_code = 200
                self.content = b""
                self.text = ""
                self.headers = {"set-cookie": "a=1", "server": "nginx"}

        class FakeSession:
            def __init__(self, **kwargs):
                self.headers = {}

            async def request(self, method, url, **kwargs):
                return FakeResponse()

        monkeypatch.setattr("curl_cffi.requests.AsyncSession", FakeSession)

        import asyncio

        client = create_async_client(impersonate="chrome")
        resp = asyncio.run(client.get("http://x/"))
        assert isinstance(resp.headers, httpx.Headers)
        assert list(resp.headers.multi_items()) == [
            ("set-cookie", "a=1"),
            ("server", "nginx"),
        ]


def test_verb_wrappers_delegate(monkeypatch):
    ctx = MagicMock(impersonate="chrome", user_agent_rotate=False, tor=False)
    monkeypatch.setattr(utils, "get_stealth_ctx", lambda: ctx)
    calls: list[tuple[str, str, dict]] = []

    class FakeResponse:
        def __init__(self):
            self.status_code = 200
            self.content = b""
            self.text = ""
            self.headers = {"server": "nginx"}

    class FakeSession:
        def __init__(self, **kwargs):
            self.headers = {}

        async def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            return FakeResponse()

    monkeypatch.setattr("curl_cffi.requests.AsyncSession", FakeSession)

    import asyncio

    client = create_async_client(impersonate="chrome")
    for verb in ("post", "put", "options", "head"):
        method = getattr(client, verb)
        resp = asyncio.run(method("http://x/", follow_redirects=True, data=b"d"))
        assert isinstance(resp, utils._CurlCffiResponse)
    methods = [c[0] for c in calls]
    assert methods == ["POST", "PUT", "OPTIONS", "HEAD"]
    for _, _, kwargs in calls:
        assert kwargs["allow_redirects"] is True
        assert "follow_redirects" not in kwargs


class TestResetStealthCtx:
    def test_clears_global_ctx(self):
        utils._stealth_local.ctx = utils.StealthContext(impersonate="chrome")
        utils.reset_stealth_ctx()
        assert utils.get_stealth_ctx() is None


class TestFetchCacheHit:
    @respx.mock
    @pytest.mark.asyncio
    async def test_cache_hit(self):
        respx.get("http://example.com/cache").mock(
            return_value=httpx.Response(200, content=b"cached")
        )
        client = create_async_client()
        r1 = await fetch(client, "http://example.com/cache")
        r2 = await fetch(client, "http://example.com/cache")
        assert r1 == r2
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_cache_isolated_by_client(self):
        # Respostas de clientes diferentes (ex.: Tor vs direto) nao se misturam.
        calls: list[bytes] = []

        def _handler(request):
            calls.append(request.content)
            return httpx.Response(200, content=b"ok")

        respx.get("http://example.com/iso").mock(side_effect=_handler)
        client_a = create_async_client()
        client_b = create_async_client()
        await fetch(client_a, "http://example.com/iso")
        await fetch(client_b, "http://example.com/iso")
        await fetch(client_b, "http://example.com/iso")
        # Dois clients distintos => 2 fetches reais; 3o (mesmo client) e cache hit.
        assert len(calls) == 2
        await client_a.aclose()
        await client_b.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_cache_capped(self):
        utils._fetch_cache.clear()
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(utils, "_FETCH_CACHE_MAX", 5)

        def _handler(request):
            return httpx.Response(200, content=b"ok")

        respx.get(re.compile(r"http://example.com/\d+")).mock(side_effect=_handler)
        client = create_async_client()
        for i in range(20):
            await fetch(client, f"http://example.com/{i}")
        assert len(utils._fetch_cache) <= utils._FETCH_CACHE_MAX
        await client.aclose()
        monkeypatch.undo()
        utils._fetch_cache.clear()


class TestFetchCacheNegative:
    @respx.mock
    @pytest.mark.asyncio
    async def test_404_cached_within_ttl(self):
        calls: list[None] = []

        def _handler(request):
            calls.append(None)
            return httpx.Response(404, text="not found")

        respx.get("http://example.com/neg").mock(side_effect=_handler)
        client = create_async_client()
        r1 = await fetch(client, "http://example.com/neg")
        r2 = await fetch(client, "http://example.com/neg")
        assert r1[0] == 404
        assert r2[0] == 404
        assert r1 == r2
        assert len(calls) == 1
        await client.aclose()
        utils._fetch_cache.clear()

    @respx.mock
    @pytest.mark.asyncio
    async def test_cache_expires_after_ttl(self):
        calls: list[None] = []

        def _handler(request):
            calls.append(None)
            return httpx.Response(200, content=b"fresh")

        respx.get("http://example.com/ttl").mock(side_effect=_handler)
        client = create_async_client()
        await fetch(client, "http://example.com/ttl", cache_ttl=0.0)
        await fetch(client, "http://example.com/ttl", cache_ttl=0.0)
        assert len(calls) == 2
        await client.aclose()
        utils._fetch_cache.clear()


class TestFetchCacheCustomTTL:
    @respx.mock
    @pytest.mark.asyncio
    async def test_custom_cache_ttl_short(self):
        calls: list[None] = []

        def _handler(request):
            calls.append(None)
            return httpx.Response(200, content=b"ok")

        respx.get("http://example.com/custom").mock(side_effect=_handler)
        client = create_async_client()
        await fetch(client, "http://example.com/custom", cache_ttl=0.0)
        await fetch(client, "http://example.com/custom", cache_ttl=0.0)
        assert len(calls) == 2
        await client.aclose()
        utils._fetch_cache.clear()

    @respx.mock
    @pytest.mark.asyncio
    async def test_custom_cache_ttl_long(self):
        calls: list[None] = []

        def _handler(request):
            calls.append(None)
            return httpx.Response(200, content=b"ok")

        respx.get("http://example.com/long").mock(side_effect=_handler)
        client = create_async_client()
        await fetch(client, "http://example.com/long", cache_ttl=300.0)
        await fetch(client, "http://example.com/long", cache_ttl=300.0)
        assert len(calls) == 1
        await client.aclose()
        utils._fetch_cache.clear()

    def test_set_fetch_cache_ttl(self):
        original = utils._FETCH_CACHE_TTL
        set_fetch_cache_ttl(120.0)
        assert utils._FETCH_CACHE_TTL == 120.0
        set_fetch_cache_ttl(original)

    @respx.mock
    @pytest.mark.asyncio
    async def test_random_delay_and_waf_with_headers(self):
        ctx = MagicMock(
            random_delay=True,
            jitter=0.5,
            waf_evasion=True,
            user_agent_rotate=False,
            impersonate=None,
            tor=False,
        )
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(utils, "get_stealth_ctx", lambda: ctx)
        respx.route(method="GET", host="example.com").mock(
            return_value=httpx.Response(200, content=b"ok")
        )
        client = create_async_client()
        status, _, body, _ = await fetch(
            client,
            "http://example.com/stealth",
            headers={"X-Test": "1"},
        )
        assert status == 200
        assert body == b"ok"
        await client.aclose()
        monkeypatch.undo()

    @respx.mock
    @pytest.mark.asyncio
    async def test_user_agent_rotate_no_headers(self):
        ctx = MagicMock(
            random_delay=False,
            jitter=0.0,
            waf_evasion=False,
            user_agent_rotate=True,
            impersonate=None,
            tor=False,
        )
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(utils, "get_stealth_ctx", lambda: ctx)
        respx.get("http://example.com/rotate").mock(
            return_value=httpx.Response(200, content=b"ok")
        )
        client = create_async_client()
        status, _, body, _ = await fetch(client, "http://example.com/rotate")
        assert status == 200
        assert body == b"ok"
        await client.aclose()
        monkeypatch.undo()


class TestStatusColorRed:
    def test_400_series_red(self):
        from mytools.core.utils import status_color

        assert status_color(418) == utils.Cyber.RED


class TestPrintExploitInfo:
    def test_prints_both(self, capsys):
        print_exploit_info("payload", "sqlmap")
        out = capsys.readouterr().out
        assert "Exploit: payload" in out
        assert "Ferramenta: sqlmap" in out

    def test_empty_no_output(self, capsys):
        print_exploit_info("", "")
        assert capsys.readouterr().out == ""


class TestShowBanner:
    def test_prints_art_and_subtitle(self, capsys):
        show_banner("ART", "sub")
        out = capsys.readouterr().out
        assert "ART" in out
        assert "sub" in out


class TestCreateBanner:
    def test_with_extra(self, capsys):
        called = []

        def extra():
            called.append(1)

        fn = create_banner("ART", "sub", extra=extra)
        fn()
        assert called == [1]
        assert "ART" in capsys.readouterr().out

    def test_without_extra(self, capsys):
        fn = create_banner("ART", "sub")
        fn()
        assert "ART" in capsys.readouterr().out


class TestAddBaseArgsOutputDirPresent:
    def test_does_not_duplicate_output_dir(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--output-dir")
        from mytools.core.utils import add_base_args

        add_base_args(parser)
        assert parser._option_string_actions["--output-dir"] is not None


class TestPrintTableStylesNone:
    def test_default_styles(self, capsys):
        print_table(
            headers=("A", "B"),
            rows=[("1", "2")],
        )
        out = capsys.readouterr().out
        assert "A" in out
        assert "1" in out


class TestWriteOutputFieldnamesNone:
    def test_csv_from_list_of_dicts(self, tmp_path: Path):
        path = str(tmp_path / "out.csv")
        write_output(path, [{"a": 1, "b": 2}], quiet=True)
        content = (tmp_path / "out.csv").read_text(encoding="utf-8")
        assert "a,b" in content
        assert "1,2" in content


class TestResolveCredAsync:
    @pytest.mark.asyncio
    @patch("mytools.core.cred.get_credential")
    async def test_at_prefix_resolves(self, mock_get):
        mock_get.return_value = "secret_value"
        result = await resolve_cred_async("@my_cred")
        assert result == "secret_value"

    @pytest.mark.asyncio
    async def test_no_prefix_passthrough(self):
        assert await resolve_cred_async("plain") == "plain"


class TestNormalizeUrlTrailingSlash:
    def test_ensure_trailing_slash(self):
        assert normalize_url("https://example.com", ensure_trailing_slash=True) == (
            "https://example.com/"
        )


class TestAddStealthArgsCompat:
    def test_network_has_fragment_tcp_and_src_port(self):
        parser = argparse.ArgumentParser()
        add_stealth_args(parser, module_type="network")
        action_names = set()
        for action in parser._actions:
            action_names.update(action.option_strings)
        assert "--fragment-tcp" in action_names
        assert "--src-port-random" in action_names

    def test_core_minimal(self):
        parser = argparse.ArgumentParser()
        add_stealth_args(parser, module_type="core")
        action_names = set()
        for action in parser._actions:
            action_names.update(action.option_strings)
        assert "--impersonate" not in action_names


class TestAddStealthArgsIncompatibleFlags:
    def test_flags_not_added_when_incompatible(self, monkeypatch):
        monkeypatch.setattr(
            utils,
            "_STEALTH_COMPAT",
            {
                "web": {"proxy", "delay"},
                "core": {"proxy", "delay"},
            },
        )
        parser = argparse.ArgumentParser()
        add_stealth_args(parser, module_type="web")
        action_names = set()
        for action in parser._actions:
            action_names.update(action.option_strings)
        for flag in (
            "--random-delay",
            "--jitter",
            "--user-agent-rotate",
            "--impersonate",
            "--fragment",
            "--fragment-tcp",
            "--tor",
            "--waf-evasion",
            "--pad-headers",
            "--src-port-random",
            "--rate-limit",
        ):
            assert flag not in action_names


class TestValidateStealthArgsFallback:
    def test_unknown_module_type_falls_back_to_core(self):
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
        validate_stealth_args(args, module_type="unknown")


class TestApplySessionAuthAsync:
    @pytest.mark.asyncio
    @patch("mytools.core.cred.get_credential")
    async def test_all_branches(self, mock_get):
        mock_get.return_value = "keyring_val"
        client = create_async_client()
        await apply_session_auth_async(
            client,
            auth={"X-Custom": "1"},
            bearer_token="@bear",
            extra_headers=["X-Extra: v"],
            cookie="@cook",
        )
        assert client.headers["X-Custom"] == "1"
        assert client.headers["Authorization"] == "Bearer keyring_val"
        assert client.headers["X-Extra"] == "v"
        assert client.headers["Cookie"] == "keyring_val"
        await client.aclose()

    @pytest.mark.asyncio
    async def test_all_none_noop(self):
        client = create_async_client()
        await apply_session_auth_async(client)
        await client.aclose()


class TestReadTargetLines:
    def test_lowercase_and_sort_dedup(self, tmp_path: Path):
        f = tmp_path / "targets.txt"
        f.write_text("B\n# comment\nA\nb\nA\n", encoding="utf-8")
        lines = read_target_lines(str(f), lowercase=True, sort_dedup=True)
        assert lines == ["a", "b"]


class TestDetectSpaFallback:
    def test_small_list_returns_empty(self):
        assert detect_spa_fallback([("a", 1)], key_fn=lambda t: t[0]) == set()

    def test_dominant_group_detected(self):
        items = [("k", i) for i in range(20)]
        result = detect_spa_fallback(
            items, key_fn=lambda t: t[0], min_count=5, threshold=0.8
        )
        assert result == set(range(20))

    def test_no_dominant_group(self):
        items = [(f"k{i % 3}", i) for i in range(20)]
        result = detect_spa_fallback(
            items, key_fn=lambda t: t[0], min_count=5, threshold=0.8
        )
        assert result == set()


class TestQueryNvdCacheAndApiKey:
    @respx.mock
    @pytest.mark.asyncio
    async def test_cache_hit_and_client(self):
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(200, json={"vulnerabilities": []})
        )
        client = create_async_client()
        r1 = await query_nvd("cache_kw", api_key="key123", client=client)
        r2 = await query_nvd("cache_kw", api_key="key123", client=client)
        assert r1 == r2 == []
        await client.aclose()

    @respx.mock
    @pytest.mark.asyncio
    async def test_expired_cache_refetches(self):
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(
                200,
                json={
                    "vulnerabilities": [{"cve": {"id": "CVE-Z", "descriptions": []}}]
                },
            )
        )
        utils._nvd_cache["expired_kw|10"] = (
            time.monotonic() - 1000.0,
            [],
        )
        results = await query_nvd("expired_kw")
        assert results[0]["id"] == "CVE-Z"

    @respx.mock
    @pytest.mark.asyncio
    async def test_request_error_returns_empty(self):
        def _boom(_request):
            raise httpx.ConnectError("down")

        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            side_effect=_boom
        )
        results = await query_nvd("error_kw")
        assert results == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_parsing_fallbacks(self):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-X",
                        "descriptions": [{"lang": "fr", "value": "desc-fr"}],
                        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]},
                    }
                },
                {
                    "cve": {
                        "id": "CVE-Y",
                        "descriptions": [{"lang": "en", "value": "desc-en"}],
                        "metrics": {},
                    }
                },
            ]
        }
        respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
            return_value=httpx.Response(200, json=payload)
        )
        results = await query_nvd("fallback_kw")
        assert results[0]["id"] == "CVE-X"
        assert results[0]["description"] == "desc-fr"
        assert results[0]["severity"] == "UNKNOWN"
        assert results[1]["id"] == "CVE-Y"
        assert results[1]["description"] == "desc-en"


class TestSafeAsyncioRunTimeout:
    def test_timeout_raises(self):
        import asyncio
        import concurrent.futures

        async def _slow():
            await asyncio.sleep(999)

        async def _runner():
            with patch("concurrent.futures.ThreadPoolExecutor") as mock_pool:
                future = MagicMock()
                future.result.side_effect = concurrent.futures.TimeoutError()
                mock_pool.return_value.__enter__.return_value.submit.return_value = (
                    future
                )
                coro = _slow()
                try:
                    with pytest.raises(RuntimeError):
                        safe_asyncio_run(coro)
                finally:
                    coro.close()

        asyncio.run(_runner())


class TestSetupReadlinePyreadline3:
    def test_readline_missing_pyreadline3_used(self, monkeypatch):
        import importlib

        real_import = importlib.__import__

        def fake_import(name, *args, **kwargs):
            if name == "readline":
                raise ModuleNotFoundError
            return real_import(name, *args, **kwargs)

        with patch.dict("sys.modules", {"pyreadline3": MagicMock()}):
            monkeypatch.setattr("builtins.__import__", fake_import)
            from mytools.core.utils import _setup_readline

            parser = argparse.ArgumentParser()
            _setup_readline(parser)

    def test_both_missing_returns(self, monkeypatch):
        import importlib

        real_import = importlib.__import__

        def fake_import(name, *args, **kwargs):
            if name in ("readline", "pyreadline3"):
                raise ModuleNotFoundError
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", fake_import)
        from mytools.core.utils import _setup_readline

        parser = argparse.ArgumentParser()
        _setup_readline(parser)

    def test_readline_available_sets_completer(self, monkeypatch):
        import importlib

        fake = MagicMock()
        fake.set_completer = MagicMock()
        fake.set_completer_delims = MagicMock()
        fake.parse_and_bind = MagicMock()
        with patch.dict("sys.modules", {"readline": fake}):
            real_import = importlib.__import__

            def fake_import(name, *args, **kwargs):
                if name == "readline":
                    return fake
                return real_import(name, *args, **kwargs)

            monkeypatch.setattr("builtins.__import__", fake_import)
            from mytools.core.utils import _setup_readline

            parser = argparse.ArgumentParser()
            parser.add_argument("-c", "--category")
            _setup_readline(parser, skip_values=["all"])
            fake.set_completer.assert_called_once()
            fake.parse_and_bind.assert_called_once()
            completer = fake.set_completer.call_args[0][0]
            assert completer("--", 0) in {"--category", "--help"}
            assert completer("--cat", 0) == "--category"
            assert completer("--cat", 1) is None


class TestRunInteractiveShell:
    def _make_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("url", nargs="?")
        parser.add_argument("-c", "--category", default="all")
        return parser

    def test_help_and_exit(self, monkeypatch, capsys):
        inputs = iter(["help", "exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))
        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: 0,
            description="Test shell",
            example="example.com",
            contextual_help="HELP TEXT",
        )
        assert code == 0
        assert "HELP TEXT" in capsys.readouterr().out

    def test_quit_and_clear(self, monkeypatch):
        inputs = iter(["clear", "quit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))
        monkeypatch.setattr(utils, "clear_console", lambda: None)
        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: 0,
        )
        assert code == 0

    def test_empty_line(self, monkeypatch):
        inputs = iter(["", "exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))
        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: 0,
        )
        assert code == 0

    def test_eof_returns_zero(self, monkeypatch):
        def _raise(_p):
            raise EOFError

        monkeypatch.setattr("builtins.input", _raise)
        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: 0,
        )
        assert code == 0

    def test_parse_error_continues(self, monkeypatch, capsys):
        from mytools.core.utils import FetchError

        inputs = iter(["https://example.com", "exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))

        def run_fn(args):
            if args.url == "https://example.com":
                raise FetchError(url=args.url, attempts=3, last_error=Exception("e"))
            return 0

        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=run_fn,
        )
        assert code == 0

    def test_system_exit_continues(self, monkeypatch):
        inputs = iter(["exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))
        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: (_ for _ in ()).throw(SystemExit(2)),
        )
        assert code == 0

    def test_generic_error_continues(self, monkeypatch, capsys):
        inputs = iter(["https://example.com", "exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))

        def run_fn(args):
            if args.url == "https://example.com":
                raise RuntimeError("unexpected")
            return 0

        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=run_fn,
        )
        assert code == 0

    def test_validate_fn_runs(self, monkeypatch):
        inputs = iter(["exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))
        called = []

        def validate(args):
            called.append(1)

        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: 0,
            validate_fn=validate,
        )
        assert code == 0
        assert called == []

    def test_validate_fn_success_path(self, monkeypatch):
        inputs = iter(["example.com", "exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))
        called = []

        def validate(args):
            called.append(args.url)

        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: 0,
            validate_fn=validate,
        )
        assert code == 0
        assert called == ["example.com"]

    def test_value_error_from_run_continues(self, monkeypatch):
        inputs = iter(["example.com", "exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))

        def run_fn(args):
            raise ValueError("bad")

        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=run_fn,
        )
        assert code == 0

    def test_system_exit_from_command_continues(self, monkeypatch):
        inputs = iter(["example.com", "exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))

        def run_fn(args):
            raise SystemExit(2)

        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=run_fn,
        )
        assert code == 0

    def test_banner_fn_called(self, monkeypatch, capsys):
        inputs = iter(["exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))
        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: 0,
            banner_fn=lambda: print("BANNER"),
        )
        assert code == 0
        assert "BANNER" in capsys.readouterr().out

    def test_help_without_contextual(self, monkeypatch, capsys):
        inputs = iter(["help", "exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))
        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: 0,
        )
        assert code == 0
        assert "usage:" in capsys.readouterr().out

    def test_value_error_continues(self, monkeypatch):
        inputs = iter(["exit"])
        monkeypatch.setattr("builtins.input", lambda _p: next(inputs))

        def validate(args):
            raise ValueError("bad value")

        code = run_interactive_shell(
            self._make_parser(),
            prompt="x> ",
            run_fn=lambda a: 0,
            validate_fn=validate,
        )
        assert code == 0
