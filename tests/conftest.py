import argparse
import asyncio
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from reconall import _get_parser_defaults
from utils import create_async_client


@pytest.fixture(scope="session")
def base_ns():
    """Namespace base com defaults de todos os modulos, construido uma vez por sessao."""
    defaults = _get_parser_defaults()
    defaults.update({
        "output": None,
        "quiet": True,
        "log_file": None,
        "color": None,
        "verbose": 0,
        "timeout": 10,
        "dry_run": False,
        "output_dir": None,
        "user_agent": "MyTools/test",
        "verify": False,
        "threads": None,
        "auth": None,
        "bearer_token": None,
        "cookie": None,
        "header": None,
    })
    return argparse.Namespace(**defaults)


@pytest.fixture(autouse=True)
def _fast_sleep(monkeypatch, request):
    """Mock asyncio.sleep para testes rodarem instantaneamente.

    Testes marcados com @pytest.mark.real_sleep usam asyncio.sleep real.
    """
    if request.node.get_closest_marker("real_sleep"):
        yield
        return
    monkeypatch.setattr(asyncio, "sleep", AsyncMock())
    yield


@pytest_asyncio.fixture
async def async_client():
    """Fixture async que fornece um httpx.AsyncClient e garante aclose."""
    client = create_async_client(user_agent="TestAgent/1.0")
    yield client
    await client.aclose()
