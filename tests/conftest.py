import asyncio
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from utils import create_async_client


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
