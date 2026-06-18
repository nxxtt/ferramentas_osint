from __future__ import annotations

import pytest_asyncio

from utils import create_async_client


@pytest_asyncio.fixture
async def async_client():
    """Fixture async que fornece um httpx.AsyncClient e garante aclose."""
    client = create_async_client(user_agent="TestAgent/1.0")
    yield client
    await client.aclose()
