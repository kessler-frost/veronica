"""tests/test_opencode.py"""

import pytest

from veronica.opencode import OpenCodeClient


def test_client_init():
    client = OpenCodeClient(base_url="http://localhost:4096")
    assert client.base_url == "http://localhost:4096"


def test_client_with_directory():
    client = OpenCodeClient(base_url="http://localhost:4096", directory="/tmp/project")
    assert client._headers["X-OpenCode-Directory"] == "/tmp/project"


@pytest.mark.asyncio
async def test_client_health_fails_when_not_running():
    client = OpenCodeClient(base_url="http://localhost:19999")
    with pytest.raises(Exception):
        await client.health()
