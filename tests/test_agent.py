"""tests/test_agent.py"""

import asyncio

import msgspec
import nats as nats_client
import pytest

from veronica.agents.base import BaseAgent


class EchoAgent(BaseAgent):
    subscribed_events = ["process_exec"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received: list[bytes] = []
        self.last_result = None

    def get_context_append(self) -> str:
        return "Echo test agent."

    async def _handle_event(self, subject: str, raw_data: bytes) -> None:
        self.received.append(raw_data)
        result = await self._call_nats_tool("exec", {"command": "echo hello", "reason": "test"})
        self.last_result = result


@pytest.mark.asyncio
async def test_agent_call_tool():
    """Test that _call_nats_tool sends NATS request and receives response."""
    try:
        nc = await nats_client.connect("nats://localhost:4222")
    except Exception:
        pytest.skip("NATS server not running")

    # Mock tool responder
    async def handler(msg):
        resp = msgspec.json.encode({"ok": True, "data": "hello"})
        await msg.respond(resp)

    await nc.subscribe("tools.exec", cb=handler)

    agent = EchoAgent(agent_id="test-echo", nats_url="nats://localhost:4222")
    agent._nc = nc
    agent._js = nc.jetstream()

    result = await agent._call_nats_tool("exec", {"command": "echo hello", "reason": "test"})
    assert result["ok"] is True
    assert result["data"] == "hello"

    await nc.close()
