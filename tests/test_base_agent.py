"""tests/test_base_agent.py"""

import asyncio
import json

import pytest
import websockets

from veronica.agents.base import BaseAgent
from veronica.protocol.messages import EventData


class EchoAgent(BaseAgent):
    """Test agent that echoes events back via a tool call."""
    subscribed_events = ["process_exec"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handled_events = []
        self.last_result = None

    async def handle_event(self, session: str, event: EventData) -> None:
        self.handled_events.append(event)
        result = await self.call_tool(session, "echo", {"msg": event.resource})
        self.last_result = result


async def mock_daemon(host, port, ready, exchange_done):
    """Mock daemon: accept one agent connection, send one event, handle tool call."""
    async def handler(ws):
        sub = json.loads(await ws.recv())
        assert sub["type"] == "subscribe"
        assert sub["agent_id"] == "test-echo"

        await ws.send(json.dumps({
            "type": "event",
            "session": "sess-1",
            "event": {
                "type": "process_exec",
                "resource": "pid:42",
                "data": {"comm": "ls"},
                "timestamp": "2026-04-04T12:00:00Z",
            },
        }))

        tc = json.loads(await ws.recv())
        assert tc["type"] == "tool_call"
        assert tc["session"] == "sess-1"
        assert tc["name"] == "echo"

        await ws.send(json.dumps({
            "type": "tool_result",
            "session": "sess-1",
            "call_id": tc["call_id"],
            "result": {"ok": True, "data": "echo: pid:42"},
        }))

        done = json.loads(await ws.recv())
        assert done["type"] == "session_done"
        assert done["session"] == "sess-1"

        exchange_done.set()
        await ws.close()

    server = await websockets.serve(handler, host, port)
    ready.set()
    await exchange_done.wait()
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_base_agent_connects_and_handles_event():
    ready = asyncio.Event()
    exchange_done = asyncio.Event()
    daemon_task = asyncio.create_task(mock_daemon("127.0.0.1", 19090, ready, exchange_done))
    await ready.wait()

    agent = EchoAgent(agent_id="test-echo", daemon_url="ws://127.0.0.1:19090")
    agent_task = asyncio.create_task(agent.run())

    await asyncio.wait_for(exchange_done.wait(), timeout=5.0)
    # Give the agent task a moment to finish processing the session
    await asyncio.sleep(0.1)

    assert len(agent.handled_events) == 1
    assert agent.handled_events[0].resource == "pid:42"
    assert agent.last_result == {"ok": True, "data": "echo: pid:42"}

    agent_task.cancel()
    daemon_task.cancel()
