"""Base agent class — WebSocket client with session handling."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from itertools import count

import msgspec
import websockets

from veronica.protocol.messages import (
    Event,
    EventData,
    SessionDone,
    Subscribe,
    ToolCall,
    ToolResult,
)

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Base class for Veronica host agents.

    Subclasses declare event subscriptions and implement handle_event.
    The base class manages the WebSocket connection and session multiplexing.
    """

    agent_id: str
    subscribed_events: list[str]

    def __init__(self, agent_id: str, daemon_url: str = "ws://localhost:9090/ws"):
        self.agent_id = agent_id
        self.daemon_url = daemon_url
        self._call_counter = count(1)
        self._pending: dict[str, asyncio.Future[dict]] = {}
        self._ws: websockets.ClientConnection | None = None

    @abstractmethod
    async def handle_event(self, session: str, event: EventData) -> None:
        """Process an event. Use self.call_tool() for daemon tools."""

    async def call_tool(self, session: str, name: str, args: dict) -> dict:
        """Call a daemon tool and wait for the result."""
        call_id = str(next(self._call_counter))
        msg = ToolCall(session=session, call_id=call_id, name=name, args=args)

        future: asyncio.Future[dict] = asyncio.get_event_loop().create_future()
        self._pending[call_id] = future

        await self._send(msg)
        return await future

    async def run(self) -> None:
        """Connect to daemon and process events."""
        async for ws in websockets.connect(self.daemon_url):
            self._ws = ws
            logger.info("agent %s connected to %s", self.agent_id, self.daemon_url)

            sub = Subscribe(agent_id=self.agent_id, events=self.subscribed_events)
            await self._send(sub)

            await self._read_loop(ws)
            logger.warning("agent %s disconnected, reconnecting...", self.agent_id)

    async def _read_loop(self, ws: websockets.ClientConnection) -> None:
        async for raw in ws:
            data = raw if isinstance(raw, bytes) else raw.encode()
            base = msgspec.json.decode(data, type=dict)
            msg_type = base.get("type")

            if msg_type == "event":
                event = msgspec.json.decode(data, type=Event)
                asyncio.create_task(self._handle_session(event.session, event.event))

            elif msg_type == "tool_result":
                result = msgspec.json.decode(data, type=ToolResult)
                future = self._pending.pop(result.call_id, None)
                if future and not future.done():
                    future.set_result(result.result)

    async def _handle_session(self, session: str, event: EventData) -> None:
        logger.info("session %s: %s on %s", session, event.type, event.resource)
        await self.handle_event(session, event)
        await self._send(SessionDone(session=session))
        logger.info("session %s: done", session)

    async def _send(self, msg: msgspec.Struct) -> None:
        if self._ws:
            await self._ws.send(msgspec.json.encode(msg))
