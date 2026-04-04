"""Base agent — NATS client with event subscription and tool calling."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

import msgspec
import nats
from nats.aio.client import Client as NATSClient

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Base class for Veronica agents.

    Subclasses set subscribed_events and implement on_event.
    """

    subscribed_events: list[str] = []

    def __init__(self, agent_id: str, nats_url: str = "nats://localhost:4222"):
        self.agent_id = agent_id
        self.nats_url = nats_url
        self._nc: NATSClient | None = None
        self._js = None

    @abstractmethod
    async def on_event(self, subject: str, data: dict) -> None:
        """Called when a subscribed event arrives. Use self.call_tool() for daemon tools."""

    async def call_tool(self, tool_name: str, payload: dict) -> dict:
        """Call a daemon tool via NATS request/reply."""
        data = msgspec.json.encode(payload)
        resp = await self._nc.request(f"tools.{tool_name}", data, timeout=30)
        return msgspec.json.decode(resp.data, type=dict)

    async def kv_get(self, bucket: str, key: str) -> dict | None:
        """Read from a NATS KV bucket."""
        kv = await self._js.key_value(bucket)
        try:
            entry = await kv.get(key)
            return msgspec.json.decode(entry.value, type=dict)
        except Exception:
            return None

    async def kv_put(self, bucket: str, key: str, value: dict) -> None:
        """Write to a NATS KV bucket."""
        kv = await self._js.key_value(bucket)
        await kv.put(key, msgspec.json.encode(value))

    async def kv_keys(self, bucket: str) -> list[str]:
        """List all keys in a NATS KV bucket."""
        kv = await self._js.key_value(bucket)
        return await kv.keys()

    async def run(self) -> None:
        """Connect to NATS and listen for events."""
        self._nc = await nats.connect(self.nats_url)
        self._js = self._nc.jetstream()

        logger.info("agent %s connected to %s", self.agent_id, self.nats_url)

        for event_type in self.subscribed_events:
            subject = f"events.{event_type}"
            await self._nc.subscribe(subject, cb=self._handle_message)
            logger.info("agent %s subscribed to %s", self.agent_id, subject)

        # Block until cancelled
        stop = asyncio.Event()
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass

    async def _handle_message(self, msg) -> None:
        subject = msg.subject
        data = msgspec.json.decode(msg.data, type=dict)
        logger.info("agent %s received %s: %s", self.agent_id, subject, data.get("resource", ""))
        await self.on_event(subject, data)

    async def close(self) -> None:
        """Disconnect from NATS."""
        if self._nc:
            await self._nc.close()
