"""Base agent — NATS client with event subscription and tool calling."""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod

import msgspec
import nats
from nats.aio.client import Client as NATSClient

from veronica.llm import LLMClient
from veronica.tools import TOOLS

logger = logging.getLogger(__name__)

BASE_SYSTEM_PROMPT = """You are Veronica, an eBPF intelligence layer embedded in a Linux OS.
You observe kernel events and can enforce policies, transform traffic,
schedule processes, and measure performance — all at kernel speed via eBPF.

You receive notifications when events matching your subscriptions occur.
Check in-flight tasks to avoid duplicate work. Act decisively when needed.

Available tools:
- exec: run a shell command in the VM
- enforce: block/allow via eBPF LSM or XDP
- transform: rewrite packets, redirect traffic via TC/XDP
- schedule: set CPU scheduling priority via sched_ext
- measure: read perf counters
- kv_get/kv_put/kv_keys: read/write shared state

If nothing needs action, respond with just: "no action needed"
"""


class BaseAgent(ABC):
    """Base class for Veronica agents.

    Subclasses set subscribed_events and implement on_event.
    """

    subscribed_events: list[str] = []

    def __init__(
        self,
        agent_id: str,
        nats_url: str = "nats://localhost:4222",
        llm_base_url: str = "http://localhost:1234",
        llm_model: str = "",
        llm_max_turns: int = 10,
    ):
        self.agent_id = agent_id
        self.nats_url = nats_url
        self._llm_base_url = llm_base_url
        self._llm_model = llm_model
        self._max_turns = llm_max_turns
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
        try:
            return await kv.keys()
        except Exception:
            return []

    async def _run_llm_loop(self, event_data: dict, context_append: str = "") -> str:
        """Run the LLM tool-calling loop. Returns final LLM response text."""
        llm = LLMClient(base_url=self._llm_base_url, model=self._llm_model)

        system = BASE_SYSTEM_PROMPT
        if context_append:
            system += f"\n\nYour specific focus: {context_append}"

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": f"eBPF event:\n{json.dumps(event_data, indent=2)}"},
        ]

        for turn in range(self._max_turns):
            response = await llm.chat(messages, tools=TOOLS)
            choice = response["choices"][0]
            msg = choice["message"]
            messages.append(msg)

            tool_calls = msg.get("tool_calls", [])
            if not tool_calls:
                await llm.close()
                return msg.get("content", "")

            for tc in tool_calls:
                name = tc["function"]["name"]
                args = json.loads(tc["function"]["arguments"])

                # KV tools are client-side (no daemon round-trip)
                if name == "kv_get":
                    result = await self.kv_get(args["bucket"], args["key"])
                elif name == "kv_put":
                    await self.kv_put(args["bucket"], args["key"], args["value"])
                    result = {"ok": True}
                elif name == "kv_keys":
                    result = await self.kv_keys(args["bucket"])
                else:
                    # Daemon tools via NATS request/reply
                    result = await self.call_tool(name, args)

                messages.append({
                    "role": "tool",
                    "content": json.dumps(result) if result is not None else "null",
                    "tool_call_id": tc["id"],
                })

        await llm.close()
        return "max turns exceeded"

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
