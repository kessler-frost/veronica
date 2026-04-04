"""Base agent — Agno-powered with NATS tool calling."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

import msgspec
import nats
from agno.agent import Agent
from agno.models.lmstudio import LMStudio
from nats.aio.client import Client as NATSClient

logger = logging.getLogger(__name__)

BASE_SYSTEM_PROMPT = """You are Veronica, an eBPF intelligence layer embedded in a Linux OS.
You observe kernel events and can enforce policies, transform traffic,
schedule processes, and measure performance — all at kernel speed via eBPF.

You receive notifications when events matching your subscriptions occur.
Check in-flight tasks to avoid duplicate work. Act decisively when needed.

If nothing needs action, respond with just: "no action needed"
"""


class BaseAgent(ABC):
    """Base class for Veronica agents. Uses Agno for the LLM loop."""

    subscribed_events: list[str] = []

    def __init__(
        self,
        agent_id: str,
        nats_url: str = "nats://localhost:4222",
        llm_base_url: str = "http://localhost:1234",
        llm_model: str = "",
    ):
        self.agent_id = agent_id
        self.nats_url = nats_url
        self._llm_base_url = llm_base_url
        self._llm_model = llm_model
        self._nc: NATSClient | None = None
        self._js = None

    async def _call_nats_tool(self, tool_name: str, payload: dict) -> dict:
        """Call a daemon tool via NATS request/reply."""
        data = msgspec.json.encode(payload)
        resp = await self._nc.request(f"tools.{tool_name}", data, timeout=30)
        return msgspec.json.decode(resp.data, type=dict)

    async def _kv_get(self, bucket: str, key: str) -> dict | None:
        kv = await self._js.key_value(bucket)
        try:
            entry = await kv.get(key)
            return msgspec.json.decode(entry.value, type=dict)
        except Exception:
            return None

    async def _kv_put(self, bucket: str, key: str, value: dict) -> None:
        kv = await self._js.key_value(bucket)
        await kv.put(key, msgspec.json.encode(value))

    async def _kv_keys(self, bucket: str) -> list[str]:
        kv = await self._js.key_value(bucket)
        try:
            return await kv.keys()
        except Exception:
            return []

    def _build_agno_agent(self, context_append: str = "") -> Agent:
        """Build an Agno Agent with NATS-backed tools."""
        instructions = BASE_SYSTEM_PROMPT
        if context_append:
            instructions += f"\nYour specific focus: {context_append}"

        async def exec_command(command: str, reason: str = "") -> str:
            """Run a shell command in the VM. Use for file ops, package installs, service management."""
            result = await self._call_nats_tool("exec", {"command": command, "reason": reason})
            return result.get("data", result.get("error", str(result)))

        async def enforce(hook: str, target: str, action: str, reason: str = "") -> str:
            """Block or allow access via eBPF LSM or XDP. Use for security enforcement."""
            result = await self._call_nats_tool("enforce", {"hook": hook, "target": target, "action": action, "reason": reason})
            return result.get("data", result.get("error", str(result)))

        async def transform(interface: str, match: str, rewrite: str, reason: str = "") -> str:
            """Rewrite packets or redirect traffic via XDP/TC."""
            result = await self._call_nats_tool("transform", {"interface": interface, "match": match, "rewrite": rewrite, "reason": reason})
            return result.get("data", result.get("error", str(result)))

        async def schedule(target: str, priority: str, reason: str = "") -> str:
            """Set CPU scheduling priority for a process or cgroup via sched_ext."""
            result = await self._call_nats_tool("schedule", {"target": target, "priority": priority, "reason": reason})
            return result.get("data", result.get("error", str(result)))

        async def measure(target: str, metric: str, duration: str = "5s") -> str:
            """Read performance counters for a process."""
            result = await self._call_nats_tool("measure", {"target": target, "metric": metric, "duration": duration})
            return result.get("data", result.get("error", str(result)))

        async def kv_get(bucket: str, key: str) -> str:
            """Read a value from shared state."""
            result = await self._kv_get(bucket, key)
            return str(result)

        async def kv_put(bucket: str, key: str, value: str) -> str:
            """Write a value to shared state. Value should be a JSON string."""
            await self._kv_put(bucket, key, msgspec.json.decode(value.encode(), type=dict))
            return "ok"

        async def kv_keys(bucket: str) -> str:
            """List all keys in a shared state bucket."""
            keys = await self._kv_keys(bucket)
            return str(keys)

        model = LMStudio(id=self._llm_model, base_url=self._llm_base_url)

        return Agent(
            model=model,
            instructions=instructions,
            tools=[exec_command, enforce, transform, schedule, measure, kv_get, kv_put, kv_keys],
            telemetry=False,
        )

    @abstractmethod
    def get_context_append(self) -> str:
        """Return per-agent context to append to the system prompt."""

    async def _handle_event(self, subject: str, raw_data: bytes) -> None:
        """Handle an incoming event using Agno agent loop."""
        event_context = raw_data.decode("utf-8")

        logger.info("agent %s received %s", self.agent_id, subject)

        agent = self._build_agno_agent(self.get_context_append())
        response = await agent.arun(f"eBPF event on {subject}:\n{event_context}")

        content = response.content if response else "no response"
        logger.info("[%s] response: %s", self.agent_id, str(content)[:200])

    async def run(self) -> None:
        """Connect to NATS and listen for events."""
        self._nc = await nats.connect(self.nats_url)
        self._js = self._nc.jetstream()

        logger.info("agent %s connected to %s", self.agent_id, self.nats_url)

        async def _on_msg(msg):
            asyncio.create_task(self._handle_event(msg.subject, msg.data))

        for event_type in self.subscribed_events:
            subject = f"events.{event_type}"
            await self._nc.subscribe(subject, cb=_on_msg)
            logger.info("agent %s subscribed to %s", self.agent_id, subject)

        stop = asyncio.Event()
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass

    async def close(self) -> None:
        if self._nc:
            await self._nc.close()
