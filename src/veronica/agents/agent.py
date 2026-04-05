"""Single Veronica agent — accumulates behaviors from veronica add."""

from __future__ import annotations

import asyncio
import logging

import msgspec
import nats
from agno.agent import Agent
from nats.aio.client import Client as NATSClient

from veronica.config import VeronicaConfig

logger = logging.getLogger(__name__)

VALID_EVENTS = frozenset({"process_exec", "process_exit", "net_connect", "file_open"})

BASE_SYSTEM_PROMPT = """You are an autonomous eBPF agent embedded in a Linux OS. You observe kernel events and act on them by calling tools. You never ask questions or explain — you just act.

ALWAYS follow this loop:
1. You receive kernel events describing what happened.
2. Call exec_command one or more times to take action.
3. Call final_answer with a short summary when done.

NEVER just investigate (ls, cat) without following up with real action. If you see a new directory was created, scaffold it. If you see a crash, fix it. If you see something suspicious, enforce a policy.

If a tool or dependency is missing, install it yourself and continue with the original task.

You run as root.
"""

DEBOUNCE_WINDOW = 2.0


class VeronicaAgent:
    """Single agent that accumulates behaviors and subscribes to events dynamically."""

    def __init__(self, cfg: VeronicaConfig | None = None, nats_url: str = "nats://localhost:4222", model=None):
        self._cfg = cfg or VeronicaConfig()
        self.nats_url = nats_url
        self._model = model or self._cfg.build_model()
        self._nc: NATSClient | None = None
        self._js = None
        self._subs: list = []
        self._event_buffer: list[dict] = []
        self._debounce_task: asyncio.Task | None = None
        self._processing: bool = False

    async def _load_config(self) -> dict:
        """Load agent config from NATS KV."""
        kv = await self._js.key_value("agents")
        entry = await kv.get("veronica")
        return msgspec.json.decode(entry.value, type=dict)

    async def _save_config(self, config: dict) -> None:
        """Save agent config to NATS KV."""
        kv = await self._js.key_value("agents")
        await kv.put("veronica", msgspec.json.encode(config))

    def _build_prompt(self, behaviors: list[str]) -> str:
        """Build system prompt from base + accumulated behaviors."""
        prompt = BASE_SYSTEM_PROMPT
        if behaviors:
            prompt += "\nYour behaviors:\n"
            for b in behaviors:
                prompt += f"- {b}\n"
        return prompt

    async def _call_nats_tool(self, tool_name: str, payload: dict) -> dict:
        data = msgspec.json.encode(payload)
        resp = await self._nc.request(f"tools.{tool_name}", data, timeout=30)
        return msgspec.json.decode(resp.data, type=dict)

    async def _kv_get(self, bucket: str, key: str) -> dict | None:
        try:
            kv = await self._js.key_value(bucket)
            entry = await kv.get(key)
            return msgspec.json.decode(entry.value, type=dict)
        except Exception:
            return None

    async def _kv_put(self, bucket: str, key: str, value: dict) -> None:
        kv = await self._js.key_value(bucket)
        await kv.put(key, msgspec.json.encode(value))

    async def _kv_keys(self, bucket: str) -> list[str]:
        try:
            kv = await self._js.key_value(bucket)
            return await kv.keys()
        except Exception:
            return []

    def _build_agno_agent(self, behaviors: list[str]) -> Agent:
        """Build Agno agent with tools and behavior-aware prompt."""
        instructions = self._build_prompt(behaviors)

        async def exec_command(command: str, reason: str = "") -> str:
            """Run a shell command in the VM. Use for file ops, package installs, service management."""
            logger.info("[veronica] TOOL exec_command: %s (%s)", command[:200], reason)
            result = await self._call_nats_tool("exec", {"command": command, "reason": reason})
            output = result.get("data", result.get("error", str(result)))
            logger.info("[veronica] TOOL exec_command result: %s", output[:200])
            return output

        async def enforce(hook: str, target: str, action: str, reason: str = "") -> str:
            """Block or allow access. hook: file_open/xdp_drop/socket_connect. action: deny/allow."""
            result = await self._call_nats_tool("enforce", {"hook": hook, "target": target, "action": action, "reason": reason})
            return result.get("data", result.get("error", str(result)))

        async def transform(interface: str, match: str, rewrite: str, reason: str = "") -> str:
            """Rewrite packets or redirect traffic."""
            result = await self._call_nats_tool("transform", {"interface": interface, "match": match, "rewrite": rewrite, "reason": reason})
            return result.get("data", result.get("error", str(result)))

        async def schedule(target: str, priority: str, reason: str = "") -> str:
            """Set CPU priority for a PID. priority: latency-sensitive/batch/normal."""
            result = await self._call_nats_tool("schedule", {"target": target, "priority": priority, "reason": reason})
            return result.get("data", result.get("error", str(result)))

        async def measure(target: str, metric: str, duration: str = "5s") -> str:
            """Read performance counters. metric: cache_misses/cycles/bandwidth/io."""
            result = await self._call_nats_tool("measure", {"target": target, "metric": metric, "duration": duration})
            return result.get("data", result.get("error", str(result)))

        async def kv_get(bucket: str, key: str) -> str:
            """Read from shared state. Buckets: agents, tasks, policies, logs."""
            result = await self._kv_get(bucket, key)
            return str(result)

        async def kv_put(bucket: str, key: str, value: str) -> str:
            """Write to shared state. Value should be a JSON string."""
            await self._kv_put(bucket, key, msgspec.json.decode(value.encode(), type=dict))
            return "ok"

        async def kv_keys(bucket: str) -> str:
            """List keys in a shared state bucket."""
            keys = await self._kv_keys(bucket)
            return str(keys)

        async def subscribe(event_types: list[str]) -> str:
            """Set which eBPF event types you receive. Replaces current subscriptions entirely. Valid: process_exec, process_exit, file_open, net_connect."""
            invalid = set(event_types) - VALID_EVENTS
            if invalid:
                return f"invalid event types: {invalid}"
            await self._update_subscriptions(event_types)
            return f"subscribed to {event_types}"

        async def final_answer(summary: str) -> str:
            """Call when done acting. Provide a short summary or 'no action needed'."""
            logger.info("[veronica] TOOL final_answer: %s", summary[:200])
            return summary

        return Agent(
            model=self._model,
            instructions=instructions,
            tools=[exec_command, enforce, transform, schedule, measure, kv_get, kv_put, kv_keys, subscribe, final_answer],
            telemetry=False,
            retries=3,
            delay_between_retries=2,
        )

    def _semantic_key(self, event: dict) -> str:
        """Extract a semantic task key from an event."""
        data = event.get("data", {})
        comm = data.get("comm", "")
        cmdline = data.get("cmdline", "")
        daddr = data.get("daddr", "")
        dport = data.get("dport", "")

        parts = cmdline.split()
        for part in reversed(parts):
            if part.startswith("/"):
                return f"veronica.path.{part}".replace(":", "-").replace("/", "_")

        if daddr:
            return f"veronica.net.{daddr}-{dport}".replace(":", "-")

        if comm:
            return f"veronica.service.{comm}".replace(":", "-")

        resource = event.get("resource", "unknown")
        return f"veronica.{resource}".replace(":", "-").replace("/", "_")

    async def _on_event(self, msg) -> None:
        """Buffer incoming events and debounce."""
        event = msgspec.json.decode(msg.data, type=dict)
        event["_subject"] = msg.subject

        key = self._semantic_key(event)
        if any(self._semantic_key(e) == key for e in self._event_buffer):
            return

        self._event_buffer.append(event)
        if len(self._event_buffer) > 20:
            self._event_buffer = self._event_buffer[-20:]

        if self._processing:
            return

        if self._debounce_task and not self._debounce_task.done():
            self._debounce_task.cancel()
        self._debounce_task = asyncio.create_task(self._flush_after_delay())

    async def _flush_after_delay(self) -> None:
        await asyncio.sleep(DEBOUNCE_WINDOW)
        await self._process_batch()

    async def _process_batch(self) -> None:
        self._processing = True
        events = self._event_buffer
        self._event_buffer = []

        if not events:
            self._processing = False
            return

        unique_events: dict[str, list[dict]] = {}
        for event in events:
            key = self._semantic_key(event)
            existing = await self._kv_get("tasks", key)
            if existing and existing.get("status") == "in_progress":
                continue
            unique_events.setdefault(key, []).append(event)

        if not unique_events:
            self._processing = False
            return

        max_batch = 5
        if len(unique_events) > max_batch:
            keys = list(unique_events.keys())[-max_batch:]
            unique_events = {k: unique_events[k] for k in keys}

        batch_lines = [f"Batch of {len(events)} eBPF events ({len(unique_events)} unique actions):"]
        for key, group in unique_events.items():
            first = group[0]
            data = first.get("data", {})
            batch_lines.append(
                f"  [{first.get('_subject', '')}] {data.get('comm', '')} "
                f"{data.get('cmdline', data.get('daddr', ''))} "
                f"(x{len(group)} events)"
            )
        batch_context = "\n".join(batch_lines)

        for key in unique_events:
            await self._kv_put("tasks", key, {"status": "in_progress"})

        logger.info("processing batch: %d events → %d unique actions", len(events), len(unique_events))

        config = await self._load_config()
        behaviors = config.get("behaviors", [])

        agent = self._build_agno_agent(behaviors)
        response = await agent.arun(batch_context)

        content = response.content if response else "no response"
        logger.info("[veronica] response: %s", str(content)[:200])

        for key in unique_events:
            await self._kv_put("tasks", key, {"status": "done", "result": str(content)[:500]})

        self._processing = False

        if self._event_buffer:
            self._debounce_task = asyncio.create_task(self._flush_after_delay())

    async def _update_subscriptions(self, event_types: list[str]) -> None:
        """Hot-swap NATS subscriptions and persist to KV."""
        # Unsubscribe from all current
        for sub in self._subs:
            await sub.unsubscribe()
        self._subs.clear()

        # Subscribe to new
        for event_type in event_types:
            sub = await self._nc.subscribe(f"events.{event_type}", cb=self._on_event)
            self._subs.append(sub)
            logger.info("subscribed to events.%s", event_type)

        # Persist
        config = await self._load_config()
        config["subscriptions"] = event_types
        await self._save_config(config)

    async def run(self) -> None:
        """Connect to NATS, load config, subscribe to events, and run forever."""
        self._nc = await nats.connect(self.nats_url)
        self._js = self._nc.jetstream()

        logger.info("veronica agent connected to %s", self.nats_url)

        config = await self._load_config()
        behaviors = config.get("behaviors", [])
        subscriptions = config.get("subscriptions", [])

        logger.info("loaded %d behaviors, subscriptions: %s", len(behaviors), subscriptions)
        for b in behaviors:
            logger.info("  behavior: %s", b)

        for event_type in subscriptions:
            sub = await self._nc.subscribe(f"events.{event_type}", cb=self._on_event)
            self._subs.append(sub)
            logger.info("subscribed to events.%s", event_type)

        stop = asyncio.Event()
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass

    async def close(self) -> None:
        for sub in self._subs:
            await sub.unsubscribe()
        if self._nc:
            await self._nc.close()
