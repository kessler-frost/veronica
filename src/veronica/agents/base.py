"""Base agent — Agno-powered with NATS tool calling and event debouncing."""

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

BASE_SYSTEM_PROMPT = """/no_think
You are Veronica, an autonomous agent embedded in a Linux OS via eBPF.
You receive kernel events and MUST take immediate action using your tools. Do NOT explain — just call tools.

RULES:
1. ALWAYS call exec_command for every actionable event. Never describe — DO.
2. You run as root. Use that power.
3. If truly nothing to do: respond "no action needed"

Example — you see "mkdir /tmp/my-fastapi-app":
  → call exec_command("cd /tmp/my-fastapi-app && uv init && uv add fastapi uvicorn", "scaffold fastapi project")
  → call exec_command("cat > /tmp/my-fastapi-app/main.py << 'EOF'\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.get('/')\ndef root(): return {'hello': 'world'}\nEOF", "create main.py")
"""

DEBOUNCE_WINDOW = 2.0  # seconds to accumulate events before processing


class BaseAgent(ABC):
    """Base class for Veronica agents. Uses Agno for the LLM loop."""

    subscribed_events: list[str] = []

    def __init__(
        self,
        agent_id: str,
        nats_url: str = "nats://localhost:4222",
        llm_base_url: str = "http://localhost:1234",
        llm_model: str = "",
        llm_semaphore: asyncio.Semaphore | None = None,
        event_filter: dict | None = None,
    ):
        self.agent_id = agent_id
        self.nats_url = nats_url
        self._llm_base_url = llm_base_url
        self._llm_model = llm_model
        self._llm_semaphore = llm_semaphore or asyncio.Semaphore(1)
        self._filter: dict = event_filter or {}
        self._nc: NATSClient | None = None
        self._js = None
        self._event_buffer: list[dict] = []
        self._debounce_task: asyncio.Task | None = None
        self._processing: bool = False

    async def _call_nats_tool(self, tool_name: str, payload: dict) -> dict:
        """Call a daemon tool via NATS request/reply."""
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

    def _build_agno_agent(self, context_append: str = "") -> Agent:
        """Build an Agno Agent with NATS-backed tools."""
        instructions = BASE_SYSTEM_PROMPT
        if context_append:
            instructions += f"\nYour job: {context_append}"

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
            """Read a value from shared state. Valid buckets: agents, tasks, policies, logs."""
            result = await self._kv_get(bucket, key)
            return str(result)

        async def kv_put(bucket: str, key: str, value: str) -> str:
            """Write a value to shared state. Valid buckets: agents, tasks, policies, logs. Value should be a JSON string."""
            await self._kv_put(bucket, key, msgspec.json.decode(value.encode(), type=dict))
            return "ok"

        async def kv_keys(bucket: str) -> str:
            """List all keys in a shared state bucket. Valid buckets: agents, tasks, policies, logs."""
            keys = await self._kv_keys(bucket)
            return str(keys)

        model = LMStudio(id=self._llm_model, base_url=self._llm_base_url, temperature=0.0)

        return Agent(
            model=model,
            instructions=instructions,
            tools=[exec_command, enforce, transform, schedule, measure, kv_get, kv_put, kv_keys],
            telemetry=False,
            retries=3,
            delay_between_retries=2,
        )

    @abstractmethod
    def get_context_append(self) -> str:
        """Return per-agent context to append to the system prompt."""

    def _semantic_key(self, event: dict) -> str:
        """Extract a semantic task key from an event — based on what's being acted on, not PID."""
        data = event.get("data", {})

        # For process events: use the command + working directory
        comm = data.get("comm", "")
        cmdline = data.get("cmdline", "")
        cwd = data.get("cwd", "")

        # Extract the meaningful path from the cmdline
        # "mkdir /home/user/my-app" → "/home/user/my-app"
        # "git clone https://... /home/user/repo" → "/home/user/repo"
        parts = cmdline.split()
        target_path = ""
        for part in reversed(parts):
            if part.startswith("/"):
                target_path = part
                break

        if target_path:
            return f"{self.agent_id}.path.{target_path}".replace(":", "-").replace("/", "_")

        # For network events: use the IP + port
        daddr = data.get("daddr", "")
        dport = data.get("dport", "")
        if daddr:
            return f"{self.agent_id}.net.{daddr}-{dport}".replace(":", "-")

        # For exit events: use the service name
        if comm:
            return f"{self.agent_id}.service.{comm}".replace(":", "-")

        # Fallback: use the resource
        resource = event.get("resource", "unknown")
        return f"{self.agent_id}.{resource}".replace(":", "-").replace("/", "_")

    def _matches_filter(self, event: dict) -> bool:
        """Check if event matches this agent's filter. Returns True if it should be processed."""
        if not self._filter:
            return True  # no filter = accept everything

        data = event.get("data", {})

        # comm whitelist
        comm_filter = self._filter.get("comm")
        if comm_filter:
            comm = data.get("comm", "")
            if comm not in comm_filter:
                return False

        # exit_codes whitelist
        exit_filter = self._filter.get("exit_codes")
        if exit_filter:
            exit_code = data.get("exit_code")
            if exit_code is not None and exit_code not in exit_filter:
                return False

        # paths whitelist (prefix match on cmdline or filename)
        paths_filter = self._filter.get("paths")
        if paths_filter:
            cmdline = data.get("cmdline", "")
            filename = data.get("filename", "")
            if not any(cmdline.find(p) >= 0 or filename.find(p) >= 0 for p in paths_filter):
                return False

        return True

    async def _on_event(self, msg) -> None:
        """Buffer incoming events and debounce — process as batch after quiet period."""
        event = msgspec.json.decode(msg.data, type=dict)
        event["_subject"] = msg.subject

        # Drop events that don't match this agent's filter
        if not self._matches_filter(event):
            return

        # Skip if we already have an event with the same semantic key in the buffer
        key = self._semantic_key(event)
        if any(self._semantic_key(e) == key for e in self._event_buffer):
            return

        self._event_buffer.append(event)

        # Cap buffer size
        if len(self._event_buffer) > 20:
            self._event_buffer = self._event_buffer[-20:]

        # Don't reset debounce timer if we're already processing a batch
        if self._processing:
            return

        # Reset the debounce timer
        if self._debounce_task and not self._debounce_task.done():
            self._debounce_task.cancel()
        self._debounce_task = asyncio.create_task(self._flush_after_delay())

    async def _flush_after_delay(self) -> None:
        """Wait for the debounce window, then process accumulated events."""
        await asyncio.sleep(DEBOUNCE_WINDOW)
        await self._process_batch()

    async def _process_batch(self) -> None:
        """Process a batch of debounced events as a single LLM call."""
        self._processing = True
        events = self._event_buffer
        self._event_buffer = []

        if not events:
            self._processing = False
            return

        # Deduplicate by semantic key — only skip in_progress tasks (not done)
        unique_events: dict[str, list[dict]] = {}
        for event in events:
            key = self._semantic_key(event)
            existing = await self._kv_get("tasks", key)
            if existing and existing.get("status") == "in_progress":
                continue
            unique_events.setdefault(key, []).append(event)

        if not unique_events:
            return

        # Cap batch size — take the most recent unique events
        max_batch = 5
        if len(unique_events) > max_batch:
            keys = list(unique_events.keys())[-max_batch:]
            unique_events = {k: unique_events[k] for k in keys}

        # Build a batch summary for the LLM
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

        # Claim all unique tasks
        for key in unique_events:
            await self._kv_put("tasks", key, {
                "agent": self.agent_id,
                "status": "in_progress",
            })

        logger.info("agent %s processing batch: %d events → %d unique actions", self.agent_id, len(events), len(unique_events))

        # Single LLM call — acquire semaphore to limit concurrent calls
        async with self._llm_semaphore:
            agent = self._build_agno_agent(self.get_context_append())
            response = await agent.arun(batch_context)

        content = response.content if response else "no response"
        logger.info("[%s] response: %s", self.agent_id, str(content)[:200])

        # Mark all tasks done
        for key in unique_events:
            await self._kv_put("tasks", key, {
                "agent": self.agent_id,
                "status": "done",
                "result": str(content)[:500],
            })

        self._processing = False

        # If events accumulated while we were processing, schedule another batch
        if self._event_buffer:
            self._debounce_task = asyncio.create_task(self._flush_after_delay())

    async def run(self) -> None:
        """Connect to NATS and listen for events."""
        self._nc = await nats.connect(self.nats_url)
        self._js = self._nc.jetstream()

        logger.info("agent %s connected to %s", self.agent_id, self.nats_url)

        for event_type in self.subscribed_events:
            subject = f"events.{event_type}"
            await self._nc.subscribe(subject, cb=self._on_event)
            logger.info("agent %s subscribed to %s", self.agent_id, subject)

        stop = asyncio.Event()
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass

    async def close(self) -> None:
        if self._nc:
            await self._nc.close()
