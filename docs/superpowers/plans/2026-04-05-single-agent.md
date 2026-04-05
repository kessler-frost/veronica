# Single Agent Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace multi-agent architecture with a single agent that accumulates behaviors from `veronica add`, eliminating agent collision and filter quality problems.

**Architecture:** One agent subscribes to event types determined by an LLM call at `veronica add` time. Behaviors are raw text strings stored in NATS KV. The system prompt is rebuilt each batch from all behaviors. A `subscribe` tool lets the agent self-correct its subscriptions at runtime.

**Tech Stack:** Python (Agno, NATS, msgspec, Typer), existing Go daemon unchanged.

**Spec:** `docs/superpowers/specs/2026-04-05-single-agent-design.md`

---

### Task 1: Replace agent.py with single-agent VeronicaAgent

**Files:**
- Create: `src/veronica/agents/agent.py`
- Modify: `src/veronica/agents/base.py` — remove `_matches_filter`, remove `get_context_append` abstract method
- Delete: `src/veronica/agents/runner.py`
- Delete: `src/veronica/agents/creator.py`
- Test: `tests/test_agent.py`

- [ ] **Step 1: Write test for VeronicaAgent behavior loading**

```python
"""tests/test_agent.py"""

import msgspec
import nats as nats_client
import pytest

from veronica.agents.agent import VeronicaAgent


@pytest.mark.asyncio
async def test_agent_builds_prompt_with_behaviors():
    """System prompt includes all behaviors from config."""
    try:
        nc = await nats_client.connect("nats://localhost:4222")
    except Exception:
        pytest.skip("NATS server not running")

    js = nc.jetstream()
    kv = await js.key_value("agents")
    await kv.put("veronica", msgspec.json.encode({
        "behaviors": ["scaffold projects", "revert dangerous permissions"],
        "subscriptions": ["process_exec"],
    }))

    agent = VeronicaAgent(nats_url="nats://localhost:4222")
    agent._nc = nc
    agent._js = js
    config = await agent._load_config()

    assert config["behaviors"] == ["scaffold projects", "revert dangerous permissions"]
    assert config["subscriptions"] == ["process_exec"]

    await kv.delete("veronica")
    await nc.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_agent.py::test_agent_builds_prompt_with_behaviors -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'veronica.agents.agent'`

- [ ] **Step 3: Create VeronicaAgent class**

Create `src/veronica/agents/agent.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_agent.py::test_agent_builds_prompt_with_behaviors -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/veronica/agents/agent.py tests/test_agent.py
git commit -m "feat: add VeronicaAgent — single agent with behavior accumulation"
```

---

### Task 2: Rewrite CLI — replace agent subcommand with top-level add/rm/list

**Files:**
- Modify: `src/veronica/cli/main.py` — remove `agent_app`, add top-level `add`/`rm`/`list` commands, update `start` to use `VeronicaAgent`

- [ ] **Step 1: Rewrite CLI**

Replace the agent subcommand section and update start command in `src/veronica/cli/main.py`:

Remove these lines at the top:
```python
from veronica.agents.creator import create_agent_config
from veronica.agents.runner import AgentRunner
```
```python
agent_app = typer.Typer(help="Manage agents.")
app.add_typer(agent_app, name="agent")
```

Replace with:
```python
from veronica.agents.agent import VeronicaAgent
```

Replace the `start` command body to use `VeronicaAgent`:
```python
@app.command()
def start():
    """Start VM, daemon, and agent. Idempotent."""
    if _veronica_already_running():
        typer.echo("Another veronica process is already running. Run `veronica stop` first.", err=True)
        raise typer.Exit(1)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if not _vm_running():
        typer.echo(f"Starting Lima VM {cfg.vm_name!r}...")
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)
    else:
        typer.echo(f"Lima VM {cfg.vm_name!r} already running.")

    typer.echo("Starting daemon...")
    _vm_shell("sudo", "systemctl", "start", "veronica")

    typer.echo("Starting agent (Ctrl+C to stop)...")
    agent = VeronicaAgent(cfg=cfg, nats_url=cfg.nats_url)
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        typer.echo("Shutting down...")
```

Remove the entire `# --- Agent subcommands ---` section (`agent_add`, `agent_list`, `agent_stop`, `agent_rm`).

Add new top-level commands:
```python
VALID_EVENTS = frozenset({"process_exec", "process_exit", "net_connect", "file_open"})

@app.command()
def add(description: str = typer.Argument(help="Natural language behavior description")):
    """Add a behavior to Veronica."""

    async def _add():
        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")

        # Load or create config
        try:
            entry = await kv.get("veronica")
            config = msgspec.json.decode(entry.value, type=dict)
        except Exception:
            config = {"behaviors": [], "subscriptions": []}

        config["behaviors"].append(description)

        # Ask LLM which events the combined behaviors need
        model = cfg.build_model()
        from agno.agent import Agent
        sub_agent = Agent(
            model=model,
            instructions="Given a list of behaviors for an eBPF agent, return ONLY a JSON array of event types needed. Valid types: process_exec, process_exit, file_open, net_connect. Example: [\"process_exec\", \"file_open\"]. No other text.",
            markdown=False,
        )
        behaviors_text = "\n".join(f"- {b}" for b in config["behaviors"])
        response = await sub_agent.arun(f"Behaviors:\n{behaviors_text}")
        content = response.content.strip() if response else "[]"

        # Parse event types from response
        json_start = content.find("[")
        json_end = content.rfind("]") + 1
        if json_start >= 0 and json_end > 0:
            event_types = msgspec.json.decode(content[json_start:json_end].encode(), type=list)
            config["subscriptions"] = [e for e in event_types if e in VALID_EVENTS]

        await kv.put("veronica", msgspec.json.encode(config))
        await nc.close()

        typer.echo(f"Added: {description}")
        typer.echo(f"  Subscriptions: {config['subscriptions']}")
        typer.echo(f"  Total behaviors: {len(config['behaviors'])}")

    asyncio.run(_add())


@app.command("list")
def list_behaviors():
    """List all behaviors."""

    async def _list():
        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")

        try:
            entry = await kv.get("veronica")
            config = msgspec.json.decode(entry.value, type=dict)
        except Exception:
            typer.echo("No behaviors configured. Run `veronica add \"...\"` to add one.")
            await nc.close()
            return

        typer.echo(f"Subscriptions: {config.get('subscriptions', [])}")
        typer.echo(f"Behaviors ({len(config.get('behaviors', []))}):")
        for i, b in enumerate(config.get("behaviors", []), 1):
            typer.echo(f"  {i}. {b}")

        await nc.close()

    asyncio.run(_list())


@app.command()
def rm(description: str = typer.Argument(help="Behavior text to remove (partial match)")):
    """Remove a behavior."""

    async def _rm():
        nc = await nats_client.connect(cfg.nats_url)
        js = nc.jetstream()
        kv = await js.key_value("agents")

        try:
            entry = await kv.get("veronica")
            config = msgspec.json.decode(entry.value, type=dict)
        except Exception:
            typer.echo("No behaviors configured.")
            await nc.close()
            return

        behaviors = config.get("behaviors", [])
        matches = [b for b in behaviors if description.lower() in b.lower()]

        if not matches:
            typer.echo(f"No behavior matching '{description}'")
            await nc.close()
            return

        for m in matches:
            behaviors.remove(m)
            typer.echo(f"Removed: {m}")

        config["behaviors"] = behaviors

        # Re-evaluate subscriptions
        if behaviors:
            model = cfg.build_model()
            from agno.agent import Agent
            sub_agent = Agent(
                model=model,
                instructions="Given a list of behaviors for an eBPF agent, return ONLY a JSON array of event types needed. Valid types: process_exec, process_exit, file_open, net_connect. No other text.",
                markdown=False,
            )
            behaviors_text = "\n".join(f"- {b}" for b in behaviors)
            response = await sub_agent.arun(f"Behaviors:\n{behaviors_text}")
            content = response.content.strip() if response else "[]"
            json_start = content.find("[")
            json_end = content.rfind("]") + 1
            if json_start >= 0 and json_end > 0:
                event_types = msgspec.json.decode(content[json_start:json_end].encode(), type=list)
                config["subscriptions"] = [e for e in event_types if e in VALID_EVENTS]
        else:
            config["subscriptions"] = []

        await kv.put("veronica", msgspec.json.encode(config))
        await nc.close()

        typer.echo(f"  Subscriptions: {config['subscriptions']}")
        typer.echo(f"  Remaining behaviors: {len(behaviors)}")

    asyncio.run(_rm())
```

- [ ] **Step 2: Verify CLI works**

Run: `uv run veronica --help`
Expected: shows `add`, `rm`, `list`, `start`, `stop`, `status`, `logs`, `build`, `run`, `setup`, `vm` — no `agent` subcommand.

- [ ] **Step 3: Commit**

```bash
git add src/veronica/cli/main.py
git commit -m "feat: replace agent subcommand with top-level add/rm/list"
```

---

### Task 3: Delete old files, update imports

**Files:**
- Delete: `src/veronica/agents/creator.py`
- Delete: `src/veronica/agents/runner.py`
- Modify: `src/veronica/agents/__init__.py` — stays empty, that's fine

- [ ] **Step 1: Delete old files**

```bash
rm src/veronica/agents/creator.py src/veronica/agents/runner.py
```

- [ ] **Step 2: Verify nothing imports them**

Run: `uv run python -c "from veronica.cli.main import app; print('ok')"`
Expected: `ok`

Run: `uv run python -c "from veronica.agents.agent import VeronicaAgent; print('ok')"`
Expected: `ok`

- [ ] **Step 3: Remove old base.py code**

In `src/veronica/agents/base.py`, the file is no longer imported by anything. Delete it entirely — all functionality is in `agent.py` now.

```bash
rm src/veronica/agents/base.py
```

- [ ] **Step 4: Update test**

The test file `tests/test_agent.py` already imports from `veronica.agents.agent` (from Task 1). Verify:

Run: `uv run pytest tests/test_agent.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: delete old multi-agent files (creator, runner, base)"
```

---

### Task 4: Update CLAUDE.md and docs

**Files:**
- Modify: `CLAUDE.md` — update CLI section, architecture description
- Modify: `README.md` — update quick start
- Modify: `docs/examples.md` — update agent creation instructions

- [ ] **Step 1: Update CLAUDE.md**

In the CLI section, replace:
```
- `uv run veronica agent add "<description>"` — Create agent from natural language via LLM
- `uv run veronica agent list` — List registered agents
- `uv run veronica agent stop <name>` — Stop an agent
- `uv run veronica agent rm <name>` — Remove an agent
```

With:
```
- `uv run veronica add "<description>"` — Add a behavior
- `uv run veronica list` — List all behaviors
- `uv run veronica rm "<description>"` — Remove a behavior (partial match)
```

In the Architecture section, update the Host Agents description:
```
- **Host Agent** (`src/veronica/agents/agent.py`): Single Python agent, runs on macOS host. Connects to daemon via NATS, accumulates behaviors from `veronica add`, subscribes to relevant event types.
```

- [ ] **Step 2: Update README.md quick start**

Replace `uv run veronica agent add` with `uv run veronica add`:
```
# Add a behavior
uv run veronica add "scaffold projects automatically based on directory creation"
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md README.md docs/examples.md
git commit -m "docs: update for single-agent architecture"
```

---

### Task 5: End-to-end test

- [ ] **Step 1: Start fresh and test the full flow**

```bash
# Ensure daemon is running
uv run veronica run systemctl start veronica

# Add behaviors
uv run veronica add "scaffold projects based on directory creation"
uv run veronica add "revert dangerous permission changes on sensitive files"

# Verify
uv run veronica list

# Start agent
uv run veronica start &
sleep 5

# Test scaffolding
uv run veronica run mkdir /tmp/my-fastapi-app
sleep 40
uv run veronica run ls /tmp/my-fastapi-app

# Test chmod revert
uv run veronica run bash -c "echo secret > /etc/test-shadow && chmod 640 /etc/test-shadow"
uv run veronica run chmod 777 /etc/test-shadow
sleep 40
uv run veronica run stat -c '%a' /etc/test-shadow

# Stop
uv run veronica stop
```

Expected: FastAPI scaffold created, permissions reverted to 640.

- [ ] **Step 2: Commit any fixes**

```bash
git add -A
git commit -m "test: verify single-agent end-to-end"
```
