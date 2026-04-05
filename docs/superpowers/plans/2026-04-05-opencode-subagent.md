# OpenCode Subagent Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Agno with OpenCode as the LLM harness. FastMCP server wraps NATS tools. Main OpenCode agent spawns subagents per behavior. Event routing per-subagent.

**Architecture:** Python host service runs FastMCP (NATS tools), thin OpenCode REST client, NATS event watcher, and CLI. OpenCode runs headless, main agent creates subagent `.md` files and spawns them. Go daemon unchanged.

**Tech Stack:** Python (FastMCP, nats-py, Typer, httpx), OpenCode (headless server), Go daemon (unchanged)

**Spec:** `docs/superpowers/specs/2026-04-05-opencode-subagent-design.md`

---

## File Structure

```
src/veronica/
  cli/main.py          — Rewrite: add/rm/list/start/stop, no agno/agent imports
  config.py            — Simplify: remove agno/openrouter, add opencode settings
  opencode.py          — NEW: thin OpenCode REST client (create session, send message, SSE events)
  mcp_server.py        — NEW: FastMCP server wrapping NATS tool calls
  watcher.py           — NEW: NATS event subscriber → routes to subagent sessions
  __init__.py           — unchanged

src/veronica/agents/   — DELETE entire directory (agent.py, __init__.py)

tests/
  test_config.py       — Update for new config fields
  test_opencode.py     — NEW: test OpenCode client
  test_mcp.py          — NEW: test MCP tool wrappers

~/.veronica/
  behaviors.json       — Behavior storage + subagent routing configs
  .opencode/           — OpenCode config dir (agents/, opencode.json)
```

---

### Task 1: Clean up — delete Agno, update deps

**Files:**
- Delete: `src/veronica/agents/` (entire directory)
- Modify: `pyproject.toml` — remove agno, openai; add fastmcp, httpx
- Modify: `src/veronica/config.py` — remove PROVIDERS/build_model, add opencode settings
- Modify: `tests/test_config.py` — update assertions

- [ ] **Step 1: Delete agents directory**

```bash
rm -rf src/veronica/agents/
```

- [ ] **Step 2: Update pyproject.toml**

Replace dependencies:
```toml
[project]
name = "veronica"
version = "0.2.0"
description = "Proactive agents at the kernel level, powered by eBPF"
requires-python = ">=3.12"
dependencies = [
    "fastmcp>=2.0",
    "httpx>=0.28",
    "msgspec>=0.19",
    "nats-py>=2.0",
    "typer>=0.15",
]
```

- [ ] **Step 3: Rewrite config.py**

```python
"""Veronica configuration."""

from pathlib import Path

from pydantic_settings import BaseSettings


class VeronicaConfig(BaseSettings):
    model_config = {"env_prefix": "VERONICA_", "env_nested_delimiter": "__"}

    nats_url: str = "nats://localhost:4222"
    vm_name: str = "veronica"
    lima_config: str = "lima/veronica.yaml"
    daemon_pkg: str = "./cmd/veronicad/"
    daemon_install_path: str = "/usr/local/bin/veronicad"
    vm_project_path: str = "/home/fimbulwinter.linux/veronica"
    opencode_port: int = 4096
    mcp_port: int = 4097
    veronica_dir: Path = Path.home() / ".veronica"

    @property
    def opencode_url(self) -> str:
        return f"http://localhost:{self.opencode_port}"

    @property
    def opencode_config_dir(self) -> Path:
        return self.veronica_dir / ".opencode"

    @property
    def behaviors_file(self) -> Path:
        return self.veronica_dir / "behaviors.json"
```

- [ ] **Step 4: Update test_config.py**

```python
"""tests/test_config.py"""

from pathlib import Path

from veronica.config import VeronicaConfig


def test_defaults():
    cfg = VeronicaConfig()
    assert cfg.nats_url == "nats://localhost:4222"
    assert cfg.vm_name == "veronica"
    assert cfg.opencode_port == 4096
    assert cfg.mcp_port == 4097
    assert cfg.veronica_dir == Path.home() / ".veronica"


def test_opencode_url():
    cfg = VeronicaConfig()
    assert cfg.opencode_url == "http://localhost:4096"
```

- [ ] **Step 5: Run tests, sync deps**

```bash
uv sync
uv run pytest tests/test_config.py -v
```

Expected: PASS (config tests), deps synced without agno/openai.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor: remove Agno, update deps for OpenCode architecture

Delete agents/, remove agno+openai deps, add fastmcp+httpx.
Config simplified: no more PROVIDERS/build_model, adds opencode settings.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: OpenCode REST client

**Files:**
- Create: `src/veronica/opencode.py`
- Create: `tests/test_opencode.py`

- [ ] **Step 1: Write test**

```python
"""tests/test_opencode.py"""

import pytest

from veronica.opencode import OpenCodeClient


def test_client_init():
    client = OpenCodeClient(base_url="http://localhost:4096")
    assert client.base_url == "http://localhost:4096"


@pytest.mark.asyncio
async def test_client_health_fails_when_not_running():
    client = OpenCodeClient(base_url="http://localhost:19999")
    with pytest.raises(Exception):
        await client.health()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_opencode.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement OpenCode client**

```python
"""Thin OpenCode REST client — create sessions, send messages, subscribe to events."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


class OpenCodeClient:
    """Minimal client for OpenCode's headless server REST API."""

    def __init__(self, base_url: str = "http://localhost:4096", directory: str | None = None):
        self.base_url = base_url
        self._headers = {}
        if directory:
            self._headers["X-OpenCode-Directory"] = directory

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def health(self) -> dict:
        async with httpx.AsyncClient() as c:
            resp = await c.get(self._url("/global/health"), headers=self._headers)
            resp.raise_for_status()
            return resp.json()

    async def create_session(self, parent_id: str | None = None) -> dict:
        body = {}
        if parent_id:
            body["parentID"] = parent_id
        async with httpx.AsyncClient() as c:
            resp = await c.post(self._url("/session"), json=body, headers=self._headers)
            resp.raise_for_status()
            return resp.json()

    async def send_message(self, session_id: str, text: str, agent: str = "build") -> dict:
        body = {
            "parts": [{"type": "text", "text": text}],
            "agent": agent,
        }
        async with httpx.AsyncClient(timeout=120) as c:
            resp = await c.post(
                self._url(f"/session/{session_id}/message"),
                json=body,
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()

    async def send_message_async(self, session_id: str, text: str, agent: str = "build") -> None:
        body = {
            "parts": [{"type": "text", "text": text}],
            "agent": agent,
        }
        async with httpx.AsyncClient() as c:
            resp = await c.post(
                self._url(f"/session/{session_id}/prompt_async"),
                json=body,
                headers=self._headers,
            )
            resp.raise_for_status()

    async def list_sessions(self) -> list:
        async with httpx.AsyncClient() as c:
            resp = await c.get(self._url("/session"), headers=self._headers)
            resp.raise_for_status()
            return resp.json()

    async def abort_session(self, session_id: str) -> None:
        async with httpx.AsyncClient() as c:
            resp = await c.post(self._url(f"/session/{session_id}/abort"), headers=self._headers)
            resp.raise_for_status()

    async def list_agents(self) -> list:
        async with httpx.AsyncClient() as c:
            resp = await c.get(self._url("/agent"), headers=self._headers)
            resp.raise_for_status()
            return resp.json()
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest tests/test_opencode.py -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/veronica/opencode.py tests/test_opencode.py
git commit -m "feat: add OpenCode REST client

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: FastMCP server wrapping NATS tools

**Files:**
- Create: `src/veronica/mcp_server.py`

- [ ] **Step 1: Implement MCP server**

```python
"""FastMCP server — exposes NATS tool responders as MCP tools for OpenCode."""

from __future__ import annotations

import asyncio
import logging

import msgspec
import nats
from fastmcp import FastMCP
from nats.aio.client import Client as NATSClient

logger = logging.getLogger(__name__)

mcp = FastMCP("veronica")


_nc: NATSClient | None = None


async def _get_nats(nats_url: str = "nats://localhost:4222") -> NATSClient:
    global _nc
    if _nc is None or _nc.is_closed:
        _nc = await nats.connect(nats_url)
    return _nc


async def _nats_request(subject: str, payload: dict, nats_url: str = "nats://localhost:4222") -> dict:
    nc = await _get_nats(nats_url)
    data = msgspec.json.encode(payload)
    resp = await nc.request(subject, data, timeout=30)
    return msgspec.json.decode(resp.data, type=dict)


@mcp.tool
async def exec_command(command: str, reason: str = "") -> str:
    """Run a shell command in the VM. Use for file ops, package installs, service management."""
    result = await _nats_request("tools.exec", {"command": command, "reason": reason})
    return result.get("data", result.get("error", str(result)))


@mcp.tool
async def enforce(hook: str, target: str, action: str, reason: str = "") -> str:
    """Block or allow access. hook: file_open/xdp_drop/socket_connect. action: deny/allow."""
    result = await _nats_request("tools.enforce", {"hook": hook, "target": target, "action": action, "reason": reason})
    return result.get("data", result.get("error", str(result)))


@mcp.tool
async def transform(interface: str, match: str, rewrite: str, reason: str = "") -> str:
    """Rewrite packets or redirect traffic. match/rewrite: key=value (e.g. dport=80)."""
    result = await _nats_request("tools.transform", {"interface": interface, "match": match, "rewrite": rewrite, "reason": reason})
    return result.get("data", result.get("error", str(result)))


@mcp.tool
async def schedule(target: str, priority: str, reason: str = "") -> str:
    """Set CPU priority for a PID. priority: latency-sensitive/batch/normal."""
    result = await _nats_request("tools.schedule", {"target": target, "priority": priority, "reason": reason})
    return result.get("data", result.get("error", str(result)))


@mcp.tool
async def measure(target: str, metric: str, duration: str = "5s") -> str:
    """Read performance counters. metric: cache_misses/cycles/bandwidth/io."""
    result = await _nats_request("tools.measure", {"target": target, "metric": metric, "duration": duration})
    return result.get("data", result.get("error", str(result)))


def run_mcp_server(port: int = 4097, nats_url: str = "nats://localhost:4222"):
    """Run the MCP server. Called from a background thread."""
    mcp.run(transport="streamable-http", port=port)
```

- [ ] **Step 2: Commit**

```bash
git add src/veronica/mcp_server.py
git commit -m "feat: FastMCP server wrapping NATS tools for OpenCode

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: NATS event watcher with subagent routing

**Files:**
- Create: `src/veronica/watcher.py`

- [ ] **Step 1: Implement event watcher**

```python
"""NATS event watcher — subscribes to eBPF events and routes to OpenCode subagent sessions."""

from __future__ import annotations

import asyncio
import logging

import msgspec
import nats

from veronica.opencode import OpenCodeClient

logger = logging.getLogger(__name__)

DEBOUNCE_WINDOW = 2.0


class EventWatcher:
    """Watches NATS events and routes them to appropriate OpenCode subagent sessions."""

    def __init__(self, nats_url: str, opencode: OpenCodeClient):
        self.nats_url = nats_url
        self._opencode = opencode
        self._nc = None
        self._subs: list = []
        self._routing: dict[str, dict] = {}  # subagent_name → {session_id, subscriptions, comm_filter}
        self._buffers: dict[str, list] = {}  # subagent_name → event buffer
        self._debounce_tasks: dict[str, asyncio.Task] = {}
        self._processing: set[str] = set()

    def set_routing(self, routing: dict[str, dict]) -> None:
        """Update routing table. Called when subagents are added/removed."""
        self._routing = routing
        logger.info("routing updated: %s", list(routing.keys()))

    async def start(self) -> None:
        """Connect to NATS and subscribe to all event types."""
        self._nc = await nats.connect(self.nats_url)
        for event_type in ["process_exec", "process_exit", "file_open", "net_connect"]:
            sub = await self._nc.subscribe(f"events.{event_type}", cb=self._on_event)
            self._subs.append(sub)
        logger.info("event watcher started, subscribed to all event types")

    async def _on_event(self, msg) -> None:
        """Route incoming event to matching subagents."""
        event = msgspec.json.decode(msg.data, type=dict)
        event_type = msg.subject.replace("events.", "")
        data = event.get("data", {})
        comm = data.get("comm", "")

        for name, config in self._routing.items():
            subs = config.get("subscriptions", [])
            comm_filter = set(config.get("comm_filter", []))

            # Check event type matches
            if event_type not in subs:
                continue

            # For process events, check comm filter
            if event_type in ("process_exec", "process_exit") and comm_filter and comm not in comm_filter:
                continue

            # Buffer the event for this subagent
            if name not in self._buffers:
                self._buffers[name] = []
            self._buffers[name].append(event)

            # Cap buffer
            if len(self._buffers[name]) > 20:
                self._buffers[name] = self._buffers[name][-20:]

            # Debounce
            if name in self._processing:
                continue
            if name in self._debounce_tasks and not self._debounce_tasks[name].done():
                self._debounce_tasks[name].cancel()
            self._debounce_tasks[name] = asyncio.create_task(self._flush(name))

    async def _flush(self, name: str) -> None:
        """After debounce window, send buffered events to the subagent's session."""
        await asyncio.sleep(DEBOUNCE_WINDOW)
        self._processing.add(name)

        events = self._buffers.pop(name, [])
        if not events:
            self._processing.discard(name)
            return

        config = self._routing.get(name, {})
        session_id = config.get("session_id")
        if not session_id:
            logger.warning("no session_id for subagent %s", name)
            self._processing.discard(name)
            return

        # Build batch summary
        lines = [f"Batch of {len(events)} eBPF events:"]
        for ev in events[:5]:
            data = ev.get("data", {})
            detail = data.get("cmdline", "") or data.get("filename", "") or data.get("daddr", "")
            lines.append(f"  {data.get('comm', '')} {detail}")
        batch_text = "\n".join(lines)

        logger.info("sending %d events to subagent %s", len(events), name)
        await self._opencode.send_message_async(session_id, batch_text)

        self._processing.discard(name)

        # If more events buffered during processing, flush again
        if name in self._buffers and self._buffers[name]:
            self._debounce_tasks[name] = asyncio.create_task(self._flush(name))

    async def stop(self) -> None:
        for sub in self._subs:
            await sub.unsubscribe()
        if self._nc:
            await self._nc.close()
```

- [ ] **Step 2: Commit**

```bash
git add src/veronica/watcher.py
git commit -m "feat: NATS event watcher with per-subagent routing

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Rewrite CLI

**Files:**
- Modify: `src/veronica/cli/main.py` — full rewrite of add/rm/list/start/stop

- [ ] **Step 1: Rewrite main.py**

Remove all agno/agent imports and the old add/rm/list/start commands. Replace with:

```python
"""Veronica CLI — manage daemon, VM, and behaviors."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import threading
from pathlib import Path

import typer

from veronica.config import VeronicaConfig
from veronica.mcp_server import run_mcp_server
from veronica.opencode import OpenCodeClient
from veronica.watcher import EventWatcher

app = typer.Typer(help="Control the Veronica eBPF intelligence layer.")
vm_app = typer.Typer(help="Manage the Lima VM lifecycle.")
app.add_typer(vm_app, name="vm")

cfg = VeronicaConfig()

MAIN_AGENT_PROMPT = """You are the Veronica orchestrator. You manage subagents that handle eBPF kernel events on a Linux VM.

When asked to add a behavior:
1. Determine which eBPF event types the subagent needs (process_exec, process_exit, file_open, net_connect)
2. Determine which command names (comms) are relevant — be strict, only exact commands that trigger the behavior
3. Write an agent markdown file using the write tool
4. Spawn the subagent

When asked to remove a behavior, kill the corresponding subagent.

When asked to list behaviors, describe the current subagents and their configurations.

Pay attention to paths in events. When acting on a file or directory, work in the same location.
If a tool or dependency is missing, install it and continue.
You run as root in the VM.
"""


def _vm_running() -> bool:
    result = subprocess.run(["limactl", "list", "--json"], capture_output=True, text=True)
    for line in result.stdout.strip().splitlines():
        inst = json.loads(line)
        if inst.get("name") == cfg.vm_name:
            return inst.get("status") == "Running"
    return False


def _vm_shell(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["limactl", "shell", cfg.vm_name, "--", *args], check=check)


def _sync_to_vm():
    """Copy project source files into the VM."""
    host_root = Path(__file__).resolve().parents[3]
    vm_path = cfg.vm_project_path
    _vm_shell("mkdir", "-p", vm_path)
    subprocess.run(["limactl", "cp", "-r", f"{host_root}/cmd", f"{cfg.vm_name}:{vm_path}/cmd"], check=True)
    subprocess.run(["limactl", "cp", "-r", f"{host_root}/internal", f"{cfg.vm_name}:{vm_path}/internal"], check=True)
    for f in ["go.mod", "go.sum"]:
        src = host_root / f
        if src.exists():
            subprocess.run(["limactl", "cp", str(src), f"{cfg.vm_name}:{vm_path}/{f}"], check=True)
    service = host_root / "lima" / "veronica.service"
    if service.exists():
        _vm_shell("mkdir", "-p", f"{vm_path}/lima")
        subprocess.run(["limactl", "cp", str(service), f"{cfg.vm_name}:{vm_path}/lima/veronica.service"], check=True)


def _load_behaviors() -> dict:
    if cfg.behaviors_file.exists():
        return json.loads(cfg.behaviors_file.read_text())
    return {"behaviors": [], "subagents": {}, "session_id": None}


def _save_behaviors(data: dict) -> None:
    cfg.veronica_dir.mkdir(parents=True, exist_ok=True)
    cfg.behaviors_file.write_text(json.dumps(data, indent=2))


def _veronica_already_running() -> bool:
    our_pid = os.getpid()
    result = subprocess.run(["pgrep", "-f", "veronica start"], capture_output=True, text=True)
    for line in result.stdout.strip().splitlines():
        pid = int(line.strip())
        if pid != our_pid:
            return True
    return False


def _setup_opencode_config():
    """Create ~/.veronica/.opencode/ with MCP config and main agent."""
    oc_dir = cfg.opencode_config_dir
    agents_dir = oc_dir / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)

    # opencode.json — MCP server config
    oc_config = {
        "mcp": {
            "veronica": {
                "type": "remote",
                "url": f"http://localhost:{cfg.mcp_port}/mcp",
            }
        }
    }
    (oc_dir / "opencode.json").write_text(json.dumps(oc_config, indent=2))

    # Main agent
    main_agent = f"""---
description: Veronica orchestrator — spawns and manages subagents for eBPF behaviors
mode: primary
---

{MAIN_AGENT_PROMPT}
"""
    (agents_dir / "main.md").write_text(main_agent)


# --- Top-level commands ---

@app.command()
def start():
    """Start VM, daemon, MCP server, OpenCode, and event watcher."""
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

    # Setup OpenCode config
    _setup_opencode_config()

    # Start MCP server in background thread
    typer.echo(f"Starting MCP server on port {cfg.mcp_port}...")
    mcp_thread = threading.Thread(target=run_mcp_server, args=(cfg.mcp_port, cfg.nats_url), daemon=True)
    mcp_thread.start()

    # Start OpenCode headless
    typer.echo("Starting OpenCode server...")
    env = os.environ.copy()
    env["OPENCODE_DIR"] = str(cfg.opencode_config_dir)
    oc_proc = subprocess.Popen(
        ["opencode", "serve", "--port", str(cfg.opencode_port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    import time
    time.sleep(3)  # Wait for OpenCode server to start

    async def _run():
        client = OpenCodeClient(base_url=cfg.opencode_url)

        # Create main session
        data = _load_behaviors()
        session = await client.create_session()
        data["session_id"] = session["id"]
        _save_behaviors(data)

        typer.echo(f"OpenCode session: {session['id']}")

        # Send initial system prompt
        await client.send_message(session["id"], MAIN_AGENT_PROMPT)

        # Replay stored behaviors
        for behavior in data.get("behaviors", []):
            typer.echo(f"Replaying: {behavior}")
            await client.send_message(
                session["id"],
                f"Create and spawn a new subagent for this behavior: {behavior}",
            )

        # Start event watcher
        watcher = EventWatcher(nats_url=cfg.nats_url, opencode=client)
        watcher.set_routing(data.get("subagents", {}))
        await watcher.start()

        typer.echo("Veronica running (Ctrl+C to stop)...")
        stop = asyncio.Event()
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass
        finally:
            await watcher.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        typer.echo("Shutting down...")
    finally:
        oc_proc.terminate()


@app.command()
def stop():
    """Stop Veronica and daemon service."""
    result = subprocess.run(["pgrep", "-f", "veronica start"], capture_output=True, text=True)
    our_pid = os.getpid()
    for line in result.stdout.strip().splitlines():
        pid = int(line.strip())
        if pid != our_pid:
            os.kill(pid, 9)
            typer.echo(f"Stopped Veronica (pid {pid})")
    # Kill OpenCode server
    subprocess.run(["pkill", "-f", "opencode serve"], capture_output=True)
    typer.echo("Stopping daemon...")
    _vm_shell("sudo", "systemctl", "stop", "veronica")


@app.command()
def status():
    """Show VM and daemon status."""
    typer.echo("=== Lima VM ===")
    subprocess.run(["limactl", "list", cfg.vm_name])
    typer.echo("\n=== Daemon ===")
    _vm_shell("sudo", "systemctl", "status", "veronica", check=False)


@app.command()
def logs():
    """Stream daemon logs."""
    limactl = subprocess.run(["which", "limactl"], capture_output=True, text=True).stdout.strip()
    os.execv(limactl, ["limactl", "shell", cfg.vm_name, "--", "sudo", "journalctl", "-u", "veronica", "-f"])


@app.command()
def build():
    """Sync source to VM, build daemon, and restart."""
    typer.echo("Syncing source to VM...")
    _sync_to_vm()
    typer.echo("Building daemon...")
    _vm_shell("bash", "-c", f"cd {cfg.vm_project_path} && sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}")
    typer.echo("Restarting service...")
    _vm_shell("sudo", "systemctl", "restart", "veronica", check=False)


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(ctx: typer.Context):
    """Run a command inside the VM as root."""
    _vm_shell("sudo", *ctx.args, check=False)


@app.command()
def setup():
    """Full setup: sync source, eBPF compile, build, install service."""
    if not _vm_running():
        typer.echo("VM not running — run `veronica vm start` first", err=True)
        raise typer.Exit(1)
    typer.echo("1/6 Syncing source to VM...")
    _sync_to_vm()
    ebpf_dir = f"{cfg.vm_project_path}/internal/ebpf/programs"
    typer.echo("2/6 Generating vmlinux.h...")
    _vm_shell("bash", "-c", f"cd {ebpf_dir} && bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h")
    typer.echo("3/6 Compiling eBPF programs...")
    for prog in ["process_exec", "file_open", "net_connect", "process_exit"]:
        _vm_shell("bash", "-c", f"cd {ebpf_dir} && clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c {prog}.c -o {prog}.o")
        typer.echo(f"   {prog}.o OK")
    typer.echo("4/6 Generating Go bindings...")
    _vm_shell("bash", "-c", f"cd {cfg.vm_project_path} && go generate ./internal/ebpf/bpf/")
    typer.echo("5/6 Building daemon...")
    _vm_shell("bash", "-c", f"cd {cfg.vm_project_path} && sudo -E go build -o {cfg.daemon_install_path} {cfg.daemon_pkg}")
    typer.echo("6/6 Installing systemd service...")
    _vm_shell("sudo", "cp", f"{cfg.vm_project_path}/lima/veronica.service", "/etc/systemd/system/veronica.service")
    _vm_shell("sudo", "systemctl", "daemon-reload")
    _vm_shell("sudo", "systemctl", "enable", "veronica")
    typer.echo("Setup complete. Run `veronica start`.")


# --- VM subcommands ---

@vm_app.command("start")
def vm_start():
    """Start the Lima VM."""
    result = subprocess.run(["limactl", "list", "--json"], capture_output=True, text=True)
    exists = any(
        json.loads(line).get("name") == cfg.vm_name
        for line in result.stdout.strip().splitlines()
        if line.strip()
    )
    if exists:
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)
    else:
        yaml_path = Path(__file__).resolve().parents[3] / cfg.lima_config
        subprocess.run(["limactl", "create", f"--name={cfg.vm_name}", str(yaml_path)], check=True)
        subprocess.run(["limactl", "start", cfg.vm_name], check=True)


@vm_app.command("stop")
def vm_stop():
    """Stop the Lima VM."""
    subprocess.run(["limactl", "stop", cfg.vm_name], check=True)


@vm_app.command("ssh")
def vm_ssh():
    """Open interactive shell in VM."""
    limactl = subprocess.run(["which", "limactl"], capture_output=True, text=True).stdout.strip()
    os.execv(limactl, ["limactl", "shell", cfg.vm_name])


# --- Behavior commands ---

@app.command()
def add(description: str = typer.Argument(help="Natural language behavior description")):
    """Add a behavior to Veronica."""
    data = _load_behaviors()
    data["behaviors"].append(description)
    _save_behaviors(data)

    session_id = data.get("session_id")
    if session_id:
        async def _add():
            client = OpenCodeClient(base_url=cfg.opencode_url)
            await client.send_message(
                session_id,
                f"Create and spawn a new subagent for this behavior: {description}",
            )
        asyncio.run(_add())
        typer.echo(f"Added and spawned: {description}")
    else:
        typer.echo(f"Added: {description} (will spawn on next `veronica start`)")


@app.command("list")
def list_behaviors():
    """List all behaviors."""
    data = _load_behaviors()
    behaviors = data.get("behaviors", [])
    subagents = data.get("subagents", {})

    if not behaviors:
        typer.echo("No behaviors configured. Run `veronica add \"...\"` to add one.")
        return

    typer.echo(f"Behaviors ({len(behaviors)}):")
    for i, b in enumerate(behaviors, 1):
        typer.echo(f"  {i}. {b}")

    if subagents:
        typer.echo(f"\nSubagents ({len(subagents)}):")
        for name, config in subagents.items():
            subs = config.get("subscriptions", [])
            comms = config.get("comm_filter", [])
            typer.echo(f"  {name}: events={subs} comms={comms}")


@app.command()
def rm(description: str = typer.Argument(help="Behavior text to remove (partial match)")):
    """Remove a behavior."""
    data = _load_behaviors()
    behaviors = data.get("behaviors", [])
    matches = [b for b in behaviors if description.lower() in b.lower()]

    if not matches:
        typer.echo(f"No behavior matching '{description}'")
        return

    for m in matches:
        behaviors.remove(m)
        typer.echo(f"Removed: {m}")

    data["behaviors"] = behaviors
    _save_behaviors(data)

    session_id = data.get("session_id")
    if session_id:
        async def _rm():
            client = OpenCodeClient(base_url=cfg.opencode_url)
            for m in matches:
                await client.send_message(
                    session_id,
                    f"Kill the subagent that handles this behavior: {m}",
                )
        asyncio.run(_rm())
```

- [ ] **Step 2: Verify CLI**

```bash
uv run veronica --help
```

Expected: shows add, rm, list, start, stop, status, logs, build, run, setup, vm.

- [ ] **Step 3: Commit**

```bash
git add src/veronica/cli/main.py
git commit -m "feat: rewrite CLI for OpenCode architecture

veronica start launches MCP server + OpenCode + event watcher.
add/rm/list manage behaviors via OpenCode sessions.
No more Agno, no more NATS KV for agent config.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Update docs

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Update CLAUDE.md**

In the Architecture section, replace the Veronica/CLI entries:
```
- **Veronica** (`src/veronica/`): Python host service. FastMCP server (NATS tools → MCP), OpenCode REST client, NATS event watcher with per-subagent routing. CLI manages behaviors and VM lifecycle.
- **OpenCode** (headless server): LLM harness. Main agent spawns subagents per behavior. Each subagent has own tools, subscriptions, and comm filters.
```

In the CLI section, update `start` description:
```
- `uv run veronica start` — Start VM + daemon + MCP server + OpenCode + event watcher (blocks, Ctrl+C to stop)
```

- [ ] **Step 2: Update README.md quick start**

Replace the quick start to mention OpenCode as a dependency:
```
Requires: macOS (Apple Silicon) or Linux, [uv](https://docs.astral.sh/uv/), [Lima](https://lima-vm.io/), [OpenCode](https://opencode.ai/), and an LLM provider configured in OpenCode.
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: update for OpenCode architecture

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: End-to-end test

- [ ] **Step 1: Full flow test**

```bash
# Nuke and recreate VM
limactl stop veronica; limactl delete veronica
uv run veronica vm start
uv run veronica setup

# Add behaviors
uv run veronica add "scaffold projects based on directory creation"
uv run veronica add "revert dangerous permission changes on sensitive files"

# Verify
uv run veronica list

# Start everything
uv run veronica start &
sleep 10

# Test: scaffold
uv run veronica run mkdir /tmp/my-fastapi-app
sleep 45
uv run veronica run ls /tmp/my-fastapi-app

# Test: chmod revert
uv run veronica run bash -c "echo secret > /etc/test-shadow && chmod 640 /etc/test-shadow"
uv run veronica run chmod 777 /etc/test-shadow
sleep 45
uv run veronica run stat -c '%a' /etc/test-shadow

# Stop
uv run veronica stop
```

- [ ] **Step 2: Commit any fixes**

```bash
git add -A
git commit -m "test: verify OpenCode subagent end-to-end

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
