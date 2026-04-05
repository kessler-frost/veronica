"""FastMCP server — exposes NATS tool responders and event subscription as MCP tools."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import msgspec
import nats
from fastmcp import FastMCP
from nats.aio.client import Client as NATSClient

if TYPE_CHECKING:
    from veronica.watcher import EventWatcher

logger = logging.getLogger(__name__)

mcp = FastMCP("veronica")

_nc: NATSClient | None = None
_watcher: EventWatcher | None = None
_behaviors_file: Path | None = None

VALID_EVENTS = frozenset({"process_exec", "process_exit", "file_open", "net_connect"})


def set_watcher(watcher: EventWatcher, behaviors_file: Path) -> None:
    """Set the watcher reference so MCP tools can update routing."""
    global _watcher, _behaviors_file
    _watcher = watcher
    _behaviors_file = behaviors_file


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


@mcp.tool
async def list_event_types() -> str:
    """List all eBPF event types you can subscribe to, with descriptions.
    Call this first to understand what events are available."""
    return json.dumps({
        "process_exec": "Fires when a new process starts (sched_process_exec tracepoint). Data: comm, cmdline, cwd, pid, uid, filename.",
        "process_exit": "Fires when a process exits (sched_process_exit tracepoint). Data: comm, pid, uid, exit_code.",
        "file_open": "Fires when a file is opened for writing (kprobe/do_sys_openat2, write-only). Data: comm, pid, filename, flags.",
        "net_connect": "Fires when a TCP connection is initiated (kprobe/tcp_v4_connect). Data: comm, pid, daddr, dport.",
    })


@mcp.tool
async def subscribe_events(agent_name: str, event_types: list[str], comm_filter: list[str] | None = None) -> str:
    """Subscribe this agent to specific eBPF event types. Call this FIRST when you start.

    Valid event_types: process_exec, process_exit, file_open, net_connect
    Optional comm_filter: list of exact command names to watch (e.g. ["mkdir", "git"]).
    If not provided, all events of the subscribed types will be delivered.
    """
    invalid = set(event_types) - VALID_EVENTS
    if invalid:
        return f"Invalid event types: {invalid}. Valid: {sorted(VALID_EVENTS)}"

    if not _watcher or not _behaviors_file:
        return "Watcher not initialized yet"

    # Update routing in watcher
    routing = _watcher._routing
    if agent_name in routing:
        routing[agent_name]["subscriptions"] = event_types
        routing[agent_name]["comm_filter"] = comm_filter or []
    else:
        return f"Unknown agent: {agent_name}. Known: {list(routing.keys())}"

    _watcher.set_routing(routing)

    # Persist to behaviors.json
    data = json.loads(_behaviors_file.read_text())
    if agent_name in data.get("subagents", {}):
        data["subagents"][agent_name]["subscriptions"] = event_types
        data["subagents"][agent_name]["comm_filter"] = comm_filter or []
        _behaviors_file.write_text(json.dumps(data, indent=2))

    logger.info("agent %s subscribed to %s comm_filter=%s", agent_name, event_types, comm_filter)
    return f"Subscribed to {event_types}" + (f" with comm_filter={comm_filter}" if comm_filter else "")


def run_mcp_server(port: int = 4097, nats_url: str = "nats://localhost:4222"):
    """Run the MCP server. Called from a background thread."""
    mcp.run(transport="streamable-http", port=port)
