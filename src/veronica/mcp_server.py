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
async def list_subscriptions() -> str:
    """List all available eBPF event types, their data fields, and filtering options.
    Call this FIRST to understand what you can subscribe to, then call subscribe to configure your event stream."""
    return json.dumps({
        "event_types": {
            "process_exec": {
                "description": "Fires when a new process starts (sched_process_exec tracepoint)",
                "data_fields": {"comm": "process name", "cmdline": "full command line", "cwd": "working directory", "pid": "process ID", "uid": "user ID", "filename": "executable path"},
            },
            "process_exit": {
                "description": "Fires when a process exits (sched_process_exit tracepoint)",
                "data_fields": {"comm": "process name", "pid": "process ID", "uid": "user ID", "exit_code": "exit status"},
            },
            "file_open": {
                "description": "Fires when a file is opened for writing (kprobe/do_sys_openat2, write-only opens in /etc/, /home/, /tmp/, /opt/, /root/, /srv/)",
                "data_fields": {"comm": "process name", "pid": "process ID", "filename": "file path", "flags": "open flags"},
            },
            "net_connect": {
                "description": "Fires when a TCP connection is initiated (kprobe/tcp_v4_connect)",
                "data_fields": {"comm": "process name", "pid": "process ID", "daddr": "destination IP", "dport": "destination port"},
            },
        },
        "filters": {
            "comm_filter": "Optional list of exact process names. Only events from these processes will be delivered. Example: ['mkdir', 'git', 'chmod']. If empty, all processes match.",
        },
    }, indent=2)


@mcp.tool
async def subscribe(agent_name: str, event_types: list[str], comm_filter: list[str] | None = None) -> str:
    """Configure which eBPF events this agent receives. Replaces any previous subscription.

    Args:
        agent_name: Your agent name (must match your .md filename without extension)
        event_types: List of event types to receive. Valid: process_exec, process_exit, file_open, net_connect
        comm_filter: Optional list of exact process names to watch. If omitted, all processes match.
    """
    invalid = set(event_types) - VALID_EVENTS
    if invalid:
        return f"Invalid event types: {invalid}. Valid: {sorted(VALID_EVENTS)}"

    if not _watcher or not _behaviors_file:
        return "Watcher not initialized yet"

    routing = _watcher._routing
    if agent_name not in routing:
        return f"Unknown agent: {agent_name}. Known: {list(routing.keys())}"

    routing[agent_name]["subscriptions"] = event_types
    routing[agent_name]["comm_filter"] = comm_filter or []
    _watcher.set_routing(routing)

    # Persist
    data = json.loads(_behaviors_file.read_text())
    if agent_name in data.get("subagents", {}):
        data["subagents"][agent_name]["subscriptions"] = event_types
        data["subagents"][agent_name]["comm_filter"] = comm_filter or []
        _behaviors_file.write_text(json.dumps(data, indent=2))

    result = f"Subscribed to {event_types}"
    if comm_filter:
        result += f" filtering for commands: {comm_filter}"
    logger.info("agent %s subscribed: events=%s comm_filter=%s", agent_name, event_types, comm_filter)
    return result


def run_mcp_server(port: int = 4097, nats_url: str = "nats://localhost:4222"):
    """Run the MCP server. Called from a background thread."""
    mcp.run(transport="streamable-http", port=port)
