"""FastMCP server — exposes NATS tool responders as MCP tools for OpenCode."""

from __future__ import annotations

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
