"""Behavior agent — receives eBPF events from the Go daemon via Agentfield,
reasons about them using LM Studio (via app.ai()), and calls daemon functions back.

On first boot, the agent self-configures: it asks LM Studio which eBPF event
types and comm filters are relevant to its behavior, then persists this config
so subsequent boots skip the configuration step."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import msgspec
from agentfield import Agent, AIConfig

logger = logging.getLogger(__name__)

VALID_EVENTS = ["process_exec", "process_exit", "file_open", "net_connect"]

EVENT_SCHEMA = {
    "process_exec": {
        "description": "Fires when a new process starts (sched_process_exec tracepoint)",
        "data_fields": {"comm": "process name", "cmdline": "full command line", "pid": "process ID", "uid": "user ID", "filename": "executable path", "ppid": "parent process ID (shell PID for terminal notification)"},
    },
    "process_exit": {
        "description": "Fires when a process exits (sched_process_exit tracepoint)",
        "data_fields": {"comm": "process name", "pid": "process ID", "uid": "user ID", "exit_code": "exit status"},
    },
    "file_open": {
        "description": "Fires when a file is opened for writing in /etc/, /home/, /tmp/, /opt/, /root/, /srv/",
        "data_fields": {"comm": "process name", "pid": "process ID", "filename": "file path", "flags": "open flags"},
    },
    "net_connect": {
        "description": "Fires when a TCP connection is initiated (kprobe/tcp_v4_connect)",
        "data_fields": {"comm": "process name", "pid": "process ID", "daddr": "destination IP", "dport": "destination port"},
    },
}

DAEMON_SKILLS = [
    "subscribe", "unsubscribe",
    "exec", "enforce", "transform", "schedule", "measure", "notify",
    "map_read", "map_write", "map_delete",
    "program_list", "program_load", "program_detach",
]


async def self_configure(app: Agent, behavior: str, agent_id: str, behaviors_file: Path) -> dict:
    """Ask LM Studio which events and filters this behavior needs.

    Returns {"subscriptions": [...], "comm_filter": [...]} and persists
    it to behaviors.json so it's skipped on subsequent boots.
    """
    prompt = (
        f"You are configuring a Veronica eBPF behavior agent.\n\n"
        f"Behavior description: {behavior}\n\n"
        f"Available eBPF event types:\n"
        f"{json.dumps(EVENT_SCHEMA, indent=2)}\n\n"
        "Based on this behavior, decide:\n"
        "1. Which event types should this agent subscribe to? (list of strings)\n"
        "2. What process name filters (comm_filter) should narrow the events? "
        "(list of exact process names like 'mkdir', 'chmod', 'git', etc. Empty list = all processes)\n\n"
        "Respond with ONLY a JSON object:\n"
        '{"subscriptions": ["event_type1", ...], "comm_filter": ["process1", ...]}'
    )

    response = await app.ai(
        system="You are a configuration assistant. Respond with valid JSON only.",
        messages=[{"role": "user", "content": prompt}],
    )

    config = msgspec.json.decode(str(response).encode(), type=dict)

    # Validate
    subs = [s for s in config.get("subscriptions", []) if s in VALID_EVENTS]
    comm_filter = config.get("comm_filter", [])
    if not subs:
        subs = VALID_EVENTS  # fallback: subscribe to everything

    result = {"subscriptions": subs, "comm_filter": comm_filter}

    # Persist to behaviors.json
    if behaviors_file.exists():
        data = json.loads(behaviors_file.read_text())
        if agent_id in data.get("behaviors", {}):
            data["behaviors"][agent_id]["config"] = result
            behaviors_file.write_text(json.dumps(data, indent=2))

    logger.info("agent %s self-configured: subscriptions=%s comm_filter=%s", agent_id, subs, comm_filter)
    return result


def create_behavior_agent(
    agent_id: str,
    behavior: str,
    agentfield_url: str,
    llm_url: str,
    llm_model: str,
    behaviors_file: Path,
    existing_config: dict | None = None,
    llm_api_key: str | None = None,
) -> Agent:
    """Create an Agentfield agent for a user-defined behavior.

    If existing_config is None, the agent will self-configure on first
    serve() by asking LM Studio which events/filters to subscribe to.
    """

    app = Agent(
        node_id=f"veronica-{agent_id}",
        version="0.2.0",
        ai_config=AIConfig(
            model=f"openai/{llm_model}",
            api_base=llm_url,
            api_key=llm_api_key,
        ),
        agentfield_server=agentfield_url,
    )

    node_id = f"veronica-{agent_id}"

    system_prompt = (
        f"You are a Veronica behavior agent. Your behavior: {behavior}\n\n"
        f"You have access to these daemon skills via the control plane:\n"
        f"{', '.join(DAEMON_SKILLS)}\n\n"
        f"Available event types and their fields:\n"
        f"{msgspec.json.encode(EVENT_SCHEMA).decode()}\n\n"
        "When you receive an eBPF event, decide if and how to react based on your behavior. "
        'Respond with a JSON object: {"action": "<skill_name>", "params": {...}} '
        'or {"action": "none"} if no action needed. Only respond with the JSON, nothing else.'
    )

    async def _boot() -> None:
        """Self-configure (if needed) and subscribe with the daemon."""
        config = existing_config
        if not config:
            logger.info("agent %s: first boot, self-configuring...", agent_id)
            config = await self_configure(app, behavior, agent_id, behaviors_file)

        # Register with daemon so it starts sending us matching events
        await app.call(
            "veronicad.subscribe",
            node_id=node_id,
            events=config["subscriptions"],
            comm_filter=config.get("comm_filter", []),
        )
        logger.info("agent %s: subscribed to daemon for %s", agent_id, config["subscriptions"])

    # Store boot task so the CLI can await it after serve()
    app._boot = _boot

    @app.reasoner(tags=["behavior"])
    async def receive_event(event: str) -> dict[str, Any]:
        """Receive an eBPF event from the daemon and reason about how to react."""
        ev = msgspec.json.decode(event.encode(), type=dict)
        event_type = ev.get("type", "unknown")
        data = ev.get("data", {})
        comm = data.get("comm", "")

        logger.info("behavior %s received %s event: %s", agent_id, event_type, comm)

        event_text = msgspec.json.encode(ev).decode()

        decision = await app.ai(
            system=system_prompt,
            messages=[{"role": "user", "content": f"eBPF event received:\n{event_text}"}],
        )

        decision_data = msgspec.json.decode(str(decision).encode(), type=dict)

        if decision_data.get("action", "none") == "none":
            logger.info("behavior %s: no action for %s event", agent_id, event_type)
            return {"acted": False}

        action = decision_data["action"]
        params = decision_data.get("params", {})
        logger.info("behavior %s: calling %s with %s", agent_id, action, params)

        result = await app.call(f"veronicad.{action}", **params)
        return {"acted": True, "action": action, "result": result}

    return app
