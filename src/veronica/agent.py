"""Behavior agent — receives eBPF events from the Go daemon via Agentfield,
reasons about them using LM Studio (via app.ai()), and calls daemon functions back."""

from __future__ import annotations

import logging
from typing import Any

import msgspec
from agentfield import Agent, AIConfig

logger = logging.getLogger(__name__)

VALID_EVENTS = frozenset({"process_exec", "process_exit", "file_open", "net_connect"})

EVENT_SCHEMA = {
    "process_exec": {
        "description": "Fires when a new process starts",
        "data_fields": {"comm": "process name", "cmdline": "full command line", "pid": "process ID", "uid": "user ID", "filename": "executable path"},
    },
    "process_exit": {
        "description": "Fires when a process exits",
        "data_fields": {"comm": "process name", "pid": "process ID", "uid": "user ID", "exit_code": "exit status"},
    },
    "file_open": {
        "description": "Fires when a file is opened for writing",
        "data_fields": {"comm": "process name", "pid": "process ID", "filename": "file path", "flags": "open flags"},
    },
    "net_connect": {
        "description": "Fires when a TCP connection is initiated",
        "data_fields": {"comm": "process name", "pid": "process ID", "daddr": "destination IP", "dport": "destination port"},
    },
}

# Available daemon skills that behavior agents can call
DAEMON_SKILLS = [
    "exec", "enforce", "transform", "schedule", "measure",
    "map_read", "map_write", "map_delete",
    "program_list", "program_load", "program_detach",
]


def create_behavior_agent(
    name: str,
    behavior: str,
    agentfield_url: str,
    lm_studio_url: str,
    lm_studio_model: str,
) -> Agent:
    """Create an Agentfield agent for a user-defined behavior.

    This is a reasoner — it uses AI (LM Studio) to decide how to react to
    eBPF events, then calls deterministic daemon skills to take action.
    """

    # AIConfig uses LiteLLM format — openai/ prefix routes to any
    # OpenAI-compatible API (which LM Studio exposes).
    app = Agent(
        node_id=f"behavior-{name}",
        version="0.2.0",
        ai_config=AIConfig(
            model=f"openai/{lm_studio_model}",
            api_base=lm_studio_url,
        ),
        agentfield_server=agentfield_url,
    )

    system_prompt = (
        f"You are a Veronica behavior agent. Your behavior: {behavior}\n\n"
        f"You have access to these daemon skills via the control plane:\n"
        f"{', '.join(DAEMON_SKILLS)}\n\n"
        f"Available event types and their fields:\n"
        f"{msgspec.json.encode(EVENT_SCHEMA).decode()}\n\n"
        "When you receive an eBPF event, decide if and how to react based on your behavior. "
        "Respond with a JSON object: {\"action\": \"<skill_name>\", \"params\": {...}} "
        "or {\"action\": \"none\"} if no action needed. Only respond with the JSON, nothing else."
    )

    @app.reasoner(tags=["behavior", name])
    async def receive_event(event: str) -> dict[str, Any]:
        """Receive an eBPF event from the daemon and reason about how to react."""
        ev = msgspec.json.decode(event.encode(), type=dict)
        event_type = ev.get("type", "unknown")
        data = ev.get("data", {})

        logger.info("behavior %s received %s event: %s", name, event_type, data.get("comm", ""))

        event_text = msgspec.json.encode(ev).decode()

        # Use Agentfield's app.ai() which routes to LM Studio via AIConfig
        decision = await app.ai(
            system=system_prompt,
            messages=[{"role": "user", "content": f"eBPF event received:\n{event_text}"}],
        )

        decision_data = msgspec.json.decode(str(decision).encode(), type=dict)

        if decision_data.get("action", "none") == "none":
            logger.info("behavior %s: no action for %s event", name, event_type)
            return {"acted": False}

        # Call the daemon skill via Agentfield control plane
        action = decision_data["action"]
        params = decision_data.get("params", {})
        logger.info("behavior %s: calling %s with %s", name, action, params)

        result = await app.call(f"veronicad.{action}", **params)
        return {"acted": True, "action": action, "result": result}

    return app
