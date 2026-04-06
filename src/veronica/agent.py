"""Behavior agent — receives eBPF events from the Go daemon via Agentfield,
reasons about them using LM Studio, and calls daemon functions back."""

from __future__ import annotations

import logging
from typing import Any

import httpx
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

# Available daemon functions that behavior agents can call
DAEMON_FUNCTIONS = [
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
    """Create an Agentfield agent for a user-defined behavior."""

    app = Agent(
        node_id=f"behavior-{name}",
        version="0.2.0",
        agentfield_server=agentfield_url,
    )

    # LM Studio client for direct LLM calls
    llm_url = f"{lm_studio_url}/v1/chat/completions"

    @app.skill()
    async def receive_event(event: str) -> dict[str, Any]:
        """Receive an eBPF event from the daemon and decide how to react."""
        ev = msgspec.json.decode(event.encode(), type=dict)
        event_type = ev.get("type", "unknown")
        data = ev.get("data", {})

        logger.info("behavior %s received %s event: %s", name, event_type, data.get("comm", ""))

        # Ask LM Studio what to do
        system_prompt = (
            f"You are a Veronica behavior agent. Your behavior: {behavior}\n\n"
            f"You have access to these daemon functions via the control plane:\n"
            f"{', '.join(DAEMON_FUNCTIONS)}\n\n"
            f"Available event types and their fields:\n"
            f"{msgspec.json.encode(EVENT_SCHEMA).decode()}\n\n"
            "When you receive an eBPF event, decide if and how to react based on your behavior. "
            "Respond with a JSON object: {\"action\": \"<function_name>\", \"params\": {...}} "
            "or {\"action\": \"none\"} if no action needed. Only respond with the JSON, nothing else."
        )

        event_text = msgspec.json.encode(ev).decode()

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(llm_url, json={
                "model": lm_studio_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"eBPF event received:\n{event_text}"},
                ],
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
            })
            resp.raise_for_status()
            llm_result = resp.json()

        decision_text = llm_result["choices"][0]["message"]["content"]
        decision = msgspec.json.decode(decision_text.encode(), type=dict)

        if decision.get("action", "none") == "none":
            logger.info("behavior %s: no action for %s event", name, event_type)
            return {"acted": False}

        # Call the daemon function via Agentfield control plane
        action = decision["action"]
        params = decision.get("params", {})
        logger.info("behavior %s: calling %s with %s", name, action, params)

        result = await app.call(f"veronicad.{action}", **params)
        return {"acted": True, "action": action, "result": result}

    return app
