"""Agent creator — translates natural language into agent config via LLM."""

from __future__ import annotations

import logging

import msgspec

from veronica.llm import LLMClient

logger = logging.getLogger(__name__)

CREATOR_PROMPT = """You are a configuration generator for Veronica, an eBPF intelligence layer.
Given a natural language description of what an agent should do, output a JSON object with:
- "name": a short kebab-case name (e.g., "project-scaffolder")
- "events": list of eBPF event types to subscribe to. Valid types: process_exec, process_exit, net_connect, file_open
- "context": a 1-2 sentence description of what the agent should focus on, written as instructions to the agent

Respond with ONLY the JSON object, no other text.

Examples:
User: "scaffold projects automatically based on directory creation"
{"name": "project-scaffolder", "events": ["process_exec"], "context": "Focus on mkdir, git clone, and project init commands. When you see one, check the directory and set it up with the appropriate tooling (uv init for Python, npm init for JS, go mod init for Go)."}

User: "block suspicious outbound connections"
{"name": "network-guardian", "events": ["net_connect"], "context": "Monitor outbound TCP connections. Flag connections to unusual IPs or ports from unexpected processes. Use enforce to block suspicious traffic."}

User: "watch for service crashes and auto-restart them"
{"name": "crash-watcher", "events": ["process_exit"], "context": "Watch for non-zero exit codes from known services (nginx, postgres, redis, etc). Investigate the crash cause and restart the service if appropriate."}
"""

VALID_EVENTS = frozenset({"process_exec", "process_exit", "net_connect", "file_open"})


async def create_agent_config(description: str, llm_base_url: str, llm_model: str) -> dict:
    """Translate natural language into agent config via LLM.

    Returns dict with keys: name, events, context
    """
    llm = LLMClient(base_url=llm_base_url, model=llm_model)

    response = await llm.chat([
        {"role": "system", "content": CREATOR_PROMPT},
        {"role": "user", "content": description},
    ])

    content = response["choices"][0]["message"]["content"]
    config = msgspec.json.decode(content.strip().encode(), type=dict)

    missing = {"name", "events", "context"} - set(config.keys())
    if missing:
        raise ValueError(f"LLM response missing fields: {missing}")

    invalid = set(config["events"]) - VALID_EVENTS
    if invalid:
        raise ValueError(f"Invalid event types: {invalid}")

    await llm.close()
    return config
