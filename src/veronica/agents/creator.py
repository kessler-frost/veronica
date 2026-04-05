"""Agent creator — translates natural language into agent config via LLM."""

from __future__ import annotations

import logging

import msgspec
from agno.agent import Agent
from agno.models.lmstudio import LMStudio

logger = logging.getLogger(__name__)

CREATOR_PROMPT = """You are a configuration generator for Veronica, an eBPF intelligence layer.
Given a natural language description of what an agent should do, output a JSON object with:
- "name": a short kebab-case name (e.g., "project-scaffolder")
- "events": list of eBPF event types to subscribe to. Valid types: process_exec, process_exit, net_connect, file_open
- "filter": object with optional filtering rules. All filters are whitelists (only matching events pass through).
  - "comm": list of command names to watch for (e.g., ["mkdir", "git", "npm"]). Omit to receive all commands.
  - "exit_codes": list of exit codes to watch for (e.g., [1, 2, 137]). Omit to receive all exit codes.
  - "paths": list of path prefixes to watch for in cmdline/filename (e.g., ["/etc/", "/var/www/"]). Omit to receive all paths.
- "context": a 1-2 sentence description of what the agent should focus on, written as instructions to the agent

Respond with ONLY the JSON object, no other text.

Examples:
User: "scaffold projects automatically based on directory creation"
{"name": "project-scaffolder", "events": ["process_exec"], "filter": {"comm": ["mkdir", "git", "npm", "uv", "cargo", "bun", "go", "pip", "poetry", "docker"]}, "context": "Focus on project creation commands. When you see one, check the directory and set it up with the appropriate tooling (uv init for Python, npm init for JS, go mod init for Go)."}

User: "block suspicious outbound connections"
{"name": "network-guardian", "events": ["net_connect"], "filter": {}, "context": "Monitor outbound TCP connections. Flag connections to unusual IPs or ports from unexpected processes. Use enforce to block suspicious traffic."}

User: "watch for service crashes and auto-restart them"
{"name": "crash-watcher", "events": ["process_exit"], "filter": {"comm": ["nginx", "postgres", "redis-server", "mongod", "mysqld", "httpd", "node", "python3", "python", "java", "gunicorn", "uvicorn"]}, "context": "Watch for non-zero exit codes from known services. Investigate the crash cause and restart the service if appropriate."}
"""

VALID_EVENTS = frozenset({"process_exec", "process_exit", "net_connect", "file_open"})


async def create_agent_config(description: str, llm_base_url: str, llm_model: str) -> dict:
    """Translate natural language into agent config via LLM.

    Returns dict with keys: name, events, context
    """
    agent = Agent(
        model=LMStudio(id=llm_model, base_url=llm_base_url),
        instructions=CREATOR_PROMPT,
        markdown=False,
        retries=3,
        delay_between_retries=2,
    )

    response = await agent.arun(description)
    content = response.content.strip() if response else ""
    logger.info("creator LLM response: %s", content[:500])

    # Extract JSON from response — model may wrap it in markdown or thinking tags
    json_start = content.find("{")
    json_end = content.rfind("}") + 1
    if json_start == -1 or json_end == 0:
        raise ValueError(f"No JSON object found in LLM response: {content[:200]}")
    content = content[json_start:json_end]

    config = msgspec.json.decode(content.encode(), type=dict)

    missing = {"name", "events", "context"} - set(config.keys())
    if missing:
        raise ValueError(f"LLM response missing fields: {missing}")

    invalid = set(config["events"]) - VALID_EVENTS
    if invalid:
        raise ValueError(f"Invalid event types: {invalid}")

    # Ensure filter is a dict (LLM might omit it)
    config.setdefault("filter", {})

    return config
