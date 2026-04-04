"""Process agent — handles process_exec, process_exit, and batch events."""

from __future__ import annotations

import asyncio
import logging

from veronica.agents.base import BaseAgent
from veronica.protocol.messages import EventData

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Veronica's process agent. You monitor process lifecycle via eBPF.
When you receive a process_exec event, analyze the command. Look for:
- Project scaffolding opportunities (user created a directory, cloned a repo)
- Suspicious binaries from non-standard paths
- Service crashes (process_exit with non-zero code)
Use shell_read to investigate (ps, ls, cat). Use request_action to take action."""


class ProcessAgent(BaseAgent):
    subscribed_events = ["process_exec", "process_exit", "batch"]

    async def handle_event(self, session: str, event: EventData) -> None:
        logger.info("process event: %s %s", event.resource, event.data)
        result = await self.call_tool(session, "shell_read", {"cmd": "ps", "args": ["aux"]})
        logger.info("ps output length: %d", len(str(result)))


def main():
    logging.basicConfig(level=logging.INFO)
    agent = ProcessAgent(agent_id="process-01")
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
