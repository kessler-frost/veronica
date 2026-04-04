"""Filesystem agent — handles file_open events."""

from __future__ import annotations

import asyncio
import logging

from veronica.agents.base import BaseAgent
from veronica.protocol.messages import EventData

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Veronica's filesystem agent. You monitor file access via eBPF.
When you receive a file_open event, check if the access is expected.
Flag access to sensitive files (shadow, SSH keys, crontabs).
Use read_file and shell_read to investigate. Use request_action to enforce policies."""


class FilesystemAgent(BaseAgent):
    subscribed_events = ["file_open"]

    async def handle_event(self, session: str, event: EventData) -> None:
        logger.info("filesystem event: %s %s", event.resource, event.data)
        filename = event.data.get("filename", "")
        result = await self.call_tool(session, "shell_read", {"cmd": "stat", "args": [filename]})
        logger.info("stat output: %s", result)


def main():
    logging.basicConfig(level=logging.INFO)
    agent = FilesystemAgent(agent_id="filesystem-01")
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
