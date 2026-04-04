"""Network agent — handles net_connect events."""

from __future__ import annotations

import asyncio
import logging

from veronica.agents.base import BaseAgent
from veronica.protocol.messages import EventData

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Veronica's network agent. You monitor TCP connections via eBPF.
When you receive a net_connect event, analyze the destination IP and port.
Flag suspicious outbound connections. Use shell_read to investigate (ss, ip, dig).
Use request_action to block traffic if needed."""


class NetworkAgent(BaseAgent):
    subscribed_events = ["net_connect"]

    async def handle_event(self, session: str, event: EventData) -> None:
        logger.info("network event: %s %s", event.resource, event.data)
        result = await self.call_tool(session, "shell_read", {"cmd": "ss", "args": ["-tnp"]})
        logger.info("ss output: %s", result)


def main():
    logging.basicConfig(level=logging.INFO)
    agent = NetworkAgent(agent_id="network-01")
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
