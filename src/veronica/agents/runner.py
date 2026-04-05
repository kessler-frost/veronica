"""Agent runner — watches NATS KV for agent configs, spawns/stops agents."""

from __future__ import annotations

import asyncio
import logging

import msgspec
import nats

from veronica.agents.base import BaseAgent
from veronica.config import VeronicaConfig

logger = logging.getLogger(__name__)


class DynamicAgent(BaseAgent):
    """An agent created from config stored in NATS KV."""

    def __init__(
        self,
        agent_id: str,
        nats_url: str,
        events: list[str],
        context_append: str,
        llm_provider: str = "openrouter",
        llm_base_url: str = "http://localhost:1234",
        llm_model: str = "",
        openrouter_model: str = "qwen/qwen3.6-plus:free",
        llm_semaphore: asyncio.Semaphore | None = None,
        event_filter: dict | None = None,
    ):
        super().__init__(
            agent_id=agent_id,
            nats_url=nats_url,
            llm_provider=llm_provider,
            llm_base_url=llm_base_url,
            llm_model=llm_model,
            openrouter_model=openrouter_model,
            llm_semaphore=llm_semaphore,
            event_filter=event_filter,
        )
        self.subscribed_events = events
        self._context_append = context_append

    def get_context_append(self) -> str:
        return self._context_append


class AgentRunner:
    """Watches the 'agents' KV bucket and manages agent lifecycle."""

    def __init__(self, cfg: VeronicaConfig):
        self.cfg = cfg
        self._nc = None
        self._tasks: dict[str, asyncio.Task] = {}
        self._agents: dict[str, BaseAgent] = {}
        self._configs: dict[str, dict] = {}
        self._llm_semaphore = asyncio.Semaphore(cfg.max_concurrent_agents)

    async def run(self) -> None:
        self._nc = await nats.connect(self.cfg.nats_url)
        js = self._nc.jetstream()

        logger.info("agent runner connected to %s", self.cfg.nats_url)

        # Load existing agents from KV
        kv = await js.key_value("agents")
        try:
            keys = await kv.keys()
        except Exception:
            keys = []

        for key in keys:
            entry = await kv.get(key)
            config = msgspec.json.decode(entry.value, type=dict)
            if config.get("status") == "active":
                await self._spawn_agent(key, config)

        # Watch for changes
        watcher = await kv.watchall()
        async for update in watcher:
            if update is None:
                continue

            agent_id = update.key

            # Handle deletion
            op = str(update.operation) if update.operation else ""
            if "DEL" in op or "PURGE" in op:
                await self._stop_agent(agent_id)
                continue

            if not update.value:
                continue
            config = msgspec.json.decode(update.value, type=dict)
            if config.get("status") == "active":
                if agent_id not in self._tasks:
                    await self._spawn_agent(agent_id, config)
                elif config != self._configs.get(agent_id):
                    # Config changed — restart with new settings
                    logger.info("config changed for %s, restarting", agent_id)
                    await self._stop_agent(agent_id)
                    await self._spawn_agent(agent_id, config)
            elif config.get("status") == "stopped" and agent_id in self._tasks:
                await self._stop_agent(agent_id)

    async def _spawn_agent(self, agent_id: str, config: dict) -> None:
        agent = DynamicAgent(
            agent_id=agent_id,
            nats_url=self.cfg.nats_url,
            events=config.get("events", []),
            context_append=config.get("context", ""),
            llm_provider=self.cfg.llm_provider,
            llm_base_url=self.cfg.llm_base_url,
            llm_model=self.cfg.llm_model,
            openrouter_model=self.cfg.openrouter_model,
            llm_semaphore=self._llm_semaphore,
            event_filter=config.get("filter"),
        )
        self._agents[agent_id] = agent
        self._configs[agent_id] = config
        self._tasks[agent_id] = asyncio.create_task(agent.run())
        logger.info("spawned agent %s subscribed to %s filter=%s", agent_id, config.get("events", []), config.get("filter", {}))

    async def _stop_agent(self, agent_id: str) -> None:
        task = self._tasks.pop(agent_id, None)
        agent = self._agents.pop(agent_id, None)
        self._configs.pop(agent_id, None)
        if task:
            task.cancel()
        if agent:
            await agent.close()
        logger.info("stopped agent %s", agent_id)

    async def close(self) -> None:
        for agent_id in list(self._tasks):
            await self._stop_agent(agent_id)
        if self._nc:
            await self._nc.close()
