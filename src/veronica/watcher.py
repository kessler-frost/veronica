"""NATS event watcher — subscribes to eBPF events and routes to OpenCode subagent sessions."""

from __future__ import annotations

import asyncio
import logging

import msgspec
import nats

from veronica.opencode import OpenCodeClient

logger = logging.getLogger(__name__)

DEBOUNCE_WINDOW = 2.0


class EventWatcher:
    """Watches NATS events and routes them to appropriate OpenCode subagent sessions."""

    def __init__(self, nats_url: str, opencode: OpenCodeClient, provider_id: str = "", model_id: str = ""):
        self.nats_url = nats_url
        self._opencode = opencode
        self._provider_id = provider_id
        self._model_id = model_id
        self._nc = None
        self._subs: list = []
        self._routing: dict[str, dict] = {}
        self._buffers: dict[str, list] = {}
        self._debounce_tasks: dict[str, asyncio.Task] = {}
        self._processing: set[str] = set()

    def set_routing(self, routing: dict[str, dict]) -> None:
        """Update routing table. Called when subagents are added/removed."""
        self._routing = routing
        logger.info("routing updated: %s", list(routing.keys()))

    async def start(self) -> None:
        """Connect to NATS and subscribe to all event types."""
        self._nc = await nats.connect(self.nats_url)
        for event_type in ["process_exec", "process_exit", "file_open", "net_connect"]:
            sub = await self._nc.subscribe(f"events.{event_type}", cb=self._on_event)
            self._subs.append(sub)
        logger.info("event watcher started, subscribed to all event types")

    async def _on_event(self, msg) -> None:
        """Route incoming event to matching subagents."""
        event = msgspec.json.decode(msg.data, type=dict)
        event_type = msg.subject.replace("events.", "")
        data = event.get("data", {})
        comm = data.get("comm", "")

        for name, config in self._routing.items():
            subs = config.get("subscriptions", [])
            comm_filter = set(config.get("comm_filter", []))

            if event_type not in subs:
                continue

            if event_type in ("process_exec", "process_exit") and comm_filter and comm not in comm_filter:
                continue

            if name not in self._buffers:
                self._buffers[name] = []
            self._buffers[name].append(event)

            if len(self._buffers[name]) > 20:
                self._buffers[name] = self._buffers[name][-20:]

            if name in self._processing:
                continue
            if name in self._debounce_tasks and not self._debounce_tasks[name].done():
                self._debounce_tasks[name].cancel()
            self._debounce_tasks[name] = asyncio.create_task(self._flush(name))

    async def _flush(self, name: str) -> None:
        """After debounce window, send buffered events to the subagent's session."""
        await asyncio.sleep(DEBOUNCE_WINDOW)
        self._processing.add(name)

        events = self._buffers.pop(name, [])
        if not events:
            self._processing.discard(name)
            return

        config = self._routing.get(name, {})
        session_id = config.get("session_id")
        if not session_id:
            logger.warning("no session_id for subagent %s", name)
            self._processing.discard(name)
            return

        lines = [f"Batch of {len(events)} eBPF events:"]
        for ev in events[:5]:
            data = ev.get("data", {})
            detail = data.get("cmdline", "") or data.get("filename", "") or data.get("daddr", "")
            lines.append(f"  {data.get('comm', '')} {detail}")
        batch_text = "\n".join(lines)

        logger.info("sending %d events to subagent %s", len(events), name)
        await self._opencode.send_message(
            session_id, batch_text,
            provider_id=self._provider_id, model_id=self._model_id,
        )

        self._processing.discard(name)

        if name in self._buffers and self._buffers[name]:
            self._debounce_tasks[name] = asyncio.create_task(self._flush(name))

    async def stop(self) -> None:
        for sub in self._subs:
            await sub.unsubscribe()
        if self._nc:
            await self._nc.close()
