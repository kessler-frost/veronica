"""Thin OpenCode REST client — create sessions, send messages, subscribe to events."""

from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger(__name__)


class OpenCodeClient:
    """Minimal client for OpenCode's headless server REST API."""

    def __init__(self, base_url: str = "http://localhost:4096", directory: str | None = None):
        self.base_url = base_url
        self._headers = {}
        if directory:
            self._headers["X-OpenCode-Directory"] = directory

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def health(self) -> dict:
        async with httpx.AsyncClient() as c:
            resp = await c.get(self._url("/global/health"), headers=self._headers)
            resp.raise_for_status()
            return resp.json()

    async def create_session(self, parent_id: str | None = None) -> dict:
        body = {}
        if parent_id:
            body["parentID"] = parent_id
        async with httpx.AsyncClient() as c:
            resp = await c.post(self._url("/session"), json=body, headers=self._headers)
            resp.raise_for_status()
            return resp.json()

    async def send_message(
        self, session_id: str, text: str, agent: str = "build",
        provider_id: str | None = None, model_id: str | None = None,
    ) -> None:
        body = {
            "parts": [{"type": "text", "text": text}],
            "agent": agent,
        }
        if provider_id and model_id:
            body["model"] = {"providerID": provider_id, "modelID": model_id}
        async with httpx.AsyncClient() as c:
            resp = await c.post(
                self._url(f"/session/{session_id}/prompt_async"),
                json=body,
                headers=self._headers,
            )
            resp.raise_for_status()

    async def send_message_and_wait(
        self, session_id: str, text: str, agent: str = "build",
        provider_id: str | None = None, model_id: str | None = None,
        timeout: float = 120,
    ) -> None:
        """Send a message and wait for session.idle SSE event (LLM finished)."""
        done = asyncio.Event()

        async def _watch():
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout + 10, read=timeout + 10)) as c:
                async with c.stream("GET", self._url("/event"), headers=self._headers) as stream:
                    async for line in stream.aiter_lines():
                        if line.startswith("data:"):
                            data = line[5:].strip()
                            if '"session.idle"' in data and session_id in data:
                                done.set()
                                return

        watch_task = asyncio.create_task(_watch())
        # Small delay to ensure SSE stream is connected before sending
        await asyncio.sleep(0.2)
        await self.send_message(session_id, text, agent, provider_id, model_id)
        try:
            await asyncio.wait_for(done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("send_message_and_wait timed out after %ss for session %s", timeout, session_id)
        finally:
            watch_task.cancel()
            try:
                await watch_task
            except asyncio.CancelledError:
                pass

    async def list_sessions(self) -> list:
        async with httpx.AsyncClient() as c:
            resp = await c.get(self._url("/session"), headers=self._headers)
            resp.raise_for_status()
            return resp.json()

    async def abort_session(self, session_id: str) -> None:
        async with httpx.AsyncClient() as c:
            resp = await c.post(self._url(f"/session/{session_id}/abort"), headers=self._headers)
            resp.raise_for_status()

    async def list_agents(self) -> list:
        async with httpx.AsyncClient() as c:
            resp = await c.get(self._url("/agent"), headers=self._headers)
            resp.raise_for_status()
            return resp.json()
