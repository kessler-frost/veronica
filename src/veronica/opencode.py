"""Thin OpenCode REST client — create sessions, send messages, subscribe to events."""

from __future__ import annotations

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
