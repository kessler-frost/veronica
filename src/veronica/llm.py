"""Async LLM client for OpenAI-compatible APIs (LM Studio, etc.)."""

from __future__ import annotations

import httpx


class LLMClient:
    """Thin async client for OpenAI-compatible chat completions."""

    def __init__(self, base_url: str = "http://localhost:1234", model: str = ""):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client = httpx.AsyncClient(timeout=120)

    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """Call chat completions API. Returns the full response dict."""
        payload = {"model": self.model, "messages": messages}
        if tools:
            payload["tools"] = tools
        resp = await self._client.post(
            f"{self.base_url}/v1/chat/completions",
            json=payload,
        )
        resp.raise_for_status()
        return resp.json()

    async def close(self):
        await self._client.aclose()
