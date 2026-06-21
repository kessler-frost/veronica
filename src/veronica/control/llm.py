"""LMStudioLLM — the production LLM adapter for the warden.

A direct call to LM Studio's OpenAI-compatible chat endpoint (per CLAUDE.md),
implementing the small `LLM` Protocol the warden/translate use. Tests inject a
mock instead, so this is never exercised on the host CI path.
"""

from __future__ import annotations

import httpx


class LMStudioLLM:
    def __init__(
        self,
        url: str,
        model: str,
        api_key: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    def complete(self, system: str, user: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        resp = httpx.post(
            f"{self.url}/v1/chat/completions",
            headers=headers,
            timeout=self.timeout,
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0,
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
