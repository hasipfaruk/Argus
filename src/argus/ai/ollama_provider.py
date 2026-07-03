"""Ollama provider — local models over HTTP.

Keeps source code inside your own environment: no SDK, no API key, just a running
Ollama server (default ``http://localhost:11434``). Uses ``httpx`` directly so it
has no extra install beyond Argus's base dependencies.
"""

from __future__ import annotations

import os

import httpx

from argus.ai.base import AIProvider
from argus.core.plugin import ai_provider


def _host() -> str:
    return os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")


@ai_provider
class OllamaProvider(AIProvider):
    name = "ollama"
    is_remote = False  # runs locally; source never leaves the machine
    default_model = "llama3.1"

    @classmethod
    def is_available(cls) -> bool:
        try:
            resp = httpx.get(f"{_host()}/api/tags", timeout=1.5)
            return resp.status_code == 200
        except Exception:
            return False

    def complete(self, system: str, user: str) -> str:
        resp = httpx.post(
            f"{_host()}/api/chat",
            json={
                "model": self.model,
                "stream": False,
                "options": {"temperature": self.temperature},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("message", {}).get("content", "").strip()
