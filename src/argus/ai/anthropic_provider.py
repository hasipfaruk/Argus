"""Anthropic (Claude) provider.

Uses the official ``anthropic`` SDK if installed and ``ANTHROPIC_API_KEY`` is set.
Import of the SDK is deferred to :meth:`complete` so the module loads even when
the optional dependency is absent, availability is reported by ``is_available``.
"""

from __future__ import annotations

import os
from typing import Any

from argus.ai.base import AIProvider
from argus.core.plugin import ai_provider


@ai_provider
class AnthropicProvider(AIProvider):
    name = "anthropic"
    is_remote = True
    # A current, capable default; override via config `ai.model`.
    default_model = "claude-sonnet-5"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client: Any | None = None

    @classmethod
    def is_available(cls) -> bool:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return True

    def _get_client(self) -> Any:
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        return self._client

    def complete(self, system: str, user: str) -> str:
        client = self._get_client()
        resp = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        # Concatenate text blocks from the response content.
        return "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        ).strip()
