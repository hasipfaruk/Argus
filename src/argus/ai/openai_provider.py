"""OpenAI provider.

Uses the official ``openai`` SDK if installed and ``OPENAI_API_KEY`` is set.
"""

from __future__ import annotations

import os

from argus.ai.base import AIProvider
from argus.core.plugin import ai_provider


@ai_provider
class OpenAIProvider(AIProvider):
    name = "openai"
    is_remote = True
    default_model = "gpt-4o"

    @classmethod
    def is_available(cls) -> bool:
        if not os.environ.get("OPENAI_API_KEY"):
            return False
        try:
            import openai  # noqa: F401
        except ImportError:
            return False
        return True

    def complete(self, system: str, user: str) -> str:
        from openai import OpenAI

        client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        resp = client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return (resp.choices[0].message.content or "").strip()
