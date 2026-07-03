"""Agent base class and shared context."""

from __future__ import annotations

import abc
from dataclasses import dataclass

from argus.ai.base import AIProvider
from argus.core.config import Config
from argus.core.models import Finding
from argus.core.project import Project


@dataclass
class AgentContext:
    project: Project
    config: Config
    ai: AIProvider


class Agent(abc.ABC):
    """Base class for finding-processing agents.

    An agent takes a finding and returns it (usually mutated). Keeping the return
    explicit lets the engine chain agents in a pipeline.
    """

    name: str = ""

    @abc.abstractmethod
    def process(self, finding: Finding, ctx: AgentContext) -> Finding:
        raise NotImplementedError

    @staticmethod
    def _uses_real_model(ctx: AgentContext) -> bool:
        """True when a real language model backs the provider (not heuristic)."""
        return ctx.ai.name != "heuristic"
