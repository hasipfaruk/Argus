"""Specialized agents.

Argus splits the "AI Security Engineer" role into focused agents, each with one
job. They operate on findings after scanning: enriching the narrative, simulating
attacks, and proposing fixes. Every agent degrades gracefully — with the
heuristic provider it uses templated reasoning; with a real model it produces
richer, context-aware analysis.
"""

from argus.agents.base import Agent, AgentContext
from argus.agents.enrichment import EnrichmentAgent
from argus.agents.exploit import AttackSimulationAgent
from argus.agents.patch import PatchAgent

__all__ = [
    "Agent",
    "AgentContext",
    "AttackSimulationAgent",
    "EnrichmentAgent",
    "PatchAgent",
]
