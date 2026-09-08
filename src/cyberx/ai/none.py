"""Default IntelligenceProvider. Heuristics-only; never talks to a network."""

from __future__ import annotations

from collections.abc import Sequence

from cyberx.ai.protocol import HypothesisDraft, ScoreAdvice
from cyberx.domain.models.findings import BrainContext, Finding


class NoneProvider:
    name = "none"
    available = False
    status_reason = "provider not configured"
    model = ""
    calls = 0
    budget = 0

    def hypothesize(self, ctx: BrainContext) -> list[HypothesisDraft]:
        del ctx
        return []

    def advise_scores(self, candidates: Sequence[object], ctx: BrainContext) -> list[ScoreAdvice]:
        del candidates, ctx
        return []

    def explain_finding(self, finding: Finding, ctx: BrainContext) -> str:
        del finding, ctx
        return ""

    def draft_report_section(self, report: object) -> str:
        del report
        return ""
