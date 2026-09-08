"""IntelligenceProvider port. AI never executes actions or mutates policy/scope."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from cyberx.domain.models.findings import BrainContext, Finding


class HypothesisDraft(BaseModel):
    """Advisory hypothesis. Never a World Model fact. Never Evidence."""

    model_config = ConfigDict(extra="ignore")

    statement: str = Field(min_length=1, max_length=500)
    rationale: str = ""
    related_canonical_keys: list[str] = Field(default_factory=list)
    suggested_action_types: list[str] = Field(default_factory=list)
    confidence: float = 0.2
    evidence_ids: list[str] = Field(default_factory=list)


class ScoreAdvice(BaseModel):
    """Bounded score hint for an existing coverage_key. Never a new action."""

    model_config = ConfigDict(extra="ignore")

    coverage_key: str = Field(min_length=1)
    delta: float
    comment: str = ""


class IntelligenceProvider(Protocol):
    name: str

    def hypothesize(self, ctx: BrainContext) -> list[HypothesisDraft]: ...

    def advise_scores(
        self, candidates: Sequence[object], ctx: BrainContext
    ) -> list[ScoreAdvice]: ...

    def explain_finding(self, finding: Finding, ctx: BrainContext) -> str: ...

    def draft_report_section(self, report: object) -> str: ...
