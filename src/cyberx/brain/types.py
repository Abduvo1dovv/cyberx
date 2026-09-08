"""Brain planning types. Decisions are structured — not free-form prose."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from cyberx.actions.scoring import ScoreFactors
from cyberx.domain.ids import PREFIX_DECISION, PREFIX_MISSION, require_id
from cyberx.domain.models.actions import ActionTarget
from cyberx.domain.models.common import DomainModel
from cyberx.domain.time import utcnow


class CandidateAction(DomainModel):
    action_type: str
    target: ActionTarget
    parameters: dict[str, Any] = Field(default_factory=dict)
    coverage_key: str
    reason: str = ""
    gap_kind: str = ""
    gap_subject: str = ""
    prerequisites: list[str] = Field(default_factory=list)
    expected_information_gain: float = 0.8
    risk: str = "info"
    cost: float = 0.5
    catalog_index: int = 0
    timeout_s: int = 30


class ScoredAction(DomainModel):
    candidate: CandidateAction
    score: float
    factors: dict[str, float] = Field(default_factory=dict)
    rejected: bool = False
    reject_reason: str = ""


class Decision(DomainModel):
    decision_id: str
    kind: str
    action: CandidateAction | None = None
    rejected: list[dict[str, str]] = Field(default_factory=list)
    rationale: str = ""
    scores: list[dict[str, str]] = Field(default_factory=list)
    context_revision: int = 0
    created_at: datetime = Field(default_factory=utcnow)
    stop_reason: str | None = None
    context_hash: str = ""

    def is_act(self) -> bool:
        return self.kind == "act" and self.action is not None


class HypothesisDelta(DomainModel):
    op: str
    statement: str
    gap_kind: str = ""
    gap_id: str = ""
    subject_id: str = ""
    confidence: float = 0.3
    rationale: str = ""
    hypothesis_id: str | None = None
    source: str = "heuristic"


class DecisionTrace(DomainModel):
    mission_id: str
    iteration: int
    context_revision: int
    context_hash: str = ""
    candidates: list[dict[str, str]] = Field(default_factory=list)
    selected_type: str | None = None
    selected_coverage_key: str | None = None
    rationale: str = ""
    policy_verdict: str | None = None
    execution_status: str | None = None
    world_revision: int = 0
    created_at: datetime = Field(default_factory=utcnow)

    def compact(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "iteration": self.iteration,
            "context_revision": self.context_revision,
            "context_hash": self.context_hash,
            "candidates": self.candidates[:20],
            "selected_type": self.selected_type,
            "selected_coverage_key": self.selected_coverage_key,
            "rationale": self.rationale[:300],
            "policy_verdict": self.policy_verdict,
            "execution_status": self.execution_status,
            "world_revision": self.world_revision,
        }


class CycleReport(DomainModel):
    mission_id: str
    iteration: int
    decision: Decision
    world_revision: int
    evidence_added: int = 0
    paused: bool = False
    completed: bool = False
    stop_reason: str | None = None
    selected_action_type: str | None = None
    coverage_key: str | None = None
    policy_verdict: str | None = None
    execution_status: str | None = None


def require_decision_id(value: str) -> str:
    return require_id(value, PREFIX_DECISION)


def require_mission(value: str) -> str:
    return require_id(value, PREFIX_MISSION)


def factors_as_dict(factors: ScoreFactors) -> dict[str, float]:
    return {
        "mission_relevance": factors.mission_relevance,
        "information_gain": factors.information_gain,
        "evidence_strength": factors.evidence_strength,
        "p_useful": factors.p_useful,
        "novelty": factors.novelty,
        "dependency_readiness": factors.dependency_readiness,
        "cost": factors.cost,
        "risk": factors.risk,
    }
