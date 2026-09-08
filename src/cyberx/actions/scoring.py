"""Deterministic v1 score formula (SPEC §15.6). Brain/planner is not implemented."""

from __future__ import annotations

from dataclasses import dataclass

from cyberx.domain.confidence import clamp01, validate_confidence
from cyberx.domain.enums import Risk

RISK_VALUE = {Risk.INFO: 0.1, Risk.LOW: 0.3, Risk.MEDIUM: 0.6}


@dataclass(frozen=True)
class ScoreFactors:
    mission_relevance: float
    information_gain: float
    evidence_strength: float
    p_useful: float
    novelty: float
    dependency_readiness: float
    cost: float
    risk: float


def compute_score(factors: ScoreFactors) -> float:
    for name, value in factors.__dict__.items():
        validate_confidence(value, field=name)
    if factors.novelty == 0.0 or factors.dependency_readiness == 0.0:
        return 0.0
    raw = (
        0.25 * factors.mission_relevance
        + 0.25 * factors.information_gain
        + 0.10 * factors.evidence_strength
        + 0.10 * factors.p_useful
        + 0.10 * factors.novelty
        + 0.10 * factors.dependency_readiness
        + 0.05 * (1.0 - factors.cost)
        + 0.05 * (1.0 - factors.risk)
    )
    return clamp01(raw)
