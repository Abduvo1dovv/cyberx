"""Findings, hypotheses, timeline."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from cyberx.domain.confidence import validate_confidence
from cyberx.domain.enums import (
    EpistemicStatus,
    FindingKind,
    FindingSeverity,
    FindingStatus,
    HypothesisSource,
    HypothesisStatus,
    TimelineKind,
)
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import (
    PREFIX_CLAIM,
    PREFIX_FINDING,
    PREFIX_HYPOTHESIS,
    PREFIX_MISSION,
    PREFIX_TIMELINE,
    require_id,
)
from cyberx.domain.models.common import DomainModel

_SHELL_MARKERS = (
    "&&",
    ";",
    "|",
    "`",
    "$(",
)


class Finding(DomainModel):
    finding_id: str
    mission_id: str
    kind: FindingKind
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=2000)
    severity: FindingSeverity
    epistemic_status: EpistemicStatus
    evidence_ids: list[str] = Field(min_length=1)
    asset_ids: list[str] = Field(min_length=1)
    created_at: datetime
    status: FindingStatus = FindingStatus.OPEN
    hypothesis_id: str | None = None
    recommendation: str | None = None
    confidence: float = 0.0
    identity_key: str = ""
    signal: str = ""
    source: str = "heuristic"
    observation_count: int = 1
    last_seen_at: datetime | None = None
    validation_state: str = ""
    validation_count: int = 0
    last_validation_result: str = ""

    @field_validator("finding_id")
    @classmethod
    def _fid(cls, value: str) -> str:
        return require_id(value, PREFIX_FINDING)

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)

    @field_validator("confidence")
    @classmethod
    def _conf(cls, value: float) -> float:
        return validate_confidence(value)

    @model_validator(mode="after")
    def _seen(self) -> Finding:
        if self.last_seen_at is None:
            self.last_seen_at = self.created_at
        if self.observation_count < 1:
            raise DomainValidationError("observation_count must be >= 1")
        if self.source == "ai":
            raise DomainValidationError("AI cannot create findings")
        return self

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Finding:
        copied = super().model_copy(update=update, deep=deep)
        return type(self).model_validate(copied.model_dump())


class Hypothesis(DomainModel):
    hypothesis_id: str
    mission_id: str
    statement: str = Field(min_length=1, max_length=500)
    status: HypothesisStatus
    confidence: float
    created_at: datetime
    rationale: str | None = None
    related_asset_ids: list[str] = Field(default_factory=list)
    related_gap_ids: list[str] = Field(default_factory=list)
    suggested_action_types: list[str] = Field(default_factory=list)
    source: HypothesisSource = HypothesisSource.HEURISTIC
    promoted_claim_id: str | None = None

    @field_validator("hypothesis_id")
    @classmethod
    def _hid(cls, value: str) -> str:
        return require_id(value, PREFIX_HYPOTHESIS)

    @field_validator("confidence")
    @classmethod
    def _conf(cls, value: float) -> float:
        return validate_confidence(value)

    @model_validator(mode="after")
    def _rules(self) -> Hypothesis:
        for marker in _SHELL_MARKERS:
            if marker in self.statement:
                raise DomainValidationError("hypothesis statement cannot contain shell commands")
        if self.source is HypothesisSource.AI and self.confidence > 0.4:
            raise DomainValidationError("AI hypothesis confidence is capped at 0.4")
        if self.status is HypothesisStatus.PROMOTED:
            if not self.promoted_claim_id:
                raise DomainValidationError("promoted hypothesis requires promoted_claim_id")
            require_id(self.promoted_claim_id, PREFIX_CLAIM)
        return self


class TimelineEvent(DomainModel):
    event_id: str
    mission_id: str
    kind: TimelineKind
    message: str = Field(min_length=1, max_length=1000)
    at: datetime
    ref_id: str | None = None
    payload_digest: str | None = None

    @field_validator("event_id")
    @classmethod
    def _eid(cls, value: str) -> str:
        return require_id(value, PREFIX_TIMELINE)

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)


class BrainContext(DomainModel):
    mission_id: str
    intent: str
    mode: str
    iteration: int
    scope_digest: str
    asset_counts: dict[str, int] = Field(default_factory=dict)
    top_assets: list[dict[str, str]] = Field(default_factory=list)
    claims: list[dict[str, str]] = Field(default_factory=list)
    gaps: list[dict[str, str]] = Field(default_factory=list)
    hypotheses: list[dict[str, str]] = Field(default_factory=list)
    coverage_keys: list[str] = Field(default_factory=list)
    recent_results: list[dict[str, str]] = Field(default_factory=list)
    recent_events: list[str] = Field(default_factory=list)
    revision: int = 0
    byte_size: int = 0
    conflicts: list[dict[str, str]] = Field(default_factory=list)
    top_findings: list[dict[str, str]] = Field(default_factory=list)
    investigations: list[dict[str, str]] = Field(default_factory=list)
    validation_candidates: list[dict[str, str]] = Field(default_factory=list)
    graph_digest: str = ""
    investigation_paths: list[dict[str, str]] = Field(default_factory=list)
    graph_focus: list[dict[str, str]] = Field(default_factory=list)
    network: dict[str, str] = Field(default_factory=dict)
    target_identity: dict[str, str] = Field(default_factory=dict)

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)
