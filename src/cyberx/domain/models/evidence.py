"""Evidence, observations, claims, gaps."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from cyberx.domain.confidence import validate_confidence
from cyberx.domain.enums import OBSERVATION_PREDICATES, EpistemicStatus
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import (
    PREFIX_ARTIFACT,
    PREFIX_CLAIM,
    PREFIX_EVIDENCE,
    PREFIX_GAP,
    PREFIX_MISSION,
    PREFIX_OBSERVATION,
    PREFIX_TOOL_RUN,
    require_id,
)
from cyberx.domain.models.common import DomainModel


class Observation(DomainModel):
    observation_id: str
    mission_id: str
    parser_id: str = Field(min_length=1)
    predicate: str
    object: Any
    subject_hint: str = Field(min_length=1)
    created_at: datetime
    extra: dict[str, Any] = Field(default_factory=dict)
    mapped: bool = True

    @field_validator("observation_id")
    @classmethod
    def _oid(cls, value: str) -> str:
        return require_id(value, PREFIX_OBSERVATION)

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)

    @model_validator(mode="after")
    def _size_and_predicate(self) -> Observation:
        blob = json.dumps(self.object, default=str)
        if len(blob.encode("utf-8")) > 8192:
            raise DomainValidationError("observation object exceeds 8KiB")
        extra_blob = json.dumps(self.extra, default=str)
        if len(extra_blob.encode("utf-8")) > 2048:
            raise DomainValidationError("observation extra exceeds 2KiB")
        self.mapped = self.predicate in OBSERVATION_PREDICATES
        return self


class Evidence(DomainModel):
    evidence_id: str
    mission_id: str
    observation_id: str
    artifact_id: str
    tool_run_id: str
    parser_id: str
    claim_preview: dict[str, Any]
    reliability: float
    created_at: datetime
    parent_evidence_id: str | None = None
    hash: str | None = None

    @field_validator("evidence_id")
    @classmethod
    def _eid(cls, value: str) -> str:
        return require_id(value, PREFIX_EVIDENCE)

    @field_validator("observation_id")
    @classmethod
    def _oid(cls, value: str) -> str:
        return require_id(value, PREFIX_OBSERVATION)

    @field_validator("artifact_id")
    @classmethod
    def _aid(cls, value: str) -> str:
        return require_id(value, PREFIX_ARTIFACT)

    @field_validator("tool_run_id")
    @classmethod
    def _rid(cls, value: str) -> str:
        return require_id(value, PREFIX_TOOL_RUN)

    @field_validator("reliability")
    @classmethod
    def _rel(cls, value: float) -> float:
        return validate_confidence(value, field="reliability")

    @field_validator("parser_id")
    @classmethod
    def _parser(cls, value: str) -> str:
        if value.lower() in {"ai", "llm", "hypothesis"}:
            raise DomainValidationError("AI cannot create Evidence")
        return value


class Claim(DomainModel):
    claim_id: str
    subject_id: str
    predicate: str
    object: Any
    epistemic_status: EpistemicStatus
    confidence: float
    evidence_ids: list[str] = Field(min_length=1)
    contradiction_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    @field_validator("claim_id")
    @classmethod
    def _cid(cls, value: str) -> str:
        return require_id(value, PREFIX_CLAIM)

    @field_validator("confidence")
    @classmethod
    def _conf(cls, value: float) -> float:
        return validate_confidence(value)

    @model_validator(mode="after")
    def _evidence(self) -> Claim:
        if not self.evidence_ids:
            raise DomainValidationError("claim requires at least one evidence_id")
        for eid in self.evidence_ids:
            require_id(eid, PREFIX_EVIDENCE)
        return self


class KnowledgeGap(DomainModel):
    gap_id: str
    kind: str
    subject_id: str | None = None
    detail: str = ""
    priority: float = 0.5
    closed: bool = False

    @field_validator("gap_id")
    @classmethod
    def _gid(cls, value: str) -> str:
        return require_id(value, PREFIX_GAP)

    @field_validator("priority")
    @classmethod
    def _pri(cls, value: float) -> float:
        return validate_confidence(value, field="priority")
