"""ValidationCandidate — a safe investigation question, never a vulnerability."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from cyberx.domain.confidence import validate_confidence
from cyberx.domain.enums import FORBIDDEN_ACTION_MARKERS, V1_ACTION_TYPES, ValidationStatus
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.identity import is_secret_shaped_name, is_secret_shaped_value
from cyberx.domain.ids import (
    PREFIX_EVIDENCE,
    PREFIX_FINDING,
    PREFIX_HYPOTHESIS,
    PREFIX_MISSION,
    PREFIX_VALIDATION,
    require_id,
)
from cyberx.domain.models.common import DomainModel
from cyberx.domain.time import utcnow

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"})


class ValidationCandidate(DomainModel):
    validation_id: str
    mission_id: str
    candidate_type: str = Field(min_length=1, max_length=64)
    identity_key: str = Field(min_length=1, max_length=400)
    status: ValidationStatus = ValidationStatus.PROPOSED
    reason: str = Field(min_length=1, max_length=500)
    finding_id: str | None = None
    asset_ids: list[str] = Field(default_factory=list)
    hypothesis_id: str | None = None
    mapped_action_type: str = ""
    coverage_key: str = ""
    locator: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    expected_predicates: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    current_confidence: float = 0.0
    priority: float = 0.0
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime | None = None
    source: str = "heuristic"

    @field_validator("validation_id")
    @classmethod
    def _vid(cls, value: str) -> str:
        return require_id(value, PREFIX_VALIDATION)

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)

    @field_validator("finding_id")
    @classmethod
    def _fid(cls, value: str | None) -> str | None:
        if value:
            return require_id(value, PREFIX_FINDING)
        return value

    @field_validator("hypothesis_id")
    @classmethod
    def _hid(cls, value: str | None) -> str | None:
        if value:
            return require_id(value, PREFIX_HYPOTHESIS)
        return value

    @field_validator("current_confidence")
    @classmethod
    def _conf(cls, value: float) -> float:
        return validate_confidence(value)

    @field_validator("priority")
    @classmethod
    def _pri(cls, value: float) -> float:
        return validate_confidence(value, field="priority")

    @field_validator("evidence_ids")
    @classmethod
    def _eids(cls, value: list[str]) -> list[str]:
        for item in value:
            require_id(item, PREFIX_EVIDENCE)
        return value

    @model_validator(mode="after")
    def _safety(self) -> ValidationCandidate:
        if self.source == "ai":
            raise DomainValidationError("AI cannot create validation candidates")
        if self.updated_at is None:
            self.updated_at = self.created_at
        action = (self.mapped_action_type or "").strip()
        if action:
            if action not in V1_ACTION_TYPES:
                raise DomainValidationError("validation may only map to catalogued v1 actions")
            lowered = action.lower()
            if any(marker in lowered for marker in FORBIDDEN_ACTION_MARKERS):
                raise DomainValidationError("unsafe validation action")
        method = str(self.parameters.get("method") or "GET").upper()
        if method in _UNSAFE_METHODS:
            raise DomainValidationError("validation cannot use unsafe HTTP methods")
        for key, raw in self.parameters.items():
            if is_secret_shaped_name(str(key)):
                raise DomainValidationError("validation parameters cannot contain secrets")
            if isinstance(raw, str) and is_secret_shaped_value(raw):
                raise DomainValidationError("validation parameters cannot contain secrets")
        return self

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> ValidationCandidate:
        copied = super().model_copy(update=update, deep=deep)
        return type(self).model_validate(copied.model_dump())
