"""Action instances, results, tool runs, policy decisions."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from cyberx.domain.confidence import validate_confidence
from cyberx.domain.enums import (
    ActionResultStatus,
    ActionStatus,
    PolicyVerdict,
    Risk,
)
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import (
    PREFIX_ACTION,
    PREFIX_ARTIFACT,
    PREFIX_DECISION,
    PREFIX_MISSION,
    PREFIX_RESULT,
    PREFIX_TOOL_RUN,
    require_id,
)
from cyberx.domain.models.common import DomainModel

_FORBIDDEN_ARGV = ("|", "||", "&&", ";", "`")


class ActionTarget(DomainModel):
    """Asset id and/or canonical locator (SPEC §2.20)."""

    asset_id: str | None = None
    canonical_locator: str | None = None

    @model_validator(mode="after")
    def _some_locator(self) -> ActionTarget:
        if not self.asset_id and not self.canonical_locator:
            raise DomainValidationError("ActionTarget requires asset_id or canonical_locator")
        return self


class ActionRequest(DomainModel):
    """Planner/operator request before it becomes a persisted Action."""

    mission_id: str
    action_type: str
    target: ActionTarget
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(default="", max_length=500)
    timeout_s: int | None = None
    prerequisites: list[str] = Field(default_factory=list)
    expected_information_gain: float | None = None
    risk: Risk | None = None

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)


class Action(DomainModel):
    action_id: str
    mission_id: str
    action_type: str
    target: ActionTarget
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(max_length=500)
    expected_information_gain: float
    risk: Risk
    timeout_s: int = Field(ge=1)
    prerequisites: list[str] = Field(default_factory=list)
    evidence_expected: list[str] = Field(default_factory=list)
    status: ActionStatus
    coverage_key: str
    created_at: datetime
    score: float | None = None
    decision_id: str | None = None
    attempt: int = 1
    parent_action_id: str | None = None

    @field_validator("action_id")
    @classmethod
    def _aid(cls, value: str) -> str:
        return require_id(value, PREFIX_ACTION)

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)

    @field_validator("expected_information_gain")
    @classmethod
    def _gain(cls, value: float) -> float:
        return validate_confidence(value, field="expected_information_gain")

    @field_validator("decision_id")
    @classmethod
    def _dec(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return require_id(value, PREFIX_DECISION)

    @field_validator("parent_action_id")
    @classmethod
    def _parent(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return require_id(value, PREFIX_ACTION)

    @field_validator("score")
    @classmethod
    def _score(cls, value: float | None) -> float | None:
        if value is None:
            return value
        return validate_confidence(value, field="score")


class ActionResult(DomainModel):
    result_id: str
    action_id: str
    tool_run_id: str
    status: ActionResultStatus
    started_at: datetime
    ended_at: datetime
    error_code: str | None = None
    error_message: str | None = Field(default=None, max_length=300)
    observation_count: int = 0
    evidence_ids: list[str] = Field(default_factory=list)

    @field_validator("result_id")
    @classmethod
    def _rid(cls, value: str) -> str:
        return require_id(value, PREFIX_RESULT)

    @field_validator("action_id")
    @classmethod
    def _aid(cls, value: str) -> str:
        return require_id(value, PREFIX_ACTION)

    @field_validator("tool_run_id")
    @classmethod
    def _tid(cls, value: str) -> str:
        return require_id(value, PREFIX_TOOL_RUN)


class ToolRun(DomainModel):
    tool_run_id: str
    action_id: str
    adapter_name: str
    argv: list[str]
    started_at: datetime
    status: str
    exit_code: int | None = None
    ended_at: datetime | None = None
    artifact_id: str | None = None
    timed_out: bool = False
    unavailable: bool = False

    @field_validator("tool_run_id")
    @classmethod
    def _rid(cls, value: str) -> str:
        return require_id(value, PREFIX_TOOL_RUN)

    @field_validator("action_id")
    @classmethod
    def _aid(cls, value: str) -> str:
        return require_id(value, PREFIX_ACTION)

    @field_validator("artifact_id")
    @classmethod
    def _art(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return require_id(value, PREFIX_ARTIFACT)

    @field_validator("argv")
    @classmethod
    def _argv(cls, value: list[str]) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise DomainValidationError("argv must be a list of strings")
        for item in value:
            stripped = item.strip()
            if stripped in _FORBIDDEN_ARGV or "&&" in item or ";" in item or "|" in item:
                raise DomainValidationError("argv contains forbidden shell operator token")
        return value


class PolicyDecision(DomainModel):
    verdict: PolicyVerdict
    reason_code: str
    message: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict is PolicyVerdict.ALLOW


class ScopeSubject(DomainModel):
    """Resolved action subject used by ScopeChecker (SPEC §4.8)."""

    ips: list[str] = Field(default_factory=list)
    fqdns: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    protocol: str | None = None
    url: str | None = None
    schemes: list[str] = Field(default_factory=list)
