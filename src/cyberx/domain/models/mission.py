"""Mission, target, and scope entities."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from cyberx.domain.confidence import validate_confidence
from cyberx.domain.enums import (
    REGISTERED_AI_PROVIDERS,
    V1_POLICY_PROFILE,
    LocatorStatus,
    MissionMode,
    MissionStatus,
    StopReason,
    TargetKind,
)
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import PREFIX_MISSION, PREFIX_SCOPE, PREFIX_TARGET, require_id
from cyberx.domain.models.common import DomainModel


class Mission(DomainModel):
    mission_id: str
    name: str = Field(min_length=1, max_length=80)
    intent: str = Field(min_length=1, max_length=4000)
    mode: MissionMode
    status: MissionStatus
    target_id: str
    scope_id: str
    policy_profile: str = V1_POLICY_PROFILE
    ai_provider: str = "none"
    max_iterations: int = Field(default=50, ge=1, le=500)
    max_runtime_s: int = Field(default=3600, ge=1, le=14400)
    min_action_score: float = 0.15
    created_at: datetime
    authorized_by: str | None = None
    authorization_note: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    stop_reason: StopReason | None = None
    iteration: int = 0
    updated_at: datetime | None = None
    pause_requested: bool = False

    @field_validator("mission_id")
    @classmethod
    def _mission_id(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)

    @field_validator("target_id")
    @classmethod
    def _target_id(cls, value: str) -> str:
        return require_id(value, PREFIX_TARGET)

    @field_validator("scope_id")
    @classmethod
    def _scope_id(cls, value: str) -> str:
        return require_id(value, PREFIX_SCOPE)

    @field_validator("ai_provider")
    @classmethod
    def _provider(cls, value: str) -> str:
        if value not in REGISTERED_AI_PROVIDERS:
            raise DomainValidationError(f"unknown ai_provider: {value}")
        return value

    @field_validator("policy_profile")
    @classmethod
    def _profile(cls, value: str) -> str:
        if value != V1_POLICY_PROFILE:
            raise DomainValidationError("v1 policy_profile must be recon_default")
        return value

    @field_validator("min_action_score")
    @classmethod
    def _score(cls, value: float) -> float:
        return validate_confidence(value, field="min_action_score")

    @model_validator(mode="after")
    def _assessment_auth(self) -> Mission:
        if self.mode is MissionMode.AUTHORIZED_ASSESSMENT and not self.authorized_by:
            raise DomainValidationError("authorized_assessment requires authorized_by")
        return self


class ObservedLocator(DomainModel):
    """One observed address of a Target. An IP is a locator, not identity."""

    locator: str = Field(min_length=1, max_length=253)
    kind: str = Field(min_length=1, max_length=16)
    status: LocatorStatus = LocatorStatus.OBSERVED
    first_seen_at: datetime
    last_seen_at: datetime
    source: str = "operator"
    evidence_ids: list[str] = Field(default_factory=list)

    def is_current(self) -> bool:
        return self.status is LocatorStatus.CURRENT


class Target(DomainModel):
    target_id: str
    mission_id: str
    raw_input: str = Field(min_length=1)
    kind: TargetKind
    normalized: str = Field(min_length=1)
    created_at: datetime
    resolved_ipv4: list[str] = Field(default_factory=list)
    resolved_ipv6: list[str] = Field(default_factory=list)
    url_scheme: str | None = None
    url_port: int | None = None
    url_path: str | None = None
    canonical_identity: str = ""
    current_locator: str | None = None
    locator_history: list[ObservedLocator] = Field(default_factory=list)
    last_observed_at: datetime | None = None

    @field_validator("target_id")
    @classmethod
    def _tid(cls, value: str) -> str:
        return require_id(value, PREFIX_TARGET)

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)

    def identity_key(self) -> str:
        return self.canonical_identity or f"identity:raw:{self.normalized.lower()[:200]}"

    def previous_locator(self) -> str | None:
        historical = [
            item.locator for item in self.locator_history if item.status is LocatorStatus.HISTORICAL
        ]
        return historical[-1] if historical else None

    def historical_locators(self) -> list[str]:
        current = self.current_locator
        out: list[str] = []
        for item in self.locator_history:
            if item.locator == current:
                continue
            if item.locator not in out:
                out.append(item.locator)
        return out


class Scope(DomainModel):
    scope_id: str
    mission_id: str
    allowed_targets: list[str] = Field(default_factory=list)
    allowed_networks: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    allowed_protocols: list[str]
    version: int = 1
    frozen: bool = False
    created_at: datetime
    excluded_targets: list[str] = Field(default_factory=list)
    excluded_networks: list[str] = Field(default_factory=list)
    excluded_ports: list[int] = Field(default_factory=list)
    time_window_start: datetime | None = None
    time_window_end: datetime | None = None
    allow_subdomains: bool = True
    follow_redirects_in_scope_only: bool = True

    @field_validator("scope_id")
    @classmethod
    def _sid(cls, value: str) -> str:
        return require_id(value, PREFIX_SCOPE)

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)

    @field_validator("allowed_ports", "excluded_ports")
    @classmethod
    def _ports(cls, value: list[int]) -> list[int]:
        for port in value:
            if port < 1 or port > 65535:
                raise DomainValidationError(f"invalid port: {port}")
        return value

    @model_validator(mode="after")
    def _non_empty_allow(self) -> Scope:
        if not self.allowed_targets and not self.allowed_networks:
            raise DomainValidationError("scope needs allowed_targets or allowed_networks")
        if not self.allowed_protocols:
            raise DomainValidationError("allowed_protocols must be non-empty")
        if self.time_window_start and self.time_window_end:
            if self.time_window_end <= self.time_window_start:
                raise DomainValidationError("time_window_end must be after start")
        return self
