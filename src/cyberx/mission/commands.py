"""MissionService command objects."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from cyberx.domain.enums import MissionMode
from cyberx.domain.models.common import DomainModel
from cyberx.mission.scope_build import ScopeOverrides


class CreateMissionCmd(DomainModel):
    name: str = Field(min_length=1, max_length=80)
    intent: str = Field(min_length=1, max_length=4000)
    raw_target: str = Field(min_length=1)
    mode: MissionMode
    ai_provider: str = "none"
    authorized_by: str | None = None
    authorization_note: str | None = None
    allow_special_targets: bool = False
    max_iterations: int = Field(default=50, ge=1, le=500)
    max_runtime_s: int = Field(default=3600, ge=1, le=14400)
    min_action_score: float = 0.15
    policy_profile: str = "recon_default"
    allowed_targets: list[str] | None = None
    allowed_networks: list[str] | None = None
    allowed_ports: list[int] | None = None
    allowed_protocols: list[str] | None = None
    excluded_targets: list[str] | None = None
    excluded_networks: list[str] | None = None
    excluded_ports: list[int] | None = None
    allow_subdomains: bool | None = None
    time_window_start: datetime | None = None
    time_window_end: datetime | None = None

    def scope_overrides(self) -> ScopeOverrides:
        return ScopeOverrides(
            allowed_targets=self.allowed_targets,
            allowed_networks=self.allowed_networks,
            allowed_ports=self.allowed_ports,
            allowed_protocols=self.allowed_protocols,
            excluded_targets=self.excluded_targets,
            excluded_networks=self.excluded_networks,
            excluded_ports=self.excluded_ports,
            allow_subdomains=self.allow_subdomains,
            time_window_start=self.time_window_start,
            time_window_end=self.time_window_end,
        )


class ConfirmLocatorCmd(DomainModel):
    """Operator-only retarget of the current locator. Never expands Scope."""

    locator: str = Field(min_length=1, max_length=253)
    actor: str = "operator"
