"""Execution-boundary contracts. No subprocess, no tool binaries here."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from pydantic import Field

from cyberx.domain.models.actions import Action, PolicyDecision
from cyberx.domain.models.common import DomainModel
from cyberx.domain.time import utcnow


class ExecutionContext(DomainModel):
    """Runtime context for one adapter invocation.

    M4 stub mode is in-memory: `workdir` is optional and unused. Real adapters
    (M10+) write artifacts under workdir without changing this contract.
    """

    mission_id: str
    action_id: str
    timeout_s: int
    rate_limit_hz: float | None = None
    scope_digest: str = ""
    stub: bool = True
    workdir: str | None = None
    allowed_targets: list[str] = Field(default_factory=list)
    allowed_networks: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    excluded_networks: list[str] = Field(default_factory=list)
    allowed_protocols: list[str] = Field(default_factory=list)
    allow_subdomains: bool = False
    source_interface: str | None = None
    source_address: str | None = None
    route_cidr: str | None = None
    reachability: str = "UNKNOWN"
    likely_tunnel: bool = False
    network_diagnostic: str = ""
    address_family: str = ""


class RawArtifact(DomainModel):
    """Adapter output. `path` is optional so stubs need no filesystem."""

    artifact_id: str
    tool_run_id: str
    adapter_name: str
    media_type: str
    sha256: str
    byte_size: int
    truncated: bool = False
    body: bytes | None = None
    path: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    mission_id: str
    source_locator: str | None = None


class AuthorizedAction(DomainModel):
    """Action that has passed catalog validation AND policy Allow. Required to execute."""

    action: Action
    decision: PolicyDecision
    issued_at: datetime = Field(default_factory=utcnow)

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


class ToolAdapter(Protocol):
    name: str
    action_types: tuple[str, ...]

    def is_available(self) -> bool: ...

    def build_argv(self, action: Action) -> list[str]: ...

    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact: ...


class ActionExecutor(Protocol):
    """Executors accept only AuthorizedAction — never a raw ActionRequest."""

    def execute(self, authorized: AuthorizedAction, ctx: ExecutionContext) -> object: ...
