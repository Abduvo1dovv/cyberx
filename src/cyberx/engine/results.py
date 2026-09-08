"""Structured execution outcome for M4 (no World Model apply)."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from cyberx.domain.models.actions import Action, ActionResult, ToolRun
from cyberx.domain.models.common import DomainModel
from cyberx.ports.execution import RawArtifact


class ExecutionOutcome(DomainModel):
    action: Action
    result: ActionResult
    tool_run: ToolRun
    artifact: RawArtifact
    observations: dict[str, Any] = Field(default_factory=dict)
