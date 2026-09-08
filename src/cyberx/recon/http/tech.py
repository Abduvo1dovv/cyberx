"""Technology detection adapter. One GET, then parser fingerprints. No AI."""

from __future__ import annotations

from typing import Any

from cyberx.domain.models.actions import Action
from cyberx.ports.execution import ExecutionContext, RawArtifact
from cyberx.recon.http.adapter import HttpAdapter


class TechAdapter(HttpAdapter):
    name = "tech_adapter"
    action_types: tuple[str, ...] = ("technology_detection",)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact:
        artifact = super().run(action, ctx)
        return artifact.model_copy(update={"adapter_name": self.name})
