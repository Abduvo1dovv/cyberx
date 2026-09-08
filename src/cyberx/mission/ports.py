"""Storage protocols used by MissionService. Domain stays free of I/O."""

from __future__ import annotations

from typing import Protocol

from cyberx.domain.models.assets import Asset
from cyberx.domain.models.findings import TimelineEvent
from cyberx.domain.models.mission import Mission, Scope, Target


class MissionBundle:
    __slots__ = ("mission", "target", "scope", "timeline", "seed_assets")

    def __init__(
        self,
        mission: Mission,
        target: Target,
        scope: Scope,
        timeline: list[TimelineEvent] | None = None,
        seed_assets: list[Asset] | None = None,
    ) -> None:
        self.mission = mission
        self.target = target
        self.scope = scope
        self.timeline = timeline or []
        self.seed_assets = seed_assets or []


class MissionStore(Protocol):
    def save(self, bundle: MissionBundle) -> None: ...

    def get(self, mission_id: str) -> MissionBundle: ...

    def list_missions(self) -> list[Mission]: ...
