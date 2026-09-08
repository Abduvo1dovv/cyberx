"""Deterministic replay from an ordered Evidence sequence. In-memory only."""

from __future__ import annotations

from collections.abc import Sequence

from cyberx.domain.models.assets import Asset
from cyberx.domain.models.evidence import Evidence
from cyberx.world.correlation import ScopeGate
from cyberx.world.model import InMemoryWorldModel


class Replay:
    def rebuild(
        self,
        mission_id: str,
        evidence: Sequence[Evidence],
        *,
        seed_assets: Sequence[Asset] = (),
        scope_gate: ScopeGate | None = None,
    ) -> InMemoryWorldModel:
        world = InMemoryWorldModel(mission_id, scope_gate=scope_gate)
        if seed_assets:
            world.seed_assets(seed_assets)
        for item in evidence:
            world.apply_evidence(item)
        return world
