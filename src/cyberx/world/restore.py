"""Hydrate an in-memory World Model from a snapshot (cache) + evidence."""

from __future__ import annotations

from collections.abc import Sequence

from cyberx.domain.models.assets import Asset
from cyberx.domain.models.evidence import Evidence
from cyberx.world.correlation import ScopeGate
from cyberx.world.model import InMemoryWorldModel
from cyberx.world.snapshot import WorldSnapshot


def hydrate_from_snapshot(
    snapshot: WorldSnapshot,
    *,
    seed_assets: Sequence[Asset] = (),
    evidence: Sequence[Evidence] = (),
    scope_gate: ScopeGate | None = None,
) -> InMemoryWorldModel:
    """Restore projected graph from a snapshot. Evidence is the source of truth index."""
    world = InMemoryWorldModel(snapshot.mission_id, scope_gate=scope_gate)
    world.hydrate(snapshot, seed_assets=seed_assets, evidence=evidence)
    return world
