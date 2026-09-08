"""Investigation priority — separate from ActionScorer (SPEC §15.6).

priority = clamp01(
    0.25 * signal_weight
  + 0.20 * confidence
  + 0.20 * asset_importance
  + 0.15 * surface_value
  + 0.10 * novelty
  + 0.05 * relationship_density
  + 0.05 * evidence_quality
)

AI never sets this score. Findings are recon signals, not vulns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cyberx.domain.confidence import clamp01
from cyberx.domain.enums import FindingStatus
from cyberx.domain.models.findings import Finding
from cyberx.world.importance import asset_importance
from cyberx.world.signals import signal_weight


@dataclass(frozen=True)
class InvestigationItem:
    finding_id: str
    title: str
    reason: str
    priority: float
    asset: str
    asset_id: str
    kind: str
    severity: str
    confidence: float


def investigation_priority(
    finding: Finding,
    *,
    asset: Any | None = None,
    world: Any | None = None,
) -> float:
    signal = finding.signal or finding.kind.value
    importance = asset_importance(asset, world) if asset is not None else 0.5
    surface = importance
    novelty = 1.0 if finding.observation_count <= 1 else 0.45
    evidence_quality = min(1.0, len(finding.evidence_ids) / 3.0)
    density = 0.0
    if world is not None and finding.asset_ids:
        related = (
            world.get_related_entities(finding.asset_ids[0])
            if hasattr(world, "get_related_entities")
            else ()
        )
        density = min(1.0, len(related) / 8.0)
    raw = (
        0.25 * signal_weight(signal)
        + 0.20 * clamp01(finding.confidence)
        + 0.20 * importance
        + 0.15 * surface
        + 0.10 * novelty
        + 0.05 * density
        + 0.05 * evidence_quality
    )
    return clamp01(raw)


def rank_investigations(world: Any, *, limit: int = 12) -> list[InvestigationItem]:
    items: list[InvestigationItem] = []
    for finding in world.get_findings():
        if finding.status is FindingStatus.INVALIDATED:
            continue
        if finding.status is FindingStatus.SUPERSEDED:
            continue
        asset = None
        asset_key = ""
        asset_id = finding.asset_ids[0] if finding.asset_ids else ""
        if asset_id:
            asset = world.peek_asset_by_id(asset_id)
            if asset is not None:
                asset_key = asset.canonical_key
        priority = investigation_priority(finding, asset=asset, world=world)
        items.append(
            InvestigationItem(
                finding_id=finding.finding_id,
                title=finding.title,
                reason=finding.signal or finding.kind.value,
                priority=priority,
                asset=asset_key,
                asset_id=asset_id,
                kind=finding.kind.value,
                severity=finding.severity.value,
                confidence=finding.confidence,
            )
        )
    items.sort(key=lambda i: (-i.priority, i.kind, i.title, i.finding_id))
    return items[:limit]
