"""Read APIs over a live World Model or a snapshot. No writes."""

from __future__ import annotations

from typing import Any

from cyberx.domain.models.assets import (
    AuthenticationSurface,
    Host,
    Port,
    Service,
    Technology,
    UrlAsset,
)
from cyberx.domain.models.evidence import Claim, Evidence, KnowledgeGap
from cyberx.domain.models.findings import Finding, Hypothesis
from cyberx.world.model import InMemoryWorldModel
from cyberx.world.snapshot import WorldSnapshot

WorldView = InMemoryWorldModel | WorldSnapshot


def get_hosts(view: WorldView) -> tuple[Host, ...]:
    return view.get_hosts()


def get_open_ports(view: WorldView) -> tuple[Port, ...]:
    return view.get_open_ports()


def get_services(view: WorldView) -> tuple[Service, ...]:
    return view.get_services()


def get_web_surfaces(view: WorldView) -> tuple[UrlAsset, ...]:
    return view.get_web_surfaces()


def get_technologies(view: WorldView) -> tuple[Technology, ...]:
    return view.get_technologies()


def get_findings(view: WorldView) -> tuple[Finding, ...]:
    return view.get_findings()


def get_hypotheses(view: WorldView) -> tuple[Hypothesis, ...]:
    return view.get_hypotheses()


def get_gaps(view: WorldView) -> list[KnowledgeGap] | tuple[KnowledgeGap, ...]:
    return view.get_gaps()


def get_conflicts(view: WorldView) -> tuple[Claim, ...]:
    return view.get_conflicts()


def get_recent_evidence(view: WorldView, limit: int = 20) -> tuple[Evidence, ...]:
    if isinstance(view, WorldSnapshot):
        return view.recent_evidence[-limit:]
    return view.get_recent_evidence(limit)


def get_related_entities(model: InMemoryWorldModel, asset_id: str):
    return model.get_related_entities(asset_id)


def get_auth_surfaces(model: InMemoryWorldModel) -> tuple[AuthenticationSurface, ...]:
    return model.get_auth_surfaces()


def summary(view: WorldView) -> dict[str, Any]:
    if isinstance(view, WorldSnapshot):
        return view.summary()
    return view.summary()
