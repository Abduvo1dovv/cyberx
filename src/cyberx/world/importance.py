"""Deterministic asset importance. No invented business criticality."""

from __future__ import annotations

from typing import Any

from cyberx.domain.confidence import clamp01
from cyberx.domain.enums import PortState
from cyberx.domain.models.assets import (
    AuthenticationSurface,
    Endpoint,
    Host,
    Port,
    Service,
    UrlAsset,
)
from cyberx.world.signals import classify_path, path_from_locator, signal_weight

_HTTP_NAMES = frozenset({"http", "https", "http-alt", "ssl/http", "https-alt"})


def asset_importance(asset: Any, world: Any | None = None) -> float:
    """0..1 investigation importance. Business criticality stays unknown."""
    if asset is None:
        return 0.5
    if getattr(asset, "out_of_scope", False):
        return 0.1
    score = 0.35
    if isinstance(asset, Host):
        score = 0.55
        if world is not None:
            ports = [
                p
                for p in world.get_ports()
                if p.host_id == asset.asset_id and p.state is PortState.OPEN
            ]
            score += min(0.2, 0.04 * len(ports))
            score += min(0.1, 0.02 * _degree(world, asset.asset_id))
    elif isinstance(asset, Port):
        score = 0.50 if asset.number in {80, 443, 22} else 0.62
        if asset.state is not PortState.OPEN:
            score = 0.25
    elif isinstance(asset, Service):
        score = 0.70 if (asset.name or "").lower() in _HTTP_NAMES else 0.58
        if (asset.name or "").lower() not in _HTTP_NAMES | {"ssh", "unknown", ""}:
            score = 0.68
    elif isinstance(asset, UrlAsset):
        signal = classify_path(asset.path or "/")
        score = 0.60 + 0.25 * signal_weight(signal or "")
        if asset.status_code and 200 <= asset.status_code < 400:
            score += 0.05
    elif isinstance(asset, Endpoint):
        signal = classify_path(path_from_locator(getattr(asset, "url_canonical", "") or ""))
        score = 0.58 + 0.3 * signal_weight(signal or "")
        if asset.auth_required:
            score = max(score, 0.84)
    elif isinstance(asset, AuthenticationSurface):
        score = 0.88
    else:
        score = 0.40
    return clamp01(score)


def _degree(world: Any, asset_id: str) -> int:
    related = world.get_related_entities(asset_id) if hasattr(world, "get_related_entities") else ()
    return max(0, len(related) - 1)
