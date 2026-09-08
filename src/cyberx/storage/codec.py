"""Explicit Domain object ↔ JSON mapping. No ORM."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from cyberx.domain.models.actions import Action, ActionResult, ToolRun
from cyberx.domain.models.assets import (
    Asset,
    AuthenticationSurface,
    Domain,
    Endpoint,
    Host,
    NetworkInterface,
    Parameter,
    Port,
    Service,
    Subdomain,
    Technology,
    UrlAsset,
)
from cyberx.domain.models.evidence import Claim, Evidence, KnowledgeGap, Observation
from cyberx.domain.models.findings import Finding, Hypothesis, TimelineEvent
from cyberx.domain.models.mission import Mission, Scope, Target

ASSET_TYPES: dict[str, type[Asset]] = {
    "host": Host,
    "interface": NetworkInterface,
    "port": Port,
    "service": Service,
    "technology": Technology,
    "domain": Domain,
    "subdomain": Subdomain,
    "url": UrlAsset,
    "endpoint": Endpoint,
    "parameter": Parameter,
    "auth_surface": AuthenticationSurface,
}


def dump_model(model: BaseModel) -> str:
    return model.model_dump_json()


def load_model(cls: type[Any], payload: str) -> Any:
    return cls.model_validate_json(payload)


def dump_asset(asset: Asset) -> str:
    return dump_model(asset)


def load_asset(kind: str, payload: str) -> Asset:
    cls = ASSET_TYPES.get(kind)
    if cls is None:
        raise ValueError(f"unknown asset kind: {kind}")
    return cls.model_validate_json(payload)


def load_mission(payload: str) -> Mission:
    return load_model(Mission, payload)


def load_target(payload: str) -> Target:
    return load_model(Target, payload)


def load_scope(payload: str) -> Scope:
    return load_model(Scope, payload)


def load_claim(payload: str) -> Claim:
    return load_model(Claim, payload)


def load_evidence(payload: str) -> Evidence:
    return load_model(Evidence, payload)


def load_observation(payload: str) -> Observation:
    return load_model(Observation, payload)


def load_gap(payload: str) -> KnowledgeGap:
    return load_model(KnowledgeGap, payload)


def load_hypothesis(payload: str) -> Hypothesis:
    return load_model(Hypothesis, payload)


def load_finding(payload: str) -> Finding:
    return load_model(Finding, payload)


def load_action(payload: str) -> Action:
    return load_model(Action, payload)


def load_result(payload: str) -> ActionResult:
    return load_model(ActionResult, payload)


def load_tool_run(payload: str) -> ToolRun:
    return load_model(ToolRun, payload)


def load_timeline(payload: str) -> TimelineEvent:
    return load_model(TimelineEvent, payload)
