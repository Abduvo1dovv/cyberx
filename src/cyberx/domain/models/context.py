"""Read-only BrainContext DTOs. Compact projections — not domain entities."""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, model_serializer

from cyberx.domain.confidence import AI_HYPOTHESIS_CONFIDENCE_CAP
from cyberx.domain.models.common import DomainModel

__all__ = [
    "AI_HYPOTHESIS_CONFIDENCE_CAP",
    "AssetContext",
    "ClaimContext",
    "ContextRow",
    "FindingContext",
    "GapContext",
    "GraphFocusContext",
    "HypothesisContext",
    "InvestigationContext",
    "NetworkContextSummary",
    "PathContext",
    "ResultContext",
    "TargetIdentityContext",
    "ValidationContext",
    "as_row_dump",
]


class ContextRow(DomainModel):
    """Attribute access is canonical. `get` is a string view for compact rows."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    def get(self, key: str, default: str = "") -> str:
        if key in type(self).model_fields:
            value = getattr(self, key)
        else:
            extra = getattr(self, "__pydantic_extra__", None) or {}
            if key not in extra:
                return default
            value = extra[key]
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            return "1" if value else "0"
        return value if isinstance(value, str) else str(value)

    def __getitem__(self, key: str) -> str:
        return self.get(key, "")

    def populated(self) -> bool:
        return any(self.get(name) for name in type(self).model_fields)

    @model_serializer(mode="wrap")
    def _omit_empty(self, serializer: Any) -> dict[str, Any]:
        data = serializer(self)
        if not isinstance(data, dict):
            return data
        return {key: value for key, value in data.items() if value not in ("", None)}


class AssetContext(ContextRow):
    kind: str = ""
    id: str = ""
    key: str = ""
    address: str = ""
    status: str = ""
    labels: str = ""
    name: str = ""
    oos: str = ""
    port_id: str = ""
    url: str = ""
    host: str = ""
    port: str = ""
    scheme: str = ""
    path: str = ""
    http_status: str = ""
    title: str = ""
    method: str = ""
    auth: str = ""
    auth_kind: str = ""
    product: str = ""
    version: str = ""
    host_id: str = ""
    number: str = ""
    protocol: str = ""
    state: str = ""
    fqdn: str = ""


class GapContext(ContextRow):
    kind: str = ""
    id: str = ""
    subject_id: str = ""
    subject_key: str = ""
    detail: str = ""
    priority: str = ""


class ClaimContext(ContextRow):
    predicate: str = ""
    object: str = ""
    status: str = ""
    subject_id: str = ""
    confidence: str = ""


class FindingContext(ContextRow):
    id: str = ""
    title: str = ""
    kind: str = ""
    signal: str = ""
    severity: str = ""
    confidence: str = ""
    asset_id: str = ""


class HypothesisContext(ContextRow):
    id: str = ""
    statement: str = ""
    status: str = ""


class ValidationContext(ContextRow):
    id: str = ""
    type: str = ""
    status: str = ""
    action: str = ""
    reason: str = ""
    priority: str = ""
    finding_id: str = ""
    coverage_key: str = ""
    locator: str = ""
    asset_id: str = ""
    hypothesis_id: str = ""
    url: str = ""
    url_id: str = ""
    host_id: str = ""
    port: str = ""


class InvestigationContext(ContextRow):
    id: str = ""
    title: str = ""
    reason: str = ""
    priority: str = ""
    asset: str = ""
    asset_id: str = ""


class PathContext(ContextRow):
    id: str = ""
    key: str = ""
    labels: str = ""
    priority: str = ""
    action: str = ""
    locator: str = ""
    questions: str = ""
    oos: str = ""
    asset_id: str = ""
    url: str = ""
    url_id: str = ""
    host_id: str = ""
    port: str = ""
    domain_id: str = ""
    fqdn: str = ""
    completeness: str = ""
    confidence: str = ""


class ResultContext(ContextRow):
    action_id: str = ""
    status: str = ""
    result_id: str = ""


class GraphFocusContext(ContextRow):
    kind: str = ""
    src: str = ""
    dst: str = ""


class NetworkContextSummary(ContextRow):
    target: str = ""
    target_ip: str = ""
    reachability: str = ""
    interface: str = ""
    source: str = ""
    route: str = ""
    tunnel: str = ""
    tunnel_hint: str = ""
    diagnostic: str = ""
    available: str = ""
    route_in_scope: str = ""
    platform: str = ""
    digest: str = ""
    changed: str = ""
    current_locator: str = ""
    historical_locator: str = ""
    identity: str = ""


class TargetIdentityContext(ContextRow):
    identity: str = ""
    kind: str = ""
    current: str = ""
    previous: str = ""
    historical: str = ""
    normalized: str = ""
    reachability: str = ""


def as_row_dump(item: Any) -> Any:
    dump = getattr(item, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    return item
