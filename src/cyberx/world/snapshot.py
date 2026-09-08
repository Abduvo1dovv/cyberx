"""Immutable World Model snapshot. Cache only; Evidence remains source of truth."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import Field

from cyberx.domain.enums import FindingStatus, PortState
from cyberx.domain.models.assets import (
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
from cyberx.domain.models.common import DomainModel
from cyberx.domain.models.evidence import Claim, Evidence, KnowledgeGap
from cyberx.domain.models.findings import Finding, Hypothesis
from cyberx.world.keys import object_key


class WorldSnapshot(DomainModel):
    mission_id: str
    revision: int
    updated_at: datetime
    digest: str
    last_evidence_id: str | None = None
    hosts: tuple[Host, ...] = ()
    interfaces: tuple[NetworkInterface, ...] = ()
    ports: tuple[Port, ...] = ()
    services: tuple[Service, ...] = ()
    technologies: tuple[Technology, ...] = ()
    domains: tuple[Domain, ...] = ()
    subdomains: tuple[Subdomain, ...] = ()
    urls: tuple[UrlAsset, ...] = ()
    endpoints: tuple[Endpoint, ...] = ()
    parameters: tuple[Parameter, ...] = ()
    auth_surfaces: tuple[AuthenticationSurface, ...] = ()
    claims: tuple[Claim, ...] = ()
    gaps: tuple[KnowledgeGap, ...] = ()
    findings: tuple[Finding, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    coverage: dict[str, str] = Field(default_factory=dict)
    unmapped: tuple[Evidence, ...] = ()
    recent_evidence: tuple[Evidence, ...] = ()

    def get_hosts(self) -> tuple[Host, ...]:
        return self.hosts

    def get_open_ports(self) -> tuple[Port, ...]:
        return tuple(p for p in self.ports if p.state is PortState.OPEN)

    def get_ports(self) -> tuple[Port, ...]:
        return self.ports

    def peek_asset_by_id(self, asset_id: str) -> Any:
        for group in (
            self.hosts,
            self.interfaces,
            self.ports,
            self.services,
            self.technologies,
            self.domains,
            self.subdomains,
            self.urls,
            self.endpoints,
            self.parameters,
            self.auth_surfaces,
        ):
            for asset in group:
                if asset.asset_id == asset_id:
                    return asset
        return None

    def get_related_entities(self, asset_id: str) -> tuple:
        root = self.peek_asset_by_id(asset_id)
        if root is None:
            return ()
        found: dict[str, Any] = {root.asset_id: root}
        parent_id = getattr(root, "parent_asset_id", None)
        if parent_id:
            parent = self.peek_asset_by_id(parent_id)
            if parent is not None:
                found[parent.asset_id] = parent
        for attr in ("host_id", "port_id", "url_id", "endpoint_id", "domain_id"):
            related_id = getattr(root, attr, None)
            if related_id:
                related = self.peek_asset_by_id(related_id)
                if related is not None:
                    found[related.asset_id] = related
        for group in (
            self.hosts,
            self.interfaces,
            self.ports,
            self.services,
            self.technologies,
            self.domains,
            self.subdomains,
            self.urls,
            self.endpoints,
            self.parameters,
            self.auth_surfaces,
        ):
            for other in group:
                if other.asset_id in found:
                    continue
                if getattr(other, "parent_asset_id", None) == asset_id:
                    found[other.asset_id] = other
                    continue
                for attr in ("host_id", "port_id", "url_id", "endpoint_id", "domain_id"):
                    if getattr(other, attr, None) == asset_id:
                        found[other.asset_id] = other
                        break
        items = list(found.values())
        items.sort(key=lambda a: a.canonical_key)
        return tuple(items)

    def get_services(self) -> tuple[Service, ...]:
        return self.services

    def get_web_surfaces(self) -> tuple[UrlAsset, ...]:
        return self.urls

    def get_technologies(self) -> tuple[Technology, ...]:
        return self.technologies

    def get_findings(self) -> tuple[Finding, ...]:
        return self.findings

    def get_claims(self, *, include_invalidated: bool = True) -> tuple[Claim, ...]:
        if include_invalidated:
            return self.claims
        return tuple(c for c in self.claims if c.epistemic_status.value != "INVALIDATED")

    def get_coverage(self) -> dict[str, str]:
        return dict(self.coverage)

    def get_auth_surfaces(self) -> tuple[AuthenticationSurface, ...]:
        return self.auth_surfaces

    def get_endpoints(self) -> tuple[Endpoint, ...]:
        return self.endpoints

    def get_hypotheses(self) -> tuple[Hypothesis, ...]:
        return self.hypotheses

    def get_gaps(self) -> tuple[KnowledgeGap, ...]:
        return self.gaps

    def get_conflicts(self) -> tuple[Claim, ...]:
        return tuple(
            c
            for c in self.claims
            if c.contradiction_ids or c.epistemic_status.value == "INVALIDATED"
        )

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {
            "host": len(self.hosts),
            "interface": len(self.interfaces),
            "port": len(self.ports),
            "service": len(self.services),
            "technology": len(self.technologies),
            "domain": len(self.domains),
            "subdomain": len(self.subdomains),
            "url": len(self.urls),
            "endpoint": len(self.endpoints),
            "parameter": len(self.parameters),
            "auth_surface": len(self.auth_surfaces),
        }
        by_status: dict[str, int] = {}
        for claim in self.claims:
            key = claim.epistemic_status.value
            by_status[key] = by_status.get(key, 0) + 1
        open_gaps = [g for g in self.gaps if not g.closed]
        open_findings = [f for f in self.findings if f.status is FindingStatus.OPEN]
        top_assets = [
            {"kind": "host", "key": h.canonical_key, "status": h.epistemic_status.value}
            for h in self.hosts[:20]
        ]
        top_assets.extend(
            {
                "kind": "service",
                "key": s.canonical_key,
                "status": s.epistemic_status.value,
            }
            for s in self.services[:15]
        )
        top_assets.extend(
            {"kind": "url", "key": u.canonical_key, "status": u.epistemic_status.value}
            for u in self.urls[:15]
        )
        return {
            "mission_id": self.mission_id,
            "revision": self.revision,
            "digest": self.digest,
            "asset_counts": counts,
            "claim_count": len(self.claims),
            "claim_counts_by_status": by_status,
            "open_gap_count": len(open_gaps),
            "conflict_count": len(self.get_conflicts()),
            "finding_count": len(open_findings),
            "hypothesis_count": len(self.hypotheses),
            "coverage_keys": sorted(self.coverage),
            "top_assets": top_assets[:50],
            "open_gaps": [
                {
                    "kind": g.kind,
                    "subject_id": g.subject_id or "",
                    "priority": g.priority,
                    "detail": g.detail,
                }
                for g in sorted(open_gaps, key=lambda g: (-g.priority, g.kind))[:50]
            ],
        }


def semantic_digest(
    *,
    mission_id: str,
    revision: int,
    assets: list[tuple[str, str, str, bool]],
    claims: list[tuple[str, str, str, str, float]],
    gaps: list[tuple[str, str, bool, str]],
    findings: list[tuple[str, str, str]],
    hypotheses: list[tuple[str, str]],
    coverage: dict[str, str],
    unmapped_count: int,
) -> str:
    """Identity-stable digest. Excludes random ULIDs so replay can compare."""
    payload = {
        "mission_id": mission_id,
        "revision": revision,
        "assets": sorted(assets),
        "claims": sorted(claims),
        "gaps": sorted(gaps),
        "findings": sorted(findings),
        "hypotheses": sorted(hypotheses),
        "coverage": dict(sorted(coverage.items())),
        "unmapped": unmapped_count,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def claim_semantic_tuple(subject_key: str, claim: Claim) -> tuple[str, str, str, str, float]:
    return (
        subject_key,
        claim.predicate,
        object_key(claim.object),
        claim.epistemic_status.value,
        round(float(claim.confidence), 6),
    )
