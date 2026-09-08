"""Project a WorldSnapshot into an attack-surface graph. Deterministic, read-only."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from cyberx.domain.enums import EpistemicStatus, GraphEdgeKind, GraphNodeKind
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
from cyberx.domain.models.graph import GraphEdge, GraphNode, GraphSnapshot
from cyberx.domain.models.validation import ValidationCandidate
from cyberx.world.snapshot import WorldSnapshot

_HTTP_NAMES = frozenset({"http", "https", "http-alt", "ssl/http", "https-alt"})
_ASSET_KIND = {
    "host": GraphNodeKind.HOST,
    "interface": GraphNodeKind.INTERFACE,
    "port": GraphNodeKind.PORT,
    "service": GraphNodeKind.SERVICE,
    "technology": GraphNodeKind.TECHNOLOGY,
    "domain": GraphNodeKind.DOMAIN,
    "subdomain": GraphNodeKind.SUBDOMAIN,
    "url": GraphNodeKind.URL,
    "endpoint": GraphNodeKind.ENDPOINT,
    "parameter": GraphNodeKind.PARAMETER,
    "auth_surface": GraphNodeKind.AUTH_SURFACE,
}


class GraphProjector:
    """World Model → graph. Callers cannot inject arbitrary edges."""

    def project(
        self,
        snapshot: WorldSnapshot,
        *,
        validation_candidates: Sequence[Any] | None = None,
    ) -> GraphSnapshot:
        builder = _Builder(snapshot)
        builder.add_assets()
        builder.add_identity_edges()
        builder.add_resolution_edges()
        builder.add_web_edges()
        builder.add_findings()
        builder.add_hypotheses()
        builder.add_validations(validation_candidates or ())
        return builder.snapshot()


class _Builder:
    def __init__(self, snapshot: WorldSnapshot) -> None:
        self.snap = snapshot
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}
        self.by_id: dict[str, Any] = {}
        for group in (
            snapshot.hosts,
            snapshot.interfaces,
            snapshot.ports,
            snapshot.services,
            snapshot.technologies,
            snapshot.domains,
            snapshot.subdomains,
            snapshot.urls,
            snapshot.endpoints,
            snapshot.parameters,
            snapshot.auth_surfaces,
        ):
            for asset in group:
                self.by_id[asset.asset_id] = asset

    def add_assets(self) -> None:
        for asset in self.by_id.values():
            kind = _ASSET_KIND.get(asset.kind.value)
            if kind is None:
                continue
            evidence = _evidence_for(self.snap, asset.asset_id)
            self._node(
                GraphNode(
                    node_id=asset.asset_id,
                    kind=kind,
                    semantic_key=asset.canonical_key,
                    label=_label(asset),
                    ref_id=asset.asset_id,
                    epistemic_status=asset.epistemic_status.value,
                    out_of_scope=bool(getattr(asset, "out_of_scope", False)),
                    confidence=_status_confidence(asset.epistemic_status),
                    evidence_ids=evidence,
                )
            )

    def add_identity_edges(self) -> None:
        for iface in self.snap.interfaces:
            host = self.by_id.get(iface.host_id)
            if isinstance(host, Host):
                self._edge(
                    GraphEdgeKind.HOSTS,
                    host,
                    iface,
                    rule="identity:interface.host_id",
                )
        for port in self.snap.ports:
            host = self.by_id.get(port.host_id)
            if isinstance(host, Host):
                self._edge(
                    GraphEdgeKind.EXPOSES,
                    host,
                    port,
                    rule="identity:port.host_id",
                    evidence=_evidence_for(self.snap, port.asset_id),
                    status=port.epistemic_status.value,
                )
        for svc in self.snap.services:
            port = self.by_id.get(svc.port_id)
            if isinstance(port, Port):
                self._edge(
                    GraphEdgeKind.RUNS,
                    port,
                    svc,
                    rule="identity:service.port_id",
                    evidence=_evidence_for(self.snap, svc.asset_id),
                    status=svc.epistemic_status.value,
                )
        for tech in self.snap.technologies:
            parent = self.by_id.get(tech.parent_asset_id)
            if parent is not None:
                self._edge(
                    GraphEdgeKind.IMPLEMENTS,
                    parent,
                    tech,
                    rule="identity:technology.parent_asset_id",
                    evidence=_evidence_for(self.snap, tech.asset_id),
                    status=tech.epistemic_status.value,
                )
        for sub in self.snap.subdomains:
            domain = self.by_id.get(sub.domain_id)
            if isinstance(domain, Domain):
                self._edge(
                    GraphEdgeKind.CONTAINS,
                    domain,
                    sub,
                    rule="identity:subdomain.domain_id",
                    evidence=_evidence_for(self.snap, sub.asset_id),
                    status=sub.epistemic_status.value,
                )
        for ep in self.snap.endpoints:
            url = self.by_id.get(ep.url_id)
            if isinstance(url, UrlAsset):
                self._edge(
                    GraphEdgeKind.CONTAINS,
                    url,
                    ep,
                    rule="identity:endpoint.url_id",
                    evidence=_evidence_for(self.snap, ep.asset_id),
                    status=ep.epistemic_status.value,
                )
        for param in self.snap.parameters:
            ep = self.by_id.get(param.endpoint_id)
            if isinstance(ep, Endpoint):
                self._edge(
                    GraphEdgeKind.CONTAINS,
                    ep,
                    param,
                    rule="identity:parameter.endpoint_id",
                    evidence=_evidence_for(self.snap, param.asset_id),
                    status=param.epistemic_status.value,
                )
        for auth in self.snap.auth_surfaces:
            parent = None
            if auth.endpoint_id:
                parent = self.by_id.get(auth.endpoint_id)
            if parent is None and auth.url_id:
                parent = self.by_id.get(auth.url_id)
            if parent is not None:
                self._edge(
                    GraphEdgeKind.AUTHENTICATES,
                    parent,
                    auth,
                    rule="identity:auth_surface.endpoint_or_url",
                    evidence=_evidence_for(self.snap, auth.asset_id),
                    status=auth.epistemic_status.value,
                )

    def add_resolution_edges(self) -> None:
        hosts_by_addr: dict[str, Host] = {}
        for host in self.snap.hosts:
            if host.ipv4:
                hosts_by_addr[host.ipv4] = host
            if host.ipv6:
                hosts_by_addr[host.ipv6] = host
            if host.hostname:
                hosts_by_addr[host.hostname.lower()] = host
        name_nodes: dict[str, Any] = {}
        for domain in self.snap.domains:
            name_nodes[domain.fqdn.lower()] = domain
        for sub in self.snap.subdomains:
            name_nodes[sub.fqdn.lower()] = sub
        for host in self.snap.hosts:
            if host.hostname:
                name_nodes.setdefault(host.hostname.lower(), host)

        for claim in self.snap.claims:
            pred = claim.predicate
            obj = claim.object
            invalidated = claim.epistemic_status is EpistemicStatus.INVALIDATED
            if pred == "host.hostname" and isinstance(obj, str):
                src = name_nodes.get(obj.lower().rstrip("."))
                dst = self.by_id.get(claim.subject_id)
                if src is not None and isinstance(dst, Host) and src is not dst:
                    self._edge(
                        GraphEdgeKind.RESOLVES_TO,
                        src,
                        dst,
                        rule="claim:host.hostname",
                        evidence=list(claim.evidence_ids),
                        status=claim.epistemic_status.value,
                        invalidated=invalidated,
                    )
            if pred == "dns.record" and isinstance(obj, dict):
                rtype = str(obj.get("type") or "").upper()
                name = str(obj.get("name") or "").lower().rstrip(".")
                value = str(obj.get("value") or "").lower().rstrip(".")
                src = name_nodes.get(name)
                if rtype in {"A", "AAAA"}:
                    dst = hosts_by_addr.get(value)
                    if src is not None and dst is not None:
                        self._edge(
                            GraphEdgeKind.RESOLVES_TO,
                            src,
                            dst,
                            rule="claim:dns.record",
                            evidence=list(claim.evidence_ids),
                            status=claim.epistemic_status.value,
                            invalidated=invalidated,
                        )
                elif rtype == "CNAME":
                    dst_name = name_nodes.get(value)
                    if src is not None and dst_name is not None and src is not dst_name:
                        self._edge(
                            GraphEdgeKind.LINKS_TO,
                            src,
                            dst_name,
                            rule="claim:dns.record.cname",
                            evidence=list(claim.evidence_ids),
                            status=claim.epistemic_status.value,
                            invalidated=invalidated,
                        )
            if pred == "host.address":
                subject = self.by_id.get(claim.subject_id)
                addr = str(obj) if not isinstance(obj, dict) else str(obj.get("value") or "")
                dst = hosts_by_addr.get(addr)
                if isinstance(subject, Host) and dst is not None and subject is not dst:
                    self._edge(
                        GraphEdgeKind.RESOLVES_TO,
                        subject,
                        dst,
                        rule="claim:host.address",
                        evidence=list(claim.evidence_ids),
                        status=claim.epistemic_status.value,
                        invalidated=invalidated,
                    )

        for host in self.snap.hosts:
            parent_id = host.parent_asset_id
            parent = self.by_id.get(parent_id) if parent_id else None
            if isinstance(parent, Host) and parent is not host:
                self._edge(
                    GraphEdgeKind.RESOLVES_TO,
                    host,
                    parent,
                    rule="identity:host.alias_parent",
                    evidence=_evidence_for(self.snap, host.asset_id),
                    status=host.epistemic_status.value,
                )
        groups: dict[str, list[Host]] = {}
        for host in self.snap.hosts:
            for label in host.labels:
                if label.startswith("identity:"):
                    groups.setdefault(label, []).append(host)
        for members in groups.values():
            members = sorted(members, key=lambda h: h.canonical_key)
            if len(members) < 2:
                continue
            base = members[0]
            for other in members[1:]:
                self._edge(
                    GraphEdgeKind.RELATED_TO,
                    base,
                    other,
                    rule="identity:shared_target",
                    evidence=_evidence_for(self.snap, other.asset_id),
                    status=other.epistemic_status.value,
                )

    def add_web_edges(self) -> None:
        for url in self.snap.urls:
            host = _host_for_url(url, self.snap.hosts)
            if host is not None:
                self._edge(
                    GraphEdgeKind.SERVES,
                    host,
                    url,
                    rule="match:url.host",
                    evidence=_evidence_for(self.snap, url.asset_id),
                    status=url.epistemic_status.value,
                    invalidated=url.out_of_scope,
                )
                for port in self.snap.ports:
                    if port.host_id == host.asset_id and port.number == url.port:
                        self._edge(
                            GraphEdgeKind.SERVES,
                            port,
                            url,
                            rule="match:url.port",
                            evidence=_evidence_for(self.snap, url.asset_id),
                            status=url.epistemic_status.value,
                        )
                        svc = next(
                            (s for s in self.snap.services if s.port_id == port.asset_id),
                            None,
                        )
                        if svc is not None and (svc.name or "") in _HTTP_NAMES:
                            self._edge(
                                GraphEdgeKind.SERVES,
                                svc,
                                url,
                                rule="identity:http_service.serves_url",
                                evidence=_evidence_for(self.snap, url.asset_id),
                                status=url.epistemic_status.value,
                            )

    def add_findings(self) -> None:
        for finding in self.snap.findings:
            key = finding.identity_key or f"{finding.kind.value}:{finding.title}"
            semantic = f"finding:{key}"[:400]
            invalidated = finding.status.value == "invalidated"
            node = GraphNode(
                node_id=finding.finding_id,
                kind=GraphNodeKind.FINDING,
                semantic_key=semantic,
                label=(finding.title or finding.kind.value)[:200],
                ref_id=finding.finding_id,
                epistemic_status=finding.epistemic_status.value,
                out_of_scope=finding.kind.value == "out_of_scope_observation",
                confidence=finding.confidence,
                evidence_ids=list(finding.evidence_ids),
            )
            self._node(node)
            for asset_id in finding.asset_ids:
                asset = self.by_id.get(asset_id)
                if asset is None:
                    continue
                self._edge(
                    GraphEdgeKind.HAS_FINDING,
                    asset,
                    node,
                    rule="identity:finding.asset_ids",
                    evidence=list(finding.evidence_ids),
                    status=finding.epistemic_status.value,
                    invalidated=invalidated or bool(getattr(asset, "out_of_scope", False)),
                )

    def add_hypotheses(self) -> None:
        for hyp in self.snap.hypotheses:
            key = f"hyp:{hyp.statement}"[:400]
            node = GraphNode(
                node_id=hyp.hypothesis_id,
                kind=GraphNodeKind.HYPOTHESIS,
                semantic_key=key,
                label=hyp.statement[:200],
                ref_id=hyp.hypothesis_id,
                epistemic_status=hyp.status.value,
                confidence=hyp.confidence,
            )
            self._node(node)
            for asset_id in hyp.related_asset_ids:
                asset = self.by_id.get(asset_id)
                if asset is None:
                    continue
                self._edge(
                    GraphEdgeKind.HAS_HYPOTHESIS,
                    asset,
                    node,
                    rule="identity:hypothesis.related_asset_ids",
                    status=hyp.status.value,
                )

    def add_validations(self, candidates: Sequence[Any]) -> None:
        for cand in candidates:
            if not isinstance(cand, ValidationCandidate):
                continue
            key = f"val:{cand.identity_key}"[:400]
            status = cand.status.value
            node = GraphNode(
                node_id=cand.validation_id,
                kind=GraphNodeKind.VALIDATION_CANDIDATE,
                semantic_key=key,
                label=(cand.reason or cand.candidate_type)[:200],
                ref_id=cand.validation_id,
                epistemic_status=status,
                out_of_scope=status == "rejected",
                confidence=float(cand.current_confidence or 0.0),
                evidence_ids=list(cand.evidence_ids or ()),
            )
            self._node(node)
            if cand.finding_id:
                fnode = self._node_by_id(cand.finding_id)
                if fnode is not None:
                    self._edge(
                        GraphEdgeKind.HAS_VALIDATION,
                        fnode,
                        node,
                        rule="identity:validation.finding_id",
                        status=status,
                    )
                    self._edge(
                        GraphEdgeKind.DERIVED_FROM,
                        node,
                        fnode,
                        rule="identity:validation.derived_from_finding",
                        status=status,
                    )
            for asset_id in cand.asset_ids or ():
                asset = self.by_id.get(asset_id)
                if asset is None:
                    continue
                self._edge(
                    GraphEdgeKind.HAS_VALIDATION,
                    asset,
                    node,
                    rule="identity:validation.asset_ids",
                    status=status,
                    invalidated=bool(getattr(asset, "out_of_scope", False)),
                )

    def _node_by_id(self, node_id: str) -> GraphNode | None:
        for node in self.nodes.values():
            if node.node_id == node_id or node.ref_id == node_id:
                return node
        return None

    def _node(self, node: GraphNode) -> GraphNode:
        existing = self.nodes.get(node.semantic_key)
        if existing is None:
            self.nodes[node.semantic_key] = node
            return node
        merged_eids = list(dict.fromkeys([*existing.evidence_ids, *node.evidence_ids]))
        self.nodes[node.semantic_key] = existing.model_copy(update={"evidence_ids": merged_eids})
        return self.nodes[node.semantic_key]

    def _edge(
        self,
        kind: GraphEdgeKind,
        src: Any,
        dst: Any,
        *,
        rule: str,
        evidence: list[str] | None = None,
        status: str = "",
        invalidated: bool = False,
    ) -> None:
        src_key = src.semantic_key if isinstance(src, GraphNode) else src.canonical_key
        dst_key = dst.semantic_key if isinstance(dst, GraphNode) else dst.canonical_key
        src_id = src.node_id if isinstance(src, GraphNode) else src.asset_id
        if isinstance(dst, GraphNode):
            dst_id = dst.node_id
        else:
            dst_id = getattr(dst, "asset_id", "")
        token = f"{kind.value}|{src_key}|{dst_key}"
        evidence = list(evidence or [])
        existing = self.edges.get(token)
        if existing is not None:
            merged = list(dict.fromkeys([*existing.evidence_ids, *evidence]))
            keep_invalid = existing.invalidated and invalidated
            self.edges[token] = existing.model_copy(
                update={
                    "evidence_ids": merged,
                    "invalidated": keep_invalid,
                    "epistemic_status": status or existing.epistemic_status,
                }
            )
            return
        self.edges[token] = GraphEdge(
            kind=kind,
            src_key=src_key,
            dst_key=dst_key,
            src_id=src_id,
            dst_id=dst_id,
            rule=rule,
            epistemic_status=status,
            evidence_ids=evidence,
            invalidated=invalidated,
        )

    def snapshot(self) -> GraphSnapshot:
        nodes = tuple(sorted(self.nodes.values(), key=lambda n: (n.kind.value, n.semantic_key)))
        edges = tuple(
            sorted(self.edges.values(), key=lambda e: (e.kind.value, e.src_key, e.dst_key))
        )
        digest = graph_digest(nodes, edges, revision=self.snap.revision)
        conflicts = sum(1 for e in edges if e.invalidated) + sum(
            1 for c in self.snap.get_conflicts()
        )
        return GraphSnapshot(
            mission_id=self.snap.mission_id,
            revision=self.snap.revision,
            digest=digest,
            nodes=nodes,
            edges=edges,
            conflict_count=conflicts,
        )


def graph_digest(
    nodes: Sequence[GraphNode],
    edges: Sequence[GraphEdge],
    *,
    revision: int,
) -> str:
    payload = {
        "revision": revision,
        "nodes": sorted(
            (n.kind.value, n.semantic_key, n.out_of_scope, n.epistemic_status) for n in nodes
        ),
        "edges": sorted((e.kind.value, e.src_key, e.dst_key, e.invalidated, e.rule) for e in edges),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _label(asset: Any) -> str:
    if isinstance(asset, Host):
        return asset.ipv4 or asset.ipv6 or asset.hostname or asset.display_name
    if isinstance(asset, Port):
        return f"{asset.number}/{asset.protocol.value} {asset.state.value}"
    if isinstance(asset, Service):
        return asset.name
    if isinstance(asset, Domain):
        return asset.fqdn
    if isinstance(asset, Subdomain):
        return asset.fqdn
    if isinstance(asset, UrlAsset):
        return f"{asset.scheme}://{asset.host}:{asset.port}{asset.path or '/'}"
    if isinstance(asset, Endpoint):
        return f"{asset.method.value} {asset.url_canonical}"
    if isinstance(asset, AuthenticationSurface):
        return f"auth {asset.auth_kind.value}"
    if isinstance(asset, Technology):
        return asset.product if not asset.version else f"{asset.product}/{asset.version}"
    if isinstance(asset, Parameter):
        return asset.name
    if isinstance(asset, NetworkInterface):
        return asset.ip
    return getattr(asset, "display_name", None) or asset.canonical_key


def _host_for_url(url: UrlAsset, hosts: Sequence[Host]) -> Host | None:
    needle = (url.host or "").lower()
    for host in hosts:
        if host.ipv4 == needle or (host.ipv6 or "").lower() == needle:
            return host
        if (host.hostname or "").lower() == needle:
            return host
    return None


def _evidence_for(snapshot: WorldSnapshot, asset_id: str) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for claim in snapshot.claims:
        if claim.subject_id != asset_id:
            continue
        if claim.epistemic_status is EpistemicStatus.INVALIDATED:
            continue
        for eid in claim.evidence_ids:
            if eid not in seen:
                seen.add(eid)
                ids.append(eid)
    return ids


def _status_confidence(status: EpistemicStatus) -> float:
    return {
        EpistemicStatus.UNKNOWN: 0.0,
        EpistemicStatus.SUSPECTED: 0.3,
        EpistemicStatus.KNOWN: 0.6,
        EpistemicStatus.SUPPORTED: 0.75,
        EpistemicStatus.CONFIRMED: 0.95,
        EpistemicStatus.INVALIDATED: 0.0,
    }.get(status, 0.4)
