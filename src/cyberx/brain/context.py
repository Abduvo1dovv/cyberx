"""BrainContextBuilder — compact, deterministic, ≤ 32 KiB (SPEC §3.11)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from cyberx.domain.enums import EpistemicStatus, HypothesisStatus
from cyberx.domain.models.actions import ActionResult
from cyberx.domain.models.assets import (
    AuthenticationSurface,
    Endpoint,
    Host,
    Service,
    Technology,
    UrlAsset,
)
from cyberx.domain.models.findings import BrainContext, TimelineEvent
from cyberx.domain.models.mission import Mission, Scope, Target
from cyberx.domain.models.network import NetworkContext
from cyberx.graph.paths import PathPlanner
from cyberx.graph.projector import GraphProjector
from cyberx.validation.engine import ValidationEngine
from cyberx.world.keys import object_key
from cyberx.world.priority import rank_investigations
from cyberx.world.snapshot import WorldSnapshot

MAX_BYTES = 32768
_CLAIM_VALUE_CHARS = 200


def _sha16(blob: str) -> str:
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def scope_digest(scope: Scope) -> str:
    payload = scope.model_dump(mode="json")
    digest = _sha16(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    ports = "all" if not scope.allowed_ports else ",".join(str(p) for p in scope.allowed_ports)
    proto = ",".join(scope.allowed_protocols)
    summary = (
        f"hosts={len(scope.allowed_targets)} nets={len(scope.allowed_networks)} "
        f"ports={ports} proto={proto}"
    )
    return f"{digest} {summary}"


def _clip(value: Any, limit: int = _CLAIM_VALUE_CHARS) -> str:
    text = value if isinstance(value, str) else object_key(value)
    if len(text) <= limit:
        return text
    return text[:limit]


def _compact_host(host: Host) -> dict[str, str]:
    address = host.ipv4 or host.ipv6 or host.hostname or ""
    return {
        "kind": "host",
        "id": host.asset_id,
        "key": host.canonical_key,
        "address": address,
        "status": host.epistemic_status.value,
        "labels": ",".join(host.labels),
    }


def _compact_service(svc: Service) -> dict[str, str]:
    return {
        "kind": "service",
        "id": svc.asset_id,
        "key": svc.canonical_key,
        "name": svc.name,
        "port_id": svc.port_id,
        "status": svc.epistemic_status.value,
    }


def _compact_url(url: UrlAsset) -> dict[str, str]:
    locator = f"{url.scheme}://{url.host}:{url.port}{url.path or '/'}"
    return {
        "kind": "url",
        "id": url.asset_id,
        "key": url.canonical_key,
        "url": locator,
        "host": url.host,
        "port": str(url.port),
        "scheme": url.scheme,
        "path": url.path or "/",
        "status": url.epistemic_status.value,
        "http_status": str(url.status_code or ""),
        "title": url.title or "",
    }


def _compact_endpoint(ep: Endpoint) -> dict[str, str]:
    return {
        "kind": "endpoint",
        "id": ep.asset_id,
        "key": ep.canonical_key,
        "method": ep.method.value,
        "url": ep.url_canonical,
        "auth": "1" if ep.auth_required else "0",
        "status": ep.epistemic_status.value,
    }


def _compact_auth(auth: AuthenticationSurface) -> dict[str, str]:
    return {
        "kind": "auth_surface",
        "id": auth.asset_id,
        "key": auth.canonical_key,
        "auth_kind": auth.auth_kind.value,
        "status": auth.epistemic_status.value,
    }


def _compact_tech(tech: Technology) -> dict[str, str]:
    return {
        "kind": "technology",
        "id": tech.asset_id,
        "key": tech.canonical_key,
        "product": tech.product,
        "version": tech.version or "",
        "status": tech.epistemic_status.value,
    }


class BrainContextBuilder:
    def build(
        self,
        snapshot: WorldSnapshot,
        mission: Mission,
        *,
        scope: Scope | None = None,
        recent_results: Sequence[ActionResult] = (),
        recent_events: Sequence[TimelineEvent | str] = (),
        validation_candidates: Sequence[Any] | None = None,
        network_context: NetworkContext | None = None,
        target: Target | None = None,
        previous_network_digest: str | None = None,
    ) -> BrainContext:
        digest = scope_digest(scope) if scope is not None else _sha16(mission.scope_id)
        counts = snapshot.summary()["asset_counts"]
        top: list[dict[str, str]] = []
        for host in snapshot.hosts[:50]:
            if "alias" in host.labels or "historical" in host.labels:
                continue
            top.append(_compact_host(host))
        for svc in snapshot.services:
            if len(top) >= 50:
                break
            top.append(_compact_service(svc))
        for url in snapshot.urls:
            if len(top) >= 50:
                break
            top.append(_compact_url(url))
        for ep in snapshot.endpoints:
            if len(top) >= 50:
                break
            top.append(_compact_endpoint(ep))
        for auth in snapshot.auth_surfaces:
            if len(top) >= 50:
                break
            top.append(_compact_auth(auth))
        for tech in snapshot.technologies:
            if len(top) >= 50:
                break
            top.append(_compact_tech(tech))
        for port in snapshot.ports:
            if len(top) >= 50:
                break
            top.append(
                {
                    "kind": "port",
                    "id": port.asset_id,
                    "key": port.canonical_key,
                    "host_id": port.host_id,
                    "number": str(port.number),
                    "protocol": port.protocol.value,
                    "state": port.state.value,
                    "status": port.epistemic_status.value,
                }
            )
        for domain in snapshot.domains:
            if len(top) >= 50:
                break
            top.append(
                {
                    "kind": "domain",
                    "id": domain.asset_id,
                    "key": domain.canonical_key,
                    "fqdn": domain.fqdn,
                    "status": domain.epistemic_status.value,
                }
            )
        for sub in snapshot.subdomains:
            if len(top) >= 50:
                break
            top.append(
                {
                    "kind": "subdomain",
                    "id": sub.asset_id,
                    "key": sub.canonical_key,
                    "fqdn": sub.fqdn,
                    "status": sub.epistemic_status.value,
                }
            )
        for net in (scope.allowed_networks if scope is not None else [])[:5]:
            if len(top) >= 50:
                break
            top.append({"kind": "network", "key": f"net:{net}", "address": net})
        top = top[:50]

        live_claims = [
            c for c in snapshot.claims if c.epistemic_status is not EpistemicStatus.INVALIDATED
        ]
        live_claims.sort(key=lambda c: (-c.confidence, c.predicate, c.claim_id))
        claims = [
            {
                "predicate": c.predicate,
                "object": _clip(c.object),
                "status": c.epistemic_status.value,
                "subject_id": c.subject_id,
                "confidence": f"{c.confidence:.3f}",
            }
            for c in live_claims[:200]
        ]
        conflicts = [
            {
                "predicate": c.predicate,
                "object": _clip(c.object),
                "status": c.epistemic_status.value,
                "subject_id": c.subject_id,
            }
            for c in snapshot.get_conflicts()[:20]
        ]
        open_gaps = [g for g in snapshot.gaps if not g.closed]
        open_gaps.sort(key=lambda g: (-g.priority, g.kind, g.gap_id))
        key_by_id = {a.asset_id: a.canonical_key for a in _all_assets(snapshot)}
        gaps = [
            {
                "kind": g.kind,
                "id": g.gap_id,
                "subject_id": g.subject_id or "",
                "subject_key": key_by_id.get(g.subject_id or "", ""),
                "detail": g.detail,
                "priority": f"{g.priority:.2f}",
            }
            for g in open_gaps[:50]
        ]
        hyps = [
            h
            for h in snapshot.hypotheses
            if h.status in {HypothesisStatus.OPEN, HypothesisStatus.SUPPORTED}
        ]
        hyp_rows = [
            {
                "id": h.hypothesis_id,
                "statement": h.statement[:200],
                "status": h.status.value,
            }
            for h in hyps[:20]
        ]
        coverage = sorted(snapshot.coverage)
        results = [
            {
                "action_id": r.action_id,
                "status": r.status.value,
                "result_id": r.result_id,
            }
            for r in list(recent_results)[-5:]
        ]
        events: list[str] = []
        for item in list(recent_events)[-10:]:
            events.append(item if isinstance(item, str) else item.message[:200])

        investigations = [
            {
                "id": item.finding_id,
                "title": item.title[:120],
                "reason": item.reason,
                "priority": f"{item.priority:.2f}",
                "asset": item.asset,
                "asset_id": item.asset_id,
            }
            for item in rank_investigations(snapshot, limit=8)
        ]
        top_findings = [
            {
                "id": f.finding_id,
                "title": f.title[:120],
                "kind": f.kind.value,
                "signal": f.signal or f.kind.value,
                "severity": f.severity.value,
                "confidence": f"{f.confidence:.2f}",
                "asset_id": f.asset_ids[0] if f.asset_ids else "",
            }
            for f in snapshot.get_findings()[:8]
        ]
        raw_cands = (
            list(validation_candidates)
            if validation_candidates is not None
            else ValidationEngine().evaluate(snapshot)
        )
        compact_cands = [
            {
                "id": c.validation_id,
                "type": c.candidate_type,
                "status": c.status.value,
                "action": c.mapped_action_type,
                "reason": c.reason[:160],
                "priority": f"{c.priority:.2f}",
                "finding_id": c.finding_id or "",
                "coverage_key": c.coverage_key,
                "locator": c.locator,
                "asset_id": c.asset_ids[0] if c.asset_ids else "",
                "hypothesis_id": c.hypothesis_id or "",
                "url": str(c.parameters.get("url") or ""),
                "url_id": str(c.parameters.get("url_id") or ""),
                "host_id": str(c.parameters.get("host_id") or ""),
                "port": str(c.parameters.get("port") or ""),
            }
            for c in raw_cands[:8]
        ]

        graph = GraphProjector().project(snapshot, validation_candidates=raw_cands)
        paths = PathPlanner().plan(graph, snapshot, validation_candidates=raw_cands)
        compact_paths = [_compact_path(p) for p in paths[:5]]
        compact_focus = _graph_focus(graph, paths)
        network = network_context.compact() if network_context is not None else {}
        if network_context is not None:
            gaps = _with_network_gap(gaps, network_context)
            net_digest = network_context.digest()
            if previous_network_digest and previous_network_digest != net_digest:
                network["changed"] = "1"
            else:
                network["changed"] = "0"
        identity = _compact_target(target) if target is not None else {}
        if identity and network:
            identity["reachability"] = network.get("reachability") or "UNKNOWN"
            network["current_locator"] = identity.get("current") or ""
            network["historical_locator"] = identity.get("previous") or ""
            network["identity"] = identity.get("identity") or ""

        ctx = BrainContext(
            mission_id=mission.mission_id,
            intent=mission.intent,
            mode=mission.mode.value,
            iteration=mission.iteration,
            scope_digest=digest,
            asset_counts={str(k): int(v) for k, v in counts.items()},
            top_assets=top,
            claims=claims,
            gaps=gaps,
            hypotheses=hyp_rows,
            coverage_keys=coverage,
            recent_results=results,
            recent_events=events,
            revision=snapshot.revision,
            conflicts=conflicts,
            top_findings=top_findings,
            investigations=investigations,
            validation_candidates=compact_cands,
            graph_digest=graph.digest,
            investigation_paths=compact_paths,
            graph_focus=compact_focus,
            network=network,
            target_identity=identity,
        )
        return _fit(ctx)


def _compact_target(target: Target) -> dict[str, str]:
    historical = target.historical_locators()
    return {
        "identity": target.identity_key(),
        "kind": target.kind.value,
        "current": target.current_locator or target.normalized,
        "previous": target.previous_locator() or "",
        "historical": ",".join(historical[:8]),
        "normalized": target.normalized,
    }


def _with_network_gap(gaps: list[dict[str, str]], network: NetworkContext) -> list[dict[str, str]]:
    """BrainContext-only diagnostic. Not a World Model gap kind."""
    status = network.reachability.value
    kind_map = {
        "ROUTE_MISSING": "target.route_missing",
        "UNREACHABLE": "target.unreachable",
        "BLOCKED": "target.blocked",
    }
    kind = kind_map.get(status)
    if not kind:
        return gaps
    row = {
        "kind": kind,
        "id": "",
        "subject_id": "",
        "subject_key": "",
        "detail": network.diagnostic[:160],
        "priority": "1.00",
    }
    return [row, *[g for g in gaps if g.get("kind") != kind]][:50]


def _all_assets(snapshot: WorldSnapshot):
    return (
        list(snapshot.hosts)
        + list(snapshot.interfaces)
        + list(snapshot.ports)
        + list(snapshot.services)
        + list(snapshot.technologies)
        + list(snapshot.domains)
        + list(snapshot.subdomains)
        + list(snapshot.urls)
        + list(snapshot.endpoints)
        + list(snapshot.parameters)
        + list(snapshot.auth_surfaces)
    )


def _compact_path(path: Any) -> dict[str, str]:
    params = path.parameters or {}
    return {
        "id": path.path_id,
        "key": path.semantic_key[:200],
        "labels": " → ".join(path.labels[:8])[:160],
        "priority": f"{path.priority:.2f}",
        "action": path.action_type,
        "locator": path.locator[:160],
        "questions": "; ".join(path.unresolved_questions[:3])[:160],
        "oos": "1" if path.out_of_scope else "0",
        "asset_id": params.get("host_id") or params.get("url_id") or params.get("domain_id") or "",
        "url": params.get("url") or "",
        "url_id": params.get("url_id") or "",
        "host_id": params.get("host_id") or "",
        "port": params.get("port") or "",
        "domain_id": params.get("domain_id") or "",
        "fqdn": params.get("fqdn") or "",
        "completeness": f"{path.completeness:.2f}",
        "confidence": f"{path.confidence:.2f}",
    }


def _graph_focus(graph: Any, paths: Sequence[Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in paths[:5]:
        for token in path.edges:
            if token in seen:
                continue
            seen.add(token)
            parts = token.split("|", 2)
            if len(parts) != 3:
                continue
            kind, src, dst = parts
            src_node = graph.node_by_key(src)
            dst_node = graph.node_by_key(dst)
            out.append(
                {
                    "kind": kind,
                    "src": (src_node.label if src_node is not None else src)[:80],
                    "dst": (dst_node.label if dst_node is not None else dst)[:80],
                }
            )
            if len(out) >= 8:
                return out
    if len(out) < 8:
        for edge in graph.get_edges(include_invalidated=False)[:8]:
            token = edge.identity_key
            if token in seen:
                continue
            seen.add(token)
            src_node = graph.node_by_key(edge.src_key)
            dst_node = graph.node_by_key(edge.dst_key)
            out.append(
                {
                    "kind": edge.kind.value,
                    "src": (src_node.label if src_node is not None else edge.src_key)[:80],
                    "dst": (dst_node.label if dst_node is not None else edge.dst_key)[:80],
                }
            )
            if len(out) >= 8:
                break
    return out[:8]


def _size(ctx: BrainContext) -> int:
    blob = ctx.model_dump(mode="json")
    blob.pop("byte_size", None)
    return len(json.dumps(blob, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _fit(ctx: BrainContext) -> BrainContext:
    current = ctx
    size = _size(current)
    if size > MAX_BYTES and current.recent_events:
        current = current.model_copy(update={"recent_events": []})
        size = _size(current)
    if size > MAX_BYTES and len(current.claims) > 50:
        current = current.model_copy(update={"claims": current.claims[:50]})
        size = _size(current)
    if size > MAX_BYTES and len(current.top_assets) > 20:
        current = current.model_copy(update={"top_assets": current.top_assets[:20]})
        size = _size(current)
    if size > MAX_BYTES and current.hypotheses:
        current = current.model_copy(update={"hypotheses": current.hypotheses[:5]})
        size = _size(current)
    if size > MAX_BYTES and current.investigations:
        current = current.model_copy(update={"investigations": current.investigations[:3]})
        size = _size(current)
    if size > MAX_BYTES and current.top_findings:
        current = current.model_copy(update={"top_findings": current.top_findings[:3]})
        size = _size(current)
    if size > MAX_BYTES and current.validation_candidates:
        current = current.model_copy(
            update={"validation_candidates": current.validation_candidates[:3]}
        )
        size = _size(current)
    if size > MAX_BYTES and current.graph_focus:
        current = current.model_copy(update={"graph_focus": current.graph_focus[:3]})
        size = _size(current)
    if size > MAX_BYTES and len(current.investigation_paths) > 2:
        current = current.model_copy(
            update={"investigation_paths": current.investigation_paths[:2]}
        )
        size = _size(current)
    if size > MAX_BYTES and current.graph_focus:
        current = current.model_copy(update={"graph_focus": []})
        size = _size(current)
    if size > MAX_BYTES and current.investigation_paths:
        current = current.model_copy(
            update={"investigation_paths": current.investigation_paths[:1]}
        )
        size = _size(current)
    if size > MAX_BYTES and current.network:
        keep = {
            "reachability": current.network.get("reachability", "UNKNOWN"),
            "current_locator": current.network.get("current_locator", ""),
            "digest": current.network.get("digest", ""),
        }
        current = current.model_copy(update={"network": keep})
        size = _size(current)
    if size > MAX_BYTES and current.target_identity:
        keep_id = {
            "identity": current.target_identity.get("identity", ""),
            "current": current.target_identity.get("current", ""),
            "previous": current.target_identity.get("previous", ""),
        }
        current = current.model_copy(update={"target_identity": keep_id})
        size = _size(current)
    return current.model_copy(update={"byte_size": _size(current)})


def context_hash(ctx: BrainContext) -> str:
    blob = ctx.model_dump(mode="json")
    blob.pop("byte_size", None)
    text = json.dumps(blob, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
