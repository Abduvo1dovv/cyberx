"""Structured mission reports. Investigation only — never exploit guidance."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cyberx import __release__, __version__
from cyberx.domain.enums import EpistemicStatus, FindingStatus
from cyberx.graph.paths import PathPlanner
from cyberx.graph.projector import GraphProjector
from cyberx.graph.tree import render_path_line
from cyberx.validation.engine import ValidationEngine
from cyberx.world.priority import rank_investigations

_FORBIDDEN_RE = re.compile(
    r"\b(how to exploit|spawn a shell|privilege escalation|meterpreter)\b",
    re.IGNORECASE,
)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _label_status(status: str) -> str:
    token = (status or "").upper()
    if token in {"CONFIRMED", "KNOWN", "SUPPORTED"}:
        return f"FACT (status={token})"
    if token == "SUSPECTED":
        return "UNCONFIRMED"
    if token == "INVALIDATED":
        return "INVALIDATED"
    if token == "UNKNOWN":
        return "UNKNOWN"
    return token or "UNKNOWN"


def build_report(
    *,
    bundle: Any,
    world: Any,
    traces: list[Any],
    network: Any | None,
) -> dict[str, Any]:
    mission = bundle.mission
    target = bundle.target
    scope = bundle.scope
    snap = world.snapshot()
    candidates = ValidationEngine().evaluate(world)
    graph = GraphProjector().project(snap, validation_candidates=candidates)
    paths = PathPlanner().plan(graph, snap, validation_candidates=candidates)
    open_gaps = [g for g in snap.gaps if not g.closed]
    facts = [
        f
        for f in snap.findings
        if f.status is FindingStatus.OPEN
        and f.epistemic_status
        in {EpistemicStatus.SUPPORTED, EpistemicStatus.CONFIRMED, EpistemicStatus.KNOWN}
    ]
    invalidated = [c for c in snap.claims if c.epistemic_status is EpistemicStatus.INVALIDATED]
    payload: dict[str, Any] = {
        "version": __version__,
        "kind": __release__,
        "mission": {
            "mission_id": mission.mission_id,
            "name": mission.name,
            "intent": mission.intent,
            "mode": mission.mode.value,
            "status": mission.status.value,
            "stop_reason": mission.stop_reason.value if mission.stop_reason else None,
            "ai_provider": mission.ai_provider,
            "iteration": mission.iteration,
            "created_at": _iso(mission.created_at),
            "started_at": _iso(mission.started_at),
            "ended_at": _iso(mission.ended_at),
        },
        "target": {
            "raw_input": target.raw_input,
            "kind": target.kind.value,
            "normalized": target.normalized,
            "identity": target.identity_key(),
            "current_locator": target.current_locator or target.normalized,
            "locator_history": [
                {
                    "locator": item.locator,
                    "kind": item.kind,
                    "status": item.status.value,
                    "source": item.source,
                    "first_seen_at": _iso(item.first_seen_at),
                    "last_seen_at": _iso(item.last_seen_at),
                }
                for item in target.locator_history
            ],
        },
        "scope": {
            "frozen": scope.frozen,
            "allowed_targets": list(scope.allowed_targets),
            "allowed_networks": list(scope.allowed_networks),
            "allowed_ports": list(scope.allowed_ports),
            "allowed_protocols": list(scope.allowed_protocols),
            "excluded_targets": list(scope.excluded_targets),
            "allow_subdomains": scope.allow_subdomains,
        },
        "network": network.compact() if network is not None else {},
        "assets": {
            "hosts": len(snap.hosts),
            "ports": len(snap.ports),
            "services": len(snap.services),
            "technologies": len(snap.technologies),
            "domains": len(snap.domains),
            "subdomains": len(snap.subdomains),
            "urls": len(snap.urls),
            "endpoints": len(snap.endpoints),
        },
        "hosts": [
            {
                "id": h.asset_id,
                "key": h.canonical_key,
                "address": h.ipv4 or h.ipv6 or h.hostname,
                "status": _label_status(h.epistemic_status.value),
                "labels": list(h.labels),
            }
            for h in snap.hosts[:200]
        ],
        "ports": [
            {
                "number": p.number,
                "protocol": p.protocol.value,
                "state": p.state.value,
                "status": _label_status(p.epistemic_status.value),
            }
            for p in snap.ports[:400]
        ],
        "services": [
            {
                "name": s.name,
                "product": s.product,
                "version": s.version,
                "status": _label_status(s.epistemic_status.value),
            }
            for s in snap.services[:200]
        ],
        "technologies": [
            {
                "product": t.product,
                "version": t.version,
                "status": _label_status(t.epistemic_status.value),
            }
            for t in snap.technologies[:200]
        ],
        "domains": [
            {
                "fqdn": d.fqdn,
                "status": _label_status(d.epistemic_status.value),
            }
            for d in snap.domains[:200]
        ],
        "subdomains": [
            {
                "fqdn": s.fqdn,
                "status": _label_status(s.epistemic_status.value),
            }
            for s in snap.subdomains[:200]
        ],
        "urls": [
            {
                "url": f"{u.scheme}://{u.host}:{u.port}{u.path or '/'}",
                "status_code": u.status_code,
                "status": _label_status(u.epistemic_status.value),
            }
            for u in snap.urls[:200]
        ],
        "endpoints": [
            {
                "method": e.method.value,
                "url": e.url_canonical,
                "status": _label_status(e.epistemic_status.value),
            }
            for e in snap.endpoints[:200]
        ],
        "findings": [
            {
                "title": f.title,
                "kind": f.kind.value,
                "severity": f.severity.value,
                "label": "FACT",
                "status": _label_status(f.epistemic_status.value),
                "summary": f.summary,
            }
            for f in facts[:100]
        ],
        "hypotheses": [
            {
                "statement": h.statement,
                "label": "HYPOTHESIS / NOT CONFIRMED",
                "status": h.status.value,
                "confidence": h.confidence,
                "source": h.source.value,
            }
            for h in snap.hypotheses[:50]
        ],
        "validation_candidates": [
            {
                "type": c.candidate_type,
                "reason": c.reason,
                "action": c.mapped_action_type,
                "status": c.status.value,
            }
            for c in candidates[:20]
        ],
        "investigation_paths": [render_path_line(p) for p in paths[:8]],
        "evidence": [
            {
                "evidence_id": e.evidence_id,
                "parser_id": e.parser_id,
                "reliability": e.reliability,
                "claim_preview": e.claim_preview,
            }
            for e in list(snap.recent_evidence)[-50:]
        ],
        "actions_performed": [
            {
                "iteration": t.iteration,
                "action_type": t.selected_type,
                "coverage_key": t.selected_coverage_key,
                "status": t.execution_status,
                "rationale": t.rationale,
            }
            for t in traces
        ],
        "timeline": [
            {
                "at": _iso(ev.at),
                "kind": ev.kind.value,
                "message": ev.message,
            }
            for ev in bundle.timeline[-50:]
        ],
        "unresolved_knowledge_gaps": [
            {
                "kind": g.kind,
                "detail": g.detail,
                "label": "UNKNOWN",
                "priority": g.priority,
            }
            for g in open_gaps[:50]
        ],
        "recommended_next_investigation": [
            {"title": item.title, "reason": item.reason, "priority": item.priority}
            for item in rank_investigations(world, limit=8)
        ],
        "invalidated_claims": [
            {
                "predicate": c.predicate,
                "object": str(c.object)[:200],
                "label": "INVALIDATED",
            }
            for c in invalidated[:50]
        ],
    }
    _assert_safe(payload)
    return payload


def render_markdown(payload: dict[str, Any]) -> str:
    mission = payload["mission"]
    target = payload["target"]
    network = payload.get("network") or {}
    lines = [
        f"# {payload['kind']}",
        "",
        f"Version: `{payload['version']}`",
        "",
        "Investigation report. Facts, hypotheses, and unknowns are labeled separately.",
        "This is not an exploit guide.",
        "",
        "## Mission",
        f"- Name: {mission['name']}",
        f"- Id: `{mission['mission_id']}`",
        f"- Status: {mission['status']}",
        f"- Mode: {mission['mode']}",
        f"- Intent: {mission['intent']}",
        f"- Iteration: {mission['iteration']}",
        f"- Provider: {mission['ai_provider']}",
        f"- Stop reason: {mission['stop_reason'] or '-'}",
        "",
        "## Target identity",
        f"- Identity: `{target['identity']}`",
        f"- Current locator: `{target['current_locator']}`",
        f"- Raw input: `{target['raw_input']}`",
        f"- Normalized: `{target['normalized']}`",
        f"- Kind: {target['kind']}",
        "",
        "## Locator history",
    ]
    history = target.get("locator_history") or []
    if not history:
        lines.append("- (none)")
    for item in history:
        lines.append(f"- `{item['locator']}`  status={item['status']}  source={item['source']}")
    lines.extend(
        [
            "",
            "## Scope (frozen authority)",
            f"- Frozen: {payload['scope']['frozen']}",
            f"- Targets: {', '.join(payload['scope']['allowed_targets']) or '-'}",
            f"- Networks: {', '.join(payload['scope']['allowed_networks']) or '-'}",
            "",
            "## Network context (informational)",
            f"- Reachability: {network.get('reachability', 'UNKNOWN')}",
            f"- Interface: {network.get('interface') or '-'}",
            f"- Source: {network.get('source') or '-'}",
            f"- Route: {network.get('route') or '-'}",
            f"- Tunnel: {network.get('tunnel') or 'none'} (heuristic, unverified)",
            "",
            "## Assets",
        ]
    )
    for key, count in payload["assets"].items():
        lines.append(f"- {key}: {count}")
    lines.extend(["", "## Hosts"])
    _bullets(lines, payload.get("hosts") or [], _fmt_host)
    lines.extend(["", "## Ports"])
    _bullets(lines, payload.get("ports") or [], _fmt_port)
    lines.extend(["", "## Services"])
    _bullets(lines, payload.get("services") or [], _fmt_service)
    lines.extend(["", "## Technologies"])
    _bullets(lines, payload.get("technologies") or [], _fmt_tech)
    lines.extend(["", "## Domains / subdomains"])
    _bullets(lines, payload.get("domains") or [], _fmt_fqdn)
    _bullets(lines, payload.get("subdomains") or [], _fmt_fqdn)
    lines.extend(["", "## URLs"])
    _bullets(lines, payload.get("urls") or [], _fmt_url)
    lines.extend(["", "## Endpoints"])
    _bullets(lines, payload.get("endpoints") or [], _fmt_endpoint)
    lines.extend(["", "## Findings (FACT only)"])
    if not payload["findings"]:
        lines.append("- (none)")
    for item in payload["findings"]:
        lines.append(f"- FACT [{item['status']}] {item['title']} — {item['summary']}")
    lines.extend(["", "## Hypotheses (NOT facts)"])
    if not payload["hypotheses"]:
        lines.append("- (none)")
    for item in payload["hypotheses"]:
        lines.append(f"- HYPOTHESIS / NOT CONFIRMED [{item['status']}] {item['statement']}")
    lines.extend(["", "## Validation candidates (questions only)"])
    _bullets(lines, payload.get("validation_candidates") or [], _fmt_candidate)
    lines.extend(["", "## Investigation paths"])
    lines.append("Catalog-only next observations. Not an attack chain.")
    _bullets(lines, payload.get("investigation_paths") or [], str)
    lines.extend(["", "## Evidence"])
    _bullets(lines, payload.get("evidence") or [], _fmt_evidence)
    lines.extend(["", "## Unresolved gaps (UNKNOWN)"])
    if not payload["unresolved_knowledge_gaps"]:
        lines.append("- (none)")
    for item in payload["unresolved_knowledge_gaps"]:
        lines.append(f"- UNKNOWN {item['kind']} {item['detail']}".rstrip())
    lines.extend(["", "## Recommended next investigation"])
    lines.append("Investigation only. Not an attack queue.")
    recs = payload.get("recommended_next_investigation") or []
    if not recs:
        lines.append("- (none)")
    for item in recs:
        lines.append(f"- {item['title']}  reason={item['reason']}")
    lines.extend(["", "## Actions performed"])
    if not payload["actions_performed"]:
        lines.append("- (none)")
    for item in payload["actions_performed"]:
        lines.append(
            f"- iter {item['iteration']}: {item['action_type'] or '-'} "
            f"status={item['status'] or '-'}"
        )
    lines.extend(["", "## Timeline"])
    _bullets(lines, payload.get("timeline") or [], _fmt_event)
    lines.extend(["", "## Invalidated claims"])
    _bullets(lines, payload.get("invalidated_claims") or [], _fmt_invalidated)
    lines.extend(
        [
            "",
            "## Non-goals",
            "This report contains reconnaissance and intelligence only.",
            "It does not include offensive modules, sessions, weaponized content,",
            "or credential attacks.",
            "",
        ]
    )
    text = "\n".join(lines)
    _assert_safe(text)
    return text


def write_report(payload: dict[str, Any], directory: str | Path) -> tuple[Path, Path]:
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    json_path = folder / "report.json"
    md_path = folder / "report.md"
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(payload) + "\n", encoding="utf-8")
    return json_path, md_path


def _bullets(lines: list[str], items: list[Any], fmt) -> None:
    if not items:
        lines.append("- (none)")
        return
    for item in items[:40]:
        lines.append(f"- {fmt(item)}")


def _fmt_host(item: dict[str, Any]) -> str:
    return f"`{item.get('address')}`  {item.get('status')}"


def _fmt_port(item: dict[str, Any]) -> str:
    return f"{item.get('protocol')}/{item.get('number')} {item.get('state')}  {item.get('status')}"


def _fmt_service(item: dict[str, Any]) -> str:
    product = item.get("product") or ""
    version = item.get("version") or ""
    return f"{item.get('name')} {product} {version}  {item.get('status')}".strip()


def _fmt_tech(item: dict[str, Any]) -> str:
    version = item.get("version") or ""
    return f"{item.get('product')} {version}  {item.get('status')}".strip()


def _fmt_fqdn(item: dict[str, Any]) -> str:
    return f"`{item.get('fqdn')}`  {item.get('status')}"


def _fmt_url(item: dict[str, Any]) -> str:
    return f"`{item.get('url')}`  {item.get('status_code') or '-'}  {item.get('status')}"


def _fmt_endpoint(item: dict[str, Any]) -> str:
    return f"{item.get('method')} `{item.get('url')}`  {item.get('status')}"


def _fmt_candidate(item: dict[str, Any]) -> str:
    return f"{item.get('type')} → {item.get('action') or '-'}  {item.get('reason')}"


def _fmt_evidence(item: dict[str, Any]) -> str:
    return f"`{item.get('evidence_id')}` parser={item.get('parser_id')} r={item.get('reliability')}"


def _fmt_event(item: dict[str, Any]) -> str:
    return f"{item.get('kind')}: {item.get('message')}"


def _fmt_invalidated(item: dict[str, Any]) -> str:
    return f"INVALIDATED {item.get('predicate')} {item.get('object')}"


def _assert_safe(payload: Any) -> None:
    blob = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    if _FORBIDDEN_RE.search(blob):
        raise ValueError("report must not contain exploit guidance")
