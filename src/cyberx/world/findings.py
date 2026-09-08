"""FindingFactory.maybe_emit — findings are derived, never a substitute for claims."""

from __future__ import annotations

from typing import Any

from cyberx.domain.enums import (
    EpistemicStatus,
    FindingKind,
    FindingSeverity,
    FindingStatus,
    PortState,
)
from cyberx.domain.ids import PREFIX_FINDING, new_id
from cyberx.domain.models.findings import Finding
from cyberx.domain.time import utcnow
from cyberx.world.signals import (
    classify_http_status,
    classify_path,
    classify_port,
    classify_title,
    path_from_locator,
    signal_title,
)

_REPORTABLE = {
    EpistemicStatus.KNOWN,
    EpistemicStatus.SUPPORTED,
    EpistemicStatus.CONFIRMED,
}
_UNUSUAL_STATUS = frozenset({500, 502, 503})
_INVESTIGATE = "Investigate as reconnaissance; do not treat as a validated vulnerability."


def collect_findings(world: Any) -> list[Finding]:
    existing: dict[str, Finding] = {}
    for finding in world.get_findings():
        if finding.status is FindingStatus.INVALIDATED:
            continue
        if finding.identity_key:
            existing[finding.identity_key] = finding
        else:
            existing[f"{finding.kind.value}:{tuple(finding.asset_ids)}"] = finding

    out: list[Finding] = []
    now = utcnow()
    mission_id = world.mission_id

    def add(
        kind: FindingKind,
        asset_ids: list[str],
        title: str,
        summary: str,
        severity: FindingSeverity,
        status: EpistemicStatus,
        evidence_ids: list[str],
        *,
        signal: str,
        identity: str,
    ) -> None:
        if not evidence_ids:
            return
        confidence = _min_confidence(world, asset_ids, evidence_ids)
        epistemic = _bounded_epistemic(world, asset_ids, status)
        token = identity
        prev = existing.get(token)
        if prev is None:
            candidate = existing.get(f"{kind.value}:{tuple(asset_ids)}")
            if candidate is not None and not candidate.identity_key:
                prev = candidate
        if prev is not None:
            merged = list(dict.fromkeys([*prev.evidence_ids, *evidence_ids]))[:16]
            new_ids = set(merged) - set(prev.evidence_ids)
            if not new_ids and prev.signal == signal and prev.identity_key == token:
                return
            updated = prev.model_copy(
                update={
                    "title": title,
                    "summary": summary,
                    "severity": severity,
                    "epistemic_status": epistemic,
                    "evidence_ids": merged,
                    "confidence": confidence,
                    "observation_count": prev.observation_count + (1 if new_ids else 0),
                    "last_seen_at": now if new_ids else prev.last_seen_at,
                    "signal": signal,
                    "identity_key": token,
                    "source": "heuristic",
                }
            )
            existing[token] = updated
            out.append(updated)
            return
        created = Finding(
            finding_id=new_id(PREFIX_FINDING),
            mission_id=mission_id,
            kind=kind,
            title=title,
            summary=summary,
            severity=severity,
            epistemic_status=epistemic,
            evidence_ids=list(evidence_ids)[:16],
            asset_ids=asset_ids,
            created_at=now,
            status=FindingStatus.OPEN,
            confidence=confidence,
            identity_key=token,
            signal=signal,
            source="heuristic",
            observation_count=1,
            last_seen_at=now,
            recommendation=_INVESTIGATE,
        )
        existing[token] = created
        out.append(created)

    for port in world.get_ports():
        if port.state is not PortState.OPEN:
            continue
        if port.epistemic_status not in _REPORTABLE:
            continue
        signal = classify_port(port.number)
        if port.out_of_scope:
            kind = FindingKind.OUT_OF_SCOPE_OBSERVATION
            title = f"Out of scope observation: open port {port.number}/{port.protocol.value}"
            severity = FindingSeverity.INFO
        else:
            kind = FindingKind.OPEN_PORT
            title = signal_title(signal, detail=f"{port.number}/{port.protocol.value}")
            severity = FindingSeverity.LOW if signal == "unusual_service" else FindingSeverity.INFO
        evidence_ids = world.evidence_ids_for_asset(port.asset_id)
        if not evidence_ids:
            evidence_ids = world.evidence_ids_for_subject_key(port.canonical_key)
        add(
            kind,
            [port.asset_id],
            title,
            f"{port.canonical_key} observed {port.state.value}",
            severity,
            port.epistemic_status,
            list(evidence_ids),
            signal=signal,
            identity=f"{kind.value}:{signal}:{port.canonical_key}",
        )

    for auth in world.get_auth_surfaces():
        if auth.epistemic_status not in _REPORTABLE or auth.out_of_scope:
            continue
        evidence_ids = world.evidence_ids_for_asset(auth.asset_id)
        if not evidence_ids:
            evidence_ids = world.evidence_ids_for_subject_key(auth.canonical_key)
        if not evidence_ids and auth.parent_asset_id:
            evidence_ids = world.evidence_ids_for_asset(auth.parent_asset_id)
        add(
            FindingKind.AUTH_SURFACE,
            [auth.asset_id],
            signal_title("auth_surface", detail=auth.auth_kind.value),
            auth.canonical_key,
            FindingSeverity.LOW,
            auth.epistemic_status,
            list(evidence_ids),
            signal="auth_surface",
            identity=f"auth_surface:{auth.canonical_key}",
        )

    for url in world.get_web_surfaces():
        if url.out_of_scope or url.epistemic_status not in _REPORTABLE:
            continue
        evidence_ids = world.evidence_ids_for_asset(url.asset_id)
        if not evidence_ids:
            evidence_ids = world.evidence_ids_for_subject_key(url.canonical_key)
        path = url.path or "/"
        listing = classify_title(url.title)
        http_signal = classify_http_status(url.status_code, path)
        path_signal = classify_path(path)
        signals: list[tuple[str, FindingKind, FindingSeverity, str]] = []
        if listing:
            signals.append(
                (
                    listing,
                    FindingKind.INTERESTING_PATH,
                    FindingSeverity.INFO,
                    signal_title(listing),
                )
            )
        if http_signal == "unusual_status" or url.status_code in _UNUSUAL_STATUS:
            signals.append(
                (
                    "unusual_status",
                    FindingKind.ANOMALY,
                    FindingSeverity.INFO,
                    signal_title("unusual_status", detail=str(url.status_code or "")),
                )
            )
        if http_signal == "unusual_redirect":
            signals.append(
                (
                    "unusual_redirect",
                    FindingKind.ANOMALY,
                    FindingSeverity.INFO,
                    signal_title("unusual_redirect", detail=path),
                )
            )
        interesting = (
            http_signal
            if http_signal
            in {
                "admin_surface",
                "auth_surface",
                "api_surface",
                "backup_looking_path",
                "upload_surface",
                "debug_surface",
                "internal_surface",
                "interesting_endpoint",
                "management_surface",
            }
            else path_signal
        )
        if interesting:
            severity = (
                FindingSeverity.LOW
                if interesting in {"admin_surface", "auth_surface", "backup_looking_path"}
                else FindingSeverity.INFO
            )
            detail = path
            if url.status_code:
                detail = f"{path} {url.status_code}"
            signals.append(
                (
                    interesting,
                    FindingKind.INTERESTING_PATH,
                    severity,
                    signal_title(interesting, detail=detail),
                )
            )
        for signal, kind, severity, title in signals:
            add(
                kind,
                [url.asset_id],
                title,
                url.canonical_key,
                severity,
                url.epistemic_status,
                list(evidence_ids),
                signal=signal,
                identity=f"{kind.value}:{signal}:{url.canonical_key}",
            )

    for ep in world.get_endpoints():
        if ep.out_of_scope or ep.epistemic_status not in _REPORTABLE:
            continue
        path = path_from_locator(getattr(ep, "url_canonical", "") or "")
        signal = classify_path(path)
        if not signal:
            continue
        evidence_ids = world.evidence_ids_for_asset(ep.asset_id)
        if not evidence_ids:
            evidence_ids = world.evidence_ids_for_subject_key(ep.canonical_key)
        add(
            FindingKind.INTERESTING_PATH,
            [ep.asset_id],
            signal_title(signal, detail=f"{ep.method.value} {path}"),
            ep.canonical_key,
            FindingSeverity.LOW
            if signal in {"admin_surface", "auth_surface"}
            else FindingSeverity.INFO,
            ep.epistemic_status,
            list(evidence_ids),
            signal=signal,
            identity=f"interesting_path:{signal}:{ep.canonical_key}",
        )

    for tech in world.get_technologies():
        if tech.out_of_scope or tech.epistemic_status not in _REPORTABLE:
            continue
        evidence_ids = world.evidence_ids_for_asset(tech.asset_id)
        if not evidence_ids:
            evidence_ids = world.evidence_ids_for_subject_key(tech.canonical_key)
        if not evidence_ids and tech.parent_asset_id:
            evidence_ids = world.evidence_ids_for_asset(tech.parent_asset_id)
        if not evidence_ids and getattr(tech, "parent_canonical", ""):
            evidence_ids = world.evidence_ids_for_subject_key(tech.parent_canonical)
        if tech.version:
            signal = "version_disclosure"
            title = signal_title(signal, detail=f"{tech.product} {tech.version}")
            summary = f"{tech.canonical_key} version fingerprint (strong if banner/header)"
        else:
            signal = "tech_observed"
            title = signal_title(signal, detail=f"{tech.product} (weak fingerprint)")
            summary = f"{tech.canonical_key} product observed without version"
        add(
            FindingKind.TECHNOLOGY,
            [tech.asset_id],
            title,
            summary,
            FindingSeverity.INFO,
            tech.epistemic_status,
            list(evidence_ids),
            signal=signal,
            identity=f"technology:{signal}:{tech.canonical_key}",
        )
    return out


def invalidate_stale_findings(world: Any) -> None:
    live_eids = set()
    for claim in world.get_claims(include_invalidated=False):
        live_eids.update(claim.evidence_ids)
    for finding in world.get_findings():
        if finding.status is FindingStatus.INVALIDATED:
            continue
        if finding.evidence_ids and not any(eid in live_eids for eid in finding.evidence_ids):
            world.put_finding(
                finding.model_copy(
                    update={
                        "status": FindingStatus.INVALIDATED,
                        "epistemic_status": EpistemicStatus.INVALIDATED,
                    }
                )
            )


def _min_confidence(world: Any, asset_ids: list[str], evidence_ids: list[str]) -> float:
    wanted = set(asset_ids)
    eids = set(evidence_ids)
    scores: list[float] = []
    for claim in world.get_claims(include_invalidated=False):
        if claim.subject_id in wanted or eids.intersection(claim.evidence_ids):
            scores.append(float(claim.confidence))
    if not scores:
        return 0.5
    return min(scores)


def _bounded_epistemic(
    world: Any, asset_ids: list[str], status: EpistemicStatus
) -> EpistemicStatus:
    if status is not EpistemicStatus.CONFIRMED:
        return status
    supporting = [
        c for c in world.get_claims(include_invalidated=False) if c.subject_id in set(asset_ids)
    ]
    weak = {EpistemicStatus.UNKNOWN, EpistemicStatus.SUSPECTED}
    if supporting and all(c.epistemic_status in weak for c in supporting):
        return EpistemicStatus.SUPPORTED
    return status
