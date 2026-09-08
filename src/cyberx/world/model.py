"""In-memory World Model. Projection of Evidence; not a database."""

from __future__ import annotations

import threading
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol

from cyberx.domain.enums import (
    OBSERVATION_PREDICATES,
    EpistemicStatus,
    PortState,
    TimelineKind,
)
from cyberx.domain.errors import InvalidWorldDelta, WorldModelError
from cyberx.domain.ids import PREFIX_MISSION, PREFIX_TIMELINE, new_id, require_id
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
from cyberx.domain.models.evidence import Claim, Evidence, KnowledgeGap
from cyberx.domain.models.findings import Finding, Hypothesis, TimelineEvent
from cyberx.domain.time import utcnow
from cyberx.world.correlation import CorrelationEngine, ScopeGate
from cyberx.world.delta import WorldDelta, WorldDeltaKind, upsert_asset_delta
from cyberx.world.findings import collect_findings, invalidate_stale_findings
from cyberx.world.gaps import GapDetector, require_gap_kind
from cyberx.world.keys import object_key
from cyberx.world.projector import WorldProjector
from cyberx.world.snapshot import WorldSnapshot, claim_semantic_tuple, semantic_digest
from cyberx.world.status import (
    apply_contradiction,
    apply_support,
    is_ai_parser,
    max_status,
    status_after_support,
    status_from_reliability,
)


class WorldModel(Protocol):
    def snapshot(self) -> WorldSnapshot: ...

    def apply(self, deltas: list[WorldDelta]) -> int: ...

    def get_gaps(self) -> list[KnowledgeGap]: ...


class InMemoryWorldModel:
    """Current belief graph for one mission. Apply is transactional."""

    def __init__(
        self,
        mission_id: str,
        *,
        scope_gate: ScopeGate | None = None,
    ) -> None:
        self._mission_id = require_id(mission_id, PREFIX_MISSION)
        self._scope_gate = scope_gate
        self._lock = threading.Lock()
        self._correlation = CorrelationEngine()
        self._projector = WorldProjector()
        self._reset()

    def _reset(self) -> None:
        self._by_key: dict[str, Asset] = {}
        self._by_id: dict[str, Asset] = {}
        self._claims_by_id: dict[str, Claim] = {}
        self._claim_spo: dict[tuple[str, str, str], str] = {}
        self._gaps: dict[str, KnowledgeGap] = {}
        self._findings: dict[str, Finding] = {}
        self._hypotheses: dict[str, Hypothesis] = {}
        self._coverage: dict[str, str] = {}
        self._unmapped: list[Evidence] = []
        self._evidence_by_id: dict[str, Evidence] = {}
        self._evidence_order: list[str] = []
        self._applied: set[str] = set()
        self._seed_assets: list[Asset] = []
        self._aliases: dict[str, str] = {}
        self._events: list[TimelineEvent] = []
        self._revision = 0
        self._updated_at: datetime = utcnow()
        self._last_evidence_id: str | None = None

    @property
    def mission_id(self) -> str:
        return self._mission_id

    @property
    def revision(self) -> int:
        return self._revision

    def peek_asset(self, canonical_key: str) -> Asset | None:
        return self._by_key.get(canonical_key)

    def peek_asset_by_id(self, asset_id: str) -> Asset | None:
        return self._by_id.get(asset_id)

    def iter_assets_raw(self):
        return self._by_id.values()

    def iter_claims_raw(self):
        return self._claims_by_id.values()

    def asset_key_by_id(self, asset_id: str | None) -> str | None:
        if not asset_id:
            return None
        asset = self._by_id.get(asset_id)
        return None if asset is None else asset.canonical_key

    def apply(self, deltas: list[WorldDelta]) -> int:
        with self._lock:
            return self._apply_unlocked(deltas)

    def apply_evidence(self, evidence: Evidence) -> int:
        with self._lock:
            return self._apply_evidence_unlocked(evidence)

    def seed_assets(self, assets: Sequence[Asset]) -> int:
        copies = [item.model_copy(deep=True) for item in assets]
        with self._lock:
            self._seed_assets.extend(copies)
            deltas = [upsert_asset_delta(item) for item in copies]
            return self._apply_unlocked(deltas)

    def record_hypothesis(self, hypothesis: Hypothesis) -> int:
        if hypothesis.mission_id != self._mission_id:
            raise WorldModelError("hypothesis.mission_id does not match World Model")
        with self._lock:
            backup = self._clone()
            try:
                stored = hypothesis.model_copy(deep=True)
                self._hypotheses[stored.hypothesis_id] = stored
                return self._finalize_revision()
            except Exception:
                self._restore(backup)
                raise

    def record_coverage(self, coverage_key: str, status: str) -> int:
        return self.apply(
            [
                WorldDelta(
                    kind=WorldDeltaKind.COVERAGE_ADD,
                    coverage_key=coverage_key,
                    coverage_status=status,
                )
            ]
        )

    def hydrate(
        self,
        snapshot: WorldSnapshot,
        *,
        seed_assets: Sequence[Asset] = (),
        evidence: Sequence[Evidence] = (),
    ) -> None:
        """Load a cached projection. Does not re-apply evidence already in the snapshot."""
        with self._lock:
            self._reset()
            self._seed_assets = [item.model_copy(deep=True) for item in seed_assets]
            collections = (
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
            )
            for group in collections:
                for asset in group:
                    self._index_asset(asset.model_copy(deep=True))
            for claim in snapshot.claims:
                stored = claim.model_copy(deep=True)
                subject = self._by_id.get(stored.subject_id)
                skey = subject.canonical_key if subject is not None else stored.subject_id
                self._store_claim(stored, skey, stored.predicate, object_key(stored.object))
            self._gaps = {g.gap_id: g.model_copy(deep=True) for g in snapshot.gaps}
            self._findings = {f.finding_id: f.model_copy(deep=True) for f in snapshot.findings}
            self._hypotheses = {
                h.hypothesis_id: h.model_copy(deep=True) for h in snapshot.hypotheses
            }
            self._coverage = dict(snapshot.coverage)
            self._unmapped = [item.model_copy(deep=True) for item in snapshot.unmapped]
            for item in snapshot.recent_evidence:
                self._register_evidence(item)
            for item in snapshot.unmapped:
                self._register_evidence(item)
            for item in evidence:
                self._register_evidence(item)
            self._last_evidence_id = snapshot.last_evidence_id
            self._revision = snapshot.revision
            self._updated_at = snapshot.updated_at

    def rebuild_from_evidence(self, evidence: Sequence[Evidence] | None = None) -> int:
        with self._lock:
            items = list(evidence if evidence is not None else self._ordered_evidence())
            seeds = [item.model_copy(deep=True) for item in self._seed_assets]
            self._reset()
            if seeds:
                self._seed_assets = [item.model_copy(deep=True) for item in seeds]
                for asset in seeds:
                    self._upsert_asset(asset)
                self._finalize_revision()
            for item in items:
                self._apply_evidence_unlocked(item)
            return self._revision

    def snapshot(self) -> WorldSnapshot:
        with self._lock:
            return self._snapshot_unlocked()

    def get_gaps(self) -> list[KnowledgeGap]:
        items = [item.model_copy(deep=True) for item in self._gaps.values()]
        items.sort(key=lambda g: (-g.priority, g.kind, g.gap_id))
        return items

    def get_hosts(self) -> tuple[Host, ...]:
        return self._copies(Host)

    def get_interfaces(self) -> tuple[NetworkInterface, ...]:
        return self._copies(NetworkInterface)

    def get_ports(self) -> tuple[Port, ...]:
        return self._copies(Port)

    def get_open_ports(self) -> tuple[Port, ...]:
        return tuple(p for p in self.get_ports() if p.state is PortState.OPEN)

    def get_services(self) -> tuple[Service, ...]:
        return self._copies(Service)

    def get_web_surfaces(self) -> tuple[UrlAsset, ...]:
        return self._copies(UrlAsset)

    def get_technologies(self) -> tuple[Technology, ...]:
        return self._copies(Technology)

    def get_domains(self) -> tuple[Domain, ...]:
        return self._copies(Domain)

    def get_subdomains(self) -> tuple[Subdomain, ...]:
        return self._copies(Subdomain)

    def get_endpoints(self) -> tuple[Endpoint, ...]:
        return self._copies(Endpoint)

    def get_parameters(self) -> tuple[Parameter, ...]:
        return self._copies(Parameter)

    def get_auth_surfaces(self) -> tuple[AuthenticationSurface, ...]:
        return self._copies(AuthenticationSurface)

    def get_findings(self) -> tuple[Finding, ...]:
        items = [item.model_copy(deep=True) for item in self._findings.values()]
        items.sort(key=lambda f: (f.kind.value, f.title, f.finding_id))
        return tuple(items)

    def get_hypotheses(self) -> tuple[Hypothesis, ...]:
        items = [item.model_copy(deep=True) for item in self._hypotheses.values()]
        items.sort(key=lambda h: h.hypothesis_id)
        return tuple(items)

    def get_claims(self, *, include_invalidated: bool = True) -> tuple[Claim, ...]:
        items = [item.model_copy(deep=True) for item in self._claims_by_id.values()]
        if not include_invalidated:
            items = [c for c in items if c.epistemic_status is not EpistemicStatus.INVALIDATED]
        items.sort(key=lambda c: (c.predicate, c.claim_id))
        return tuple(items)

    def get_conflicts(self) -> tuple[Claim, ...]:
        return tuple(
            c
            for c in self.get_claims(include_invalidated=True)
            if c.contradiction_ids or c.epistemic_status is EpistemicStatus.INVALIDATED
        )

    def get_recent_evidence(self, limit: int = 20) -> tuple[Evidence, ...]:
        ids = self._evidence_order[-limit:]
        return tuple(
            self._evidence_by_id[eid].model_copy(deep=True)
            for eid in ids
            if eid in self._evidence_by_id
        )

    def get_unmapped(self) -> tuple[Evidence, ...]:
        return tuple(item.model_copy(deep=True) for item in self._unmapped)

    def get_coverage(self) -> dict[str, str]:
        return dict(self._coverage)

    def get_related_entities(self, asset_id: str) -> tuple[Asset, ...]:
        root = self._by_id.get(asset_id)
        if root is None:
            return ()
        found: dict[str, Asset] = {root.asset_id: root}
        parent_id = root.parent_asset_id
        if parent_id and parent_id in self._by_id:
            found[parent_id] = self._by_id[parent_id]
        for attr in ("host_id", "port_id", "url_id", "endpoint_id", "domain_id"):
            related_id = getattr(root, attr, None)
            if related_id and related_id in self._by_id:
                found[related_id] = self._by_id[related_id]
        for other in self._by_id.values():
            if other.parent_asset_id == asset_id:
                found[other.asset_id] = other
            for attr in ("host_id", "port_id", "url_id", "endpoint_id", "domain_id"):
                if getattr(other, attr, None) == asset_id:
                    found[other.asset_id] = other
        items = [item.model_copy(deep=True) for item in found.values()]
        items.sort(key=lambda a: a.canonical_key)
        return tuple(items)

    def summary(self) -> dict[str, Any]:
        return self.snapshot().summary()

    def put_finding(self, finding: Finding) -> None:
        self._findings[finding.finding_id] = finding.model_copy(deep=True)

    def replace_gaps(
        self,
        desired: dict[tuple[str, str], KnowledgeGap],
        live_claims: Sequence[Claim] | None = None,
    ) -> None:
        del live_claims
        existing: dict[tuple[str, str], KnowledgeGap] = {}
        for gap in self._gaps.values():
            skey = self.asset_key_by_id(gap.subject_id) or ""
            existing[(gap.kind, skey)] = gap
        new_map: dict[str, KnowledgeGap] = {}
        for token, gap in desired.items():
            old = existing.get(token)
            if old is not None:
                new_map[old.gap_id] = old.model_copy(
                    update={"closed": False, "detail": gap.detail, "priority": gap.priority}
                )
            else:
                new_map[gap.gap_id] = gap
        for token, old in existing.items():
            if token not in desired:
                new_map[old.gap_id] = old.model_copy(update={"closed": True})
        self._gaps = new_map

    def evidence_ids_for_asset(self, asset_id: str) -> list[str]:
        ids: list[str] = []
        seen: set[str] = set()
        for claim in self._claims_by_id.values():
            if claim.subject_id != asset_id:
                continue
            if claim.epistemic_status is EpistemicStatus.INVALIDATED:
                continue
            for eid in claim.evidence_ids:
                if eid not in seen:
                    seen.add(eid)
                    ids.append(eid)
        return ids

    def evidence_ids_for_subject_key(self, canonical_key: str) -> list[str]:
        asset = self._by_key.get(canonical_key)
        if asset is None:
            return []
        return self.evidence_ids_for_asset(asset.asset_id)

    def _copies(self, cls: type) -> tuple:
        items = [
            item.model_copy(deep=True) for item in self._by_id.values() if isinstance(item, cls)
        ]
        items.sort(key=lambda a: a.canonical_key)
        return tuple(items)

    def _apply_unlocked(self, deltas: list[WorldDelta]) -> int:
        if not isinstance(deltas, list):
            raise InvalidWorldDelta("deltas must be a list")
        for delta in deltas:
            if not isinstance(delta, WorldDelta):
                raise InvalidWorldDelta("not a WorldDelta")
            delta.check()
        backup = self._clone()
        try:
            for delta in deltas:
                self._apply_one(delta)
            return self._finalize_revision()
        except Exception:
            self._restore(backup)
            raise

    def _apply_evidence_unlocked(self, evidence: Evidence) -> int:
        if evidence.mission_id != self._mission_id:
            raise WorldModelError("evidence.mission_id does not match World Model")
        if is_ai_parser(evidence.parser_id):
            raise WorldModelError("AI cannot create World Model facts")
        if evidence.evidence_id in self._applied:
            return self._revision
        backup = self._clone()
        try:
            self._register_evidence(evidence)
            preview = evidence.claim_preview or {}
            mapped = bool(preview.get("mapped", True))
            predicate = str(preview.get("predicate") or "")
            if (not mapped) or predicate not in OBSERVATION_PREDICATES:
                self._unmapped.append(evidence.model_copy(deep=True))
                return self._finalize_revision()
            bound = self._correlation.correlate(evidence, self, scope_gate=self._scope_gate)
            deltas = self._projector.project(bound)
            for delta in deltas:
                delta.check()
                self._apply_one(delta)
            return self._finalize_revision()
        except Exception:
            self._restore(backup)
            raise

    def _finalize_revision(self) -> int:
        self._revision += 1
        self._updated_at = utcnow()
        GapDetector().recompute(self)
        for finding in collect_findings(self):
            self.put_finding(finding)
        invalidate_stale_findings(self)
        return self._revision

    def _apply_one(self, delta: WorldDelta) -> None:
        if delta.kind is WorldDeltaKind.UPSERT_ASSET:
            self._upsert_asset(delta.asset)
            return
        if delta.kind is WorldDeltaKind.UPSERT_CLAIM:
            assert delta.claim is not None
            self._merge_claim(delta.claim)
            return
        if delta.kind is WorldDeltaKind.INVALIDATE_CLAIM:
            claim = self._claims_by_id.get(delta.claim_id or "")
            if claim is None:
                raise InvalidWorldDelta(f"unknown claim_id {delta.claim_id}")
            contra = list(claim.contradiction_ids)
            if delta.evidence_id and delta.evidence_id not in contra:
                contra.append(delta.evidence_id)
            subject = self._by_id.get(claim.subject_id)
            skey = subject.canonical_key if subject else claim.subject_id
            self._store_claim(
                claim.model_copy(
                    update={
                        "epistemic_status": EpistemicStatus.INVALIDATED,
                        "contradiction_ids": contra,
                        "updated_at": utcnow(),
                    }
                ),
                skey,
                claim.predicate,
                object_key(claim.object),
            )
            return
        if delta.kind is WorldDeltaKind.OPEN_GAP:
            assert delta.gap is not None
            require_gap_kind(delta.gap.kind)
            self._gaps[delta.gap.gap_id] = delta.gap.model_copy(deep=True)
            return
        if delta.kind is WorldDeltaKind.CLOSE_GAP:
            gap = self._gaps.get(delta.gap_id or "")
            if gap is None:
                raise InvalidWorldDelta(f"unknown gap_id {delta.gap_id}")
            self._gaps[gap.gap_id] = gap.model_copy(update={"closed": True})
            return
        if delta.kind is WorldDeltaKind.COVERAGE_ADD:
            assert delta.coverage_key is not None
            self._coverage[delta.coverage_key] = delta.coverage_status or "completed"
            return
        raise InvalidWorldDelta(f"unknown WorldDelta kind: {delta.kind}")

    def _upsert_asset(self, incoming: Asset) -> Asset:
        incoming = incoming.model_copy(deep=True)
        existing = self._by_key.get(incoming.canonical_key)
        if existing is None:
            self._index_asset(incoming)
            if "alias" in incoming.labels and incoming.parent_asset_id:
                parent = self._by_id.get(incoming.parent_asset_id)
                if parent is not None:
                    self._aliases[incoming.canonical_key] = parent.canonical_key
            return incoming
        updates: dict[str, Any] = {
            "last_seen_at": utcnow(),
            "out_of_scope": existing.out_of_scope or incoming.out_of_scope,
            "labels": list(dict.fromkeys([*existing.labels, *incoming.labels])),
            "epistemic_status": max_status(existing.epistemic_status, incoming.epistemic_status),
        }
        if incoming.display_name:
            updates["display_name"] = incoming.display_name
        if incoming.parent_asset_id and not existing.parent_asset_id:
            updates["parent_asset_id"] = incoming.parent_asset_id
        if isinstance(existing, Port) and isinstance(incoming, Port):
            if incoming.state is not PortState.UNKNOWN:
                updates["state"] = incoming.state
            if incoming.reason:
                updates["reason"] = incoming.reason
        if isinstance(existing, Service) and isinstance(incoming, Service):
            if incoming.name and incoming.name != "unknown":
                updates["name"] = incoming.name
                updates["display_name"] = incoming.name
            if incoming.product:
                updates["product"] = incoming.product
            if incoming.version:
                updates["version"] = incoming.version
            if incoming.banner:
                updates["banner"] = incoming.banner
        if isinstance(existing, UrlAsset) and isinstance(incoming, UrlAsset):
            if incoming.status_code is not None:
                updates["status_code"] = incoming.status_code
            if incoming.title:
                updates["title"] = incoming.title
            if incoming.content_type:
                updates["content_type"] = incoming.content_type
        if isinstance(existing, Host) and isinstance(incoming, Host):
            if incoming.hostname:
                updates["hostname"] = incoming.hostname
            if incoming.os_hint:
                updates["os_hint"] = incoming.os_hint
        if isinstance(existing, Endpoint) and isinstance(incoming, Endpoint):
            if incoming.last_status is not None:
                updates["last_status"] = incoming.last_status
            if incoming.auth_required:
                updates["auth_required"] = True
        merged = existing.model_copy(update=updates)
        self._index_asset(merged)
        if "alias" in merged.labels and merged.parent_asset_id:
            parent = self._by_id.get(merged.parent_asset_id)
            if parent is not None:
                self._aliases[merged.canonical_key] = parent.canonical_key
        return merged

    def _merge_claim(self, incoming: Claim) -> None:
        now = utcnow()
        subject = self._by_id.get(incoming.subject_id)
        if subject is None:
            raise InvalidWorldDelta("claim subject asset is missing")
        skey = subject.canonical_key
        pred = incoming.predicate
        okey = object_key(incoming.object)
        spo = (skey, pred, okey)
        new_eids = list(incoming.evidence_ids)
        if spo in self._claim_spo:
            existing = self._claims_by_id[self._claim_spo[spo]]
            merged_eids = list(existing.evidence_ids)
            confidence = existing.confidence
            status = existing.epistemic_status
            added = False
            for eid in new_eids:
                if eid in merged_eids:
                    continue
                reliability = self._reliability_of(eid, incoming.confidence)
                confidence = apply_support(confidence, reliability)
                merged_eids.append(eid)
                added = True
            if not added:
                return
            evidences = self._evidences(merged_eids)
            open_c = self._has_open_contradiction(skey, pred, okey)
            if status is not EpistemicStatus.INVALIDATED:
                status = status_after_support(
                    pred, confidence, evidences, open_contradiction=open_c
                )
            updated = existing.model_copy(
                update={
                    "confidence": confidence,
                    "evidence_ids": merged_eids,
                    "epistemic_status": status,
                    "updated_at": now,
                }
            )
            self._store_claim(updated, skey, pred, okey)
            self._side_effects(updated, subject)
            return

        siblings = [
            self._claims_by_id[cid]
            for (sk, p, ok), cid in list(self._claim_spo.items())
            if sk == skey and p == pred and ok != okey
        ]
        reliability = incoming.confidence
        eid = new_eids[0]
        for sib in siblings:
            contra = list(dict.fromkeys([*sib.contradiction_ids, eid]))
            if sib.epistemic_status is EpistemicStatus.INVALIDATED:
                self._store_claim(
                    sib.model_copy(update={"contradiction_ids": contra, "updated_at": now}),
                    skey,
                    pred,
                    object_key(sib.object),
                )
                continue
            new_c, invalidated = apply_contradiction(sib.confidence, reliability)
            updates: dict[str, Any] = {
                "confidence": new_c,
                "contradiction_ids": contra,
                "updated_at": now,
            }
            if invalidated:
                updates["epistemic_status"] = EpistemicStatus.INVALIDATED
            elif new_c < 0.30:
                updates["epistemic_status"] = EpistemicStatus.SUSPECTED
            self._store_claim(sib.model_copy(update=updates), skey, pred, object_key(sib.object))
            self._record_conflict(sib, incoming, skey, pred)

        contra_ids: list[str] = []
        for sib in siblings:
            current = self._claims_by_id.get(sib.claim_id, sib)
            contra_ids.extend(current.evidence_ids)
        status = incoming.epistemic_status
        if siblings:
            status = status_from_reliability(pred, reliability)
        elif self._evidences(new_eids):
            status = status_after_support(
                pred,
                incoming.confidence,
                self._evidences(new_eids),
                open_contradiction=False,
            )
        stored = incoming.model_copy(
            update={
                "contradiction_ids": list(
                    dict.fromkeys([*incoming.contradiction_ids, *contra_ids])
                ),
                "epistemic_status": status,
                "updated_at": now,
            }
        )
        self._store_claim(stored, skey, pred, okey)
        self._side_effects(stored, subject)

    def _side_effects(self, claim: Claim, subject: Asset) -> None:
        status = claim.epistemic_status
        pred = claim.predicate
        obj = claim.object
        updates: dict[str, Any] = {"last_seen_at": utcnow()}
        if status is not EpistemicStatus.INVALIDATED:
            updates["epistemic_status"] = max_status(subject.epistemic_status, status)
        if isinstance(subject, Port) and pred == "port.state":
            try:
                updates["state"] = PortState(str(obj).lower())
            except ValueError:
                updates["state"] = PortState.UNKNOWN
        if isinstance(subject, Service):
            if pred == "service.name":
                updates["name"] = str(obj).lower()
                updates["display_name"] = str(obj).lower()
            elif pred == "service.product":
                updates["product"] = str(obj)
            elif pred == "service.version":
                updates["version"] = str(obj)
            elif pred == "service.banner":
                updates["banner"] = str(obj)[:256]
        if isinstance(subject, UrlAsset):
            if pred == "http.status":
                try:
                    updates["status_code"] = int(obj)
                except (TypeError, ValueError):
                    pass
            elif pred == "http.title":
                updates["title"] = str(obj)[:128]
            elif pred == "http.header" and isinstance(obj, dict):
                if str(obj.get("name") or "").lower() == "content-type":
                    updates["content_type"] = str(obj.get("value") or "")[:128]
        if isinstance(subject, Endpoint) and pred == "auth.seen":
            updates["auth_required"] = True
        if isinstance(subject, Host) and pred == "host.hostname":
            updates["hostname"] = str(obj)
        merged = subject.model_copy(update=updates)
        self._index_asset(merged)
        if pred == "http.status" and isinstance(subject, UrlAsset):
            try:
                code = int(obj)
            except (TypeError, ValueError):
                code = None
            if code is not None:
                for asset in list(self._by_id.values()):
                    if isinstance(asset, Endpoint) and asset.url_id == subject.asset_id:
                        self._index_asset(asset.model_copy(update={"last_status": code}))

    def _store_claim(self, claim: Claim, skey: str, pred: str, okey: str) -> None:
        self._claims_by_id[claim.claim_id] = claim
        self._claim_spo[(skey, pred, okey)] = claim.claim_id

    def _index_asset(self, asset: Asset) -> None:
        self._by_key[asset.canonical_key] = asset
        self._by_id[asset.asset_id] = asset

    def _register_evidence(self, evidence: Evidence) -> None:
        self._evidence_by_id[evidence.evidence_id] = evidence.model_copy(deep=True)
        if evidence.evidence_id not in self._applied:
            self._evidence_order.append(evidence.evidence_id)
            self._applied.add(evidence.evidence_id)
        self._last_evidence_id = evidence.evidence_id

    def _evidences(self, ids: Sequence[str]) -> list[Evidence]:
        return [self._evidence_by_id[eid] for eid in ids if eid in self._evidence_by_id]

    def _reliability_of(self, eid: str, fallback: float) -> float:
        item = self._evidence_by_id.get(eid)
        return item.reliability if item is not None else fallback

    def _has_open_contradiction(self, skey: str, pred: str, okey: str) -> bool:
        for (sk, p, ok), cid in self._claim_spo.items():
            if sk != skey or p != pred or ok == okey:
                continue
            claim = self._claims_by_id[cid]
            if claim.epistemic_status is not EpistemicStatus.INVALIDATED:
                return True
        return False

    def _record_conflict(self, old: Claim, new: Claim, skey: str, pred: str) -> None:
        self._events.append(
            TimelineEvent(
                event_id=new_id(PREFIX_TIMELINE),
                mission_id=self._mission_id,
                kind=TimelineKind.WORLD,
                message=f"conflict {pred} on {skey}",
                at=utcnow(),
                ref_id=old.claim_id,
            )
        )

    def _ordered_evidence(self) -> list[Evidence]:
        return [
            self._evidence_by_id[eid] for eid in self._evidence_order if eid in self._evidence_by_id
        ]

    def _snapshot_unlocked(self) -> WorldSnapshot:
        hosts = self._copies(Host)
        ports = self._copies(Port)
        services = self._copies(Service)
        techs = self._copies(Technology)
        domains = self._copies(Domain)
        subdomains = self._copies(Subdomain)
        urls = self._copies(UrlAsset)
        endpoints = self._copies(Endpoint)
        params = self._copies(Parameter)
        auths = self._copies(AuthenticationSurface)
        ifaces = self._copies(NetworkInterface)
        claims = tuple(item.model_copy(deep=True) for item in self._claims_by_id.values())
        gaps = tuple(item.model_copy(deep=True) for item in self._gaps.values())
        findings = tuple(item.model_copy(deep=True) for item in self._findings.values())
        hyps = tuple(item.model_copy(deep=True) for item in self._hypotheses.values())
        unmapped = tuple(item.model_copy(deep=True) for item in self._unmapped)
        recent = tuple(
            self._evidence_by_id[eid].model_copy(deep=True)
            for eid in self._evidence_order[-20:]
            if eid in self._evidence_by_id
        )
        assets_sem = [
            (a.kind.value, a.canonical_key, a.epistemic_status.value, a.out_of_scope)
            for a in self._by_id.values()
        ]
        claims_sem = [
            claim_semantic_tuple(self.asset_key_by_id(c.subject_id) or "", c)
            for c in self._claims_by_id.values()
        ]
        gaps_sem = [
            (g.kind, self.asset_key_by_id(g.subject_id) or "", g.closed, g.detail)
            for g in self._gaps.values()
        ]
        findings_sem = [(f.kind.value, f.title, f.status.value) for f in self._findings.values()]
        hyps_sem = [(h.statement, h.status.value) for h in self._hypotheses.values()]
        digest = semantic_digest(
            mission_id=self._mission_id,
            revision=self._revision,
            assets=assets_sem,
            claims=claims_sem,
            gaps=gaps_sem,
            findings=findings_sem,
            hypotheses=hyps_sem,
            coverage=dict(self._coverage),
            unmapped_count=len(self._unmapped),
        )
        return WorldSnapshot(
            mission_id=self._mission_id,
            revision=self._revision,
            updated_at=self._updated_at,
            digest=digest,
            last_evidence_id=self._last_evidence_id,
            hosts=hosts,
            interfaces=ifaces,
            ports=ports,
            services=services,
            technologies=techs,
            domains=domains,
            subdomains=subdomains,
            urls=urls,
            endpoints=endpoints,
            parameters=params,
            auth_surfaces=auths,
            claims=claims,
            gaps=gaps,
            findings=findings,
            hypotheses=hyps,
            coverage=dict(self._coverage),
            unmapped=unmapped,
            recent_evidence=recent,
        )

    def _clone(self) -> dict[str, Any]:
        by_id = {k: v.model_copy(deep=True) for k, v in self._by_id.items()}
        by_key = {asset.canonical_key: asset for asset in by_id.values()}
        return {
            "by_key": by_key,
            "by_id": by_id,
            "claims_by_id": {k: v.model_copy(deep=True) for k, v in self._claims_by_id.items()},
            "claim_spo": dict(self._claim_spo),
            "gaps": {k: v.model_copy(deep=True) for k, v in self._gaps.items()},
            "findings": {k: v.model_copy(deep=True) for k, v in self._findings.items()},
            "hypotheses": {k: v.model_copy(deep=True) for k, v in self._hypotheses.items()},
            "coverage": dict(self._coverage),
            "unmapped": [item.model_copy(deep=True) for item in self._unmapped],
            "evidence_by_id": {k: v.model_copy(deep=True) for k, v in self._evidence_by_id.items()},
            "evidence_order": list(self._evidence_order),
            "applied": set(self._applied),
            "seed_assets": [item.model_copy(deep=True) for item in self._seed_assets],
            "aliases": dict(self._aliases),
            "events": [item.model_copy(deep=True) for item in self._events],
            "revision": self._revision,
            "updated_at": self._updated_at,
            "last_evidence_id": self._last_evidence_id,
        }

    def _restore(self, backup: dict[str, Any]) -> None:
        self._by_key = backup["by_key"]
        self._by_id = backup["by_id"]
        self._claims_by_id = backup["claims_by_id"]
        self._claim_spo = backup["claim_spo"]
        self._gaps = backup["gaps"]
        self._findings = backup["findings"]
        self._hypotheses = backup["hypotheses"]
        self._coverage = backup["coverage"]
        self._unmapped = backup["unmapped"]
        self._evidence_by_id = backup["evidence_by_id"]
        self._evidence_order = backup["evidence_order"]
        self._applied = backup["applied"]
        self._seed_assets = backup["seed_assets"]
        self._aliases = backup["aliases"]
        self._events = backup["events"]
        self._revision = backup["revision"]
        self._updated_at = backup["updated_at"]
        self._last_evidence_id = backup["last_evidence_id"]
