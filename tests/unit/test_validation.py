"""M14 validation intelligence: safe questions, catalog-only mappings."""

from __future__ import annotations

import pytest
from tests.conftest import artifact_from_fixture, create_cmd

from cyberx.actions.catalog import DEFAULT_CATALOG
from cyberx.brain.context import BrainContextBuilder
from cyberx.brain.planner import Planner
from cyberx.domain.enums import (
    V1_ACTION_TYPES,
    EpistemicStatus,
    FindingKind,
    FindingSeverity,
    HypothesisSource,
    HypothesisStatus,
    MissionMode,
    ValidationStatus,
)
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import (
    PREFIX_EVIDENCE,
    PREFIX_FINDING,
    PREFIX_HOST,
    PREFIX_HYPOTHESIS,
    PREFIX_MISSION,
    PREFIX_SCOPE,
    PREFIX_TARGET,
    PREFIX_VALIDATION,
    new_id,
)
from cyberx.domain.models.actions import ActionRequest, ActionTarget
from cyberx.domain.models.findings import Finding, Hypothesis
from cyberx.domain.models.mission import Mission, Scope
from cyberx.domain.models.validation import ValidationCandidate
from cyberx.domain.time import utcnow
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.policy.engine import PolicyEngine
from cyberx.validation.engine import ValidationEngine
from cyberx.validation.mappings import UNSAFE_CANDIDATE_TYPES
from cyberx.world.model import InMemoryWorldModel


def _apply(world: InMemoryWorldModel, relative: str, adapter: str, media: str) -> None:
    artifact = artifact_from_fixture(
        relative,
        adapter_name=adapter,
        media_type=media,
        mission_id=world.mission_id,
        source_locator="http://10.10.11.23/",
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    for item in evidence:
        world.apply_evidence(item)


def _mission_scope(world: InMemoryWorldModel) -> tuple[Mission, Scope]:
    now = utcnow()
    from cyberx.domain.enums import MissionStatus

    mission = Mission(
        mission_id=world.mission_id,
        name="box",
        intent="enumerate surface",
        mode=MissionMode.CTF,
        status=MissionStatus.RUNNING,
        target_id=new_id(PREFIX_TARGET),
        scope_id=new_id(PREFIX_SCOPE),
        created_at=now,
        started_at=now,
        iteration=1,
    )
    scope = Scope(
        scope_id=mission.scope_id,
        mission_id=world.mission_id,
        allowed_targets=["10.10.11.23"],
        allowed_networks=[],
        allowed_ports=[],
        allowed_protocols=["tcp", "http", "https", "dns"],
        frozen=True,
        created_at=now,
    )
    return mission, scope


def test_catalog_unchanged_no_validate_action() -> None:
    assert "validate" not in V1_ACTION_TYPES
    assert DEFAULT_CATALOG.get("validate") is None
    assert DEFAULT_CATALOG.get("exploit_http") is None
    assert tuple(DEFAULT_CATALOG.types()) == V1_ACTION_TYPES


def test_http_surface_candidate_from_open_http_port() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    cands = ValidationEngine().evaluate(world)
    http = [c for c in cands if c.candidate_type == "http_surface"]
    assert http
    assert all(c.mapped_action_type == "http_probe" for c in http)
    assert all(c.status is ValidationStatus.PROPOSED for c in http)
    assert all(c.mapped_action_type in V1_ACTION_TYPES for c in http)
    assert all(c.evidence_ids for c in http)
    assert all(c.finding_id for c in http)


def test_admin_403_proposes_http_probe_not_exploit() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    cands = ValidationEngine().evaluate(world)
    admin = [c for c in cands if "admin" in c.locator and c.mapped_action_type == "http_probe"]
    assert admin
    assert all("exploit" not in c.reason.lower() for c in admin)
    assert all(c.parameters.get("method") in (None, "GET") for c in admin)
    assert all("password" not in c.parameters for c in admin)


def test_weak_tech_maps_to_technology_detection() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    cands = ValidationEngine().evaluate(world)
    tech = [c for c in cands if c.candidate_type == "technology_fingerprint"]
    assert tech
    assert all(c.mapped_action_type == "technology_detection" for c in tech)
    assert all(c.status is ValidationStatus.PROPOSED for c in tech)
    assert all("exploit" not in c.reason.lower() for c in tech)


def test_auth_surface_does_not_submit_credentials() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    cands = ValidationEngine().evaluate(world)
    auth = [c for c in cands if c.candidate_type == "authentication_surface"]
    assert auth
    blob = " ".join(str(c.parameters) for c in auth).lower()
    assert "password" not in blob
    assert "username" not in blob
    assert all(c.mapped_action_type == "endpoint_discovery" for c in auth)
    assert all(c.parameters.get("method") in (None, "GET") for c in auth)


def test_candidate_dedup_is_deterministic() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    first = ValidationEngine().evaluate(world)
    second = ValidationEngine().evaluate(world)
    keys = [c.identity_key for c in first]
    assert keys == [c.identity_key for c in second]
    assert len(keys) == len(set(keys))
    assert {c.validation_id for c in first} == {c.validation_id for c in second}


def test_coverage_key_suppresses_repeat() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    engine = ValidationEngine()
    proposed = [c for c in engine.evaluate(world) if c.status is ValidationStatus.PROPOSED]
    assert proposed
    target = proposed[0]
    assert target.coverage_key
    world.record_coverage(target.coverage_key, "completed")
    later = engine.evaluate(world)
    match = [c for c in later if c.identity_key == target.identity_key]
    assert match
    assert match[0].status in {
        ValidationStatus.SUPPORTED,
        ValidationStatus.INCONCLUSIVE,
    }


def test_changed_evidence_revalidation() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    engine = ValidationEngine()
    first = [c for c in engine.evaluate(world) if c.candidate_type == "http_surface"]
    assert first
    target = first[0]
    assert target.status is ValidationStatus.PROPOSED
    world.record_coverage(target.coverage_key, "completed")
    blocked = [c for c in engine.evaluate(world) if c.identity_key == target.identity_key]
    assert blocked
    assert blocked[0].status is ValidationStatus.INCONCLUSIVE
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    later = [c for c in engine.evaluate(world) if c.identity_key == target.identity_key]
    assert later
    assert later[0].status is ValidationStatus.SUPPORTED
    assert later[0].mapped_action_type == "http_probe"


def test_finding_and_hypothesis_association() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    engine = ValidationEngine()
    cands = engine.evaluate(world)
    assert cands
    finding = next(f for f in world.get_findings() if f.finding_id == cands[0].finding_id)
    hyp = Hypothesis(
        hypothesis_id=new_id(PREFIX_HYPOTHESIS),
        mission_id=world.mission_id,
        statement="HTTP surface exposes an authentication boundary",
        status=HypothesisStatus.OPEN,
        confidence=0.3,
        created_at=utcnow(),
        related_asset_ids=list(finding.asset_ids),
        source=HypothesisSource.HEURISTIC,
    )
    world.record_hypothesis(hyp)
    linked = engine.evaluate(world)
    engine.sync_findings(world, linked)
    assert any(c.hypothesis_id == hyp.hypothesis_id for c in linked)
    findings = {f.finding_id: f for f in world.get_findings()}
    for cand in linked:
        assert cand.finding_id in findings
        stamped = findings[cand.finding_id]
        assert stamped.validation_state == cand.status.value
        assert cand.evidence_ids
        assert cand.evidence_ids == list(findings[cand.finding_id].evidence_ids)


def test_priority_is_deterministic() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    cands = ValidationEngine().evaluate(world)
    scores = [c.priority for c in cands]
    assert scores == sorted(scores, reverse=True)
    assert all(0.0 <= c.priority <= 1.0 for c in cands)


def test_unsafe_and_ai_candidates_rejected() -> None:
    now = utcnow()
    mid = new_id(PREFIX_MISSION)
    with pytest.raises(DomainValidationError):
        ValidationCandidate(
            validation_id=new_id(PREFIX_VALIDATION),
            mission_id=mid,
            candidate_type="http_surface",
            identity_key="x",
            reason="x",
            mapped_action_type="exploit_http",
            created_at=now,
        )
    with pytest.raises(DomainValidationError):
        ValidationCandidate(
            validation_id=new_id(PREFIX_VALIDATION),
            mission_id=mid,
            candidate_type="http_surface",
            identity_key="x",
            reason="x",
            source="ai",
            created_at=now,
        )
    with pytest.raises(DomainValidationError):
        ValidationCandidate(
            validation_id=new_id(PREFIX_VALIDATION),
            mission_id=mid,
            candidate_type="http_surface",
            identity_key="x",
            reason="x",
            parameters={"password": "admin"},
            created_at=now,
        )
    with pytest.raises(DomainValidationError):
        ValidationCandidate(
            validation_id=new_id(PREFIX_VALIDATION),
            mission_id=mid,
            candidate_type="http_surface",
            identity_key="x",
            reason="x",
            parameters={"method": "POST", "url": "http://10.10.11.23/login"},
            created_at=now,
        )
    with pytest.raises(DomainValidationError):
        Finding(
            finding_id=new_id(PREFIX_FINDING),
            mission_id=mid,
            kind=FindingKind.ANOMALY,
            title="x",
            summary="y",
            severity=FindingSeverity.INFO,
            epistemic_status=EpistemicStatus.KNOWN,
            evidence_ids=[new_id(PREFIX_EVIDENCE)],
            asset_ids=[new_id(PREFIX_HOST)],
            created_at=now,
            source="heuristic",
        ).model_copy(update={"source": "ai"})
    assert "sql_injection" in UNSAFE_CANDIDATE_TYPES


def test_unsupported_validation_rejected() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    now = utcnow()
    finding = Finding(
        finding_id=new_id(PREFIX_FINDING),
        mission_id=world.mission_id,
        kind=FindingKind.ANOMALY,
        title="injection",
        summary="not a v1 validation target",
        severity=FindingSeverity.INFO,
        epistemic_status=EpistemicStatus.KNOWN,
        evidence_ids=[new_id(PREFIX_EVIDENCE)],
        asset_ids=[new_id(PREFIX_HOST)],
        created_at=now,
        signal="sql_injection",
        identity_key="anomaly:sql_injection:x",
    )
    world.put_finding(finding)
    cands = ValidationEngine().evaluate(world)
    assert cands
    assert all(c.status is ValidationStatus.REJECTED for c in cands)
    assert all(not c.mapped_action_type for c in cands)
    assert all("unsupported" in c.reason for c in cands)


def test_brain_context_and_planner_use_validation_candidates() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    mission, scope = _mission_scope(world)
    ctx = BrainContextBuilder().build(world.snapshot(), mission, scope=scope)
    assert ctx.validation_candidates
    assert ctx.byte_size <= 32768
    for row in ctx.validation_candidates:
        action = row.get("action") or ""
        assert action in V1_ACTION_TYPES or action == ""
    planner = Planner()
    proposed = planner.propose(ctx, DEFAULT_CATALOG)
    types = {c.action_type for c in proposed}
    assert types <= set(V1_ACTION_TYPES)
    assert "exploit_http" not in types
    assert "validate" not in types


def test_oos_finding_is_rejected() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    now = utcnow()
    finding = Finding(
        finding_id=new_id(PREFIX_FINDING),
        mission_id=world.mission_id,
        kind=FindingKind.OUT_OF_SCOPE_OBSERVATION,
        title="out of scope",
        summary="ignored",
        severity=FindingSeverity.INFO,
        epistemic_status=EpistemicStatus.KNOWN,
        evidence_ids=[new_id(PREFIX_EVIDENCE)],
        asset_ids=[new_id(PREFIX_HOST)],
        created_at=now,
        signal="admin_surface",
        identity_key="oos:admin",
    )
    world.put_finding(finding)
    cands = ValidationEngine().evaluate(world)
    assert cands
    assert all(c.status is ValidationStatus.REJECTED for c in cands)
    assert all(not c.mapped_action_type for c in cands)


def test_invalidated_finding_expires_candidate() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    finding = next(f for f in world.get_findings() if f.signal == "admin_surface")
    from cyberx.domain.enums import FindingStatus

    world.put_finding(finding.model_copy(update={"status": FindingStatus.INVALIDATED}))
    cands = ValidationEngine().evaluate(world)
    expired = [c for c in cands if c.finding_id == finding.finding_id]
    assert expired
    assert all(c.status is ValidationStatus.EXPIRED for c in expired)


def test_policy_and_scope_still_gate_mapped_actions() -> None:
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    bundle = service.get_bundle(mission.mission_id)
    policy = PolicyEngine()
    allowed = policy.authorize(
        ActionRequest(
            mission_id=bundle.mission.mission_id,
            action_type="http_probe",
            target=ActionTarget(canonical_locator="http://10.10.11.23/"),
            parameters={"url": "http://10.10.11.23/"},
            reason="validation candidate",
            prerequisites=["service.http_unprobed"],
        ),
        bundle.mission,
        bundle.scope,
    )
    assert allowed.allowed
    denied = policy.authorize(
        ActionRequest(
            mission_id=bundle.mission.mission_id,
            action_type="http_probe",
            target=ActionTarget(canonical_locator="http://8.8.8.8/"),
            parameters={"url": "http://8.8.8.8/"},
            reason="validation candidate",
            prerequisites=["service.http_unprobed"],
        ),
        bundle.mission,
        bundle.scope,
    )
    assert not denied.allowed
    exploit = policy.authorize(
        ActionRequest(
            mission_id=bundle.mission.mission_id,
            action_type="validate_sqli",
            target=ActionTarget(canonical_locator="http://10.10.11.23/"),
            parameters={},
            reason="no",
        ),
        bundle.mission,
        bundle.scope,
    )
    assert not exploit.allowed
    assert exploit.reason_code == "forbidden_action_kind"


def test_candidate_action_mapping_stays_in_catalog() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    for cand in ValidationEngine().evaluate(world):
        if cand.mapped_action_type:
            assert cand.mapped_action_type in V1_ACTION_TYPES
            assert "exploit" not in cand.mapped_action_type
            assert cand.mapped_action_type != "validate"
            assert "password" not in cand.parameters
            assert cand.parameters.get("cmd") is None
            assert cand.parameters.get("argv") is None
