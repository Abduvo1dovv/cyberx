"""Adaptive validation: recon evidence → candidate → catalog action, no exploit."""

from __future__ import annotations

from tests.conftest import artifact_from_fixture

from cyberx.actions.catalog import DEFAULT_CATALOG
from cyberx.brain.context import BrainContextBuilder
from cyberx.brain.facade import Brain
from cyberx.domain.enums import V1_ACTION_TYPES, MissionMode, ValidationStatus
from cyberx.domain.ids import PREFIX_MISSION, PREFIX_SCOPE, PREFIX_TARGET, new_id
from cyberx.domain.models.mission import Mission, Scope
from cyberx.domain.time import utcnow
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.validation.engine import ValidationEngine
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


def test_nmap_http_then_validation_prefers_catalog_action() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    engine = ValidationEngine()
    cands = engine.evaluate(world)
    assert any(c.candidate_type in {"http_surface", "technology_fingerprint"} for c in cands)
    assert all(c.mapped_action_type in V1_ACTION_TYPES or not c.mapped_action_type for c in cands)
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
        iteration=2,
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
    engine.sync_findings(world, cands)
    ctx = BrainContextBuilder().build(
        world.snapshot(), mission, scope=scope, validation_candidates=cands
    )
    assert ctx.validation_candidates
    assert ctx.top_findings
    decision = Brain().decide(ctx, DEFAULT_CATALOG, min_score=0.15)
    if decision.action is not None:
        assert decision.action.action_type in V1_ACTION_TYPES
        assert "exploit" not in decision.action.action_type
        assert "validate" not in decision.action.action_type
        assert "password" not in decision.action.parameters
        assert decision.action.parameters.get("cmd") is None
    findings = {f.finding_id: f for f in world.get_findings()}
    for cand in cands:
        if cand.finding_id and cand.finding_id in findings:
            stamped = findings[cand.finding_id]
            assert (
                stamped.validation_state
                in {
                    "",
                    cand.status.value,
                }
                or stamped.validation_state == cand.status.value
            )


def test_auth_candidate_never_becomes_credential_action() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    cands = ValidationEngine().evaluate(world)
    auth = [c for c in cands if c.candidate_type == "authentication_surface"]
    assert auth
    assert {c.status for c in auth} <= {
        ValidationStatus.PROPOSED,
        ValidationStatus.SUPPORTED,
        ValidationStatus.INCONCLUSIVE,
        ValidationStatus.REJECTED,
    }
    for cand in auth:
        assert cand.mapped_action_type == "endpoint_discovery"
        assert "password" not in cand.parameters
        assert cand.parameters.get("username") is None
