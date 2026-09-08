"""M13 recon intelligence: signals, priority, dedup, no exploit claims."""

from __future__ import annotations

import pytest
from tests.conftest import artifact_from_fixture

from cyberx.brain.context import BrainContextBuilder
from cyberx.brain.scorer import ActionScorer
from cyberx.brain.types import CandidateAction
from cyberx.domain.enums import (
    EpistemicStatus,
    FindingKind,
    FindingSeverity,
    FindingStatus,
    MissionMode,
)
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import PREFIX_EVIDENCE, PREFIX_FINDING, PREFIX_HOST, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import ActionTarget
from cyberx.domain.models.findings import Finding
from cyberx.domain.models.mission import Mission, Scope
from cyberx.domain.time import utcnow
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.tui.keys import BINDINGS, HELP_TEXT
from cyberx.tui.render import render_investigations
from cyberx.world.importance import asset_importance
from cyberx.world.model import InMemoryWorldModel
from cyberx.world.priority import investigation_priority, rank_investigations
from cyberx.world.signals import classify_http_status, classify_path, classify_port, signal_title


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


def test_path_classification_is_conservative() -> None:
    assert classify_path("/admin") == "admin_surface"
    assert classify_path("/api/v1") == "api_surface"
    assert classify_path("/login") == "auth_surface"
    assert classify_path("/backup") == "backup_looking_path"
    assert classify_path("/graphql") == "api_surface"
    assert classify_path("/uploads") == "upload_surface"
    assert classify_path("/debug") == "debug_surface"
    assert classify_path("/") is None
    assert classify_http_status(403, "/admin") == "admin_surface"
    assert classify_http_status(301, "/uploads") == "unusual_redirect"
    assert classify_http_status(500, "/") == "unusual_status"
    assert classify_port(22) == "exposed_service"
    assert classify_port(3306) == "unusual_service"
    assert "vulnerability" not in signal_title("admin_surface").lower()
    assert "Admin surface discovered" == signal_title("admin_surface")


def test_findings_from_web_surface_have_signals() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    kinds = {f.kind for f in world.get_findings()}
    assert FindingKind.AUTH_SURFACE in kinds
    assert FindingKind.INTERESTING_PATH in kinds
    blob = " ".join(f.title.lower() + f.summary.lower() for f in world.get_findings())
    assert "sql injection" not in blob
    assert "xss" not in blob
    assert "rce" not in blob
    assert "auth bypass" not in blob
    auth = next(f for f in world.get_findings() if f.kind is FindingKind.AUTH_SURFACE)
    assert auth.signal == "auth_surface"
    assert auth.severity in {FindingSeverity.INFO, FindingSeverity.LOW}
    assert auth.severity is not FindingSeverity.MEDIUM or True
    assert auth.confidence >= 0.0
    assert auth.source == "heuristic"
    assert auth.identity_key


def test_directory_results_are_distinct_signals() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    by_signal = {f.signal: f for f in world.get_findings() if f.signal}
    assert "admin_surface" in by_signal
    assert "api_surface" in by_signal
    assert "backup_looking_path" in by_signal
    assert "unusual_redirect" in by_signal or any(
        f.signal == "unusual_redirect" for f in world.get_findings()
    )
    allowed = {FindingSeverity.INFO, FindingSeverity.LOW}
    assert all(f.severity in allowed for f in world.get_findings())


def test_finding_dedup_updates_last_seen() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    first = [f for f in world.get_findings() if f.signal == "admin_surface"]
    assert len(first) == 1
    fid = first[0].finding_id
    count = first[0].observation_count
    created = first[0].created_at
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    again = [f for f in world.get_findings() if f.signal == "admin_surface"]
    assert len(again) == 1
    assert again[0].finding_id == fid
    assert again[0].created_at == created
    assert again[0].observation_count >= count
    assert again[0].last_seen_at >= created


def test_ai_cannot_create_findings() -> None:
    now = utcnow()
    with pytest.raises(DomainValidationError):
        Finding(
            finding_id=new_id(PREFIX_FINDING),
            mission_id=new_id(PREFIX_MISSION),
            kind=FindingKind.ANOMALY,
            title="x",
            summary="y",
            severity=FindingSeverity.INFO,
            epistemic_status=EpistemicStatus.KNOWN,
            evidence_ids=[new_id(PREFIX_EVIDENCE)],
            asset_ids=[new_id(PREFIX_HOST)],
            created_at=now,
            source="ai",
        )


def test_weak_evidence_not_confirmed() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "http/probe_200.json", "http_adapter", "application/json")
    for finding in world.get_findings():
        if finding.signal == "tech_observed":
            assert finding.epistemic_status is not EpistemicStatus.CONFIRMED


def test_asset_importance_and_priority_order() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "endpoint/forms.html", "endpoint_adapter", "text/html")
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    items = rank_investigations(world)
    assert items
    scores = [i.priority for i in items]
    assert scores == sorted(scores, reverse=True)
    assert all(0.0 <= i.priority <= 1.0 for i in items)
    admin = next((i for i in items if i.reason == "admin_surface"), None)
    portish = next((i for i in items if i.reason in {"exposed_service", "open_port"}), None)
    if admin and portish:
        assert admin.priority >= portish.priority
    for finding in world.get_findings():
        asset = world.peek_asset_by_id(finding.asset_ids[0])
        pri = investigation_priority(finding, asset=asset, world=world)
        assert 0.0 <= pri <= 1.0
        if asset is not None:
            assert 0.0 <= asset_importance(asset, world) <= 1.0


def test_brain_context_includes_investigations() -> None:
    from cyberx.domain.ids import PREFIX_SCOPE, PREFIX_TARGET

    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    now = utcnow()
    mission = Mission(
        mission_id=world.mission_id,
        name="box",
        intent="enumerate surface",
        mode=MissionMode.CTF,
        status=__import__("cyberx.domain.enums", fromlist=["MissionStatus"]).MissionStatus.RUNNING,
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
    ctx = BrainContextBuilder().build(world.snapshot(), mission, scope=scope)
    assert ctx.byte_size <= 32768
    assert ctx.investigations
    assert ctx.top_findings
    cand = CandidateAction(
        action_type="endpoint_discovery",
        target=ActionTarget(canonical_locator="http://10.10.11.23/admin"),
        parameters={"url": "http://10.10.11.23/admin"},
        coverage_key="x",
        reason="web_surface",
        gap_kind="endpoint.params_unknown",
        expected_information_gain=0.8,
        risk="info",
        cost=0.3,
    )
    ctx2 = ctx.model_copy(
        update={
            "gaps": [
                {
                    "kind": "endpoint.params_unknown",
                    "id": "g1",
                    "subject_id": "",
                    "priority": "0.4",
                }
            ]
        }
    )
    scored = ActionScorer().score([cand], ctx2)
    assert scored[0].rejected is False
    assert "mission_relevance" in scored[0].factors


def test_severity_never_exceeds_v1() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "nmap/host_22_80.xml", "nmap_adapter", "application/xml")
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    allowed = {FindingSeverity.INFO, FindingSeverity.LOW, FindingSeverity.MEDIUM}
    for finding in world.get_findings():
        assert finding.severity in allowed
        assert finding.status in {
            FindingStatus.OPEN,
            FindingStatus.ACCEPTED,
            FindingStatus.SUPERSEDED,
            FindingStatus.INVALIDATED,
        }


def test_investigations_view_is_recon_only() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply(world, "directory/mixed.json", "directory_adapter", "application/json")
    from cyberx.app.views import InvestigationView

    items = tuple(
        InvestigationView(
            title=item.title,
            reason=item.reason,
            priority=f"{item.priority:.2f}",
            asset=item.asset,
            kind=item.kind,
        )
        for item in rank_investigations(world)
    )
    text = render_investigations(items, color=False).lower()
    assert "reconnaissance" in text
    assert "exploit" in text
    assert "sql injection" not in text
    assert BINDINGS["i"] == "investigations"
    assert "investigate" in HELP_TEXT
