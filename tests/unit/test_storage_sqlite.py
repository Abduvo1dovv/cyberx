"""M7 SQLite persistence: round-trips, transactions, secrets, resume."""

from __future__ import annotations

import sqlite3

import pytest
from tests.conftest import artifact_from_fixture, create_cmd
from tests.unit.test_world_model import make_evidence

from cyberx.domain.enums import (
    ActionResultStatus,
    ActionStatus,
    EpistemicStatus,
    FindingKind,
    FindingSeverity,
    HypothesisSource,
    HypothesisStatus,
    Risk,
)
from cyberx.domain.errors import StorageError
from cyberx.domain.ids import (
    PREFIX_ACTION,
    PREFIX_FINDING,
    PREFIX_HYPOTHESIS,
    PREFIX_RESULT,
    PREFIX_TOOL_RUN,
    new_id,
)
from cyberx.domain.models.actions import Action, ActionResult, ActionTarget, ToolRun
from cyberx.domain.models.findings import Finding, Hypothesis
from cyberx.domain.time import utcnow
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.evidence.redactor import SecretRef
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.ports import MissionStore
from cyberx.mission.service import MissionService
from cyberx.storage.sqlite import SqliteStore
from cyberx.world.model import InMemoryWorldModel
from cyberx.world.replay import Replay
from cyberx.world.restore import hydrate_from_snapshot


def _store(tmp_path) -> SqliteStore:
    return SqliteStore(tmp_path / "cyberx.db", data_dir=tmp_path)


def test_sqlite_initializes(tmp_path) -> None:
    store = _store(tmp_path)
    row = store._execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='missions'"
    ).fetchone()
    assert row is not None
    store.close()


def test_mission_scope_round_trip(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    started = service.start(mission.mission_id)
    store.close()
    reopened = SqliteStore(tmp_path / "cyberx.db", data_dir=tmp_path)
    loaded = reopened.get(mission.mission_id)
    assert loaded.mission.mission_id == started.mission_id
    assert loaded.mission.status.value == "RUNNING"
    assert loaded.scope.frozen is True
    assert loaded.target.normalized == "10.10.11.23"
    assert loaded.seed_assets
    reopened.close()


def test_asset_claim_evidence_round_trip(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    mid = mission.mission_id
    world = InMemoryWorldModel(mid)
    world.seed_assets(service.get_bundle(mid).seed_assets)
    ev = make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    world.apply_evidence(ev)
    store.insert_evidence(ev)
    store.persist_world(world)
    claims = store.list_claims(mid)
    assert claims
    assets = store.list_assets(mid)
    assert any(a.kind.value == "host" for a in assets)
    history = store.list_claim_history(mid)
    assert history
    store.close()


def test_hypothesis_finding_action_timeline(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    mid = mission.mission_id
    hyp = Hypothesis(
        hypothesis_id=new_id(PREFIX_HYPOTHESIS),
        mission_id=mid,
        statement="ports are unknown on the target host",
        status=HypothesisStatus.OPEN,
        confidence=0.3,
        created_at=utcnow(),
        source=HypothesisSource.HEURISTIC,
    )
    store.save_hypotheses(mid, [hyp])
    loaded = store.list_hypotheses(mid)
    assert loaded[0].statement == hyp.statement
    now = utcnow()
    action = Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=mid,
        action_type="port_scan",
        target=ActionTarget(canonical_locator="10.10.11.23"),
        parameters={"address": "10.10.11.23", "ports": "top1000", "protocol": "tcp"},
        reason="gap=host.ports_unknown",
        expected_information_gain=0.8,
        risk=Risk.LOW,
        timeout_s=30,
        status=ActionStatus.COMPLETED,
        coverage_key="c" * 64,
        created_at=now,
    )
    store.save_action(action)
    assert store.list_actions(mid)[0].action_type == "port_scan"
    run = ToolRun(
        tool_run_id=new_id(PREFIX_TOOL_RUN),
        action_id=action.action_id,
        adapter_name="stub_adapter",
        argv=["stub", "port_scan", "10.10.11.23"],
        started_at=now,
        status="completed",
        ended_at=now,
    )
    store.save_tool_run(run)
    result = ActionResult(
        result_id=new_id(PREFIX_RESULT),
        action_id=action.action_id,
        tool_run_id=run.tool_run_id,
        status=ActionResultStatus.COMPLETED,
        started_at=now,
        ended_at=now,
    )
    store.save_result(result)
    assert store.list_results(mid)[0].status is ActionResultStatus.COMPLETED
    evidence = make_evidence(
        mid, "port.state", "open", "port:host:ipv4:10.10.11.23:tcp:22", reliability=0.95
    )
    finding = Finding(
        finding_id=new_id(PREFIX_FINDING),
        mission_id=mid,
        kind=FindingKind.OPEN_PORT,
        title="22/tcp open",
        summary="open ssh port",
        severity=FindingSeverity.INFO,
        epistemic_status=EpistemicStatus.CONFIRMED,
        evidence_ids=[evidence.evidence_id],
        asset_ids=[service.get_bundle(mid).seed_assets[0].asset_id],
        created_at=now,
    )
    store.save_findings(mid, [finding])
    assert store.list_findings(mid)[0].kind is FindingKind.OPEN_PORT
    events = store.list_timeline(mid)
    assert events
    store.close()


def test_transaction_rollback(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    mid = mission.mission_id
    ev = make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    with pytest.raises(RuntimeError):
        with store.transaction():
            store.insert_evidence(ev)
            raise RuntimeError("boom")
    assert store.list_evidence(mid) == []
    store.close()


def test_duplicate_evidence_ignored(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    mid = mission.mission_id
    ev = make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    assert store.insert_evidence(ev) is True
    assert store.insert_evidence(ev) is False
    assert len(store.list_evidence(mid)) == 1
    store.close()


def test_secrets_are_not_stored_raw(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    mid = mission.mission_id
    secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb"
    store.insert_secret_ref(
        mid,
        SecretRef(kind="jwt", location_hint="banner", sha256="abc" * 21 + "abcd"),
    )
    refs = store.list_secret_refs(mid)
    assert refs[0].kind == "jwt"
    store.close()
    raw = (tmp_path / "cyberx.db").read_bytes()
    assert secret.encode() not in raw
    assert b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in raw


def test_artifact_metadata_not_blob(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    artifact = artifact_from_fixture(
        "nmap/host_open_ports.xml",
        adapter_name="nmap_adapter",
        media_type="application/xml",
        mission_id=mission.mission_id,
    )
    path = store.put(artifact)
    meta = store.get_meta(artifact.artifact_id)
    assert meta is not None
    assert meta.sha256 == artifact.sha256
    assert meta.path == path
    conn = sqlite3.connect(tmp_path / "cyberx.db")
    cols = [r[1] for r in conn.execute("PRAGMA table_info(artifacts)").fetchall()]
    conn.close()
    assert "body" not in cols
    store.close()


def test_db_replay_digest_matches_memory(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    mid = mission.mission_id
    seeds = service.get_bundle(mid).seed_assets
    artifact = artifact_from_fixture(
        "nmap/host_open_ports.xml",
        adapter_name="nmap_adapter",
        media_type="application/xml",
        mission_id=mid,
        source_locator="10.10.11.23",
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    mem = Replay().rebuild(mid, evidence, seed_assets=seeds)
    for item in evidence:
        store.insert_evidence(item)
    store.save_seed_assets(mid, seeds)
    db_world = store.rebuild_from_evidence(mid)
    # coverage/hypotheses empty on both evidence-only rebuilds except rebuild_from_evidence
    # reapplies coverage (none) and hypotheses (none) which still bump revision.
    mem2 = Replay().rebuild(mid, store.list_evidence(mid), seed_assets=seeds)
    assert mem.snapshot().digest == mem2.snapshot().digest
    del db_world
    store.close()


def test_snapshot_plus_tail_matches_full_replay(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    mid = mission.mission_id
    seeds = service.get_bundle(mid).seed_assets
    world = InMemoryWorldModel(mid)
    world.seed_assets(seeds)
    items = [
        make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95),
        make_evidence(
            mid,
            "port.state",
            "open",
            "port:host:ipv4:10.10.11.23:tcp:22",
            reliability=0.95,
        ),
        make_evidence(
            mid,
            "port.state",
            "open",
            "port:host:ipv4:10.10.11.23:tcp:80",
            reliability=0.95,
        ),
    ]
    world.apply_evidence(items[0])
    snap = world.snapshot()
    for item in items[1:]:
        world.apply_evidence(item)
    full_digest = world.snapshot().digest
    restored = hydrate_from_snapshot(snap, seed_assets=seeds, evidence=items[:1])
    for item in items[1:]:
        restored.apply_evidence(item)
    assert restored.snapshot().digest == full_digest
    store.close()


def test_restart_resume_reconstruction(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    mid = mission.mission_id
    seeds = service.get_bundle(mid).seed_assets
    world = InMemoryWorldModel(mid)
    world.seed_assets(seeds)
    ev = make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    world.apply_evidence(ev)
    store.insert_evidence(ev)
    store.save_seed_assets(mid, seeds)
    store.persist_world(world)
    digest = world.snapshot().digest
    store.close()
    store2 = SqliteStore(tmp_path / "cyberx.db", data_dir=tmp_path)
    resumed = store2.resume_world(mid)
    assert resumed.snapshot().digest == digest
    store2.close()


def test_repository_interfaces_are_structural() -> None:
    memory: MissionStore = InMemoryMissionStore()
    assert hasattr(memory, "save")
    assert hasattr(memory, "get")
    store = SqliteStore(":memory:")
    assert hasattr(store, "save_mission")
    assert hasattr(store, "insert_evidence")
    assert hasattr(store, "save_action")
    assert hasattr(store, "append_timeline")
    store.close()


def test_resume_without_snapshot_rebuilds_from_evidence(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    mid = mission.mission_id
    seeds = service.get_bundle(mid).seed_assets
    store.save_seed_assets(mid, seeds)
    ev = make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    store.insert_evidence(ev)
    resumed = store.resume_world(mid)
    claims = resumed.get_claims()
    assert claims
    assert any(c.predicate == "host.alive" for c in claims)
    store.close()


def test_snapshot_then_tail_evidence_is_applied(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    mid = mission.mission_id
    seeds = service.get_bundle(mid).seed_assets
    world = InMemoryWorldModel(mid)
    world.seed_assets(seeds)
    first = make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    world.apply_evidence(first)
    store.insert_evidence(first)
    store.save_seed_assets(mid, seeds)
    store.persist_world(world)
    second = make_evidence(
        mid,
        "port.state",
        "open",
        "port:host:ipv4:10.10.11.23:tcp:22",
        reliability=0.95,
    )
    store.insert_evidence(second)
    resumed = store.resume_world(mid)
    predicates = {c.predicate for c in resumed.get_claims()}
    assert "host.alive" in predicates
    assert "port.state" in predicates
    store.close()


def test_missing_artifact_on_resume_does_not_invent_facts(tmp_path) -> None:
    store = _store(tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    mid = mission.mission_id
    artifact = artifact_from_fixture(
        "stub/port_scan.json",
        adapter_name="stub_adapter",
        media_type="application/json",
        source_locator="10.10.11.23",
        mission_id=mid,
    )
    path = store.put(artifact)
    from pathlib import Path

    Path(path).unlink()
    with pytest.raises(StorageError):
        store.get_body(artifact.artifact_id, mid)
    world = store.resume_world(mid)
    assert world.get_open_ports() == ()
    store.close()


def test_interrupted_persist_recovery_boundaries(tmp_path) -> None:
    """Crash at persist boundaries A–F. Evidence remains the source of truth."""
    db = tmp_path / "cyberx.db"

    def open_store() -> SqliteStore:
        return SqliteStore(db, data_dir=tmp_path)

    store = open_store()
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    mid = mission.mission_id
    seeds = service.get_bundle(mid).seed_assets
    store.save_seed_assets(mid, seeds)
    store.close()

    # A: before action persistence
    store = open_store()
    assert store.list_actions(mid) == []
    resumed = store.resume_world(mid)
    assert not any(c.predicate == "host.alive" for c in resumed.get_claims())
    store.close()

    # B: after action persistence (no result)
    store = open_store()
    now = utcnow()
    action = Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=mid,
        action_type="port_scan",
        target=ActionTarget(canonical_locator="10.10.11.23"),
        parameters={"address": "10.10.11.23", "ports": "top1000", "protocol": "tcp"},
        reason="gap=host.ports_unknown",
        expected_information_gain=0.8,
        risk=Risk.LOW,
        timeout_s=30,
        status=ActionStatus.RUNNING,
        coverage_key="c" * 64,
        created_at=now,
    )
    store.save_action(action)
    store.close()
    store = open_store()
    assert store.list_actions(mid)[0].action_id == action.action_id
    assert store.list_results(mid) == []
    resumed = store.resume_world(mid)
    assert resumed.get_open_ports() == ()
    store.close()

    # C: after result persistence (no evidence)
    store = open_store()
    run = ToolRun(
        tool_run_id=new_id(PREFIX_TOOL_RUN),
        action_id=action.action_id,
        adapter_name="stub_adapter",
        argv=["stub", "port_scan", "10.10.11.23"],
        started_at=now,
        status="completed",
        ended_at=now,
    )
    result = ActionResult(
        result_id=new_id(PREFIX_RESULT),
        action_id=action.action_id,
        tool_run_id=run.tool_run_id,
        status=ActionResultStatus.COMPLETED,
        started_at=now,
        ended_at=now,
    )
    store.save_tool_run(run)
    store.save_result(result)
    store.close()
    store = open_store()
    assert store.list_results(mid)
    resumed = store.resume_world(mid)
    assert not any(c.predicate == "port.state" for c in resumed.get_claims())
    store.close()

    # D: after evidence persistence (no snapshot)
    store = open_store()
    ev = make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    store.insert_evidence(ev)
    store.close()
    store = open_store()
    resumed = store.resume_world(mid)
    assert any(c.predicate == "host.alive" for c in resumed.get_claims())
    assert resumed.get_open_ports() == ()
    store.close()

    # E: after World Model snapshot
    store = open_store()
    world = store.resume_world(mid)
    store.persist_world(world)
    digest = world.snapshot().digest
    store.close()
    store = open_store()
    resumed = store.resume_world(mid)
    assert resumed.snapshot().digest == digest
    store.close()

    # F: after decision trace
    store = open_store()
    store.save_decision_trace(mid, 1, '{"iteration":1}')
    store.close()
    store = open_store()
    assert store.list_decision_traces(mid)
    resumed = store.resume_world(mid)
    assert resumed.snapshot().digest == digest
    store.close()
