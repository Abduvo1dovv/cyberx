"""Pre-v2 architecture/reliability contracts. No new recon capability."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from tests.conftest import artifact_from_fixture, create_cmd
from tests.unit.test_world_model import make_evidence

from cyberx.brain.context import BrainContextBuilder, context_hash
from cyberx.brain.dedup import merge_candidates
from cyberx.brain.locators import hosts_for_ip_actions, locator_is_obsolete
from cyberx.brain.planner import Planner
from cyberx.brain.types import CandidateAction
from cyberx.config import ActionLimits, AppConfig
from cyberx.domain.confidence import AI_HYPOTHESIS_CONFIDENCE_CAP, apply_supporting
from cyberx.domain.enums import V1_ACTION_TYPES, HypothesisSource, HypothesisStatus, MissionMode
from cyberx.domain.errors import DomainValidationError, ParseError, StorageError
from cyberx.domain.ids import (
    PREFIX_ARTIFACT,
    PREFIX_HOST,
    PREFIX_HYPOTHESIS,
    PREFIX_MISSION,
    PREFIX_TOOL_RUN,
    new_id,
)
from cyberx.domain.models.actions import ActionTarget
from cyberx.domain.models.context import AssetContext, GapContext
from cyberx.domain.models.findings import BrainContext, Hypothesis
from cyberx.domain.time import utcnow
from cyberx.engine.loop import MAX_ACTION_ATTEMPTS, MissionEngine
from cyberx.evidence.integrity import verify_raw_artifact
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.ports.events import DomainEvent, EventType
from cyberx.ports.execution import RawArtifact
from cyberx.storage.artifacts import FileArtifactStore
from cyberx.storage.sqlite import SqliteStore
from cyberx.world.model import InMemoryWorldModel


def _running():
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    return service, mission.mission_id


def test_brain_context_rows_are_typed() -> None:
    ctx = BrainContext(
        mission_id=new_id(PREFIX_MISSION),
        intent="x",
        mode="ctf",
        iteration=0,
        scope_digest="abc",
        top_assets=[{"kind": "host", "id": "hst_1", "address": "10.10.11.23"}],
        gaps=[{"kind": "host.ports_unknown", "id": "g1"}],
        network={"reachability": "REACHABLE"},
    )
    assert isinstance(ctx.top_assets[0], AssetContext)
    assert ctx.top_assets[0].kind == "host"
    assert ctx.top_assets[0].address == "10.10.11.23"
    assert isinstance(ctx.gaps[0], GapContext)
    assert ctx.gaps[0].kind == "host.ports_unknown"
    assert ctx.network.reachability == "REACHABLE"
    assert ctx.network.get("reachability") == "REACHABLE"


def test_one_brain_context_per_cycle() -> None:
    service, mid = _running()

    class CountingBuilder(BrainContextBuilder):
        def __init__(self) -> None:
            self.calls = 0
            self.hashes: list[str] = []

        def build(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            self.calls += 1
            ctx = super().build(*args, **kwargs)
            self.hashes.append(context_hash(ctx))
            return ctx

    builder = CountingBuilder()
    engine = MissionEngine(service, builder=builder)
    report = engine.run_one_cycle(mid)
    assert report.selected_action_type == "port_scan"
    assert builder.calls == 1
    assert len(set(builder.hashes)) == 1
    traces = engine.traces(mid)
    assert traces
    assert traces[0].context_hash == builder.hashes[0]


def test_event_reader_does_not_need_sink_internals() -> None:
    sink = InMemoryEventSink()
    sink.emit(DomainEvent(event_type=EventType.AI_REQUESTED, mission_id="mis_x", payload={}))
    sink.emit(DomainEvent(event_type=EventType.PARSE_COMPLETED, payload={}))
    assert sink.emitted_count() == 2
    recent = list(sink.iter_recent(after=0, limit=1))
    assert len(recent) == 1
    assert recent[0].event_type is EventType.AI_REQUESTED
    rest = list(sink.iter_recent(after=1, limit=10))
    assert rest[0].event_type is EventType.PARSE_COMPLETED


def test_candidate_dedup_by_coverage_key() -> None:
    target = ActionTarget(canonical_locator="10.10.11.23")
    planner = CandidateAction(
        action_type="port_scan",
        target=target,
        parameters={"address": "10.10.11.23", "ports": "top1000", "protocol": "tcp"},
        coverage_key="k" * 64,
        reason="gap=host.ports_unknown",
        expected_information_gain=0.8,
        source="planner",
    )
    path = CandidateAction(
        action_type="port_scan",
        target=target,
        parameters={"address": "10.10.11.23", "ports": "top1000", "protocol": "tcp"},
        coverage_key="k" * 64,
        reason="investigation path",
        expected_information_gain=0.62,
        source="path",
    )
    merged = merge_candidates([planner, path])
    assert len(merged) == 1
    assert merged[0].expected_information_gain == 0.8
    assert "gap=host.ports_unknown" in merged[0].reason
    assert "investigation path" in merged[0].reason
    assert "planner" in merged[0].source
    assert "path" in merged[0].source


def test_ai_hypothesis_confidence_cap() -> None:
    mid = new_id(PREFIX_MISSION)
    with pytest.raises(DomainValidationError, match="capped at 0.4"):
        Hypothesis(
            hypothesis_id=new_id(PREFIX_HYPOTHESIS),
            mission_id=mid,
            statement="maybe wordpress",
            status=HypothesisStatus.OPEN,
            confidence=0.41,
            created_at=utcnow(),
            source=HypothesisSource.AI,
        )
    ok = Hypothesis(
        hypothesis_id=new_id(PREFIX_HYPOTHESIS),
        mission_id=mid,
        statement="maybe wordpress",
        status=HypothesisStatus.OPEN,
        confidence=AI_HYPOTHESIS_CONFIDENCE_CAP,
        created_at=utcnow(),
        source=HypothesisSource.AI,
    )
    assert ok.confidence == AI_HYPOTHESIS_CONFIDENCE_CAP
    with pytest.raises(DomainValidationError):
        ok.model_copy(update={"confidence": 0.9})


def test_non_ai_evidence_can_raise_claim_confidence() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    first = make_evidence(
        mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.4, parser_id="stub"
    )
    world.apply_evidence(first)
    claims = world.get_claims()
    assert claims
    before = claims[0].confidence
    assert before <= 0.4 + 1e-9
    second = make_evidence(
        mid,
        "host.alive",
        True,
        "host:ipv4:10.10.11.23",
        reliability=0.95,
        parser_id="nmap_xml",
    )
    world.apply_evidence(second)
    after = world.get_claims()[0].confidence
    assert after > before
    assert after > AI_HYPOTHESIS_CONFIDENCE_CAP
    assert after == pytest.approx(apply_supporting(before, 0.95))


def test_historical_locator_is_not_an_action_target() -> None:
    current_id = new_id(PREFIX_HOST)
    stale_id = new_id(PREFIX_HOST)
    hist_id = new_id(PREFIX_HOST)
    oos_id = new_id(PREFIX_HOST)
    ctx = BrainContext(
        mission_id=new_id(PREFIX_MISSION),
        intent="x",
        mode=MissionMode.CTF.value,
        iteration=0,
        scope_digest="abc",
        top_assets=[
            {
                "kind": "host",
                "id": hist_id,
                "address": "10.10.11.23",
                "labels": "historical",
            },
            {
                "kind": "host",
                "id": stale_id,
                "address": "10.10.11.60",
                "labels": "observed",
            },
            {
                "kind": "host",
                "id": oos_id,
                "address": "8.8.8.8",
                "oos": "1",
            },
            {
                "kind": "host",
                "id": current_id,
                "address": "10.10.11.45",
                "labels": "current_locator",
            },
        ],
        gaps=[{"kind": "host.ports_unknown", "id": "g1", "subject_id": current_id}],
        target_identity={
            "current": "10.10.11.45",
            "previous": "10.10.11.23",
            "historical": "10.10.11.23,10.10.11.60",
        },
    )
    assert locator_is_obsolete(ctx, "10.10.11.23") is True
    assert locator_is_obsolete(ctx, "10.10.11.60") is True
    assert locator_is_obsolete(ctx, "10.10.11.45") is False
    live = hosts_for_ip_actions(ctx)
    assert [h.address for h in live] == ["10.10.11.45"]
    locators = {c.target.canonical_locator for c in Planner().propose(ctx)}
    assert "10.10.11.45" in locators
    assert "10.10.11.23" not in locators
    assert "10.10.11.60" not in locators
    assert "8.8.8.8" not in locators
    types = {c.action_type for c in Planner().propose(ctx)}
    assert "retarget" not in types
    assert "confirm_locator" not in types
    assert "retarget" not in V1_ACTION_TYPES


def test_artifact_hash_mismatch_is_parse_error() -> None:
    artifact = artifact_from_fixture(
        "stub/port_scan.json",
        adapter_name="stub_adapter",
        media_type="application/json",
        source_locator="10.10.11.23",
    )
    bad = artifact.model_copy(update={"sha256": "0" * 64})
    with pytest.raises(ParseError, match="hash"):
        verify_raw_artifact(bad)
    with pytest.raises(ParseError):
        EvidencePipeline().normalize(bad)


def test_missing_artifact_file_fails_closed(tmp_path) -> None:
    store = FileArtifactStore(tmp_path)
    with pytest.raises(StorageError, match="missing"):
        store.get("art_missing", "mis_missing")


def test_corrupt_on_disk_artifact_does_not_parse(tmp_path) -> None:
    artifact = artifact_from_fixture(
        "stub/port_scan.json",
        adapter_name="stub_adapter",
        media_type="application/json",
        source_locator="10.10.11.23",
    )
    files = FileArtifactStore(tmp_path)
    path = files.put(artifact)
    Path(path).write_bytes(b"tampered")
    loaded = artifact.model_copy(update={"body": None, "path": path})
    with pytest.raises(ParseError, match="hash"):
        EvidencePipeline().normalize(loaded)


def test_truncated_empty_artifact_fails_closed() -> None:
    empty = hashlib.sha256(b"").hexdigest()
    artifact = RawArtifact(
        artifact_id=new_id(PREFIX_ARTIFACT),
        tool_run_id=new_id(PREFIX_TOOL_RUN),
        adapter_name="stub_adapter",
        media_type="application/json",
        sha256=empty,
        byte_size=0,
        truncated=True,
        body=b"",
        mission_id=new_id(PREFIX_MISSION),
        source_locator="10.10.11.23",
    )
    with pytest.raises(ParseError, match="truncated"):
        verify_raw_artifact(artifact)


def test_artifact_size_mismatch_and_bound_fail_closed() -> None:
    artifact = artifact_from_fixture(
        "stub/port_scan.json",
        adapter_name="stub_adapter",
        media_type="application/json",
        source_locator="10.10.11.23",
    )
    wrong_size = artifact.model_copy(update={"byte_size": artifact.byte_size + 8})
    with pytest.raises(ParseError, match="size"):
        verify_raw_artifact(wrong_size)
    huge = b"x" * (ActionLimits().max_artifact_bytes + 1)
    over = RawArtifact(
        artifact_id=artifact.artifact_id,
        tool_run_id=artifact.tool_run_id,
        adapter_name="stub_adapter",
        media_type="application/octet-stream",
        sha256=hashlib.sha256(huge).hexdigest(),
        byte_size=len(huge),
        body=huge,
        mission_id=artifact.mission_id,
        source_locator="10.10.11.23",
    )
    with pytest.raises(ParseError, match="size"):
        verify_raw_artifact(over)


def test_action_limits_are_single_source() -> None:
    limits = ActionLimits()
    assert limits.max_attempts == MAX_ACTION_ATTEMPTS
    assert limits.max_artifact_bytes == AppConfig().actions.max_artifact_bytes
    digest = hashlib.sha256(b"x").hexdigest()
    assert len(digest) == 64


def test_engine_persistence_protocol_is_implemented(tmp_path) -> None:
    store = SqliteStore(tmp_path / "cyberx.db", data_dir=tmp_path)
    for name in (
        "persist_world",
        "resume_world",
        "save_runtime",
        "get_runtime",
        "save_action",
        "put",
        "insert_evidence",
        "append_timeline",
        "save_decision_trace",
        "transaction",
        "get_body",
    ):
        assert callable(getattr(store, name))
    store.close()
