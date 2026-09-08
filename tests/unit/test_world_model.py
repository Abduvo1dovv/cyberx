"""World Model apply, epistemics, mutation fence, invalid deltas."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from cyberx.domain.confidence import apply_supporting
from cyberx.domain.enums import EpistemicStatus, HypothesisSource, HypothesisStatus
from cyberx.domain.errors import DomainValidationError, InvalidWorldDelta, WorldModelError
from cyberx.domain.ids import (
    PREFIX_ARTIFACT,
    PREFIX_EVIDENCE,
    PREFIX_HYPOTHESIS,
    PREFIX_MISSION,
    PREFIX_OBSERVATION,
    PREFIX_TOOL_RUN,
    new_id,
)
from cyberx.domain.models.evidence import Claim, Evidence
from cyberx.domain.models.findings import Hypothesis
from cyberx.domain.time import utcnow
from cyberx.world.delta import WorldDelta, WorldDeltaKind
from cyberx.world.model import InMemoryWorldModel


def make_evidence(
    mission_id: str,
    predicate: str,
    obj: Any,
    subject_hint: str,
    *,
    reliability: float = 0.9,
    parser_id: str = "stub",
    tool_run_id: str | None = None,
    mapped: bool = True,
    action_type: str | None = None,
) -> Evidence:
    preview: dict[str, Any] = {
        "predicate": predicate,
        "object": obj,
        "subject_hint": subject_hint,
        "mapped": mapped,
    }
    if action_type:
        preview["action_type"] = action_type
    return Evidence(
        evidence_id=new_id(PREFIX_EVIDENCE),
        mission_id=mission_id,
        observation_id=new_id(PREFIX_OBSERVATION),
        artifact_id=new_id(PREFIX_ARTIFACT),
        tool_run_id=tool_run_id or new_id(PREFIX_TOOL_RUN),
        parser_id=parser_id,
        claim_preview=preview,
        reliability=reliability,
        created_at=utcnow(),
        hash="test",
    )


def test_first_evidence_creates_fact() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    ev = make_evidence(
        mid,
        "host.alive",
        True,
        "host:ipv4:10.10.11.23",
        reliability=0.95,
        parser_id="stub",
    )
    rev = world.apply_evidence(ev)
    assert rev == 1
    hosts = world.get_hosts()
    assert len(hosts) == 1
    assert hosts[0].canonical_key == "host:ipv4:10.10.11.23"
    claims = world.get_claims()
    assert len(claims) == 1
    claim = claims[0]
    assert claim.predicate == "host.alive"
    assert claim.object is True
    assert claim.epistemic_status is EpistemicStatus.CONFIRMED
    assert claim.confidence == pytest.approx(0.95)
    assert ev.evidence_id in claim.evidence_ids
    assert world.get_recent_evidence()[0].evidence_id == ev.evidence_id


def test_duplicate_evidence_ignored() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    ev = make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    r1 = world.apply_evidence(ev)
    r2 = world.apply_evidence(ev)
    assert r1 == r2
    claims = world.get_claims()
    assert len(claims) == 1
    assert claims[0].evidence_ids == [ev.evidence_id]
    assert claims[0].confidence == pytest.approx(0.95)


def test_support_increases_confidence() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    hint = "url:http://10.10.11.23:80/"
    first = make_evidence(
        mid, "http.title", "Stub Host", hint, reliability=0.85, parser_id="http_probe"
    )
    second = make_evidence(mid, "http.title", "Stub Host", hint, reliability=0.85, parser_id="tech")
    world.apply_evidence(first)
    world.apply_evidence(second)
    claim = world.get_claims()[0]
    expected = apply_supporting(0.85, 0.85)
    assert claim.confidence == pytest.approx(expected)
    assert set(claim.evidence_ids) == {first.evidence_id, second.evidence_id}
    assert claim.epistemic_status is EpistemicStatus.CONFIRMED


def test_contradiction_invalidates() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    hint = "port:host:ipv4:10.10.11.23:tcp:22"
    open_ev = make_evidence(mid, "port.state", "open", hint, reliability=0.95)
    closed_ev = make_evidence(mid, "port.state", "closed", hint, reliability=0.95)
    world.apply_evidence(open_ev)
    world.apply_evidence(closed_ev)
    claims = world.get_claims(include_invalidated=True)
    by_obj = {c.object: c for c in claims}
    assert by_obj["open"].epistemic_status is EpistemicStatus.INVALIDATED
    assert by_obj["open"].confidence == pytest.approx(0.95)
    assert closed_ev.evidence_id in by_obj["open"].contradiction_ids
    assert by_obj["closed"].epistemic_status is EpistemicStatus.CONFIRMED
    assert by_obj["closed"].object == "closed"
    invalidated = [c for c in claims if c.epistemic_status is EpistemicStatus.INVALIDATED]
    assert invalidated
    conflicts = world.get_conflicts()
    assert len(conflicts) >= 1


def test_weaker_contradiction_reduces_confidence() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    hint = "port:host:ipv4:10.10.11.23:tcp:80"
    strong = make_evidence(mid, "port.state", "open", hint, reliability=0.95)
    weak = make_evidence(mid, "port.state", "closed", hint, reliability=0.20)
    world.apply_evidence(strong)
    world.apply_evidence(weak)
    by_obj = {c.object: c for c in world.get_claims(include_invalidated=True)}
    assert by_obj["open"].epistemic_status is not EpistemicStatus.INVALIDATED
    assert by_obj["open"].confidence == pytest.approx(0.95 * (1 - 0.5 * 0.20))
    assert by_obj["closed"].epistemic_status is EpistemicStatus.SUSPECTED
    assert weak.evidence_id in by_obj["open"].contradiction_ids


def test_invalidated_claims_remain_queryable() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    hint = "port:host:ipv4:10.10.11.23:tcp:22"
    world.apply_evidence(make_evidence(mid, "port.state", "open", hint, reliability=0.95))
    world.apply_evidence(make_evidence(mid, "port.state", "closed", hint, reliability=0.95))
    live = world.get_claims(include_invalidated=False)
    all_claims = world.get_claims(include_invalidated=True)
    assert any(c.epistemic_status is EpistemicStatus.INVALIDATED for c in all_claims)
    assert all(c.epistemic_status is not EpistemicStatus.INVALIDATED for c in live)


def test_claim_evidence_provenance() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    ev = make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    world.apply_evidence(ev)
    claim = world.get_claims()[0]
    stored = world.get_recent_evidence()[0]
    assert claim.evidence_ids == [ev.evidence_id]
    assert stored.observation_id == ev.observation_id
    assert stored.artifact_id == ev.artifact_id
    assert stored.tool_run_id == ev.tool_run_id
    assert stored.parser_id == ev.parser_id


def test_unmapped_observations_cannot_create_facts() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    ev = make_evidence(
        mid,
        "foo.bar",
        "x",
        "host:ipv4:10.10.11.23",
        reliability=0.0,
        mapped=False,
    )
    world.apply_evidence(ev)
    assert world.get_claims() == ()
    assert world.get_unmapped()
    assert world.get_unmapped()[0].evidence_id == ev.evidence_id


def test_ai_only_suggestions_cannot_create_facts() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    with pytest.raises(DomainValidationError):
        make_evidence(mid, "host.alive", True, "host:ipv4:1.2.3.4", parser_id="ai")
    hyp = Hypothesis(
        hypothesis_id=new_id(PREFIX_HYPOTHESIS),
        mission_id=mid,
        statement="the box might be a web server",
        status=HypothesisStatus.OPEN,
        confidence=0.4,
        created_at=utcnow(),
        source=HypothesisSource.AI,
    )
    world.record_hypothesis(hyp)
    assert world.get_claims() == ()
    assert world.get_hosts() == ()
    assert world.get_hypotheses()[0].source is HypothesisSource.AI
    forged = Evidence.model_construct(
        evidence_id=new_id(PREFIX_EVIDENCE),
        mission_id=mid,
        observation_id=new_id(PREFIX_OBSERVATION),
        artifact_id=new_id(PREFIX_ARTIFACT),
        tool_run_id=new_id(PREFIX_TOOL_RUN),
        parser_id="llm",
        claim_preview={
            "predicate": "host.alive",
            "object": True,
            "subject_hint": "host:ipv4:10.10.11.23",
            "mapped": True,
        },
        reliability=0.99,
        created_at=utcnow(),
    )
    with pytest.raises(WorldModelError):
        world.apply_evidence(forged)
    assert world.get_claims() == ()


def test_invalid_world_delta_rejected() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    delta = WorldDelta(kind=WorldDeltaKind.UPSERT_CLAIM, claim=None)
    with pytest.raises(InvalidWorldDelta):
        world.apply([delta])
    with pytest.raises(InvalidWorldDelta):
        world.apply([WorldDelta(kind=WorldDeltaKind.UPSERT_ASSET, asset=None)])
    with pytest.raises(InvalidWorldDelta):
        world.apply([WorldDelta(kind=WorldDeltaKind.COVERAGE_ADD)])
    with pytest.raises(ValidationError):
        WorldDelta(kind="delete_entity")  # type: ignore[arg-type]
    with pytest.raises(InvalidWorldDelta):
        world.apply("not-a-list")  # type: ignore[arg-type]


def test_world_model_no_unrestricted_public_mutation() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    world.apply_evidence(
        make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    )
    for name in dir(world):
        if name.startswith("_"):
            continue
        value = getattr(world, name)
        assert not isinstance(value, dict), f"public dict {name}"
        assert not isinstance(value, list), f"public list {name}"
    hosts = world.get_hosts()
    original = hosts[0].display_name
    hosts[0].display_name = "mutated"
    assert world.get_hosts()[0].display_name == original
    claims = world.get_claims()
    claims[0].confidence = 0.01
    assert world.get_claims()[0].confidence != pytest.approx(0.01)
    snap = world.snapshot()
    snap.hosts[0].display_name = "snap-mut"
    assert world.get_hosts()[0].display_name == original


def test_coverage_add_and_summary() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    world.apply(
        [
            WorldDelta(
                kind=WorldDeltaKind.COVERAGE_ADD,
                coverage_key="port_scan:host:ipv4:10.10.11.23",
                coverage_status="completed",
            )
        ]
    )
    assert "port_scan:host:ipv4:10.10.11.23" in world.get_coverage()
    summary = world.summary()
    assert summary["mission_id"] == mid
    assert summary["revision"] >= 1
    assert "asset_counts" in summary


def test_claim_without_evidence_cannot_be_built() -> None:
    with pytest.raises(Exception):
        Claim(
            claim_id="clm_" + "0" * 26,
            subject_id="hst_" + "0" * 26,
            predicate="host.alive",
            object=True,
            epistemic_status=EpistemicStatus.KNOWN,
            confidence=0.5,
            evidence_ids=[],
            created_at=utcnow(),
            updated_at=utcnow(),
        )
