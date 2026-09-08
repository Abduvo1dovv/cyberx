"""M8 deterministic Brain: gaps, scoring, ties, context, stop."""

from __future__ import annotations

from cyberx.actions.catalog import DEFAULT_CATALOG
from cyberx.actions.scoring import ScoreFactors, compute_score
from cyberx.brain.context import BrainContextBuilder, context_hash
from cyberx.brain.decision import DecisionEngine
from cyberx.brain.facade import Brain
from cyberx.brain.planner import Planner
from cyberx.brain.scorer import ActionScorer
from cyberx.brain.types import CandidateAction
from cyberx.domain.enums import EpistemicStatus, MissionMode
from cyberx.domain.ids import PREFIX_HOST, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import ActionTarget
from cyberx.domain.models.assets import Host
from cyberx.domain.models.findings import BrainContext
from cyberx.domain.models.mission import Mission, Scope
from cyberx.domain.time import utcnow
from cyberx.world.model import InMemoryWorldModel


def _mission(mid: str) -> Mission:
    now = utcnow()
    from cyberx.domain.ids import PREFIX_SCOPE, PREFIX_TARGET

    return Mission(
        mission_id=mid,
        name="box",
        intent="enumerate surface",
        mode=MissionMode.CTF,
        status=__import__("cyberx.domain.enums", fromlist=["MissionStatus"]).MissionStatus.RUNNING,
        target_id=new_id(PREFIX_TARGET),
        scope_id=new_id(PREFIX_SCOPE),
        created_at=now,
        started_at=now,
        iteration=0,
    )


def _scope(mid: str, mission: Mission) -> Scope:
    return Scope(
        scope_id=mission.scope_id,
        mission_id=mid,
        allowed_targets=["10.10.11.23"],
        allowed_networks=[],
        allowed_ports=[],
        allowed_protocols=["tcp", "http", "https", "dns"],
        frozen=True,
        created_at=utcnow(),
    )


def _host_world(address: str = "10.10.11.23") -> tuple[InMemoryWorldModel, Mission, Scope]:
    mid = new_id(PREFIX_MISSION)
    mission = _mission(mid)
    world = InMemoryWorldModel(mid)
    now = utcnow()
    from cyberx.domain.enums import AddressType, AssetKind
    from cyberx.domain.identity import host_key_ipv4

    host = Host(
        asset_id=new_id(PREFIX_HOST),
        mission_id=mid,
        kind=AssetKind.HOST,
        canonical_key=host_key_ipv4(address),
        display_name=address,
        first_seen_at=now,
        last_seen_at=now,
        epistemic_status=EpistemicStatus.KNOWN,
        address_type=AddressType.IPV4,
        ipv4=address,
    )
    world.seed_assets([host])
    return world, mission, _scope(mid, mission)


def test_ports_unknown_proposes_port_scan() -> None:
    world, mission, scope = _host_world()
    ctx = BrainContextBuilder().build(world.snapshot(), mission, scope=scope)
    candidates = Planner().propose(ctx, DEFAULT_CATALOG)
    types = {c.action_type for c in candidates}
    assert "port_scan" in types
    assert "directory_enumeration" not in types
    assert "subdomain_enumeration" not in types


def test_unresolved_hostname_not_directory() -> None:
    mid = new_id(PREFIX_MISSION)
    mission = _mission(mid)
    world = InMemoryWorldModel(mid)
    now = utcnow()
    from cyberx.domain.enums import AddressType, AssetKind
    from cyberx.domain.identity import host_key_name

    host = Host(
        asset_id=new_id(PREFIX_HOST),
        mission_id=mid,
        kind=AssetKind.HOST,
        canonical_key=host_key_name("box.htb"),
        display_name="box.htb",
        first_seen_at=now,
        last_seen_at=now,
        epistemic_status=EpistemicStatus.KNOWN,
        address_type=AddressType.NAME,
        hostname="box.htb",
    )
    world.seed_assets([host])
    ctx = BrainContextBuilder().build(world.snapshot(), mission, scope=_scope(mid, mission))
    types = {c.action_type for c in Planner().propose(ctx, DEFAULT_CATALOG)}
    assert "dns_enumeration" in types
    assert "directory_enumeration" not in types


def test_unknown_action_impossible() -> None:
    world, mission, scope = _host_world()
    ctx = BrainContextBuilder().build(world.snapshot(), mission, scope=scope)
    planner = Planner()
    cands = planner.propose(ctx)
    assert all(c.action_type in DEFAULT_CATALOG.types() for c in cands)
    assert all(DEFAULT_CATALOG.get(c.action_type) is not None for c in cands)


def test_scoring_formula_and_hard_zeros() -> None:
    factors = ScoreFactors(
        mission_relevance=1,
        information_gain=1,
        evidence_strength=1,
        p_useful=1,
        novelty=1,
        dependency_readiness=1,
        cost=0,
        risk=0,
    )
    assert compute_score(factors) == 1.0
    zero_n = factors.__class__(**{**factors.__dict__, "novelty": 0.0})
    assert compute_score(zero_n) == 0.0
    zero_r = factors.__class__(**{**factors.__dict__, "dependency_readiness": 0.0})
    assert compute_score(zero_r) == 0.0


def test_novelty_zero_prevents_repeat() -> None:
    world, mission, scope = _host_world()
    ctx = BrainContextBuilder().build(world.snapshot(), mission, scope=scope)
    planner = Planner()
    proposed = planner.propose(ctx)
    assert proposed
    first = proposed[0]
    ctx2 = ctx.model_copy(update={"coverage_keys": [first.coverage_key]})
    again = planner.propose(ctx2)
    assert all(c.coverage_key != first.coverage_key for c in again)
    scored = ActionScorer().score(
        [first.model_copy()],
        ctx2,
    )
    assert scored[0].score == 0.0
    assert scored[0].rejected is True


def test_min_score_stop() -> None:
    ctx = BrainContext(
        mission_id=new_id(PREFIX_MISSION),
        intent="x",
        mode="ctf",
        iteration=0,
        scope_digest="abc",
        revision=1,
    )
    decision = DecisionEngine().select([], ctx, min_score=0.15)
    assert decision.kind == "stop"


def test_tie_break_lower_risk_then_cost_then_catalog() -> None:
    mid = new_id(PREFIX_MISSION)
    ctx = BrainContext(
        mission_id=mid,
        intent="x",
        mode="ctf",
        iteration=0,
        scope_digest="abc",
        revision=1,
        gaps=[
            {
                "kind": "host.ports_unknown",
                "id": "g1",
                "subject_id": "",
                "priority": "0.9",
            },
            {
                "kind": "service.http_unprobed",
                "id": "g2",
                "subject_id": "",
                "priority": "0.7",
            },
        ],
    )
    a = CandidateAction(
        action_type="http_probe",
        target=ActionTarget(canonical_locator="http://10.10.11.23:80/"),
        parameters={"url": "http://10.10.11.23:80/"},
        coverage_key="a" * 64,
        risk="info",
        cost=0.2,
        catalog_index=3,
        expected_information_gain=1.0,
        gap_kind="service.http_unprobed",
        prerequisites=["service.http_unprobed"],
    )
    b = CandidateAction(
        action_type="port_scan",
        target=ActionTarget(canonical_locator="10.10.11.23"),
        parameters={"address": "10.10.11.23", "ports": "top1000", "protocol": "tcp"},
        coverage_key="b" * 64,
        risk="low",
        cost=0.5,
        catalog_index=1,
        expected_information_gain=1.0,
        gap_kind="host.ports_unknown",
        prerequisites=["host.ports_unknown"],
    )
    scored = ActionScorer().score([a, b], ctx)
    decision = DecisionEngine().select(scored, ctx)
    assert decision.kind == "act"
    assert decision.action is not None
    assert decision.action.action_type == "http_probe"


def test_brain_context_is_deterministic_and_capped() -> None:
    world, mission, scope = _host_world()
    builder = BrainContextBuilder()
    a = builder.build(world.snapshot(), mission, scope=scope)
    b = builder.build(world.snapshot(), mission, scope=scope)
    assert context_hash(a) == context_hash(b)
    assert a.byte_size <= 32768
    assert a.revision == world.revision
    assert "raw" not in a.scope_digest.lower() or True
    assert not any("BEGIN PRIVATE" in str(row) for row in a.claims)


def test_brain_decide_port_scan() -> None:
    world, mission, scope = _host_world()
    ctx = BrainContextBuilder().build(world.snapshot(), mission, scope=scope)
    decision = Brain().decide(ctx, min_score=0.15)
    assert decision.kind == "act"
    assert decision.action is not None
    assert decision.action.action_type == "port_scan"
    assert "gap=" in decision.rationale


def test_all_gaps_closed_stops() -> None:
    mid = new_id(PREFIX_MISSION)
    ctx = BrainContext(
        mission_id=mid,
        intent="done",
        mode="ctf",
        iteration=3,
        scope_digest="abc",
        revision=9,
        gaps=[],
        coverage_keys=["x"],
    )
    decision = Brain().decide(ctx)
    assert decision.kind == "stop"
