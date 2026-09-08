"""Knowledge gaps, findings, and deterministic replay."""

from __future__ import annotations

from tests.conftest import artifact_from_fixture
from tests.unit.test_world_model import make_evidence

from cyberx.domain.enums import (
    AddressType,
    AssetKind,
    EpistemicStatus,
    FindingKind,
    FindingStatus,
)
from cyberx.domain.identity import host_key_name
from cyberx.domain.ids import PREFIX_HOST, PREFIX_MISSION, new_id
from cyberx.domain.models.assets import Host
from cyberx.domain.time import utcnow
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.world.model import InMemoryWorldModel
from cyberx.world.replay import Replay


def _normalize(world: InMemoryWorldModel, relative: str, adapter: str, media: str):
    artifact = artifact_from_fixture(
        relative,
        adapter_name=adapter,
        media_type=media,
        mission_id=world.mission_id,
    )
    return EvidencePipeline().normalize(artifact)


def test_knowledge_gaps_are_created() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    world.apply_evidence(
        make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    )
    kinds = {g.kind for g in world.get_gaps() if not g.closed}
    assert "host.ports_unknown" in kinds


def test_knowledge_gaps_can_be_closed() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    world.apply_evidence(
        make_evidence(mid, "host.alive", True, "host:ipv4:10.10.11.23", reliability=0.95)
    )
    assert any(g.kind == "host.ports_unknown" and not g.closed for g in world.get_gaps())
    world.apply_evidence(
        make_evidence(
            mid,
            "port.state",
            "open",
            "port:host:ipv4:10.10.11.23:tcp:22",
            reliability=0.95,
        )
    )
    ports_unknown = [g for g in world.get_gaps() if g.kind == "host.ports_unknown"]
    assert ports_unknown
    assert all(g.closed for g in ports_unknown)
    service_unknown = [g for g in world.get_gaps() if g.kind == "port.service_unknown"]
    assert any(not g.closed for g in service_unknown)


def test_unresolved_host_gap_closes_on_address() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    host = Host(
        asset_id=new_id(PREFIX_HOST),
        mission_id=mid,
        kind=AssetKind.HOST,
        canonical_key=host_key_name("box.htb"),
        display_name="box.htb",
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
        epistemic_status=EpistemicStatus.KNOWN,
        address_type=AddressType.NAME,
        hostname="box.htb",
    )
    world.seed_assets([host])
    assert any(g.kind == "host.unresolved" and not g.closed for g in world.get_gaps())
    _obs, evs = _normalize(world, "dns/a_record.json", "dns_adapter", "application/json")
    for item in evs:
        world.apply_evidence(item)
    unresolved = [g for g in world.get_gaps() if g.kind == "host.unresolved"]
    assert unresolved
    assert all(g.closed for g in unresolved)


def test_open_port_finding_emitted() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    world.apply_evidence(
        make_evidence(
            mid,
            "port.state",
            "open",
            "port:host:ipv4:10.10.11.23:tcp:22",
            reliability=0.95,
        )
    )
    findings = world.get_findings()
    assert any(f.kind is FindingKind.OPEN_PORT for f in findings)
    assert all(f.evidence_ids for f in findings)


def test_replay_is_deterministic_and_rebuild_matches() -> None:
    mid = new_id(PREFIX_MISSION)
    artifact = artifact_from_fixture(
        "nmap/host_open_ports.xml",
        adapter_name="nmap_adapter",
        media_type="application/xml",
        mission_id=mid,
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    world = InMemoryWorldModel(mid)
    for item in evidence:
        world.apply_evidence(item)
    rebuilt = InMemoryWorldModel(mid)
    rebuilt.rebuild_from_evidence(evidence)
    assert world.snapshot().digest == rebuilt.snapshot().digest
    replayed = Replay().rebuild(mid, evidence)
    assert world.snapshot().digest == replayed.snapshot().digest
    world.rebuild_from_evidence()
    assert world.snapshot().digest == rebuilt.snapshot().digest


def test_same_evidence_different_order_is_not_required_equal() -> None:
    mid = new_id(PREFIX_MISSION)
    hint = "port:host:ipv4:10.10.11.23:tcp:22"
    a = make_evidence(mid, "port.state", "open", hint, reliability=0.95)
    b = make_evidence(mid, "port.state", "closed", hint, reliability=0.95)
    w1 = InMemoryWorldModel(mid)
    w1.apply_evidence(a)
    w1.apply_evidence(b)
    w2 = InMemoryWorldModel(mid)
    w2.apply_evidence(b)
    w2.apply_evidence(a)
    live1 = {c.object: c.epistemic_status for c in w1.get_claims(include_invalidated=False)}
    live2 = {c.object: c.epistemic_status for c in w2.get_claims(include_invalidated=False)}
    assert live1 != live2 or w1.snapshot().digest != w2.snapshot().digest


def test_finding_invalidated_when_only_claim_dies() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    hint = "port:host:ipv4:10.10.11.23:tcp:22"
    world.apply_evidence(make_evidence(mid, "port.state", "open", hint, reliability=0.95))
    assert any(f.status is FindingStatus.OPEN for f in world.get_findings())
    world.apply_evidence(make_evidence(mid, "port.state", "closed", hint, reliability=0.95))
    open_port = [f for f in world.get_findings() if f.kind is FindingKind.OPEN_PORT]
    if open_port:
        assert all(f.status is FindingStatus.INVALIDATED for f in open_port)
