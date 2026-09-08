"""DNS correlation, host merge, gaps, idempotency."""

from __future__ import annotations

from tests.conftest import artifact_from_fixture

from cyberx.domain.ids import PREFIX_MISSION, new_id
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.world.gaps import GapDetector
from cyberx.world.model import InMemoryWorldModel


def _apply(world: InMemoryWorldModel, relative: str, adapter: str = "dns_adapter") -> None:
    artifact = artifact_from_fixture(
        relative,
        adapter_name=adapter,
        media_type="application/json",
        mission_id=world.mission_id,
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    for item in evidence:
        world.apply_evidence(item)


def test_a_record_merges_name_host() -> None:
    from cyberx.domain.enums import AddressType, AssetKind, EpistemicStatus
    from cyberx.domain.identity import host_key_name
    from cyberx.domain.ids import PREFIX_HOST
    from cyberx.domain.models.assets import Host
    from cyberx.domain.time import utcnow

    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    now = utcnow()
    world.seed_assets(
        [
            Host(
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
        ]
    )
    _apply(world, "dns/a_record.json")
    ips = {h.ipv4 for h in world.get_hosts() if h.ipv4}
    assert "10.10.11.23" in ips


def test_mixed_records_create_subdomains_and_close_gap() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    _apply(world, "dns/mixed_records.json")
    names = {s.fqdn for s in world.get_subdomains()}
    assert {"www.box.htb", "mail.box.htb", "ns1.box.htb"} <= names
    domains = world.get_domains()
    assert any(d.fqdn == "box.htb" for d in domains)
    GapDetector().recompute(world)
    open_kinds = {g.kind for g in world.get_gaps() if not g.closed}
    assert "domain.subdomains_unknown" not in open_kinds


def test_idempotent_replay() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    _apply(world, "dns/mixed_records.json")
    hosts = len(world.get_hosts())
    subs = len(world.get_subdomains())
    claims = len(world.get_claims())
    _apply(world, "dns/mixed_records.json")
    assert len(world.get_hosts()) == hosts
    assert len(world.get_subdomains()) == subs
    assert len(world.get_claims()) == claims


def test_nxdomain_does_not_create_assets() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    _apply(world, "dns/nxdomain.json")
    assert not world.get_hosts()
    assert not world.get_subdomains()
    assert not world.get_domains()
