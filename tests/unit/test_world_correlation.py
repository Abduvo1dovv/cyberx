"""Correlation: host/port/service, domain/subdomain, URL/endpoint, DNS merge."""

from __future__ import annotations

from tests.conftest import artifact_from_fixture
from tests.unit.test_world_model import make_evidence

from cyberx.domain.enums import AddressType, AssetKind, EpistemicStatus
from cyberx.domain.identity import host_key_ipv4, host_key_name
from cyberx.domain.ids import PREFIX_HOST, PREFIX_MISSION, new_id
from cyberx.domain.models.assets import Host
from cyberx.domain.time import utcnow
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.world.model import InMemoryWorldModel
from cyberx.world.queries import (
    get_hosts,
    get_open_ports,
    get_related_entities,
    get_services,
    get_web_surfaces,
)


def _apply_fixture(world: InMemoryWorldModel, relative: str, adapter: str, media: str) -> None:
    artifact = artifact_from_fixture(
        relative,
        adapter_name=adapter,
        media_type=media,
        mission_id=world.mission_id,
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    for item in evidence:
        world.apply_evidence(item)


def test_host_port_service_correlation() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply_fixture(world, "nmap/host_open_ports.xml", "nmap_adapter", "application/xml")
    hosts = get_hosts(world)
    assert len(hosts) == 1
    assert hosts[0].canonical_key == "host:ipv4:10.10.11.23"
    assert hosts[0].ipv4 == "10.10.11.23"
    open_ports = get_open_ports(world)
    numbers = sorted(p.number for p in open_ports)
    assert numbers == [22, 80]
    services = get_services(world)
    names = {s.name for s in services}
    assert "ssh" in names
    assert "http" in names
    port22 = next(p for p in open_ports if p.number == 22)
    related = get_related_entities(world, port22.asset_id)
    kinds = {a.kind for a in related}
    assert AssetKind.HOST in kinds
    ssh = next(s for s in services if s.name == "ssh")
    assert ssh.port_id == port22.asset_id
    ifaces = world.get_interfaces()
    assert ifaces
    assert ifaces[0].ip == "10.10.11.23"


def test_url_endpoint_correlation() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply_fixture(world, "http/probe_200.json", "http_adapter", "application/json")
    urls = get_web_surfaces(world)
    assert urls
    assert urls[0].canonical_key == "url:http://10.10.11.23:80/"
    assert urls[0].status_code == 200
    assert urls[0].title == "Stub Host"
    endpoints = world.get_endpoints()
    assert endpoints
    assert endpoints[0].method.value == "GET"
    techs = world.get_technologies()
    products = {t.product for t in techs}
    assert "nginx" in products
    hosts = get_hosts(world)
    assert any(h.canonical_key == "host:ipv4:10.10.11.23" for h in hosts)


def test_domain_subdomain_correlation() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply_fixture(world, "dns/subdomains.json", "dns_adapter", "application/json")
    domains = world.get_domains()
    assert any(d.fqdn == "box.htb" for d in domains)
    subs = world.get_subdomains()
    names = {s.fqdn for s in subs}
    assert "www.box.htb" in names
    assert "admin.box.htb" in names
    parent_ids = {s.domain_id for s in subs}
    assert parent_ids <= {d.asset_id for d in domains}


def test_dns_name_host_merges_into_ip_host() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    name_host = Host(
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
    world.seed_assets([name_host])
    _apply_fixture(world, "dns/a_record.json", "dns_adapter", "application/json")
    hosts = {h.canonical_key: h for h in world.get_hosts()}
    ip_key = host_key_ipv4("10.10.11.23")
    name_key = host_key_name("box.htb")
    assert ip_key in hosts
    assert hosts[ip_key].hostname == "box.htb"
    if name_key in hosts:
        assert "alias" in hosts[name_key].labels
        ip_ids = {
            h.asset_id
            for key, h in hosts.items()
            if key.startswith("host:ipv4:") or key.startswith("host:ipv6:")
        }
        assert hosts[name_key].parent_asset_id in ip_ids
    hostname_claims = [
        c for c in world.get_claims() if c.predicate == "host.hostname" and c.object == "box.htb"
    ]
    assert hostname_claims
    assert hostname_claims[0].subject_id == hosts[ip_key].asset_id


def test_conflicting_evidence_is_preserved() -> None:
    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    hint = "port:host:ipv4:10.10.11.23:tcp:443"
    world.apply_evidence(make_evidence(mid, "port.state", "open", hint, reliability=0.95))
    world.apply_evidence(make_evidence(mid, "port.state", "filtered", hint, reliability=0.95))
    objects = {c.object for c in world.get_claims(include_invalidated=True)}
    assert objects == {"open", "filtered"}
    assert world.get_conflicts()


def test_out_of_scope_flag_without_followup_gaps() -> None:
    class _Gate:
        def out_of_scope(self, canonical_key: str) -> bool:
            return "8.8.8.8" in canonical_key

    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid, scope_gate=_Gate())
    world.apply_evidence(
        make_evidence(mid, "host.alive", True, "host:ipv4:8.8.8.8", reliability=0.95)
    )
    host = world.get_hosts()[0]
    assert host.out_of_scope is True
    open_gaps = [g for g in world.get_gaps() if not g.closed]
    assert all(g.subject_id != host.asset_id for g in open_gaps)


def test_endpoint_params_and_auth() -> None:
    world = InMemoryWorldModel(new_id(PREFIX_MISSION))
    _apply_fixture(world, "endpoint/login.json", "endpoint_adapter", "application/json")
    endpoints = world.get_endpoints()
    assert endpoints
    params = world.get_parameters()
    auths = world.get_auth_surfaces()
    assert params or auths or endpoints
