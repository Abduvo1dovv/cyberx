"""DNS parser: records, NXDOMAIN, mixed case, no World Model."""

from __future__ import annotations

from tests.conftest import artifact_from_fixture, load_golden, shapes

from cyberx.evidence.parsers.dns import DnsParser
from cyberx.evidence.pipeline import EvidencePipeline


def test_a_aaaa_golden_unchanged() -> None:
    artifact = artifact_from_fixture(
        "dns/a_record.json", adapter_name="dns_adapter", media_type="application/json"
    )
    assert shapes(DnsParser().parse(artifact)) == load_golden("dns/a_record.golden.json")


def test_mixed_records_emit_subdomains_and_hosts() -> None:
    artifact = artifact_from_fixture(
        "dns/mixed_records.json", adapter_name="dns_adapter", media_type="application/json"
    )
    obs = DnsParser().parse(artifact)
    types = {o.object["type"] for o in obs if o.predicate == "dns.record"}
    assert types == {"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
    subs = {o.object for o in obs if o.predicate == "dns.subdomain"}
    assert "www.box.htb" in subs
    assert "mail.box.htb" in subs
    assert "ns1.box.htb" in subs
    assert "box.htb" not in subs
    hosts = {o.object for o in obs if o.predicate == "host.address"}
    assert "10.10.10.10" in hosts
    assert "10.10.10.11" in hosts


def test_nxdomain_and_timeout_are_empty() -> None:
    nx = artifact_from_fixture(
        "dns/nxdomain.json", adapter_name="dns_adapter", media_type="application/json"
    )
    to = artifact_from_fixture(
        "dns/timeout.json", adapter_name="dns_adapter", media_type="application/json"
    )
    assert DnsParser().parse(nx) == []
    assert DnsParser().parse(to) == []


def test_subdomain_mixed_case_dedup_in_world() -> None:
    from cyberx.domain.ids import PREFIX_MISSION, new_id
    from cyberx.world.model import InMemoryWorldModel

    mid = new_id(PREFIX_MISSION)
    world = InMemoryWorldModel(mid)
    artifact = artifact_from_fixture(
        "dns/subdomains_mixed.json",
        adapter_name="subdomain_adapter",
        media_type="application/json",
        mission_id=mid,
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    for item in evidence:
        world.apply_evidence(item)
    names = {s.fqdn for s in world.get_subdomains()}
    assert "www.box.htb" in names
    assert "mail.box.htb" in names
    assert "admin.box.htb" in names
    assert len([s for s in world.get_subdomains() if s.fqdn == "www.box.htb"]) == 1
    assert not any("evil.example" in s.fqdn for s in world.get_subdomains())


def test_evidence_traceable() -> None:
    artifact = artifact_from_fixture(
        "dns/mixed_records.json", adapter_name="dns_adapter", media_type="application/json"
    )
    _obs, evidence = EvidencePipeline().normalize(artifact)
    assert evidence
    for item in evidence:
        assert item.artifact_id == artifact.artifact_id
        assert item.parser_id == "dns"
