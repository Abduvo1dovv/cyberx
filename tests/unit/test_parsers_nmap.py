from __future__ import annotations

import pytest
from tests.conftest import artifact_from_fixture, load_golden, shapes

from cyberx.domain.errors import ParseError
from cyberx.evidence.factory import EvidenceFactory, reliability_for
from cyberx.evidence.parsers.nmap_xml import NmapXmlParser
from cyberx.evidence.pipeline import EvidencePipeline


def _art(name: str, **kwargs):
    return artifact_from_fixture(
        f"nmap/{name}",
        adapter_name="nmap_adapter",
        media_type="application/xml",
        **kwargs,
    )


def test_nmap_open_ports_golden() -> None:
    artifact = _art("host_open_ports.xml")
    expected = load_golden("nmap/host_open_ports.golden.json")
    first = NmapXmlParser().parse(artifact)
    second = NmapXmlParser().parse(artifact)
    assert shapes(first) == expected
    assert shapes(second) == expected
    assert all(item.parser_id == "nmap_xml" for item in first)
    assert all(item.mapped for item in first)


def test_nmap_empty_hosts() -> None:
    assert NmapXmlParser().parse(_art("empty_hosts.xml")) == []


def test_nmap_malformed_root_fails_closed() -> None:
    with pytest.raises(ParseError) as err:
        NmapXmlParser().parse(_art("malformed.xml"))
    assert err.value.code == "invalid_xml"


def test_nmap_xxe_rejected() -> None:
    with pytest.raises(ParseError) as err:
        NmapXmlParser().parse(_art("xxe.xml"))
    assert err.value.code == "unsafe_xml"


def test_nmap_reads_path_when_body_missing() -> None:
    artifact = _art("host_open_ports.xml", in_memory=False)
    assert artifact.body is None
    assert artifact.path
    expected = load_golden("nmap/host_open_ports.golden.json")
    assert shapes(NmapXmlParser().parse(artifact)) == expected


def test_nmap_22_only() -> None:
    obs = NmapXmlParser().parse(_art("host_22.xml"))
    ports = [o for o in obs if o.predicate == "port.state"]
    assert {o.object for o in ports} == {"open"}
    assert any(o.extra.get("number") == 22 for o in ports)


def test_nmap_22_80_and_hostname() -> None:
    obs = NmapXmlParser().parse(_art("host_22_80.xml"))
    numbers = {o.extra.get("number") for o in obs if o.predicate == "port.state"}
    assert numbers == {22, 80}
    names = {o.object for o in obs if o.predicate == "host.hostname"}
    assert "box.htb" in names
    products = {o.object for o in obs if o.predicate == "service.product"}
    assert "OpenSSH" in products
    versions = {o.object for o in obs if o.predicate == "service.version"}
    assert any("8.9" in str(v) for v in versions)


def test_nmap_22_80_443() -> None:
    obs = NmapXmlParser().parse(_art("host_22_80_443.xml"))
    numbers = {o.extra.get("number") for o in obs if o.predicate == "port.state"}
    assert numbers == {22, 80, 443}


def test_nmap_closed_and_filtered() -> None:
    obs = NmapXmlParser().parse(_art("host_closed_filtered.xml"))
    states = {(o.extra.get("number"), o.object) for o in obs if o.predicate == "port.state"}
    assert (21, "closed") in states
    assert (23, "filtered") in states
    filtered = next(o for o in obs if o.predicate == "port.state" and o.object == "filtered")
    assert reliability_for(filtered) == 0.70
    opened = next(o for o in obs if o.predicate == "port.state" and o.object == "open")
    assert reliability_for(opened) == 0.95


def test_nmap_multiple_hosts() -> None:
    obs = NmapXmlParser().parse(_art("multiple_hosts.xml"))
    addrs = {o.object for o in obs if o.predicate == "host.address"}
    assert addrs == {"10.10.11.23", "8.8.8.8"}


def test_nmap_truncated_xml_fails_closed() -> None:
    with pytest.raises(ParseError) as err:
        NmapXmlParser().parse(_art("truncated.xml"))
    assert err.value.code == "invalid_xml"


def test_nmap_unexpected_elements_ignored() -> None:
    obs = NmapXmlParser().parse(_art("unexpected_elements.xml"))
    assert any(o.predicate == "port.state" and o.extra.get("number") == 22 for o in obs)
    assert all(o.predicate != "os.match" for o in obs)


def test_nmap_duplicate_ports_emit_both() -> None:
    obs = NmapXmlParser().parse(_art("duplicate_ports.xml"))
    ports = [o for o in obs if o.predicate == "port.state" and o.extra.get("number") == 22]
    assert len(ports) == 2


def test_nmap_evidence_traceability() -> None:
    artifact = _art("host_22_80.xml")
    obs, evidence = EvidencePipeline().normalize(artifact)
    assert obs
    assert len(evidence) == len(obs)
    for item, ev in zip(obs, evidence, strict=True):
        assert ev.observation_id == item.observation_id
        assert ev.artifact_id == artifact.artifact_id
        assert ev.tool_run_id == artifact.tool_run_id
        assert ev.parser_id == "nmap_xml"
        assert ev.reliability > 0
    wrapped = EvidenceFactory().wrap(obs[0], artifact)
    assert wrapped.hash
