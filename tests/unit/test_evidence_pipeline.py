from __future__ import annotations

import hashlib
import json

import pytest
from tests.conftest import artifact_from_fixture, create_cmd, shapes

from cyberx.actions.catalog import DEFAULT_CATALOG
from cyberx.domain.enums import OBSERVATION_PREDICATES, V1_ACTION_TYPES, ActionResultStatus
from cyberx.domain.errors import DomainValidationError, ParseError
from cyberx.domain.ids import (
    PREFIX_ARTIFACT,
    PREFIX_MISSION,
    PREFIX_OBSERVATION,
    PREFIX_TOOL_RUN,
    new_id,
)
from cyberx.domain.models.actions import ActionRequest, ActionTarget
from cyberx.domain.models.evidence import Observation
from cyberx.domain.time import utcnow
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.evidence.factory import EvidenceFactory, reliability_for
from cyberx.evidence.parsers.stub import StubParser
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.evidence.registry import LEGAL_PARSER_IDS, ParserRegistry
from cyberx.ports.execution import RawArtifact


def _raw(body: bytes, **kwargs) -> RawArtifact:
    return RawArtifact(
        artifact_id=new_id(PREFIX_ARTIFACT),
        tool_run_id=new_id(PREFIX_TOOL_RUN),
        adapter_name=kwargs.get("adapter_name", "stub_adapter"),
        media_type=kwargs.get("media_type", "application/json"),
        sha256=hashlib.sha256(body).hexdigest(),
        byte_size=len(body),
        body=body,
        mission_id=kwargs.get("mission_id") or new_id(PREFIX_MISSION),
        source_locator=kwargs.get("source_locator"),
    )


def test_registry_is_closed() -> None:
    registry = ParserRegistry()
    assert not hasattr(registry, "register")
    with pytest.raises(TypeError):
        registry._parsers["exploit"] = object()  # type: ignore[index]
    assert registry.get("nmap_xml") is not None
    assert registry.get("ai") is None
    assert "seed" in LEGAL_PARSER_IDS


def test_every_catalog_type_has_parser() -> None:
    registry = ParserRegistry()
    for spec in DEFAULT_CATALOG.all():
        parser_id = registry.parser_id_for_adapter(spec.adapter_name)
        assert parser_id, f"no parser mapped for {spec.adapter_name}"
        assert registry.get(parser_id) is not None
    assert tuple(StubParser.action_types) == V1_ACTION_TYPES


def test_registry_unknown_adapter_fails_closed() -> None:
    artifact = artifact_from_fixture(
        "http/probe_200.json",
        adapter_name="nuclei_adapter",
        media_type="application/json",
    )
    with pytest.raises(ParseError) as err:
        ParserRegistry().parse(artifact)
    assert err.value.code == "unknown_parser"


def test_factory_wrap_sets_reliability_and_trace() -> None:
    artifact = artifact_from_fixture(
        "nmap/host_open_ports.xml",
        adapter_name="nmap_adapter",
        media_type="application/xml",
    )
    observations, evidence = EvidencePipeline().normalize(artifact)
    assert observations
    assert len(evidence) == len(observations)
    port = next(e for e in evidence if e.claim_preview["predicate"] == "port.state")
    assert port.reliability == 0.95
    assert port.artifact_id == artifact.artifact_id
    assert port.tool_run_id == artifact.tool_run_id
    assert port.hash
    assert port.claim_preview["mapped"] is True
    product = next(e for e in evidence if e.claim_preview["predicate"] == "service.product")
    assert product.reliability == 0.60


def test_directory_404_reliability() -> None:
    artifact = artifact_from_fixture(
        "directory/paths.json",
        adapter_name="directory_adapter",
        media_type="application/json",
    )
    observations, evidence = EvidencePipeline().normalize(artifact)
    nope = next(
        e
        for e in evidence
        if e.claim_preview["predicate"] == "url.seen" and "nope" in e.claim_preview["subject_hint"]
    )
    admin = next(
        e
        for e in evidence
        if e.claim_preview["predicate"] == "url.seen" and "admin" in e.claim_preview["subject_hint"]
    )
    assert nope.reliability == 0.40
    assert admin.reliability == 0.85
    assert reliability_for(next(o for o in observations if o.extra.get("status") == 404)) == 0.40


def test_unmapped_predicate_stored_not_a_fact() -> None:
    artifact = artifact_from_fixture(
        "http/probe_200.json",
        adapter_name="http_adapter",
        media_type="application/json",
    )
    obs = Observation(
        observation_id=new_id(PREFIX_OBSERVATION),
        mission_id=artifact.mission_id,
        parser_id="http_probe",
        predicate="exploit.rce",
        object={"note": "should not become a fact"},
        subject_hint="host:ipv4:10.10.11.23",
        created_at=utcnow(),
    )
    assert obs.predicate not in OBSERVATION_PREDICATES
    assert obs.mapped is False
    wrapped = EvidenceFactory().wrap(obs, artifact)
    assert wrapped.claim_preview["mapped"] is False
    assert wrapped.reliability == 0.0


def test_ai_cannot_create_evidence() -> None:
    artifact = artifact_from_fixture(
        "http/probe_200.json",
        adapter_name="http_adapter",
        media_type="application/json",
    )
    obs = Observation(
        observation_id=new_id(PREFIX_OBSERVATION),
        mission_id=artifact.mission_id,
        parser_id="llm",
        predicate="http.status",
        object=200,
        subject_hint="url:http://10.10.11.23:80/",
        created_at=utcnow(),
    )
    with pytest.raises(DomainValidationError):
        EvidenceFactory().wrap(obs, artifact)


def test_unknown_parser_id_cannot_wrap() -> None:
    artifact = artifact_from_fixture(
        "http/probe_200.json",
        adapter_name="http_adapter",
        media_type="application/json",
    )
    obs = Observation(
        observation_id=new_id(PREFIX_OBSERVATION),
        mission_id=artifact.mission_id,
        parser_id="nuclei",
        predicate="http.status",
        object=200,
        subject_hint="url:http://10.10.11.23:80/",
        created_at=utcnow(),
    )
    with pytest.raises(DomainValidationError):
        EvidenceFactory().wrap(obs, artifact)


def test_seed_parser_id_is_allowed() -> None:
    artifact = artifact_from_fixture(
        "http/probe_200.json",
        adapter_name="http_adapter",
        media_type="application/json",
    )
    obs = Observation(
        observation_id=new_id(PREFIX_OBSERVATION),
        mission_id=artifact.mission_id,
        parser_id="seed",
        predicate="host.address",
        object="10.10.11.23",
        subject_hint="host:ipv4:10.10.11.23",
        created_at=utcnow(),
    )
    wrapped = EvidenceFactory().wrap(obs, artifact)
    assert wrapped.parser_id == "seed"
    assert wrapped.reliability == 0.90


def test_mission_id_mismatch_rejected() -> None:
    artifact = artifact_from_fixture(
        "http/probe_200.json",
        adapter_name="http_adapter",
        media_type="application/json",
    )
    obs = Observation(
        observation_id=new_id(PREFIX_OBSERVATION),
        mission_id=new_id(PREFIX_MISSION),
        parser_id="http_probe",
        predicate="http.status",
        object=200,
        subject_hint="url:http://10.10.11.23:80/",
        created_at=utcnow(),
    )
    with pytest.raises(DomainValidationError):
        EvidenceFactory().wrap(obs, artifact)


def test_empty_artifact_fails_closed() -> None:
    artifact = _raw(b"", adapter_name="http_adapter")
    artifact = artifact.model_copy(update={"body": None, "path": None})
    with pytest.raises(ParseError) as err:
        ParserRegistry().parse(artifact.model_copy(update={"adapter_name": "http_adapter"}))
    assert err.value.code in {"empty_artifact", "invalid_json"}


def test_stub_parser_covers_every_catalog_type() -> None:
    payloads = {
        "network_discovery": {
            "action_type": "network_discovery",
            "hosts": [{"ip": "10.10.11.23", "alive": True}],
        },
        "port_scan": {
            "action_type": "port_scan",
            "target": "10.10.11.23",
            "ports": [{"number": 80, "protocol": "tcp", "state": "open"}],
        },
        "service_enumeration": {
            "action_type": "service_enumeration",
            "target": "10.10.11.23",
            "services": [{"port": 80, "name": "http", "product": "nginx"}],
        },
        "http_probe": {
            "action_type": "http_probe",
            "url": "http://10.10.11.23/",
            "status": 200,
            "title": "x",
        },
        "technology_detection": {
            "action_type": "technology_detection",
            "url": "http://10.10.11.23/",
            "technologies": [{"product": "nginx", "source": "header"}],
        },
        "dns_enumeration": {
            "action_type": "dns_enumeration",
            "fqdn": "box.htb",
            "records": [{"type": "A", "name": "box.htb", "value": "10.10.11.23"}],
        },
        "subdomain_enumeration": {
            "action_type": "subdomain_enumeration",
            "fqdn": "box.htb",
            "subdomains": ["www.box.htb"],
        },
        "directory_enumeration": {
            "action_type": "directory_enumeration",
            "url": "http://10.10.11.23/",
            "paths": [{"path": "/login", "status": 200}],
        },
        "endpoint_discovery": {
            "action_type": "endpoint_discovery",
            "url": "http://10.10.11.23/",
            "endpoints": [{"method": "GET", "path": "/login"}],
        },
    }
    assert set(payloads) == set(V1_ACTION_TYPES)
    parser = StubParser()
    for action_type, payload in payloads.items():
        loc = payload.get("url") or payload.get("target") or payload.get("fqdn")
        artifact = _raw(
            json.dumps(payload).encode(),
            source_locator=str(loc) if loc else None,
        )
        rows = parser.parse(artifact)
        assert rows, f"{action_type} produced no observations"
        assert all(item.parser_id == "stub" for item in rows)


def test_pipeline_does_not_apply_world_model() -> None:
    source = EvidencePipeline.normalize.__doc__ or ""
    assert "World Model" in (EvidencePipeline.__doc__ or "")
    artifact = artifact_from_fixture(
        "dns/a_record.json",
        adapter_name="dns_adapter",
        media_type="application/json",
        source_locator="box.htb",
    )
    observations, evidence = EvidencePipeline().normalize(artifact)
    assert observations and evidence
    assert "apply" not in source.lower() or "no world" in (EvidencePipeline.__doc__ or "").lower()


def test_stub_executor_artifact_parses(service) -> None:
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    bundle = service.get_bundle(mission.mission_id)
    outcome = ExecutionBoundary().run(
        ActionRequest(
            mission_id=bundle.mission.mission_id,
            action_type="http_probe",
            target=ActionTarget(canonical_locator="http://10.10.11.23/"),
            parameters={"url": "http://10.10.11.23/"},
            reason="probe",
            prerequisites=["gap_placeholder"],
        ),
        bundle.mission,
        bundle.scope,
    )
    assert outcome.result.status is ActionResultStatus.COMPLETED
    observations, evidence = EvidencePipeline().normalize(outcome.artifact)
    assert any(item.predicate == "http.status" for item in observations)
    assert any(item.object == 200 for item in observations if item.predicate == "http.status")
    assert evidence
    assert all(item.parser_id == "stub" for item in observations)
    assert outcome.observations["status"] == 200


def test_normalize_is_deterministic() -> None:
    artifact = artifact_from_fixture(
        "nmap/host_open_ports.xml",
        adapter_name="nmap_adapter",
        media_type="application/xml",
        mission_id=new_id(PREFIX_MISSION),
    )
    a, _ea = EvidencePipeline().normalize(artifact)
    b, _eb = EvidencePipeline().normalize(artifact)
    assert shapes(a) == shapes(b)
