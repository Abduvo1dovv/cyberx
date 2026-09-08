"""Golden M17 path: Grok advises existing coverage only; controls still bind."""

from __future__ import annotations

import json
import re

from tests.conftest import FIXTURES, create_cmd

from cyberx.ai.factory import build_provider
from cyberx.ai.transport import TransportResult
from cyberx.brain.facade import Brain
from cyberx.config import ProviderConfig
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.ports.events import EventType
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner


class AdaptiveTransport:
    """Returns structured Grok JSON. Advises an EXISTING coverage_key only."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.advised: list[str] = []

    def complete(self, url, headers, payload, *, timeout_s, max_bytes):
        del url, timeout_s, max_bytes
        assert "Authorization" in headers
        self.calls.append(payload)
        user = payload["messages"][1]["content"]
        if "Advise score" in user or "score deltas" in user:
            keys = re.findall(r'"coverage_key":"([^"]+)"', user)
            keys = [k for k in keys if k]
            chosen = keys[1] if len(keys) > 1 else (keys[0] if keys else "")
            self.advised.append(chosen)
            body = {
                "advice": [
                    {
                        "coverage_key": chosen,
                        "delta": 0.08,
                        "comment": "existing investigation",
                    },
                    {
                        "coverage_key": "invented-exploit-key",
                        "delta": 0.5,
                        "comment": "should be dropped",
                    },
                ]
            }
        else:
            body = {
                "hypotheses": [
                    {
                        "statement": "http service is likely behind the open web port",
                        "rationale": "port 80 was observed",
                        "related_canonical_keys": [],
                        "suggested_action_types": ["http_probe"],
                        "confidence": 0.3,
                        "evidence_ids": [],
                    }
                ]
            }
        envelope = {"choices": [{"message": {"content": json.dumps(body)}}]}
        return TransportResult(status=200, body=json.dumps(envelope).encode())


def test_grok_advises_existing_coverage_then_world_replans(tmp_path) -> None:
    xml = (FIXTURES / "nmap" / "host_22_80.xml").read_bytes()
    runner = FixtureProcessRunner(xml)
    sink = InMemoryEventSink()
    adapter = NmapAdapter(runner=runner, available=True, events=sink)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    transport = AdaptiveTransport()
    settings = ProviderConfig(
        name="grok",
        api_key="test-key",
        model="test-model",
        timeout_s=2,
        enabled=True,
    )
    provider = build_provider(settings, events=sink, transport=transport)
    brain = Brain(provider=provider)
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(
        service,
        brain=brain,
        boundary=ExecutionBoundary(executor=executor, events=sink),
        events=sink,
    )

    first = engine.run_one_cycle(mission.mission_id)
    assert first.selected_action_type == "port_scan"
    assert first.execution_status == "completed"
    assert first.evidence_added > 0
    world = engine.world(mission.mission_id)
    ports = {p.number for p in world.get_open_ports()}
    assert 22 in ports and 80 in ports
    before_keys = set(world.get_coverage())
    evidence_before = len(world.get_recent_evidence(limit=500))

    second = engine.run_one_cycle(mission.mission_id)
    assert second.selected_action_type != first.selected_action_type
    assert second.selected_action_type in {
        "http_probe",
        "service_enumeration",
        "technology_detection",
        "directory_enumeration",
        "endpoint_discovery",
        "dns_enumeration",
        "network_discovery",
    }
    assert "exploit" not in (second.selected_action_type or "")
    assert second.execution_status == "completed"
    world2 = engine.world(mission.mission_id)
    assert set(world2.get_coverage()) != before_keys or world2.revision > world.revision
    assert len(world2.get_recent_evidence(limit=500)) >= evidence_before

    kinds = {e.event_type for e in sink.events}
    assert EventType.AI_REQUESTED in kinds or EventType.AI_COMPLETED in kinds
    assert transport.calls, "Grok should be consulted after trivial port discovery"
    for payload in transport.calls:
        dumped = json.dumps(payload)
        assert "test-key" not in dumped
        user = payload["messages"][1]["content"]
        assert "<untrusted_target_data>" in user
        assert payload["messages"][0]["role"] == "system"
    if transport.advised:
        assert "invented-exploit-key" not in set(world2.get_coverage())

    third = engine.run_one_cycle(mission.mission_id)
    if not third.completed:
        assert third.selected_action_type != first.selected_action_type
    assert world2.revision >= 1


def test_grok_cannot_bypass_policy_or_catalog() -> None:
    sink = InMemoryEventSink()
    transport = AdaptiveTransport()
    settings = ProviderConfig(name="grok", api_key="test-key", model="test-model", enabled=True)
    provider = build_provider(settings, events=sink, transport=transport)
    brain = Brain(provider=provider)
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(service, brain=brain, events=sink)
    report = engine.run_one_cycle(mission.mission_id)
    assert report.selected_action_type == "port_scan"
    world = engine.world(mission.mission_id)
    for action_type in {c.split(":")[0] for c in world.get_coverage()}:
        assert "exploit" not in action_type
        assert "shell" not in action_type
    assert mission.scope_id
    bundle = service.get_bundle(mission.mission_id)
    assert bundle.scope.frozen is True
    assert "10.10.11.23" in bundle.scope.allowed_targets
