from __future__ import annotations

import json

import pytest
from tests.conftest import create_cmd

from cyberx.domain.enums import V1_ACTION_TYPES, ActionResultStatus, PolicyVerdict
from cyberx.domain.errors import ActionRejected, ExecutionBypassError, PolicyDeniedError
from cyberx.domain.ids import PREFIX_DOMAIN, PREFIX_HOST, PREFIX_URL, new_id
from cyberx.domain.models.actions import ActionRequest, ActionTarget, PolicyDecision
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.stub_executor import StubExecutor
from cyberx.observability.sink import InMemoryEventSink
from cyberx.ports.events import EventType
from cyberx.ports.execution import AuthorizedAction
from cyberx.recon.stub import StubAdapter


def _running(service):
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    return service.get_bundle(mission.mission_id)


def _probe_req(mission_id: str) -> ActionRequest:
    return ActionRequest(
        mission_id=mission_id,
        action_type="http_probe",
        target=ActionTarget(canonical_locator="http://10.10.11.23/"),
        parameters={"url": "http://10.10.11.23/"},
        reason="probe",
        prerequisites=["gap_placeholder"],
    )


def _scan_req(mission_id: str) -> ActionRequest:
    return ActionRequest(
        mission_id=mission_id,
        action_type="port_scan",
        target=ActionTarget(canonical_locator="10.10.11.23"),
        parameters={"address": "10.10.11.23", "ports": "top1000"},
        reason="ports",
        prerequisites=["gap_placeholder"],
    )


def test_happy_path_stub_http_probe(service) -> None:
    bundle = _running(service)
    sink = InMemoryEventSink()
    boundary = ExecutionBoundary(events=sink)
    outcome = boundary.run(_probe_req(bundle.mission.mission_id), bundle.mission, bundle.scope)
    assert outcome.result.status is ActionResultStatus.COMPLETED
    assert outcome.observations["status"] == 200
    assert outcome.observations["title"] == "Stub Host"
    assert outcome.tool_run.argv == ["stub", "http_probe", "http://10.10.11.23/"]
    assert "subprocess" not in outcome.tool_run.argv
    assert {e.event_type for e in sink.events} >= {
        EventType.ACTION_VALIDATED,
        EventType.POLICY_DECISION,
        EventType.ACTION_STARTED,
        EventType.ACTION_COMPLETED,
    }


def test_stub_port_scan_synthetic_ports(service) -> None:
    bundle = _running(service)
    outcome = ExecutionBoundary().run(
        _scan_req(bundle.mission.mission_id), bundle.mission, bundle.scope
    )
    ports = {p["number"] for p in outcome.observations["ports"]}
    assert ports == {22, 80, 443}


def test_stub_is_deterministic(service) -> None:
    bundle = _running(service)
    boundary = ExecutionBoundary()
    a = boundary.run(_scan_req(bundle.mission.mission_id), bundle.mission, bundle.scope)
    b = boundary.run(_scan_req(bundle.mission.mission_id), bundle.mission, bundle.scope)
    body_a = json.loads(a.artifact.body.decode())
    body_b = json.loads(b.artifact.body.decode())
    assert body_a["ports"] == body_b["ports"]
    payload_a = {k: v for k, v in a.observations.items() if k != "coverage_key"}
    payload_b = {k: v for k, v in b.observations.items() if k != "coverage_key"}
    assert payload_a == payload_b


def test_out_of_scope_never_reaches_executor(service) -> None:
    bundle = _running(service)
    req = ActionRequest(
        mission_id=bundle.mission.mission_id,
        action_type="port_scan",
        target=ActionTarget(canonical_locator="1.2.3.4"),
        parameters={"address": "1.2.3.4", "ports": "top1000"},
        reason="bad",
        prerequisites=["gap_placeholder"],
    )
    with pytest.raises(PolicyDeniedError) as err:
        ExecutionBoundary().run(req, bundle.mission, bundle.scope)
    assert err.value.reason_code == "not_in_allowlist"


def test_executor_cannot_bypass_policy() -> None:
    with pytest.raises(ExecutionBypassError):
        StubExecutor().execute(object())  # type: ignore[arg-type]


def test_denied_authorized_action_rejected(service) -> None:
    bundle = _running(service)
    authorized = ExecutionBoundary().authorize(
        _scan_req(bundle.mission.mission_id), bundle.mission, bundle.scope
    )
    fake = AuthorizedAction(
        action=authorized.action,
        decision=PolicyDecision(verdict=PolicyVerdict.DENY, reason_code="denied"),
    )
    with pytest.raises(ExecutionBypassError):
        StubExecutor().execute(fake)


def test_adapter_never_uses_shell() -> None:
    from cyberx.actions.validator import ActionValidator
    from cyberx.domain.ids import PREFIX_MISSION, new_id

    action = ActionValidator().validate(
        ActionRequest(
            mission_id=new_id(PREFIX_MISSION),
            action_type="dns_enumeration",
            target=ActionTarget(canonical_locator="box.htb"),
            parameters={"fqdn": "box.htb"},
            reason="dns",
            prerequisites=["gap_placeholder"],
        )
    )
    argv = StubAdapter().build_argv(action)
    assert argv[0] == "stub"
    assert all("|" not in part and ";" not in part and "&&" not in part for part in argv)


def test_directory_and_tech_stubs(service) -> None:
    bundle = _running(service)
    boundary = ExecutionBoundary()
    tech = boundary.run(
        ActionRequest(
            mission_id=bundle.mission.mission_id,
            action_type="technology_detection",
            target=ActionTarget(canonical_locator="http://10.10.11.23/"),
            parameters={"url": "http://10.10.11.23/"},
            reason="tech",
            prerequisites=["gap_placeholder"],
        ),
        bundle.mission,
        bundle.scope,
    )
    assert tech.observations["technologies"][0]["product"] == "nginx"
    dirs = boundary.run(
        ActionRequest(
            mission_id=bundle.mission.mission_id,
            action_type="directory_enumeration",
            target=ActionTarget(canonical_locator="http://10.10.11.23/"),
            parameters={"url": "http://10.10.11.23/"},
            reason="dirs",
            prerequisites=["gap_placeholder"],
        ),
        bundle.mission,
        bundle.scope,
    )
    paths = {p["path"] for p in dirs.observations["paths"]}
    assert "/admin" in paths


def test_created_mission_cannot_execute(service) -> None:
    mission = service.create(create_cmd())
    bundle = service.get_bundle(mission.mission_id)
    with pytest.raises(PolicyDeniedError) as err:
        ExecutionBoundary().run(_scan_req(mission.mission_id), bundle.mission, bundle.scope)
    assert err.value.reason_code == "mission_not_running"


def test_paused_mission_cannot_execute(service) -> None:
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    service.pause(mission.mission_id)
    bundle = service.get_bundle(mission.mission_id)
    with pytest.raises(PolicyDeniedError) as err:
        ExecutionBoundary().run(_scan_req(mission.mission_id), bundle.mission, bundle.scope)
    assert err.value.reason_code == "mission_not_running"


def test_stopped_mission_cannot_execute(service) -> None:
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    service.stop(mission.mission_id)
    bundle = service.get_bundle(mission.mission_id)
    with pytest.raises(PolicyDeniedError) as err:
        ExecutionBoundary().run(_scan_req(mission.mission_id), bundle.mission, bundle.scope)
    assert err.value.reason_code == "mission_not_running"


def test_unknown_type_emits_rejected_and_never_runs(service) -> None:
    bundle = _running(service)
    sink = InMemoryEventSink()
    with pytest.raises(ActionRejected):
        ExecutionBoundary(events=sink).run(
            ActionRequest(
                mission_id=bundle.mission.mission_id,
                action_type="nuclei_scan",
                target=ActionTarget(canonical_locator="10.10.11.23"),
                parameters={},
                reason="no",
                prerequisites=["gap_placeholder"],
            ),
            bundle.mission,
            bundle.scope,
        )
    kinds = {e.event_type for e in sink.events}
    assert EventType.ACTION_REJECTED in kinds
    assert EventType.ACTION_STARTED not in kinds
    assert EventType.ACTION_COMPLETED not in kinds


def test_stub_simulates_every_catalog_type(service) -> None:
    host_id = new_id(PREFIX_HOST)
    url_id = new_id(PREFIX_URL)
    domain_id = new_id(PREFIX_DOMAIN)
    cases = [
        ("network_discovery", "10.10.11.0/24", {"network": "10.10.11.0/24"}, "10.10.11.0/24"),
        ("port_scan", "10.10.11.23", {"address": "10.10.11.23", "ports": "top1000"}, "10.10.11.23"),
        (
            "service_enumeration",
            "10.10.11.23",
            {"host_id": host_id, "port": 80},
            "10.10.11.23",
        ),
        ("http_probe", "10.10.11.23", {"url": "http://10.10.11.23/"}, "http://10.10.11.23/"),
        (
            "technology_detection",
            "10.10.11.23",
            {"url": "http://10.10.11.23/", "url_id": url_id},
            "http://10.10.11.23/",
        ),
        ("dns_enumeration", "box.htb", {"fqdn": "box.htb"}, "box.htb"),
        (
            "subdomain_enumeration",
            "box.htb",
            {"fqdn": "box.htb", "domain_id": domain_id},
            "box.htb",
        ),
        (
            "directory_enumeration",
            "10.10.11.23",
            {"url": "http://10.10.11.23/"},
            "http://10.10.11.23/",
        ),
        (
            "endpoint_discovery",
            "10.10.11.23",
            {"url": "http://10.10.11.23/"},
            "http://10.10.11.23/",
        ),
    ]
    seen: list[str] = []
    for action_type, raw_target, params, locator in cases:
        mission = service.create(create_cmd(raw_target=raw_target))
        service.confirm(mission.mission_id)
        service.start(mission.mission_id)
        bundle = service.get_bundle(mission.mission_id)
        outcome = ExecutionBoundary().run(
            ActionRequest(
                mission_id=mission.mission_id,
                action_type=action_type,
                target=ActionTarget(canonical_locator=locator),
                parameters=params,
                reason="stub-catalog",
                prerequisites=["gap_placeholder"],
            ),
            bundle.mission,
            bundle.scope,
        )
        assert outcome.result.status is ActionResultStatus.COMPLETED, action_type
        assert isinstance(outcome.tool_run.argv, list)
        assert all(isinstance(part, str) for part in outcome.tool_run.argv)
        assert outcome.tool_run.argv[0] == "stub"
        assert outcome.tool_run.argv[1] == action_type
        assert outcome.observations["action_type"] == action_type
        assert outcome.artifact.body
        seen.append(action_type)
    assert tuple(seen) == V1_ACTION_TYPES


def test_stub_adapter_always_available() -> None:
    adapter = StubAdapter()
    assert adapter.is_available() is True
    assert adapter.name == "stub_adapter"
