"""M8 MissionEngine loop: cycles, pause/stop, brakes, traces."""

from __future__ import annotations

from tests.conftest import create_cmd

from cyberx.domain.enums import MissionStatus, StopReason
from cyberx.domain.errors import AdapterUnavailable
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.stub_executor import StubExecutor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.ports.execution import AuthorizedAction, ExecutionContext


def _running_service(**overrides):
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd(**overrides))
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    return service, mission.mission_id


def test_one_complete_cycle() -> None:
    service, mid = _running_service()
    engine = MissionEngine(service)
    report = engine.run_one_cycle(mid)
    assert report.selected_action_type == "port_scan"
    assert report.execution_status == "completed"
    assert report.evidence_added > 0
    world = engine.world(mid)
    assert world.get_open_ports()
    assert service.get(mid).iteration == 1


def test_cycle_two_changes_after_evidence() -> None:
    service, mid = _running_service()
    engine = MissionEngine(service)
    first = engine.run_one_cycle(mid)
    second = engine.run_one_cycle(mid)
    assert first.selected_action_type == "port_scan"
    assert second.selected_action_type != first.selected_action_type
    assert second.selected_action_type in {
        "http_probe",
        "service_enumeration",
        "technology_detection",
        "directory_enumeration",
        "endpoint_discovery",
    }
    assert second.evidence_added > 0


def test_duplicate_action_prevented() -> None:
    service, mid = _running_service()
    engine = MissionEngine(service)
    types = []
    for _ in range(4):
        report = engine.run_one_cycle(mid)
        if report.completed:
            break
        types.append(report.selected_action_type)
    assert types.count("port_scan") == 1


def test_pause_at_cycle_boundary() -> None:
    service, mid = _running_service()
    engine = MissionEngine(service)
    engine.run_one_cycle(mid)
    service.pause(mid)
    report = engine.run_one_cycle(mid)
    assert report.paused is True
    assert service.get(mid).status is MissionStatus.PAUSED


def test_stop_prevents_additional_actions() -> None:
    service, mid = _running_service()
    engine = MissionEngine(service)
    engine.run_one_cycle(mid)
    service.stop(mid, StopReason.OPERATOR)
    report = engine.run_one_cycle(mid)
    assert report.completed is True
    assert service.get(mid).status is MissionStatus.STOPPED


def test_max_iterations() -> None:
    service, mid = _running_service(max_iterations=1)
    engine = MissionEngine(service)
    first = engine.run_one_cycle(mid)
    assert first.selected_action_type == "port_scan"
    second = engine.run_one_cycle(mid)
    assert second.completed is True
    assert second.stop_reason == "max_iterations"


def test_decision_trace_recorded() -> None:
    service, mid = _running_service()
    engine = MissionEngine(service)
    engine.run_one_cycle(mid)
    traces = engine.traces(mid)
    assert traces
    assert traces[0].selected_type == "port_scan"
    assert traces[0].rationale
    assert traces[0].candidates


def test_policy_denial_does_not_fail_mission() -> None:
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    engine = MissionEngine(service)
    report = engine.run_one_cycle(mission.mission_id)
    assert report.completed is False
    assert service.get(mission.mission_id).status is MissionStatus.CONFIRMED


def test_hostname_first_action_is_dns() -> None:
    service, mid = _running_service(raw_target="box")
    engine = MissionEngine(service)
    report = engine.run_one_cycle(mid)
    assert report.selected_action_type == "dns_enumeration"
    assert report.execution_status == "completed"


class _Boom(StubExecutor):
    def execute(self, authorized: AuthorizedAction, ctx: ExecutionContext | None = None):
        raise AdapterUnavailable("stub_adapter")


class _NmapGone(StubExecutor):
    def execute(self, authorized: AuthorizedAction, ctx: ExecutionContext | None = None):
        raise AdapterUnavailable("nmap_adapter")


def test_nmap_unavailable_is_operator_visible() -> None:
    service, mid = _running_service()
    engine = MissionEngine(service, boundary=ExecutionBoundary(executor=_NmapGone()))
    report = engine.run_one_cycle(mid)
    assert report.execution_status == "unavailable"
    assert service.get(mid).status is not MissionStatus.FAILED
    messages = [event.message for event in service.get_bundle(mid).timeline]
    assert "nmap unavailable" in messages
