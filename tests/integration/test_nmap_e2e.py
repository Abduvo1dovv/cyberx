"""End-to-end Nmap path with a fixture-backed adapter. Nmap is not required."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from tests.conftest import FIXTURES, create_cmd

from cyberx.domain.enums import ActionStatus, PolicyVerdict, Risk
from cyberx.domain.ids import PREFIX_ACTION, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import Action, ActionTarget, PolicyDecision
from cyberx.domain.time import utcnow
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.engine.stub_executor import StubExecutor
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.ports.events import EventType
from cyberx.ports.execution import AuthorizedAction, ExecutionContext
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner, ProcessRunner
from cyberx.world.model import InMemoryWorldModel


def _engine(tmp_path, xml_name: str, sink=None):
    xml = (FIXTURES / "nmap" / xml_name).read_bytes()
    runner = FixtureProcessRunner(xml)
    adapter = NmapAdapter(runner=runner, available=True, events=sink)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    boundary = ExecutionBoundary(executor=executor, events=sink)
    engine = MissionEngine(service, boundary=boundary, events=sink)
    return service, mission.mission_id, engine, adapter


def test_fixture_nmap_mission_updates_world_and_replans(tmp_path) -> None:
    sink = InMemoryEventSink()
    _service, mid, engine, _adapter = _engine(tmp_path, "host_22_80.xml", sink)
    first = engine.run_one_cycle(mid)
    assert first.selected_action_type == "port_scan"
    assert first.execution_status == "completed"
    assert first.evidence_added > 0
    world = engine.world(mid)
    numbers = {p.number for p in world.get_open_ports()}
    assert 22 in numbers
    assert 80 in numbers
    services = {s.name for s in world.get_services()}
    assert "ssh" in services or "http" in services
    second = engine.run_one_cycle(mid)
    assert second.selected_action_type != first.selected_action_type
    assert second.coverage_key != first.coverage_key
    kinds = {e.event_type for e in sink.events}
    assert EventType.NMAP_STARTED in kinds
    assert EventType.PARSE_COMPLETED in kinds
    assert EventType.NMAP_COMPLETED in kinds


def test_multi_host_marks_out_of_scope(tmp_path) -> None:
    _service, mid, engine, _adapter = _engine(tmp_path, "multiple_hosts.xml")
    engine.run_one_cycle(mid)
    world = engine.world(mid)
    hosts = world.get_hosts()
    oos = [h for h in hosts if h.out_of_scope]
    scoped = [h for h in hosts if not h.out_of_scope]
    assert any("10.10.11.23" in h.canonical_key for h in scoped)
    assert any("8.8.8.8" in h.canonical_key for h in oos)
    gaps = [g for g in world.get_gaps() if not g.closed]
    for gap in gaps:
        assert "8.8.8.8" not in (gap.detail or "")
        assert "8.8.8.8" not in (gap.subject_id or "")


def test_malformed_xml_does_not_crash_engine(tmp_path) -> None:
    _service, mid, engine, _adapter = _engine(tmp_path, "truncated.xml")
    report = engine.run_one_cycle(mid)
    assert report.execution_status == "failed"
    world = engine.world(mid)
    assert not world.get_open_ports()
    coverage = world.get_coverage()
    assert any(str(v).startswith("failed") for v in coverage.values())
    mission = _service.get(mid)
    assert mission.status.value in {"RUNNING", "COMPLETED", "FAILED", "STOPPED"}


def test_stub_executor_still_works() -> None:
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(service)
    report = engine.run_one_cycle(mission.mission_id)
    assert report.selected_action_type == "port_scan"
    assert report.execution_status == "completed"
    assert isinstance(engine._boundary._executor, StubExecutor)


def test_evidence_from_nmap_xml_is_traceable(tmp_path) -> None:
    artifact_bytes = (FIXTURES / "nmap" / "host_22_80.xml").read_bytes()
    runner = FixtureProcessRunner(artifact_bytes)
    adapter = NmapAdapter(runner=runner, available=True)
    action = Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type="port_scan",
        target=ActionTarget(canonical_locator="10.10.11.23"),
        parameters={"address": "10.10.11.23", "ports": "specified", "port_list": [22, 80]},
        reason="ports",
        expected_information_gain=0.8,
        risk=Risk.LOW,
        timeout_s=30,
        status=ActionStatus.AUTHORIZED,
        coverage_key="port_scan:10.10.11.23",
        created_at=utcnow(),
    )
    authorized = AuthorizedAction(
        action=action,
        decision=PolicyDecision(verdict=PolicyVerdict.ALLOW, reason_code="allow"),
    )
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(authorized)
    obs, evidence = EvidencePipeline().normalize(outcome.artifact)
    assert obs
    world = InMemoryWorldModel(action.mission_id)
    for item in evidence:
        world.apply_evidence(item)
    assert world.get_open_ports()
    for ev in evidence:
        assert ev.artifact_id == outcome.artifact.artifact_id
        assert ev.tool_run_id == outcome.tool_run.tool_run_id


def test_fake_nmap_script_via_process_runner(tmp_path) -> None:
    script = FIXTURES / "nmap" / "fake_nmap.py"
    script.chmod(0o755)
    binary = str(script)
    adapter = NmapAdapter(binary=binary, runner=ProcessRunner(), available=True)
    action = Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type="port_scan",
        target=ActionTarget(canonical_locator="10.10.11.23"),
        parameters={"address": "10.10.11.23", "ports": "top1000"},
        reason="ports",
        expected_information_gain=0.8,
        risk=Risk.LOW,
        timeout_s=15,
        status=ActionStatus.AUTHORIZED,
        coverage_key="port_scan:10.10.11.23",
        created_at=utcnow(),
    )
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=15,
        workdir=str(tmp_path),
        stub=False,
    )
    artifact = adapter.run(action, ctx)
    assert artifact.byte_size > 0
    assert b"<nmaprun" in (artifact.body or b"")
    assert adapter._last_result is not None
    assert adapter._last_result.timed_out is False


@pytest.mark.requires_nmap
def test_live_nmap_localhost_optional(tmp_path, monkeypatch) -> None:
    if os.environ.get("CYBERX_LIVE_NMAP") != "1":
        pytest.skip("set CYBERX_LIVE_NMAP=1 to run live nmap")
    if shutil.which("nmap") is None:
        pytest.skip("nmap binary is not installed")
    target = os.environ.get("CYBERX_LIVE_NMAP_TARGET", "127.0.0.1").strip() or "127.0.0.1"
    monkeypatch.chdir(tmp_path)
    adapter = NmapAdapter()
    assert adapter.is_available()
    action = Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type="port_scan",
        target=ActionTarget(canonical_locator=target),
        parameters={"address": target, "ports": "specified", "port_list": [1]},
        reason="live-check",
        expected_information_gain=0.1,
        risk=Risk.LOW,
        timeout_s=20,
        status=ActionStatus.AUTHORIZED,
        coverage_key=f"port_scan:{target}",
        created_at=utcnow(),
    )
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=20,
        workdir="missions/live-nmap",
        stub=False,
    )
    artifact = adapter.run(action, ctx)
    assert artifact.adapter_name == "nmap_adapter"
    argv = adapter._last_argv
    assert "-4" in argv
    assert "-6" not in argv
    assert "-S" not in argv
    assert not any(t.lower().startswith("fe80:") for t in argv)
    assert argv[-1] == target
    ox = argv[argv.index("-oX") + 1]
    assert Path(ox).is_absolute()
    result = adapter._last_result
    assert result is not None
    # Empty stdout is valid when -oX wrote the artifact.
    if result.exit_code == 0 and not result.timed_out:
        assert artifact.byte_size > 0
        assert b"<nmaprun" in (artifact.body or b"")
        assert Path(ox).is_file()


def test_fake_nmap_relative_workdir_empty_stdout_feeds_world(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    script = FIXTURES / "nmap" / "fake_nmap.py"
    script.chmod(0o755)
    adapter = NmapAdapter(binary=str(script), runner=ProcessRunner(), available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir="data")
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(
        service,
        boundary=ExecutionBoundary(executor=executor),
    )
    first = engine.run_one_cycle(mission.mission_id)
    assert first.selected_action_type == "port_scan"
    assert first.execution_status == "completed"
    ox = adapter._last_argv[adapter._last_argv.index("-oX") + 1]
    assert Path(ox).is_absolute()
    assert Path(ox).is_file()
    assert adapter._last_result is not None
    assert adapter._last_result.stdout == b""
    assert adapter._last_result.exit_code == 0
    world = engine.world(mission.mission_id)
    numbers = {p.number for p in world.get_open_ports()}
    assert 22 in numbers
    assert 80 in numbers
    second = engine.run_one_cycle(mission.mission_id)
    assert second.selected_action_type != "port_scan"


def test_parser_failure_is_not_completed_coverage(tmp_path) -> None:
    _service, mid, engine, _adapter = _engine(tmp_path, "truncated.xml")
    report = engine.run_one_cycle(mid)
    assert report.execution_status == "failed"
    assert report.evidence_added == 0
    world = engine.world(mid)
    assert not world.get_open_ports()
    diag = engine._diag.get(mid) or {}
    assert diag.get("reason") == "parse_error"
    assert diag.get("status") == "failed"
    coverage = world.get_coverage()
    assert coverage
    assert all(not str(v).startswith("completed") for v in coverage.values())
