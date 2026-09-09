"""Real-world reliability: failed recon must not look like success."""

from __future__ import annotations

from tests.conftest import FIXTURES, create_cmd

from cyberx.brain.context import BrainContextBuilder
from cyberx.brain.planner import Planner
from cyberx.domain.enums import ActionResultStatus, MissionStatus, StopReason
from cyberx.domain.models.actions import ActionRequest, ActionTarget
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.graph.paths import PathPlanner
from cyberx.graph.projector import GraphProjector
from cyberx.graph.tree import render_path_line
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.network.fixtures import scenario_route_via_tun0
from cyberx.network.observer import FixtureNetworkObserver
from cyberx.network.resolver import NetworkResolver
from cyberx.ports.execution import ExecutionContext
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner
from cyberx.storage.sqlite import SqliteStore
from cyberx.tui.render import render_dashboard


def _running(store=None):
    service = MissionService(store or InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    return service, mission.mission_id


def _tun0():
    return NetworkResolver(
        observer=FixtureNetworkObserver(scenario_route_via_tun0()),
        lookup=lambda _h: [],
    )


def _nmap_engine(tmp_path, runner, *, store=None, available: bool = True):
    service, mid = _running(store)
    adapter = NmapAdapter(runner=runner, available=available)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    engine = MissionEngine(
        service,
        boundary=ExecutionBoundary(executor=executor),
        network=_tun0(),
        store=store,
    )
    return service, mid, engine, adapter


def test_failed_port_scan_does_not_complete_mission(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=1, stderr=b"Could not bind to source address")
    _service, mid, engine, adapter = _nmap_engine(tmp_path, runner)
    first = engine.run_one_cycle(mid)
    assert first.selected_action_type == "port_scan"
    assert first.execution_status == "failed"
    assert first.completed is False
    assert first.stop_reason != "no_actions"
    assert _service.get(mid).status is MissionStatus.RUNNING
    coverage = engine.world(mid).get_coverage()
    assert coverage
    assert "completed" not in coverage.values()
    assert engine.world(mid).get_open_ports() == ()
    argv = adapter._last_argv
    assert "-e" in argv
    assert argv[argv.index("-e") + 1] == "tun0"
    assert "HTB VPN" not in " ".join(argv)


def test_retryable_failure_retries_then_exhausts(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=1, stderr=b"Could not bind")
    _service, mid, engine, _adapter = _nmap_engine(tmp_path, runner)
    first = engine.run_one_cycle(mid)
    assert first.completed is False
    assert "attempted" in engine.world(mid).get_coverage().values()
    diag = engine.action_diagnostic(mid)
    assert diag["reason"] == "process_error"
    assert diag["retryable"] == "YES"
    assert diag["attempt"] == "1/2"
    second = engine.run_one_cycle(mid)
    assert second.completed is False
    assert second.execution_status == "failed"
    assert "failed" in engine.world(mid).get_coverage().values()
    assert "completed" not in engine.world(mid).get_coverage().values()
    third = engine.run_one_cycle(mid)
    assert third.completed is False
    assert _service.get(mid).status is MissionStatus.RUNNING


def test_nonretryable_failure_does_not_retry_same_coverage(tmp_path) -> None:
    runner = FixtureProcessRunner(b"not-xml", exit_code=1)
    _service, mid, engine, _adapter = _nmap_engine(tmp_path, runner)
    first = engine.run_one_cycle(mid)
    assert first.execution_status == "failed"
    assert first.completed is False
    key = first.coverage_key
    assert key
    assert engine.world(mid).get_coverage().get(key) == "failed"
    second = engine.run_one_cycle(mid)
    assert second.completed is False
    assert second.selected_action_type != "port_scan"


def test_unavailable_nmap_is_diagnostic_not_success(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", missing_binary=True)
    _service, mid, engine, _adapter = _nmap_engine(tmp_path, runner, available=False)
    report = engine.run_one_cycle(mid)
    assert report.execution_status == "unavailable"
    assert report.completed is False
    assert "unavailable" in engine.world(mid).get_coverage().values()
    assert "completed" not in engine.world(mid).get_coverage().values()
    diag = engine.action_diagnostic(mid)
    assert diag["reason"] == "adapter_unavailable"
    assert diag["retryable"] == "NO"


def test_failed_action_does_not_mark_coverage_complete(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=1)
    _service, mid, engine, _adapter = _nmap_engine(tmp_path, runner)
    engine.run_one_cycle(mid)
    assert all(status != "completed" for status in engine.world(mid).get_coverage().values())
    ctx = BrainContextBuilder().build(
        engine.world(mid).snapshot(),
        _service.get(mid),
        target=_service.get_bundle(mid).target,
        scope=_service.get_bundle(mid).scope,
    )
    assert any(gap.kind == "host.ports_unknown" for gap in ctx.gaps)


def test_planner_and_path_agree_after_exhausted_scan(tmp_path) -> None:
    runner = FixtureProcessRunner(b"not-xml", exit_code=1)
    service, mid, engine, _adapter = _nmap_engine(tmp_path, runner)
    engine.run_one_cycle(mid)
    engine.run_one_cycle(mid)
    bundle = service.get_bundle(mid)
    snap = engine.world(mid).snapshot()
    ctx = BrainContextBuilder().build(
        snap, bundle.mission, scope=bundle.scope, target=bundle.target
    )
    types = {cand.action_type for cand in Planner().propose(ctx)}
    assert "port_scan" not in types
    paths = PathPlanner().plan(GraphProjector().project(snap), snap)
    for path in paths:
        assert path.action_type != "port_scan"
        assert "next=port_scan" not in render_path_line(path)


def test_duplicate_ports_hypothesis_is_suppressed(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=1, stderr=b"Could not bind")
    _service, mid, engine, _adapter = _nmap_engine(tmp_path, runner)
    engine.run_one_cycle(mid)
    engine.run_one_cycle(mid)
    hyps = engine.world(mid).get_hypotheses()
    cores = [
        h.statement.split(" (")[0] for h in hyps if "ports have not been observed" in h.statement
    ]
    assert len(cores) == len(set(cores))
    assert len(cores) <= 1


def test_resume_after_failed_scan_keeps_incomplete_coverage(tmp_path) -> None:
    store = SqliteStore(tmp_path / "cyberx.db", data_dir=tmp_path)
    runner = FixtureProcessRunner(b"not-xml", exit_code=1)
    service, mid, engine, _adapter = _nmap_engine(tmp_path, runner, store=store)
    first = engine.run_one_cycle(mid)
    assert first.completed is False
    coverage = dict(engine.world(mid).get_coverage())
    assert coverage
    assert "completed" not in coverage.values()
    before = engine.action_diagnostic(mid)
    assert before.get("reason")
    assert before.get("attempt")
    store.close()
    store2 = SqliteStore(tmp_path / "cyberx.db", data_dir=tmp_path)
    service2 = MissionService(store2)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    engine2 = MissionEngine(
        service2,
        boundary=ExecutionBoundary(executor=executor),
        store=store2,
        network=_tun0(),
    )
    world = engine2.world(mid)
    assert "completed" not in world.get_coverage().values()
    assert world.get_open_ports() == ()
    diag = engine2.action_diagnostic(mid)
    assert diag.get("reason") == before.get("reason")
    assert diag.get("attempt") == before.get("attempt")
    report = engine2.run_one_cycle(mid)
    assert report.completed is False
    assert service2.get(mid).status is MissionStatus.RUNNING
    store2.close()


def test_network_context_is_passed_to_nmap_argv(tmp_path) -> None:
    xml = (FIXTURES / "nmap" / "host_22.xml").read_bytes()
    runner = FixtureProcessRunner(xml)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    from tests.unit.test_nmap_adapter import _authorized

    ctx = ExecutionContext(
        mission_id=_authorized().action.mission_id,
        action_id="pending",
        timeout_s=30,
        workdir=str(tmp_path),
        reachability="REACHABLE",
        source_interface="tun0",
        source_address="10.10.15.7",
    )
    outcome = executor.execute(_authorized(), ctx)
    assert outcome.result.status is ActionResultStatus.COMPLETED
    argv = runner.calls[0]
    assert "-e" in argv
    assert argv[argv.index("-e") + 1] == "tun0"
    assert "-S" in argv
    assert argv[argv.index("-S") + 1] == "10.10.15.7"
    assert argv[-1] == "10.10.11.23"


def test_failed_action_dashboard_is_explicit() -> None:
    from cyberx.app.views import (
        CurrentActionView,
        DashboardView,
        MissionStatusView,
        ScopeReviewView,
        WorldSummaryView,
    )

    dash = DashboardView(
        mission=MissionStatusView(
            mission_id="mis_01AAAAAAAAAAAAAAAAAAAAAAAA",
            name="lab",
            intent="recon",
            status="RUNNING",
            target="10.129.246.236",
            target_kind="ipv4",
            mode="ctf",
            provider="none",
            iteration=1,
            max_iterations=50,
            elapsed_s=1,
            max_runtime_s=3600,
            stop_reason=None,
            policy_profile="recon_default",
            scope=ScopeReviewView(
                allowed_targets=("10.129.246.236",),
                allowed_networks=(),
                allowed_ports=(),
                allowed_protocols=("tcp",),
                excluded_targets=(),
                excluded_networks=(),
                excluded_ports=(),
                allow_subdomains=True,
                frozen=True,
                policy_profile="recon_default",
            ),
        ),
        world=WorldSummaryView(
            revision=1,
            hosts=1,
            open_ports=0,
            services=0,
            technologies=0,
            urls=0,
            endpoints=0,
            findings=0,
            hypotheses=1,
            open_gaps=1,
            closed_gaps=0,
            host_lines=("10.129.246.236",),
            port_lines=(),
            service_lines=(),
            tech_lines=(),
            url_lines=(),
            gap_lines=("host.ports_unknown",),
            claim_lines=(),
        ),
        action=CurrentActionView(
            action_type="port_scan",
            target="10.129.246.236",
            rationale="gap=host.ports_unknown",
            score="0.72",
            coverage_key="ab",
            policy_verdict="allow",
            execution_status="failed",
            last_result="failed",
            error_code="process_error",
            attempt="1/2",
            retryable="YES",
        ),
        findings=(),
        hypotheses=(),
        events=(),
    )
    text = render_dashboard(dash)
    assert "FAILED" in text
    assert "reason: process_error" in text
    assert "attempt: 1/2" in text
    assert "retryable: YES" in text
    assert "10.129.246.236" in text
    assert "COMPLETED" not in text


def test_run_forever_does_not_complete_after_one_failed_scan(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=1, stderr=b"Could not bind to source address")
    service, mid, engine, _adapter = _nmap_engine(tmp_path, runner)
    reports = engine.run_forever(mid)
    assert reports
    assert reports[0].selected_action_type == "port_scan"
    assert reports[0].execution_status == "failed"
    assert reports[0].completed is False
    assert len(reports) > 1
    assert not any(item.completed and item.stop_reason == "no_actions" for item in reports)
    terminal = reports[-1]
    assert terminal.completed is True
    assert terminal.stop_reason == "stalled"
    assert service.get(mid).status is MissionStatus.COMPLETED
    assert service.get(mid).stop_reason is StopReason.STALLED
    assert "completed" not in engine.world(mid).get_coverage().values()
    assert engine.world(mid).get_open_ports() == ()


def test_failed_scan_uses_actual_execution_boundary(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=1, stderr=b"Could not bind to source address")
    service, mid, engine, adapter = _nmap_engine(tmp_path, runner)
    report = engine.run_one_cycle(mid)
    assert report.policy_verdict == "allow"
    assert report.execution_status == "failed"
    assert report.completed is False
    assert adapter._last_result is not None
    assert adapter._last_result.exit_code == 1
    argv = adapter._last_argv
    assert argv[0] == "nmap"
    assert "-e" in argv and argv[argv.index("-e") + 1] == "tun0"
    assert argv[-1] == "10.10.11.23"
    assert "-S" in runner.calls[0]
    assert runner.calls[0][runner.calls[0].index("-S") + 1] == "10.10.14.5"
    if len(runner.calls) > 1:
        assert "-e" in runner.calls[1]
        assert "-S" not in runner.calls[1]
    bundle = service.get_bundle(mid)
    outcome = engine._boundary.run(
        ActionRequest(
            mission_id=mid,
            action_type="port_scan",
            target=ActionTarget(canonical_locator="10.10.11.23"),
            parameters={"address": "10.10.11.23", "ports": "top1000", "protocol": "tcp"},
            reason="boundary",
            timeout_s=30,
            prerequisites=["host.ports_unknown"],
        ),
        bundle.mission,
        bundle.scope,
        ctx=ExecutionContext(
            mission_id=mid,
            action_id="pending",
            timeout_s=30,
            workdir=str(tmp_path),
            reachability="REACHABLE",
            source_interface="tun0",
            source_address="10.10.14.5",
        ),
    )
    assert outcome.result.status is ActionResultStatus.FAILED
    assert outcome.result.error_code == "process_error"
    assert outcome.artifact.byte_size == 0


def test_stub_mode_still_works() -> None:
    service, mid = _running()
    engine = MissionEngine(service)
    report = engine.run_one_cycle(mid)
    assert report.selected_action_type == "port_scan"
    assert report.execution_status == "completed"
    assert report.completed is False
    assert engine.world(mid).get_open_ports()
    assert service.get(mid).status is MissionStatus.RUNNING


def test_scope_does_not_expand_after_failed_scan(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=1, stderr=b"Could not bind")
    service, mid, engine, _adapter = _nmap_engine(tmp_path, runner)
    before = list(service.get_bundle(mid).scope.allowed_targets)
    engine.run_one_cycle(mid)
    engine.run_one_cycle(mid)
    after = service.get_bundle(mid).scope
    assert after.frozen is True
    assert list(after.allowed_targets) == before
    assert "8.8.8.8" not in after.allowed_targets
