"""Golden path: tun0 route is informational. Policy/scope still bind."""

from __future__ import annotations

from tests.conftest import FIXTURES, create_cmd

from cyberx.domain.enums import PolicyVerdict, ReachabilityStatus
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.network.fixtures import scenario_no_route, scenario_route_via_tun0
from cyberx.network.observer import FixtureNetworkObserver
from cyberx.network.resolver import NetworkResolver
from cyberx.observability.sink import InMemoryEventSink
from cyberx.policy.engine import PolicyEngine
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner


def _wired(tmp_path, snapshot, xml_name: str = "host_22_80.xml"):
    xml = (FIXTURES / "nmap" / xml_name).read_bytes()
    adapter = NmapAdapter(
        runner=FixtureProcessRunner(xml), available=True, events=InMemoryEventSink()
    )
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    resolver = NetworkResolver(observer=FixtureNetworkObserver(snapshot), lookup=lambda _h: [])
    engine = MissionEngine(
        service,
        boundary=ExecutionBoundary(executor=executor),
        network=resolver,
    )
    return service, mission.mission_id, engine, adapter


def test_tun0_route_reaches_nmap_without_bypassing_scope(tmp_path) -> None:
    service, mid, engine, adapter = _wired(tmp_path, scenario_route_via_tun0())
    bundle = service.get_bundle(mid)
    before_nets = list(bundle.scope.allowed_networks)
    before_targets = list(bundle.scope.allowed_targets)
    net = engine.network_context(mid)
    assert net.selected_interface == "tun0"
    assert net.reachability is ReachabilityStatus.REACHABLE
    assert "HTB VPN" not in net.diagnostic

    report = engine.run_one_cycle(mid)
    assert report.selected_action_type == "port_scan"
    assert report.execution_status == "completed"
    assert report.evidence_added > 0
    argv = adapter._last_argv
    assert "-e" in argv
    assert argv[argv.index("-e") + 1] == "tun0"
    assert "-S" in argv
    assert argv[argv.index("-S") + 1] == "10.10.14.5"
    assert "shell=True" not in " ".join(argv)

    world = engine.world(mid)
    assert any(p.number == 22 for p in world.get_open_ports())

    after = service.get_bundle(mid).scope
    assert after.allowed_networks == before_nets
    assert after.allowed_targets == before_targets

    from cyberx.actions.validator import ActionValidator
    from cyberx.domain.models.actions import ActionRequest, ActionTarget

    request = ActionRequest(
        mission_id=mid,
        action_type="port_scan",
        target=ActionTarget(canonical_locator="8.8.8.8"),
        parameters={"address": "8.8.8.8", "ports": "top100", "protocol": "tcp"},
        reason="oos",
        timeout_s=30,
        prerequisites=["host.ports_unknown"],
    )
    policy = PolicyEngine()
    action = ActionValidator().validate(request)
    decision = policy.authorize(action, bundle.mission, bundle.scope)
    assert decision.verdict is PolicyVerdict.DENY


def test_route_missing_does_not_waste_nmap_cycles(tmp_path) -> None:
    _service, mid, engine, adapter = _wired(tmp_path, scenario_no_route())
    report = engine.run_one_cycle(mid)
    assert report.selected_action_type is None or report.completed is True
    assert adapter._last_argv == []
    assert engine.world(mid).revision >= 0
    net = engine.network_context(mid)
    assert net.reachability is ReachabilityStatus.ROUTE_MISSING
