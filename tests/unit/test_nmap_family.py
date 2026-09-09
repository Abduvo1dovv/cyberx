"""IPv4 dual-stack tun0 must not bind IPv6 link-local. IPv6 stays conservative."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import FIXTURES, create_cmd

from cyberx.domain.enums import ActionResultStatus, ActionStatus, MissionStatus, Risk
from cyberx.domain.identity import address_family, is_ipv6_link_local
from cyberx.domain.ids import PREFIX_ACTION, PREFIX_HOST, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import Action, ActionTarget
from cyberx.domain.time import utcnow
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.network.fixtures import (
    scenario_dual_stack_tun0,
    scenario_route_via_dual_stack_tun0,
)
from cyberx.network.observer import FixtureNetworkObserver
from cyberx.network.resolver import NetworkResolver
from cyberx.network.routing import source_address
from cyberx.ports.execution import ExecutionContext
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.argv import bind_args, build_nmap_argv, family_args, target_family
from cyberx.recon.nmap.process import FixtureProcessRunner, looks_like_nsock_bind_error


def _action(locator: str, params: dict | None = None, action_type: str = "port_scan") -> Action:
    return Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type=action_type,
        target=ActionTarget(canonical_locator=locator),
        parameters=params or {"address": locator, "ports": "top1000"},
        reason="test",
        expected_information_gain=0.8,
        risk=Risk.LOW,
        timeout_s=30,
        status=ActionStatus.AUTHORIZED,
        coverage_key=f"{action_type}:{locator}",
        created_at=utcnow(),
    )


def test_target_family_classifies_addresses() -> None:
    assert address_family("10.129.92.49") == "ipv4"
    assert target_family("10.129.92.49") == "ipv4"
    assert target_family("2001:db8::1") == "ipv6"
    assert target_family("fe80::1") == "ipv6"
    assert target_family("box.htb") == "hostname"
    assert family_args("ipv4") == ["-4"]
    assert family_args("hostname") == ["-4"]
    assert family_args("ipv6") == ["-6"]
    assert is_ipv6_link_local("fe80::1") is True
    assert is_ipv6_link_local("10.10.15.212") is False


def test_ipv4_dual_stack_tun0_argv_never_binds_fe80() -> None:
    action = _action("10.129.92.49", {"address": "10.129.92.49", "ports": "top1000"})
    argv = build_nmap_argv(
        action,
        xml_path="/tmp/scan.xml",
        timeout_s=180,
        source_interface="tun0",
        source_address="10.10.15.212",
    )
    assert argv[0] == "nmap"
    assert "-4" in argv
    assert "-6" not in argv
    assert "-Pn" in argv
    assert "-e" in argv
    assert argv[argv.index("-e") + 1] == "tun0"
    assert "-S" not in argv
    assert not any(t.lower().startswith("fe80:") for t in argv)
    assert "eth0" not in argv
    assert argv[-1] == "10.129.92.49"


def test_ipv4_ignores_link_local_source_address() -> None:
    action = _action("10.129.92.49", {"address": "10.129.92.49", "ports": "top1000"})
    argv = build_nmap_argv(
        action,
        xml_path="/tmp/scan.xml",
        timeout_s=30,
        source_interface="tun0",
        source_address="fe80::dead:beef",
    )
    assert "-e" in argv
    assert "-S" not in argv
    assert not any(t.lower().startswith("fe80:") for t in argv)
    assert bind_args("tun0", "fe80::1", family="ipv4") == ["-e", "tun0"]


def test_ipv6_argv_is_conservative() -> None:
    host_id = new_id(PREFIX_HOST)
    action = _action(
        "2001:db8::10",
        {"host_id": host_id, "port": 80},
        action_type="service_enumeration",
    )
    argv = build_nmap_argv(
        action,
        xml_path="/tmp/scan.xml",
        timeout_s=90,
        source_interface="tun0",
        source_address="fe80::1",
    )
    assert "-6" in argv
    assert "-4" not in argv
    assert "-e" in argv
    assert argv[argv.index("-e") + 1] == "tun0"
    assert "-S" not in argv
    assert not any(t.lower().startswith("fe80:") for t in argv)


def test_hostname_defaults_to_ipv4_mode() -> None:
    action = _action("box.htb", {"address": "box.htb", "ports": "top100"})
    argv = build_nmap_argv(action, xml_path="/tmp/scan.xml", timeout_s=30)
    assert "-4" in argv
    assert "-6" not in argv


def test_dual_stack_source_address_is_ipv4_not_link_local() -> None:
    snap = scenario_dual_stack_tun0()
    tun = next(i for i in snap.interfaces if i.name == "tun0")
    src = source_address(tun, "10.129.92.49")
    assert src == "10.10.15.212"
    assert is_ipv6_link_local(src) is False
    v6 = source_address(tun, "2001:db8::1")
    assert v6 is None


def test_dual_stack_resolver_picks_tun0_ipv4() -> None:
    resolver = NetworkResolver(
        observer=FixtureNetworkObserver(scenario_dual_stack_tun0()),
        lookup=lambda _h: [],
    )
    ctx = resolver.resolve("10.129.92.49")
    assert ctx.selected_interface == "tun0"
    assert ctx.source_address == "10.10.15.212"
    assert ctx.compact()["family"] == "ipv4"
    assert "fe80" not in (ctx.source_address or "")


def test_engine_ipv4_scan_on_dual_stack_tun0_does_not_bind_fe80(tmp_path) -> None:
    xml = (FIXTURES / "nmap" / "host_22_80.xml").read_bytes()
    runner = FixtureProcessRunner(xml)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(
        service,
        boundary=ExecutionBoundary(executor=executor),
        network=NetworkResolver(
            observer=FixtureNetworkObserver(scenario_route_via_dual_stack_tun0()),
            lookup=lambda _h: [],
        ),
    )
    report = engine.run_one_cycle(mission.mission_id)
    assert report.selected_action_type == "port_scan"
    assert report.execution_status == "completed"
    argv = adapter._last_argv
    assert "-4" in argv
    assert "-e" in argv
    assert argv[argv.index("-e") + 1] == "tun0"
    assert "-S" not in argv
    assert not any(t.lower().startswith("fe80:") for t in argv)
    assert "eth0" not in argv
    diag = engine.action_diagnostic(mission.mission_id)
    assert diag.get("family") == "ipv4"
    assert diag.get("interface") == "tun0"
    world = engine.world(mission.mission_id)
    numbers = {p.number for p in world.get_open_ports()}
    assert 22 in numbers and 80 in numbers


def test_failed_nsock_does_not_complete_or_invent_ports(tmp_path) -> None:
    nsock = b"NSOCK ERROR mksock_bind_addr() Bind to fe80::1 failed: Invalid argument"
    assert looks_like_nsock_bind_error(nsock)
    runner = FixtureProcessRunner(b"", exit_code=1, stderr=nsock)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(
        service,
        boundary=ExecutionBoundary(executor=executor),
        network=NetworkResolver(
            observer=FixtureNetworkObserver(scenario_route_via_dual_stack_tun0()),
            lookup=lambda _h: [],
        ),
    )
    report = engine.run_one_cycle(mission.mission_id)
    assert report.execution_status == "failed"
    assert report.completed is False
    assert service.get(mission.mission_id).status is MissionStatus.RUNNING
    assert "completed" not in engine.world(mission.mission_id).get_coverage().values()
    assert engine.world(mission.mission_id).get_open_ports() == ()
    diag = engine.action_diagnostic(mission.mission_id)
    assert diag["reason"] == "process_error"
    assert diag["retryable"] == "YES"
    first = runner.calls[0]
    assert "-4" in first
    assert "-e" in first
    second = runner.calls[1] if len(runner.calls) > 1 else first
    assert "-4" in second
    assert "eth0" not in second
    assert "-S" not in second


def test_adapter_does_not_pass_source_bind_for_ipv4(tmp_path) -> None:
    xml = (FIXTURES / "nmap" / "host_22.xml").read_bytes()
    runner = FixtureProcessRunner(xml)
    adapter = NmapAdapter(runner=runner, available=True)
    ctx = ExecutionContext(
        mission_id=new_id(PREFIX_MISSION),
        action_id=new_id(PREFIX_ACTION),
        timeout_s=30,
        workdir=str(tmp_path),
        reachability="REACHABLE",
        source_interface="tun0",
        source_address="10.10.15.212",
        address_family="ipv4",
        route_cidr="10.129.0.0/16",
    )
    artifact = adapter.run(_action("10.129.92.49"), ctx)
    assert artifact.byte_size > 0
    argv = runner.calls[0]
    assert "-4" in argv
    assert "-S" not in argv
    assert argv[argv.index("-e") + 1] == "tun0"


def test_http_still_independent_of_nmap_bind(tmp_path) -> None:
    from cyberx.recon.http.adapter import HttpAdapter
    from cyberx.recon.http.transport import FixtureTransport, HttpRawResponse

    body = (FIXTURES / "http" / "html_200.html").read_bytes()
    transport = FixtureTransport(
        HttpRawResponse(
            url="http://10.10.11.23/",
            status=200,
            headers={"server": "nginx"},
            body=body,
        )
    )
    adapter = HttpAdapter(transport=transport, available=True)
    action = Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type="http_probe",
        target=ActionTarget(canonical_locator="http://10.10.11.23/"),
        parameters={"url": "http://10.10.11.23/"},
        reason="http",
        expected_information_gain=0.5,
        risk=Risk.LOW,
        timeout_s=10,
        status=ActionStatus.AUTHORIZED,
        coverage_key="http_probe:http://10.10.11.23/",
        created_at=utcnow(),
    )
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=10,
        workdir=str(tmp_path),
        reachability="REACHABLE",
        source_interface="tun0",
        source_address="10.10.15.212",
        stub=False,
        allowed_targets=["10.10.11.23"],
        allowed_protocols=["http", "https"],
    )
    artifact = adapter.run(action, ctx)
    assert artifact.byte_size > 0
    assert adapter._last_argv[0] == "GET"
    assert "-e" not in adapter._last_argv
    assert "-S" not in adapter._last_argv
    assert "-4" not in adapter._last_argv


def test_argv_construction_does_not_need_nmap_binary() -> None:
    action = _action("10.10.11.23")
    argv = build_nmap_argv(
        action,
        xml_path=str(Path("/tmp") / "scan.xml"),
        timeout_s=30,
        source_interface="tun0",
    )
    assert argv[0] == "nmap"
    assert "-4" in argv
    assert ActionResultStatus.FAILED.value == "failed"
