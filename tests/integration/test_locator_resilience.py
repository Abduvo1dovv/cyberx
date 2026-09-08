"""M18 golden CTF: VPN source change, target reset, operator-confirmed locator."""

from __future__ import annotations

import pytest
from tests.conftest import FIXTURES, create_cmd

from cyberx.actions.coverage import coverage_key
from cyberx.app.facade import OperatorFacade
from cyberx.brain.context import BrainContextBuilder
from cyberx.brain.planner import Planner
from cyberx.config import AppConfig
from cyberx.domain.enums import LocatorStatus, ReachabilityStatus
from cyberx.domain.errors import LocatorRejected
from cyberx.domain.models.actions import ActionTarget
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.graph.projector import GraphProjector
from cyberx.mission.commands import ConfirmLocatorCmd
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.network.fixtures import (
    _default_eth,
    _eth0,
    _htb_via_tun0,
    _lan_eth,
    _tun0,
    scenario_tun0_source_changed,
    scenario_unreachable,
)
from cyberx.network.observer import ObservedNetwork
from cyberx.network.resolver import NetworkResolver
from cyberx.observability.sink import InMemoryEventSink
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner
from cyberx.storage.sqlite import SqliteStore


class SwapObserver:
    def __init__(self, snapshot: ObservedNetwork) -> None:
        self.snapshot = snapshot

    def inspect(self) -> ObservedNetwork:
        return self.snapshot


def _lab(source: str, *, unreachable: bool = False) -> ObservedNetwork:
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0(ip=source)),
        routes=(_lan_eth(), _htb_via_tun0(), _default_eth()),
        reachability_override=ReachabilityStatus.UNREACHABLE if unreachable else None,
    )


def test_golden_ctf_reset_and_operator_confirm(tmp_path) -> None:
    xml = (FIXTURES / "nmap" / "host_22_80.xml").read_bytes()
    adapter = NmapAdapter(
        runner=FixtureProcessRunner(xml), available=True, events=InMemoryEventSink()
    )
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    store = InMemoryMissionStore()
    service = MissionService(store)
    observer = SwapObserver(_lab("10.10.14.10"))
    resolver = NetworkResolver(observer=observer, lookup=lambda _h: ["10.10.11.45"])
    engine = MissionEngine(
        service,
        boundary=ExecutionBoundary(executor=executor),
        network=resolver,
    )
    facade = OperatorFacade(AppConfig(), service, engine, stub_mode=False)

    mission = service.create(
        create_cmd(
            name="ctf-target",
            raw_target="10.10.11.23",
            allowed_networks=["10.10.11.0/24"],
        )
    )
    mid = mission.mission_id
    service.confirm(mid)
    service.start(mid)
    target = service.get_bundle(mid).target
    assert target.canonical_identity == "identity:ipv4:10.10.11.23"
    assert target.current_locator == "10.10.11.23"

    net1 = engine.network_context(mid)
    assert net1.selected_interface == "tun0"
    assert net1.source_address == "10.10.14.10"
    digest1 = net1.digest()

    report = engine.run_one_cycle(mid)
    assert report.selected_action_type == "port_scan"
    assert report.execution_status == "completed"
    assert report.evidence_added > 0
    world = engine.world(mid)
    old_ports = [p.number for p in world.get_open_ports()]
    assert 22 in old_ports or 80 in old_ports
    old_host_keys = {h.canonical_key for h in world.snapshot().hosts}
    old_coverage = dict(world.get_coverage())
    first_key = coverage_key(
        "port_scan",
        ActionTarget(canonical_locator="10.10.11.23"),
        {"address": "10.10.11.23", "ports": "top1000", "protocol": "tcp"},
    )
    scope_before = list(service.get_bundle(mid).scope.allowed_targets)
    nets_before = list(service.get_bundle(mid).scope.allowed_networks)

    observer.snapshot = scenario_tun0_source_changed(ip="10.10.14.17")
    net2 = engine.network_context(mid)
    assert net2.source_address == "10.10.14.17"
    assert net2.digest() != digest1

    observer.snapshot = _lab("10.10.14.17", unreachable=True)
    bundle = service.get_bundle(mid)
    net3 = engine._observe_network(mid, bundle.target, bundle.scope)
    assert net3.reachability is ReachabilityStatus.UNREACHABLE
    stale = service.get_bundle(mid).target
    assert any(
        item.locator == "10.10.11.23" and item.status is LocatorStatus.UNREACHABLE
        for item in stale.locator_history
    )
    assert stale.canonical_identity == "identity:ipv4:10.10.11.23"

    discovered = service.observe_locator(mid, "10.10.11.45", source="dns")
    assert discovered.current_locator == "10.10.11.23"
    assert any(item.locator == "10.10.11.45" for item in discovered.locator_history)

    facade.confirm_locator(mid, "10.10.11.45")
    confirmed = service.get_bundle(mid).target
    assert confirmed.current_locator == "10.10.11.45"
    assert confirmed.previous_locator() == "10.10.11.23"
    assert confirmed.canonical_identity == "identity:ipv4:10.10.11.23"
    after_scope = service.get_bundle(mid).scope
    assert after_scope.allowed_targets == scope_before
    assert after_scope.allowed_networks == nets_before
    assert after_scope.frozen is True

    observer.snapshot = _lab("10.10.14.17")
    ctx = BrainContextBuilder().build(
        engine.world(mid).snapshot(),
        service.get(mid),
        scope=after_scope,
        network_context=engine.network_context(mid),
        target=service.get_bundle(mid).target,
    )
    proposed = Planner().propose(ctx)
    locators = {c.target.canonical_locator for c in proposed}
    types = {c.action_type for c in proposed}
    assert "port_scan" in types
    assert "10.10.11.45" in locators
    assert "10.10.11.23" not in locators
    new_key = coverage_key(
        "port_scan",
        ActionTarget(canonical_locator="10.10.11.45"),
        {"address": "10.10.11.45", "ports": "top1000", "protocol": "tcp"},
    )
    assert new_key != first_key
    assert new_key not in old_coverage

    snap = engine.world(mid).snapshot()
    assert old_host_keys <= {h.canonical_key for h in snap.hosts}
    assert any(h.ipv4 == "10.10.11.23" for h in snap.hosts)
    assert any(h.ipv4 == "10.10.11.45" for h in snap.hosts)
    assert any(p.number in old_ports for p in engine.world(mid).get_open_ports())
    graph = GraphProjector().project(snap)
    keys = {n.semantic_key for n in graph.nodes}
    assert any("10.10.11.23" in k for k in keys)
    assert any("10.10.11.45" in k for k in keys)

    messages = [e.message for e in service.get_bundle(mid).timeline]
    assert any("confirmed locator" in m for m in messages)
    assert any("unreachable" in m.lower() for m in messages)

    with pytest.raises(LocatorRejected, match="AI"):
        service.confirm_locator(mid, ConfirmLocatorCmd(locator="10.10.11.60", actor="ai"))


def test_golden_ai_cannot_retarget_or_expand(tmp_path) -> None:
    del tmp_path
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd(allowed_networks=["10.10.11.0/24"]))
    service.confirm(mission.mission_id)
    mid = mission.mission_id
    frozen = list(service.get_bundle(mid).scope.allowed_networks)
    try:
        service.confirm_locator(mid, ConfirmLocatorCmd(locator="10.10.11.45", actor="ai"))
        raise AssertionError("expected LocatorRejected")
    except LocatorRejected as exc:
        assert "AI" in str(exc)
    try:
        service.confirm_locator(mid, ConfirmLocatorCmd(locator="8.8.8.8", actor="operator"))
        raise AssertionError("expected out of scope")
    except LocatorRejected:
        pass
    assert service.get_bundle(mid).scope.allowed_networks == frozen
    assert service.get_bundle(mid).target.current_locator == "10.10.11.23"


def test_mission_resume_after_network_change(tmp_path) -> None:
    db = SqliteStore(tmp_path / "cyberx.db", data_dir=tmp_path)
    service = MissionService(db)
    observer = SwapObserver(_lab("10.10.14.10"))
    xml = (FIXTURES / "nmap" / "host_22_80.xml").read_bytes()
    adapter = NmapAdapter(
        runner=FixtureProcessRunner(xml), available=True, events=InMemoryEventSink()
    )
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    engine = MissionEngine(
        service,
        boundary=ExecutionBoundary(executor=executor),
        store=db,
        network=NetworkResolver(observer=observer, lookup=lambda _h: []),
    )
    mission = service.create(create_cmd(name="resume-ctf", allowed_networks=["10.10.11.0/24"]))
    mid = mission.mission_id
    service.confirm(mid)
    service.start(mid)
    engine.run_one_cycle(mid)
    observer.snapshot = scenario_unreachable()
    engine.network_context(mid)
    service.pause(mid)
    db.close()

    reopened = SqliteStore(tmp_path / "cyberx.db", data_dir=tmp_path)
    service2 = MissionService(reopened)
    observer.snapshot = _lab("10.10.14.17")
    engine2 = MissionEngine(
        service2,
        store=reopened,
        network=NetworkResolver(observer=observer, lookup=lambda _h: []),
    )
    loaded = service2.get_bundle(mid)
    assert loaded.target.current_locator == "10.10.11.23"
    assert loaded.scope.frozen is True
    world = engine2.world(mid)
    assert world.snapshot().hosts
    # Must not silently continue on a new host.
    assert loaded.target.current_locator != "10.10.11.45"
    service2.resume(mid)
    service2.confirm_locator(mid, ConfirmLocatorCmd(locator="10.10.11.45", actor="operator"))
    engine2.sync_locator_hosts(mid)
    assert service2.get_bundle(mid).target.current_locator == "10.10.11.45"
    assert any(h.ipv4 == "10.10.11.23" for h in engine2.world(mid).snapshot().hosts)
    reopened.close()
