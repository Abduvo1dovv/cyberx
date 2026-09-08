"""M18 target identity, locator history, network digest, operator confirmation."""

from __future__ import annotations

import pytest
from tests.conftest import create_cmd

from cyberx.actions.coverage import coverage_key
from cyberx.brain.context import BrainContextBuilder
from cyberx.brain.planner import Planner
from cyberx.domain.enums import (
    V1_ACTION_TYPES,
    LocatorStatus,
    MissionMode,
    ReachabilityStatus,
)
from cyberx.domain.errors import LocatorRejected
from cyberx.domain.identity import target_identity_key
from cyberx.domain.models.actions import ActionTarget
from cyberx.domain.time import utcnow
from cyberx.graph.projector import GraphProjector
from cyberx.mission.commands import ConfirmLocatorCmd
from cyberx.mission.locator import locator_in_scope
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.network.fixtures import (
    scenario_no_route,
    scenario_route_changed,
    scenario_route_via_tun0,
    scenario_timeout,
    scenario_tun0_gone,
    scenario_tun0_reappear,
    scenario_tun0_source_changed,
)
from cyberx.network.observer import FixtureNetworkObserver
from cyberx.network.resolver import NetworkResolver
from cyberx.world.model import InMemoryWorldModel


def _service() -> MissionService:
    return MissionService(InMemoryMissionStore())


def _armed(service: MissionService, **overrides):
    mission = service.create(create_cmd(**overrides))
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    return service.get_bundle(mission.mission_id)


def test_target_ip_initial_identity() -> None:
    bundle = _armed(_service())
    target = bundle.target
    assert target.kind.value == "ipv4"
    assert target.canonical_identity == target_identity_key("ipv4", "10.10.11.23")
    assert target.current_locator == "10.10.11.23"
    assert target.locator_history[0].status is LocatorStatus.CURRENT
    assert target.locator_history[0].source == "operator"


def test_hostname_identity() -> None:
    bundle = _armed(_service(), raw_target="example.htb")
    target = bundle.target
    assert target.canonical_identity == "identity:name:example.htb"
    assert target.current_locator == "example.htb"
    assert "ipv4" not in target.canonical_identity


def test_observed_address_history_and_change() -> None:
    service = _service()
    bundle = _armed(service, allowed_networks=["10.10.11.0/24"])
    mid = bundle.mission.mission_id
    first = service.observe_locator(mid, "10.10.11.23", source="recon")
    second = service.observe_locator(mid, "10.10.11.45", source="dns")
    locators = [item.locator for item in second.locator_history]
    assert "10.10.11.23" in locators
    assert "10.10.11.45" in locators
    assert second.current_locator == "10.10.11.23"
    observed = [item for item in second.locator_history if item.locator == "10.10.11.45"][0]
    assert observed.status is LocatorStatus.OBSERVED
    assert first.canonical_identity == second.canonical_identity


def test_same_hostname_different_ip() -> None:
    service = _service()
    bundle = _armed(service, raw_target="example.htb", allowed_networks=["10.10.11.0/24"])
    mid = bundle.mission.mission_id
    service.observe_locator(mid, "10.10.11.23", source="dns")
    service.observe_locator(mid, "10.10.11.45", source="dns")
    target = service.get_bundle(mid).target
    assert target.canonical_identity == "identity:name:example.htb"
    assert target.current_locator == "example.htb"
    assert "10.10.11.23" in target.resolved_ipv4
    assert "10.10.11.45" in target.resolved_ipv4
    assert target.current_locator != "10.10.11.45"


def test_multiple_observed_addresses() -> None:
    service = _service()
    bundle = _armed(service, allowed_networks=["10.10.11.0/24"])
    mid = bundle.mission.mission_id
    service.observe_locator(mid, "10.10.11.23")
    service.observe_locator(mid, "10.10.11.45")
    service.observe_locator(mid, "10.10.11.60")
    history = service.get_bundle(mid).target.locator_history
    assert len({item.locator for item in history}) == 3


def test_unreachable_old_address_is_not_identity_invalid() -> None:
    service = _service()
    bundle = _armed(service)
    mid = bundle.mission.mission_id
    updated = service.mark_locator_unreachable(mid, "10.10.11.23")
    current = [item for item in updated.locator_history if item.locator == "10.10.11.23"][0]
    assert current.status is LocatorStatus.UNREACHABLE
    assert updated.canonical_identity == bundle.target.canonical_identity
    assert updated.current_locator == "10.10.11.23"


def test_new_address_discovery_does_not_retarget() -> None:
    service = _service()
    bundle = _armed(service, allowed_networks=["10.10.11.0/24"])
    mid = bundle.mission.mission_id
    updated = service.observe_locator(mid, "10.10.11.45", source="dns")
    assert updated.current_locator == "10.10.11.23"
    assert any(item.locator == "10.10.11.45" for item in updated.locator_history)


def test_operator_confirmed_locator_change() -> None:
    service = _service()
    bundle = _armed(service, allowed_networks=["10.10.11.0/24"])
    mid = bundle.mission.mission_id
    service.observe_locator(mid, "10.10.11.45", source="dns")
    updated = service.confirm_locator(
        mid, ConfirmLocatorCmd(locator="10.10.11.45", actor="operator")
    )
    assert updated.current_locator == "10.10.11.45"
    assert updated.previous_locator() == "10.10.11.23"
    old = [item for item in updated.locator_history if item.locator == "10.10.11.23"][0]
    assert old.status is LocatorStatus.HISTORICAL
    new = [item for item in updated.locator_history if item.locator == "10.10.11.45"][0]
    assert new.status is LocatorStatus.CURRENT
    events = [e.message for e in service.get_bundle(mid).timeline]
    assert any("confirmed locator" in msg for msg in events)
    assert bundle.scope.allowed_targets == service.get_bundle(mid).scope.allowed_targets


def test_out_of_scope_locator_change_denied() -> None:
    service = _service()
    bundle = _armed(service)
    mid = bundle.mission.mission_id
    with pytest.raises(LocatorRejected, match="scope"):
        service.confirm_locator(mid, ConfirmLocatorCmd(locator="10.10.12.9", actor="operator"))
    target = service.get_bundle(mid).target
    assert target.current_locator == "10.10.11.23"
    assert "10.10.12.9" not in service.get_bundle(mid).scope.allowed_targets
    assert not locator_in_scope("10.10.12.9", bundle.scope, mode=MissionMode.CTF)


def test_coverage_key_changes_with_locator_and_identical_preserves() -> None:
    params = {"address": "10.10.11.23", "ports": "top1000", "protocol": "tcp"}
    a = coverage_key("port_scan", ActionTarget(canonical_locator="10.10.11.23"), params)
    b = coverage_key(
        "port_scan",
        ActionTarget(canonical_locator="10.10.11.45"),
        {"address": "10.10.11.45", "ports": "top1000", "protocol": "tcp"},
    )
    c = coverage_key("port_scan", ActionTarget(canonical_locator="10.10.11.23"), params)
    assert a != b
    assert a == c


def test_network_digest_changes_for_source_route_and_iface() -> None:
    resolver = NetworkResolver(observer=FixtureNetworkObserver(scenario_route_via_tun0()))
    a = resolver.resolve("10.10.11.23")
    b = NetworkResolver(observer=FixtureNetworkObserver(scenario_tun0_source_changed())).resolve(
        "10.10.11.23"
    )
    c = NetworkResolver(observer=FixtureNetworkObserver(scenario_route_changed())).resolve(
        "10.10.11.23"
    )
    d = NetworkResolver(observer=FixtureNetworkObserver(scenario_tun0_gone())).resolve(
        "10.10.11.23"
    )
    e = NetworkResolver(observer=FixtureNetworkObserver(scenario_tun0_reappear())).resolve(
        "10.10.11.23"
    )
    assert a.source_address == "10.10.14.5"
    assert b.source_address == "10.10.14.17"
    assert a.digest() != b.digest()
    assert a.selected_interface == "tun0"
    assert c.selected_interface == "eth0"
    assert a.digest() != c.digest()
    assert d.selected_interface != "tun0"
    assert a.digest() != d.digest()
    assert e.selected_interface == "tun0"
    assert e.source_address == "10.10.14.17"
    assert d.digest() != e.digest()
    assert b.digest() == e.digest()


def test_timeout_is_not_persisted_as_permanent_fact() -> None:
    service = _service()
    bundle = _armed(service)
    mid = bundle.mission.mission_id
    world = InMemoryWorldModel(mid)
    world.seed_assets(bundle.seed_assets)
    net = NetworkResolver(observer=FixtureNetworkObserver(scenario_timeout())).resolve(
        "10.10.11.23"
    )
    assert net.reachability is ReachabilityStatus.TIMEOUT
    ctx = BrainContextBuilder().build(
        world.snapshot(),
        bundle.mission,
        scope=bundle.scope,
        network_context=net,
        target=bundle.target,
    )
    assert ctx.network.get("reachability") == "TIMEOUT"
    assert all(g.get("kind") != "target.unreachable" for g in ctx.gaps)
    predicates = {c.predicate for c in world.snapshot().claims}
    assert "host.alive" not in predicates or all(
        c.object != "TIMEOUT" for c in world.snapshot().claims
    )
    target = service.get_bundle(mid).target
    assert all(item.status is not LocatorStatus.UNREACHABLE for item in target.locator_history)


def test_brain_context_current_vs_historical_and_avoids_obsolete() -> None:
    service = _service()
    bundle = _armed(service, allowed_networks=["10.10.11.0/24"])
    mid = bundle.mission.mission_id
    service.confirm_locator(mid, ConfirmLocatorCmd(locator="10.10.11.45", actor="operator"))
    bundle = service.get_bundle(mid)
    world = InMemoryWorldModel(mid)
    world.seed_assets(bundle.seed_assets)
    net = NetworkResolver(observer=FixtureNetworkObserver(scenario_no_route())).resolve(
        "10.10.11.45"
    )
    # Force a reachable context on the new locator via tun0-style fixture bound to 10.10.11.0/24
    net = NetworkResolver(observer=FixtureNetworkObserver(scenario_route_via_tun0())).resolve(
        "10.10.11.45"
    )
    ctx = BrainContextBuilder().build(
        world.snapshot(),
        bundle.mission,
        scope=bundle.scope,
        network_context=net,
        target=bundle.target,
    )
    assert ctx.target_identity.get("current") == "10.10.11.45"
    assert ctx.target_identity.get("previous") == "10.10.11.23"
    assert "10.10.11.23" in (ctx.target_identity.get("historical") or "")
    types = {c.action_type for c in Planner().propose(ctx)}
    locators = {c.target.canonical_locator for c in Planner().propose(ctx)}
    assert "port_scan" in types
    assert "10.10.11.45" in locators
    assert "10.10.11.23" not in locators


def test_ai_cannot_change_target_locator() -> None:
    service = _service()
    bundle = _armed(service, allowed_networks=["10.10.11.0/24"])
    with pytest.raises(LocatorRejected, match="AI"):
        service.confirm_locator(
            bundle.mission.mission_id,
            ConfirmLocatorCmd(locator="10.10.11.45", actor="ai"),
        )
    assert service.get_bundle(bundle.mission.mission_id).target.current_locator == "10.10.11.23"
    assert "retarget" not in V1_ACTION_TYPES
    assert "confirm_locator" not in V1_ACTION_TYPES


def test_ai_cannot_expand_scope() -> None:
    service = _service()
    bundle = _armed(service)
    mid = bundle.mission.mission_id
    frozen = list(bundle.scope.allowed_targets)
    with pytest.raises(LocatorRejected):
        service.confirm_locator(mid, ConfirmLocatorCmd(locator="8.8.8.8", actor="operator"))
    with pytest.raises(LocatorRejected):
        service.confirm_locator(mid, ConfirmLocatorCmd(locator="8.8.8.8", actor="ai"))
    after = service.get_bundle(mid).scope
    assert after.allowed_targets == frozen
    assert after.frozen is True


def test_graph_keeps_historical_hosts_queryable() -> None:
    from cyberx.domain.enums import AddressType, AssetKind, EpistemicStatus
    from cyberx.domain.identity import host_key_ipv4
    from cyberx.domain.ids import PREFIX_HOST, PREFIX_MISSION, new_id
    from cyberx.domain.models.assets import Host

    mid = new_id(PREFIX_MISSION)
    now = utcnow()
    world = InMemoryWorldModel(mid)
    old = Host(
        asset_id=new_id(PREFIX_HOST),
        mission_id=mid,
        kind=AssetKind.HOST,
        canonical_key=host_key_ipv4("10.10.11.23"),
        display_name="10.10.11.23",
        first_seen_at=now,
        last_seen_at=now,
        epistemic_status=EpistemicStatus.KNOWN,
        address_type=AddressType.IPV4,
        ipv4="10.10.11.23",
        labels=["identity:ipv4:10.10.11.23", "historical"],
    )
    new = Host(
        asset_id=new_id(PREFIX_HOST),
        mission_id=mid,
        kind=AssetKind.HOST,
        canonical_key=host_key_ipv4("10.10.11.45"),
        display_name="10.10.11.45",
        first_seen_at=now,
        last_seen_at=now,
        epistemic_status=EpistemicStatus.KNOWN,
        address_type=AddressType.IPV4,
        ipv4="10.10.11.45",
        labels=["identity:ipv4:10.10.11.23", "current_locator"],
    )
    world.seed_assets([old, new])
    graph = GraphProjector().project(world.snapshot())
    keys = {n.semantic_key for n in graph.nodes}
    assert host_key_ipv4("10.10.11.23") in keys
    assert host_key_ipv4("10.10.11.45") in keys
    related = [e for e in graph.edges if e.kind.value == "RELATED_TO"]
    assert related
