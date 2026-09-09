"""M16 network awareness: fixtures, routing, planner gating, no VPN client."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberx.brain.context import BrainContextBuilder
from cyberx.brain.planner import Planner
from cyberx.domain.enums import GAP_KINDS, ReachabilityStatus
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import PREFIX_HOST, PREFIX_MISSION, new_id
from cyberx.domain.models.assets import Host
from cyberx.domain.models.mission import Mission, Scope
from cyberx.domain.time import utcnow
from cyberx.network.fixtures import (
    SCENARIOS,
    TARGET,
    scenario_iface_down,
    scenario_no_route,
    scenario_oos_route,
    scenario_route_via_tun0,
)
from cyberx.network.observer import (
    FixtureNetworkObserver,
    LinuxProcObserver,
    ObservedAddress,
)
from cyberx.network.resolver import NetworkResolver
from cyberx.recon.nmap.argv import bind_args
from cyberx.world.model import InMemoryWorldModel


def _scope(mid: str, extra_nets: list[str] | None = None) -> Scope:
    return Scope(
        scope_id="scp_01AAAAAAAAAAAAAAAAAAAAAAAA",
        mission_id=mid,
        allowed_targets=[TARGET],
        allowed_networks=list(extra_nets or []),
        allowed_ports=[],
        allowed_protocols=["tcp", "http", "https", "dns"],
        frozen=True,
        created_at=utcnow(),
    )


def _resolve(name: str, *, extra_nets: list[str] | None = None) -> object:
    mid = new_id(PREFIX_MISSION)
    observer = FixtureNetworkObserver(SCENARIOS[name])
    return NetworkResolver(observer=observer, lookup=lambda _h: []).resolve(
        TARGET, scope=_scope(mid, extra_nets)
    )


def test_twelve_fixture_scenarios() -> None:
    no_tun = _resolve("no_tunnel")
    assert no_tun.reachability is ReachabilityStatus.REACHABLE
    assert no_tun.selected_interface == "eth0"
    assert no_tun.likely_tunnel is False
    assert "HTB" not in no_tun.diagnostic
    assert "HTB VPN" not in no_tun.compact().values()

    present = _resolve("tun0_present")
    assert present.selected_interface == "eth0"
    assert present.tunnel_present is True
    assert present.likely_tunnel is False
    assert present.compact()["tunnel"] == "present_unused"

    multi = _resolve("multiple_tunnels")
    assert multi.selected_interface == "tun0"
    assert multi.likely_tunnel is True
    assert multi.source_address == "10.10.14.5"

    wg = _resolve("wireguard")
    assert wg.selected_interface == "wg0"
    assert wg.tunnel_hint == "wireguard"
    assert "HTB VPN" not in wg.diagnostic

    via_tun = _resolve("route_via_tun0")
    assert via_tun.selected_interface == "tun0"
    assert via_tun.selected_route == "10.10.11.0/24"
    assert via_tun.source_address == "10.10.14.5"
    assert via_tun.reachability is ReachabilityStatus.REACHABLE
    assert via_tun.compact()["tunnel"] == "detected_unverified"

    via_eth = _resolve("route_via_eth0")
    assert via_eth.selected_interface == "eth0"
    assert via_eth.likely_tunnel is False

    missing = _resolve("no_route")
    assert missing.reachability is ReachabilityStatus.ROUTE_MISSING
    assert "host down" in missing.diagnostic.lower() or "no route" in missing.diagnostic.lower()

    down = _resolve("unreachable")
    assert down.reachability is ReachabilityStatus.UNREACHABLE
    assert down.selected_interface == "tun0"

    timeout = _resolve("timeout")
    assert timeout.reachability is ReachabilityStatus.TIMEOUT
    assert "transient" in timeout.diagnostic.lower()

    unavailable = _resolve("unavailable")
    assert unavailable.reachability is ReachabilityStatus.UNKNOWN
    assert unavailable.available is False

    oos = _resolve("oos_route")
    assert "10.10.10.0/24" in oos.oos_routes
    assert oos.selected_interface == "tun0"

    candidates = _resolve("multiple_candidates")
    assert candidates.selected_interface == "tun0"
    assert candidates.selected_route == "10.10.11.0/24"


def test_iface_down_is_blocked_not_missing() -> None:
    resolver = NetworkResolver(
        observer=FixtureNetworkObserver(scenario_iface_down()),
        lookup=lambda _h: [],
    )
    ctx = resolver.resolve(TARGET)
    assert ctx.reachability is ReachabilityStatus.BLOCKED
    assert ctx.reachability is not ReachabilityStatus.ROUTE_MISSING


def test_hostname_lookup_failure_is_unknown() -> None:
    resolver = NetworkResolver(
        observer=FixtureNetworkObserver(scenario_route_via_tun0()),
        lookup=lambda _h: [],
    )
    ctx = resolver.resolve("box.htb")
    assert ctx.reachability is ReachabilityStatus.UNKNOWN
    assert ctx.reachability is not ReachabilityStatus.UNREACHABLE


def test_oos_route_does_not_imply_scope_mutation() -> None:
    mid = new_id(PREFIX_MISSION)
    scope = _scope(mid)
    frozen_targets = list(scope.allowed_targets)
    frozen_nets = list(scope.allowed_networks)
    resolver = NetworkResolver(
        observer=FixtureNetworkObserver(scenario_oos_route()),
        lookup=lambda _h: [],
    )
    ctx = resolver.resolve(TARGET, scope=scope)
    assert ctx.oos_routes
    assert scope.allowed_targets == frozen_targets
    assert scope.allowed_networks == frozen_nets
    assert "10.10.10.0/24" not in scope.allowed_networks


def test_route_missing_suppresses_ip_actions() -> None:
    from cyberx.domain.enums import AddressType, AssetKind, EpistemicStatus
    from cyberx.domain.identity import host_key_ipv4

    mid = new_id(PREFIX_MISSION)
    now = utcnow()
    mission = Mission(
        mission_id=mid,
        name="box",
        intent="enumerate surface",
        mode=__import__("cyberx.domain.enums", fromlist=["MissionMode"]).MissionMode.CTF,
        status=__import__("cyberx.domain.enums", fromlist=["MissionStatus"]).MissionStatus.RUNNING,
        target_id="tgt_01AAAAAAAAAAAAAAAAAAAAAAAA",
        scope_id="scp_01AAAAAAAAAAAAAAAAAAAAAAAA",
        created_at=now,
        started_at=now,
    )
    world = InMemoryWorldModel(mid)
    host = Host(
        asset_id=new_id(PREFIX_HOST),
        mission_id=mid,
        kind=AssetKind.HOST,
        canonical_key=host_key_ipv4(TARGET),
        display_name=TARGET,
        first_seen_at=now,
        last_seen_at=now,
        epistemic_status=EpistemicStatus.KNOWN,
        address_type=AddressType.IPV4,
        ipv4=TARGET,
    )
    world.seed_assets([host])
    net = NetworkResolver(
        observer=FixtureNetworkObserver(scenario_no_route()),
        lookup=lambda _h: [],
    ).resolve(TARGET, scope=_scope(mid))
    ctx = BrainContextBuilder().build(
        world.snapshot(), mission, scope=_scope(mid), network_context=net
    )
    assert ctx.network.get("reachability") == "ROUTE_MISSING"
    assert any(g.get("kind") == "target.route_missing" for g in ctx.gaps)
    assert "target.route_missing" not in GAP_KINDS
    types = {c.action_type for c in Planner().propose(ctx)}
    assert "port_scan" not in types
    assert "http_probe" not in types


def test_timeout_does_not_suppress_and_is_not_a_gap_kind() -> None:
    from cyberx.domain.enums import (
        AddressType,
        AssetKind,
        EpistemicStatus,
        MissionMode,
        MissionStatus,
    )
    from cyberx.domain.identity import host_key_ipv4

    mid = new_id(PREFIX_MISSION)
    now = utcnow()
    mission = Mission(
        mission_id=mid,
        name="box",
        intent="enumerate surface",
        mode=MissionMode.CTF,
        status=MissionStatus.RUNNING,
        target_id="tgt_01AAAAAAAAAAAAAAAAAAAAAAAA",
        scope_id="scp_01AAAAAAAAAAAAAAAAAAAAAAAA",
        created_at=now,
        started_at=now,
    )
    world = InMemoryWorldModel(mid)
    host = Host(
        asset_id=new_id(PREFIX_HOST),
        mission_id=mid,
        kind=AssetKind.HOST,
        canonical_key=host_key_ipv4(TARGET),
        display_name=TARGET,
        first_seen_at=now,
        last_seen_at=now,
        epistemic_status=EpistemicStatus.KNOWN,
        address_type=AddressType.IPV4,
        ipv4=TARGET,
    )
    world.seed_assets([host])
    net = NetworkResolver(
        observer=FixtureNetworkObserver(SCENARIOS["timeout"]),
        lookup=lambda _h: [],
    ).resolve(TARGET)
    ctx = BrainContextBuilder().build(
        world.snapshot(), mission, scope=_scope(mid), network_context=net
    )
    assert ctx.network.get("reachability") == "TIMEOUT"
    assert all(g.get("kind") != "target.route_missing" for g in ctx.gaps)
    types = {c.action_type for c in Planner().propose(ctx)}
    assert "port_scan" in types


def test_linux_proc_observer_reads_injected_tree(tmp_path: Path) -> None:
    sys_net = tmp_path / "sys" / "class" / "net"
    (sys_net / "tun0").mkdir(parents=True)
    (sys_net / "eth0").mkdir(parents=True)
    (sys_net / "tun0" / "type").write_text("65534\n")
    (sys_net / "tun0" / "operstate").write_text("up\n")
    (sys_net / "tun0" / "flags").write_text("0x1081\n")
    (sys_net / "eth0" / "type").write_text("1\n")
    (sys_net / "eth0" / "operstate").write_text("up\n")
    (sys_net / "eth0" / "flags").write_text("0x1003\n")
    proc = tmp_path / "proc" / "net"
    proc.mkdir(parents=True)
    proc.joinpath("route").write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "tun0\t000B0A0A\t00000000\t0001\t0\t0\t50\t00FFFFFF\t0\t0\t0\n"
        "eth0\t00000000\t010010AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    )
    proc.joinpath("if_inet6").write_text("")

    def lookup(name: str) -> list[ObservedAddress]:
        if name == "tun0":
            return [ObservedAddress(ip="10.10.14.5", prefix=24, family=4)]
        if name == "eth0":
            return [ObservedAddress(ip="172.16.0.5", prefix=24, family=4)]
        return []

    observer = LinuxProcObserver(root=tmp_path, address_lookup=lookup)
    snap = observer.inspect()
    assert snap.available is True
    names = {i.name for i in snap.interfaces}
    assert "tun0" in names
    dests = {r.destination for r in snap.routes}
    assert "10.10.11.0/24" in dests
    ctx = NetworkResolver(observer=observer, lookup=lambda _h: []).resolve(TARGET)
    assert ctx.selected_interface == "tun0"
    assert ctx.source_address == "10.10.14.5"
    assert ctx.likely_tunnel is True


def test_malformed_route_table_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "proc" / "net").mkdir(parents=True)
    (tmp_path / "sys" / "class" / "net").mkdir(parents=True)
    (tmp_path / "proc" / "net" / "route").write_text("not a route table\n????\n")
    observer = LinuxProcObserver(root=tmp_path, address_lookup=lambda _n: [])
    snap = observer.inspect()
    assert snap.platform == "linux"


def test_unsupported_platform_is_unknown() -> None:
    observer = LinuxProcObserver(platform="darwin", address_lookup=lambda _n: [])
    snap = observer.inspect()
    assert snap.available is False
    ctx = NetworkResolver(observer=observer, lookup=lambda _h: []).resolve(TARGET)
    assert ctx.reachability is ReachabilityStatus.UNKNOWN


def test_nmap_bind_args_are_optional_and_validated() -> None:
    assert bind_args(None, None) == []
    assert bind_args("tun0", "10.10.14.5") == ["-e", "tun0"]
    assert "-S" not in bind_args("tun0", "10.10.14.5")
    assert bind_args("tun0", "fe80::1", family="ipv4") == ["-e", "tun0"]
    with pytest.raises(DomainValidationError):
        bind_args("tun0;id", None)
    with pytest.raises(DomainValidationError):
        bind_args("-e", None)
    with pytest.raises(DomainValidationError):
        bind_args("tun0", "not-an-ip")


def test_network_package_is_not_a_vpn_client() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "cyberx" / "network"
    blob = "\n".join(p.read_text(encoding="utf-8") for p in root.rglob("*.py"))
    for banned in (
        "shell=True",
        "os.system",
        "openvpn",
        "wg-quick",
        "iptables",
        "ip route add",
        "password",
        "credential",
        "HTB VPN",
    ):
        assert banned not in blob
