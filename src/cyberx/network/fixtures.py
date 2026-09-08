"""Deterministic ObservedNetwork snapshots. No real VPN required."""

from __future__ import annotations

from cyberx.domain.enums import ReachabilityStatus
from cyberx.network.observer import (
    ARPHRD_ETHER,
    ARPHRD_NONE,
    ObservedAddress,
    ObservedInterface,
    ObservedNetwork,
    ObservedRoute,
)

TARGET = "10.10.11.23"


def _eth0() -> ObservedInterface:
    return ObservedInterface(
        name="eth0",
        addresses=(ObservedAddress(ip="172.16.0.5", prefix=24, family=4),),
        operstate="up",
        arphrd=ARPHRD_ETHER,
        flags=0x1003,
    )


def _tun0(*, ip: str = "10.10.14.5") -> ObservedInterface:
    return ObservedInterface(
        name="tun0",
        addresses=(ObservedAddress(ip=ip, prefix=24, family=4),),
        operstate="up",
        arphrd=ARPHRD_NONE,
        flags=0x1081,
    )


def _tun1() -> ObservedInterface:
    return ObservedInterface(
        name="tun1",
        addresses=(ObservedAddress(ip="10.10.20.5", prefix=24, family=4),),
        operstate="up",
        arphrd=ARPHRD_NONE,
        flags=0x1081,
    )


def _wg0() -> ObservedInterface:
    return ObservedInterface(
        name="wg0",
        addresses=(ObservedAddress(ip="10.10.30.2", prefix=24, family=4),),
        operstate="up",
        arphrd=ARPHRD_NONE,
        flags=0x1081,
    )


def _default_eth() -> ObservedRoute:
    return ObservedRoute(
        destination="0.0.0.0/0",
        gateway="172.16.0.1",
        interface="eth0",
        metric=100,
        prefix_len=0,
        default=True,
    )


def _lan_eth() -> ObservedRoute:
    return ObservedRoute(
        destination="172.16.0.0/24",
        gateway=None,
        interface="eth0",
        metric=0,
        prefix_len=24,
    )


def _htb_via_tun0() -> ObservedRoute:
    return ObservedRoute(
        destination="10.10.11.0/24",
        gateway=None,
        interface="tun0",
        metric=50,
        prefix_len=24,
    )


def scenario_no_tunnel() -> ObservedNetwork:
    """1. No tunnel — target via eth0 default route."""
    return ObservedNetwork(
        interfaces=(_eth0(),),
        routes=(_lan_eth(), _default_eth()),
    )


def scenario_tun0_present() -> ObservedNetwork:
    """2. tun0 present but unused — target still via eth0."""
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0()),
        routes=(_lan_eth(), _default_eth()),
    )


def scenario_multiple_tunnels() -> ObservedNetwork:
    """3. Multiple tunnel interfaces — selected by the matching route."""
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0(), _tun1(), _wg0()),
        routes=(_lan_eth(), _htb_via_tun0(), _default_eth()),
    )


def scenario_wireguard() -> ObservedNetwork:
    """4. WireGuard-like interface carries the target route."""
    return ObservedNetwork(
        interfaces=(_eth0(), _wg0()),
        routes=(
            _lan_eth(),
            ObservedRoute(
                destination="10.10.11.0/24",
                gateway=None,
                interface="wg0",
                metric=20,
                prefix_len=24,
            ),
            _default_eth(),
        ),
    )


def scenario_route_via_tun0() -> ObservedNetwork:
    """5. Target route through tun0 (HTB-style lab, unverified)."""
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0()),
        routes=(_lan_eth(), _htb_via_tun0(), _default_eth()),
    )


def scenario_route_via_eth0() -> ObservedNetwork:
    """6. Target route through a normal interface."""
    return ObservedNetwork(
        interfaces=(_eth0(),),
        routes=(
            ObservedRoute(
                destination="10.10.11.0/24",
                gateway="172.16.0.1",
                interface="eth0",
                metric=10,
                prefix_len=24,
            ),
            _lan_eth(),
            _default_eth(),
        ),
    )


def scenario_no_route() -> ObservedNetwork:
    """7. No matching route and no default."""
    return ObservedNetwork(
        interfaces=(_eth0(),),
        routes=(_lan_eth(),),
    )


def scenario_unreachable() -> ObservedNetwork:
    """8. Route exists; injected UNREACHABLE (host down, not no-route)."""
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0()),
        routes=(_lan_eth(), _htb_via_tun0(), _default_eth()),
        reachability_override=ReachabilityStatus.UNREACHABLE,
    )


def scenario_timeout() -> ObservedNetwork:
    """9. Transient TIMEOUT. Must not become a World Model fact."""
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0()),
        routes=(_lan_eth(), _htb_via_tun0(), _default_eth()),
        reachability_override=ReachabilityStatus.TIMEOUT,
    )


def scenario_unavailable() -> ObservedNetwork:
    """10. Route information unavailable."""
    return ObservedNetwork(
        platform="linux",
        available=False,
        diagnostic="route information unavailable",
    )


def scenario_oos_route() -> ObservedNetwork:
    """11. Extra out-of-scope route recorded for diagnostics only."""
    extra = ObservedRoute(
        destination="10.10.10.0/24",
        gateway=None,
        interface="tun0",
        metric=60,
        prefix_len=24,
    )
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0()),
        routes=(_lan_eth(), extra, _htb_via_tun0(), _default_eth()),
    )


def scenario_multiple_candidates() -> ObservedNetwork:
    """12. Two candidate interfaces — longest prefix, then lowest metric."""
    via_eth = ObservedRoute(
        destination="10.10.0.0/16",
        gateway="172.16.0.1",
        interface="eth0",
        metric=5,
        prefix_len=16,
    )
    via_tun = ObservedRoute(
        destination="10.10.11.0/24",
        gateway=None,
        interface="tun0",
        metric=50,
        prefix_len=24,
    )
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0()),
        routes=(_lan_eth(), via_eth, via_tun, _default_eth()),
    )


def scenario_iface_down() -> ObservedNetwork:
    """Route exists but tun0 is down → BLOCKED."""
    down = ObservedInterface(
        name="tun0",
        addresses=(ObservedAddress(ip="10.10.14.5", prefix=24, family=4),),
        operstate="down",
        arphrd=ARPHRD_NONE,
        flags=0,
    )
    return ObservedNetwork(
        interfaces=(_eth0(), down),
        routes=(_lan_eth(), _htb_via_tun0()),
    )


def scenario_tun0_source_changed(*, ip: str = "10.10.14.17") -> ObservedNetwork:
    """Same tun0 route, different source address (VPN reassignment)."""
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0(ip=ip)),
        routes=(_lan_eth(), _htb_via_tun0(), _default_eth()),
    )


def scenario_tun0_gone() -> ObservedNetwork:
    """tun0 disappeared; only eth0 remains."""
    return ObservedNetwork(
        interfaces=(_eth0(),),
        routes=(_lan_eth(), _default_eth()),
    )


def scenario_tun0_reappear(*, ip: str = "10.10.14.17") -> ObservedNetwork:
    """tun0 reappears after disappearing, possibly with a new source IP."""
    return ObservedNetwork(
        interfaces=(_eth0(), _tun0(ip=ip)),
        routes=(_lan_eth(), _htb_via_tun0(), _default_eth()),
    )


def scenario_route_changed() -> ObservedNetwork:
    """Target route moved from tun0 to eth0."""
    return scenario_route_via_eth0()


SCENARIOS: dict[str, ObservedNetwork] = {
    "no_tunnel": scenario_no_tunnel(),
    "tun0_present": scenario_tun0_present(),
    "multiple_tunnels": scenario_multiple_tunnels(),
    "wireguard": scenario_wireguard(),
    "route_via_tun0": scenario_route_via_tun0(),
    "route_via_eth0": scenario_route_via_eth0(),
    "no_route": scenario_no_route(),
    "unreachable": scenario_unreachable(),
    "timeout": scenario_timeout(),
    "unavailable": scenario_unavailable(),
    "oos_route": scenario_oos_route(),
    "multiple_candidates": scenario_multiple_candidates(),
    "tun0_source_changed": scenario_tun0_source_changed(),
    "tun0_gone": scenario_tun0_gone(),
    "tun0_reappear": scenario_tun0_reappear(),
}
