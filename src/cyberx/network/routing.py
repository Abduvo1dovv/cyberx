"""Deterministic route selection and tunnel heuristics. No I/O."""

from __future__ import annotations

import ipaddress

from cyberx.domain.enums import ReachabilityStatus
from cyberx.network.observer import (
    ARPHRD_NONE,
    TUNNEL_ARPHRD,
    ObservedInterface,
    ObservedNetwork,
    ObservedRoute,
)

_TUNNEL_PREFIXES = ("tun", "tap", "wg", "utun", "ppp")
_NOT_TUNNEL = {"lo"}


def tunnel_hint(name: str, arphrd: int | None) -> tuple[bool, str]:
    """Return (likely_tunnel, kind_hint). Never names a VPN provider."""
    token = (name or "").lower().split(":")[0]
    if token in _NOT_TUNNEL or token.startswith("lo") or token.startswith("dummy"):
        return False, ""
    if token.startswith("wg"):
        return True, "wireguard"
    if token.startswith("tun"):
        return True, "tun"
    if token.startswith("tap"):
        return True, "tap"
    if token.startswith("utun"):
        return True, "utun"
    if token.startswith("ppp"):
        return True, "tunnel"
    if arphrd in TUNNEL_ARPHRD and arphrd != ARPHRD_NONE:
        return True, "tunnel"
    if arphrd == ARPHRD_NONE and not token.startswith(("eth", "en", "wlan", "wl", "br")):
        return True, "tunnel"
    return False, ""


def select_route(
    target_ip: str, routes: tuple[ObservedRoute, ...] | list[ObservedRoute]
) -> ObservedRoute | None:
    """Longest prefix, then lowest metric. Default route is the fallback."""
    try:
        addr = ipaddress.ip_address(target_ip)
    except ValueError:
        return None
    matches: list[ObservedRoute] = []
    default: ObservedRoute | None = None
    for route in routes:
        try:
            net = ipaddress.ip_network(route.destination, strict=False)
        except ValueError:
            continue
        if net.version != addr.version:
            continue
        if route.default or route.prefix_len == 0:
            if default is None or route.metric < default.metric:
                default = route
            continue
        if addr in net:
            matches.append(route)
    if matches:
        matches.sort(key=lambda r: (-r.prefix_len, r.metric, r.interface))
        return matches[0]
    return default


def source_address(iface: ObservedInterface | None, target_ip: str | None) -> str | None:
    if iface is None:
        return None
    family = 4
    if target_ip:
        try:
            family = ipaddress.ip_address(target_ip).version
        except ValueError:
            family = 4
    for addr in iface.addresses:
        if addr.family == family:
            return addr.ip
    if iface.addresses:
        return iface.addresses[0].ip
    return None


def iface_by_name(snapshot: ObservedNetwork, name: str | None) -> ObservedInterface | None:
    if not name:
        return None
    for iface in snapshot.interfaces:
        if iface.name == name:
            return iface
    return None


def reachability_for(
    snapshot: ObservedNetwork,
    route: ObservedRoute | None,
    iface: ObservedInterface | None,
) -> ReachabilityStatus:
    if snapshot.reachability_override is not None:
        return snapshot.reachability_override
    if not snapshot.available:
        return ReachabilityStatus.UNKNOWN
    if route is None:
        return ReachabilityStatus.ROUTE_MISSING
    if iface is None:
        return ReachabilityStatus.ROUTE_MISSING
    state = (iface.operstate or "").lower()
    if state in {"down", "lowerlayerdown", "notpresent"}:
        return ReachabilityStatus.BLOCKED
    # IFF_UP is bit 0 when flags come from /sys (hex includes IFF_UP=0x1).
    if iface.flags and (iface.flags & 0x1) == 0:
        return ReachabilityStatus.BLOCKED
    return ReachabilityStatus.REACHABLE
