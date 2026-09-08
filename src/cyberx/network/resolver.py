"""Resolve a mission target against local routing state. Read-only."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

from cyberx.domain.enums import ReachabilityStatus
from cyberx.domain.models.mission import Scope
from cyberx.domain.models.network import (
    NetAddress,
    NetInterface,
    NetRoute,
    NetworkContext,
)
from cyberx.network.observer import (
    LinuxProcObserver,
    NetworkObserver,
    ObservedInterface,
    ObservedNetwork,
    ObservedRoute,
)
from cyberx.network.routing import (
    iface_by_name,
    reachability_for,
    select_route,
    source_address,
    tunnel_hint,
)

Lookup = Callable[[str], list[str]]


def _system_lookup(host: str) -> list[str]:
    import socket

    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError, TimeoutError, ValueError):
        return []
    seen: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if ip not in seen:
            seen.append(ip)
    return seen


def target_host(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if "://" in text:
        host = urlsplit(text).hostname
        return host or text
    return text


class NetworkResolver:
    """Map a target string to a NetworkContext. Never mutates routes or scope."""

    def __init__(
        self,
        observer: NetworkObserver | None = None,
        *,
        lookup: Lookup | None = None,
    ) -> None:
        self._observer = observer or LinuxProcObserver()
        self._lookup = lookup if lookup is not None else _system_lookup

    def resolve(
        self,
        target: str,
        *,
        scope: Scope | None = None,
        resolved_ips: Sequence[str] = (),
    ) -> NetworkContext:
        host = target_host(target)
        try:
            snapshot = self._observer.inspect()
        except Exception:
            return NetworkContext.unavailable(host or target, diagnostic="observer failed")
        if not snapshot.available:
            return NetworkContext.unavailable(
                host or target,
                diagnostic=snapshot.diagnostic or "network information unavailable",
                platform=snapshot.platform,
            )
        target_ip, lookup_diag = self._target_ip(host, resolved_ips)
        if host and _is_name(host) and target_ip is None:
            return self._assemble(
                snapshot,
                host=host,
                target_ip=None,
                route=None,
                iface=None,
                reachability=ReachabilityStatus.UNKNOWN,
                diagnostic=lookup_diag or "hostname lookup failed",
                scope=scope,
            )
        route = select_route(target_ip, snapshot.routes) if target_ip else None
        iface = iface_by_name(snapshot, route.interface if route is not None else None)
        status = reachability_for(snapshot, route, iface)
        diagnostic = _diagnostic(status, route, iface, lookup_diag)
        return self._assemble(
            snapshot,
            host=host or target,
            target_ip=target_ip,
            route=route,
            iface=iface,
            reachability=status,
            diagnostic=diagnostic,
            scope=scope,
        )

    def _target_ip(self, host: str, resolved_ips: Sequence[str]) -> tuple[str | None, str]:
        for candidate in list(resolved_ips) + [host]:
            if not candidate:
                continue
            try:
                net = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                continue
            return str(net.network_address), ""
            # ip_network accepts host addresses as /32
        if not host or not _is_name(host):
            return None, "target is not an address"
        ips = []
        try:
            ips = list(self._lookup(host))
        except Exception:
            return None, "hostname lookup failed"
        for ip in ips:
            try:
                return str(ipaddress.ip_address(ip)), ""
            except ValueError:
                continue
        return None, "hostname lookup failed"

    def _assemble(
        self,
        snapshot: ObservedNetwork,
        *,
        host: str,
        target_ip: str | None,
        route: ObservedRoute | None,
        iface: ObservedInterface | None,
        reachability: ReachabilityStatus,
        diagnostic: str,
        scope: Scope | None,
    ) -> NetworkContext:
        interfaces = [_to_iface(item) for item in snapshot.interfaces]
        routes = [_to_route(item) for item in snapshot.routes]
        tunnel_present = any(item.likely_tunnel for item in interfaces)
        likely = False
        hint = ""
        if iface is not None:
            likely, hint = tunnel_hint(iface.name, iface.arphrd)
        selected_route = route.destination if route is not None else None
        default = next((r.destination for r in routes if r.default), None)
        in_scope = _route_in_scope(selected_route, scope)
        oos = _oos_routes(routes, scope)
        src = source_address(iface, target_ip)
        return NetworkContext(
            target=host,
            target_ip=target_ip,
            reachability=reachability,
            selected_interface=iface.name if iface is not None else None,
            source_address=src,
            selected_route=selected_route,
            default_route=default,
            likely_tunnel=likely,
            tunnel_unverified=likely,
            tunnel_hint=hint,
            tunnel_present=tunnel_present,
            diagnostic=diagnostic,
            platform=snapshot.platform,
            available=snapshot.available,
            route_in_scope=in_scope,
            oos_routes=oos[:4],
            interfaces=interfaces,
            routes=routes,
        )


def _to_iface(item: ObservedInterface) -> NetInterface:
    likely, hint = tunnel_hint(item.name, item.arphrd)
    return NetInterface(
        name=item.name,
        addresses=[NetAddress(ip=a.ip, prefix=a.prefix, family=a.family) for a in item.addresses],
        operstate=item.operstate,
        flags=item.flags,
        arphrd=item.arphrd,
        likely_tunnel=likely,
        tunnel_unverified=likely,
        kind_hint=hint,
    )


def _to_route(item: ObservedRoute) -> NetRoute:
    return NetRoute(
        destination=item.destination,
        gateway=item.gateway,
        interface=item.interface,
        metric=item.metric,
        prefix_len=item.prefix_len,
        default=item.default,
    )


def _is_name(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return False
    except ValueError:
        return True


def _diagnostic(
    status: ReachabilityStatus,
    route: ObservedRoute | None,
    iface: ObservedInterface | None,
    lookup_diag: str,
) -> str:
    if status is ReachabilityStatus.ROUTE_MISSING:
        return "no route to target (not the same as host down)"
    if status is ReachabilityStatus.BLOCKED:
        name = iface.name if iface is not None else "interface"
        return f"route exists but {name} is down"
    if status is ReachabilityStatus.UNREACHABLE:
        return "target is unreachable"
    if status is ReachabilityStatus.TIMEOUT:
        return "connectivity check timed out (transient)"
    if status is ReachabilityStatus.UNKNOWN:
        return lookup_diag or "reachability unknown"
    if route is not None and iface is not None:
        via = f" via {iface.name}"
        if route.destination:
            via += f" route={route.destination}"
        return f"routing-level reachable{via}"
    return "routing-level reachable"


def _route_in_scope(route_cidr: str | None, scope: Scope | None) -> bool | None:
    if scope is None or not route_cidr:
        return None
    try:
        net = ipaddress.ip_network(route_cidr, strict=False)
    except ValueError:
        return None
    if net.prefixlen == 0:
        return None
    for item in scope.allowed_networks:
        try:
            allowed = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if net.version != allowed.version:
            continue
        if net.subnet_of(allowed) or allowed.subnet_of(net):
            return True
    for item in scope.allowed_targets:
        try:
            addr = ipaddress.ip_address(item)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


def _oos_routes(routes: list[NetRoute], scope: Scope | None) -> list[str]:
    if scope is None:
        return []
    out: list[str] = []
    for route in routes:
        if route.default:
            continue
        flag = _route_in_scope(route.destination, scope)
        if flag is False and route.destination not in out:
            out.append(route.destination)
    return out
