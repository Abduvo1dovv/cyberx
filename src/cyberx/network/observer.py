"""Observe local interfaces and routes. Read-only. No process launcher. No mutation."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cyberx.domain.enums import ReachabilityStatus

# Linux ARPHRD numbers from include/uapi/linux/if_arp.h
ARPHRD_ETHER = 1
ARPHRD_PPP = 512
ARPHRD_TUNNEL = 768
ARPHRD_TUNNEL6 = 769
ARPHRD_LOOPBACK = 772
ARPHRD_SIT = 776
ARPHRD_IPGRE = 778
ARPHRD_NONE = 65534
ARPHRD_VOID = 65535

TUNNEL_ARPHRD = frozenset({ARPHRD_PPP, ARPHRD_TUNNEL, ARPHRD_TUNNEL6, ARPHRD_IPGRE, ARPHRD_NONE})

Reader = Callable[[str], str]


@dataclass(frozen=True)
class ObservedAddress:
    ip: str
    prefix: int | None = None
    family: int = 4


@dataclass(frozen=True)
class ObservedInterface:
    name: str
    addresses: tuple[ObservedAddress, ...] = ()
    operstate: str = "unknown"
    arphrd: int | None = None
    flags: int = 0


@dataclass(frozen=True)
class ObservedRoute:
    destination: str
    interface: str
    gateway: str | None = None
    metric: int = 0
    prefix_len: int = 0
    default: bool = False


@dataclass(frozen=True)
class ObservedNetwork:
    interfaces: tuple[ObservedInterface, ...] = ()
    routes: tuple[ObservedRoute, ...] = ()
    platform: str = "linux"
    available: bool = True
    diagnostic: str = ""
    reachability_override: ReachabilityStatus | None = None


class NetworkObserver(Protocol):
    def inspect(self) -> ObservedNetwork: ...


class FixtureNetworkObserver:
    """Deterministic observer for tests. Never touches the real OS."""

    def __init__(self, snapshot: ObservedNetwork) -> None:
        self._snapshot = snapshot

    def inspect(self) -> ObservedNetwork:
        return self._snapshot


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


class LinuxProcObserver:
    """Read /sys and /proc. Never runs `ip`, `route`, or a shell."""

    def __init__(
        self,
        *,
        root: str | Path = "/",
        reader: Reader | None = None,
        address_lookup: Callable[[str], Sequence[ObservedAddress]] | None = None,
        platform: str | None = None,
    ) -> None:
        self._root = Path(root)
        self._reader = reader or _read_text
        self._address_lookup = address_lookup
        self._platform = platform if platform is not None else sys.platform

    def inspect(self) -> ObservedNetwork:
        if not self._platform.startswith("linux"):
            return ObservedNetwork(
                platform=self._platform or "unknown",
                available=False,
                diagnostic="unsupported platform",
            )
        try:
            interfaces = self._interfaces()
            routes = self._routes()
        except OSError as exc:
            return ObservedNetwork(
                platform="linux",
                available=False,
                diagnostic=f"network inspect failed: {type(exc).__name__}",
            )
        except (ValueError, UnicodeError):
            return ObservedNetwork(
                platform="linux",
                available=False,
                diagnostic="malformed system network output",
            )
        if not interfaces and not routes:
            return ObservedNetwork(
                platform="linux",
                available=False,
                diagnostic="route information unavailable",
            )
        return ObservedNetwork(
            interfaces=tuple(interfaces),
            routes=tuple(routes),
            platform="linux",
            available=True,
        )

    def _path(self, *parts: str) -> str:
        return str(self._root.joinpath(*parts))

    def _try_read(self, *parts: str) -> str | None:
        path = self._path(*parts)
        try:
            return self._reader(path)
        except OSError:
            return None

    def _interfaces(self) -> list[ObservedInterface]:
        sys_net = Path(self._path("sys", "class", "net"))
        names: list[str] = []
        try:
            names = sorted(p.name for p in sys_net.iterdir() if not p.name.startswith("."))
        except OSError:
            names = []
        if not names:
            names = _if_names()
        out: list[ObservedInterface] = []
        for name in names:
            oper = (self._try_read("sys", "class", "net", name, "operstate") or "unknown").strip()
            type_raw = (self._try_read("sys", "class", "net", name, "type") or "").strip()
            flags_raw = (self._try_read("sys", "class", "net", name, "flags") or "").strip()
            arphrd: int | None
            try:
                arphrd = int(type_raw, 0) if type_raw else None
            except ValueError:
                arphrd = None
            try:
                flags = int(flags_raw, 0) if flags_raw else 0
            except ValueError:
                flags = 0
            addresses = tuple(self._addresses(name))
            out.append(
                ObservedInterface(
                    name=name,
                    addresses=addresses,
                    operstate=oper or "unknown",
                    arphrd=arphrd,
                    flags=flags,
                )
            )
        return out

    def _addresses(self, name: str) -> list[ObservedAddress]:
        if self._address_lookup is not None:
            return list(self._address_lookup(name))
        found: list[ObservedAddress] = []
        ipv4 = _ioctl_ipv4(name)
        if ipv4 is not None:
            found.append(ipv4)
        found.extend(self._ipv6_addresses(name))
        return found

    def _ipv6_addresses(self, name: str) -> list[ObservedAddress]:
        raw = self._try_read("proc", "net", "if_inet6")
        if not raw:
            return []
        out: list[ObservedAddress] = []
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            hexaddr, _idx, prefix_hex, _scope, _flags, iface = parts[:6]
            if iface != name:
                continue
            try:
                prefix = int(prefix_hex, 16)
                ip = _hex_ipv6(hexaddr)
            except ValueError:
                continue
            out.append(ObservedAddress(ip=ip, prefix=prefix, family=6))
        return out

    def _routes(self) -> list[ObservedRoute]:
        out: list[ObservedRoute] = []
        raw4 = self._try_read("proc", "net", "route")
        if raw4:
            out.extend(_parse_proc_net_route(raw4))
        raw6 = self._try_read("proc", "net", "ipv6_route")
        if raw6:
            out.extend(_parse_proc_net_ipv6_route(raw6))
        return out


def _if_names() -> list[str]:
    try:
        import socket

        return [name for _idx, name in socket.if_nameindex()]
    except OSError:
        return []


def _ioctl_ipv4(name: str) -> ObservedAddress | None:
    try:
        import fcntl
        import socket
        import struct
    except ImportError:
        return None
    if not name or name.startswith("-") or "/" in name or "\x00" in name:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("256s", name.encode("ascii", "replace")[:15])
        try:
            res = fcntl.ioctl(sock.fileno(), 0x8915, ifreq)  # SIOCGIFADDR
        except OSError:
            return None
        ip = socket.inet_ntoa(res[20:24])
        prefix = 32
        try:
            mask_raw = fcntl.ioctl(sock.fileno(), 0x891B, ifreq)  # SIOCGIFNETMASK
            mask = socket.inet_ntoa(mask_raw[20:24])
            import ipaddress

            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        except (OSError, ValueError):
            prefix = 32
        return ObservedAddress(ip=ip, prefix=prefix, family=4)
    finally:
        sock.close()


def _hex_le_ipv4(token: str) -> str:
    import socket
    import struct

    packed = struct.pack("<I", int(token, 16))
    return socket.inet_ntoa(packed)


def _hex_ipv6(token: str) -> str:
    import ipaddress

    clean = token.strip()
    if len(clean) != 32:
        raise ValueError("ipv6 hex")
    raw = bytes.fromhex(clean)
    return str(ipaddress.IPv6Address(raw))


def _prefix_from_mask(mask_hex: str) -> int:
    import ipaddress

    mask = _hex_le_ipv4(mask_hex)
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def _parse_proc_net_route(text: str) -> list[ObservedRoute]:
    lines = text.splitlines()
    if not lines:
        return []
    out: list[ObservedRoute] = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest_hex, gw_hex, flags_hex, _ref, _use, metric_s, mask_hex = parts[:8]
        try:
            flags = int(flags_hex, 16)
            metric = int(metric_s)
            dest = _hex_le_ipv4(dest_hex)
            mask_prefix = _prefix_from_mask(mask_hex)
            gateway = _hex_le_ipv4(gw_hex)
        except ValueError:
            continue
        if flags & 0x1 == 0:
            continue
        if gateway == "0.0.0.0":
            gateway_val: str | None = None
        else:
            gateway_val = gateway
        default = dest == "0.0.0.0" and mask_prefix == 0
        cidr = f"{dest}/{mask_prefix}"
        out.append(
            ObservedRoute(
                destination=cidr,
                gateway=gateway_val,
                interface=iface,
                metric=metric,
                prefix_len=mask_prefix,
                default=default,
            )
        )
    return out


def _parse_proc_net_ipv6_route(text: str) -> list[ObservedRoute]:
    out: list[ObservedRoute] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        dest_hex, plen_hex, _src, _splen, gw_hex, metric_hex, _ref, _use, flags_hex, iface = parts[
            :10
        ]
        try:
            prefix = int(plen_hex, 16)
            dest = _hex_ipv6(dest_hex)
            metric = int(metric_hex, 16)
            flags = int(flags_hex, 16)
            gateway = _hex_ipv6(gw_hex) if int(gw_hex, 16) else None
        except ValueError:
            continue
        if flags & 0x1 == 0 and iface != "lo":
            # IPv6 table often omits RTF_UP; keep routes with an interface.
            pass
        default = dest == "::" and prefix == 0
        cidr = f"{dest}/{prefix}"
        out.append(
            ObservedRoute(
                destination=cidr,
                gateway=gateway if gateway and gateway != "::" else None,
                interface=iface,
                metric=metric,
                prefix_len=prefix,
                default=default,
            )
        )
    return out
