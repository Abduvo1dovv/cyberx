"""Read-only local network observation. Not World Model evidence. Not authorization."""

from __future__ import annotations

import hashlib
import json

from pydantic import Field

from cyberx.domain.enums import ReachabilityStatus
from cyberx.domain.models.common import DomainModel


class NetAddress(DomainModel):
    ip: str
    prefix: int | None = None
    family: int = 4


class NetInterface(DomainModel):
    name: str
    addresses: list[NetAddress] = Field(default_factory=list)
    operstate: str = "unknown"
    flags: int = 0
    arphrd: int | None = None
    likely_tunnel: bool = False
    tunnel_unverified: bool = False
    kind_hint: str = ""


class NetRoute(DomainModel):
    destination: str
    gateway: str | None = None
    interface: str
    metric: int = 0
    prefix_len: int = 0
    default: bool = False


class NetworkContext(DomainModel):
    """Immutable snapshot of local routing relevant to one mission target.

    Informational only. Never mutates Scope. Never authorizes an action.
    Never claims a VPN provider. TIMEOUT is transient and must not be
    persisted as a World Model fact.
    """

    target: str
    target_ip: str | None = None
    reachability: ReachabilityStatus = ReachabilityStatus.UNKNOWN
    selected_interface: str | None = None
    source_address: str | None = None
    selected_route: str | None = None
    default_route: str | None = None
    likely_tunnel: bool = False
    tunnel_unverified: bool = False
    tunnel_hint: str = ""
    tunnel_present: bool = False
    diagnostic: str = ""
    platform: str = "unknown"
    available: bool = False
    route_in_scope: bool | None = None
    oos_routes: list[str] = Field(default_factory=list)
    interfaces: list[NetInterface] = Field(default_factory=list)
    routes: list[NetRoute] = Field(default_factory=list)

    def tunnel_token(self) -> str:
        if self.likely_tunnel:
            return "detected_unverified"
        if self.tunnel_present:
            return "present_unused"
        return "none"

    def digest(self) -> str:
        """Deterministic identity of meaningful routing/locator state."""
        payload = {
            "target": self.target,
            "target_ip": self.target_ip or "",
            "reachability": self.reachability.value,
            "interface": self.selected_interface or "",
            "source": self.source_address or "",
            "route": self.selected_route or "",
            "tunnel": self.tunnel_token(),
            "tunnel_present": self.tunnel_present,
            "available": self.available,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    def compact(self) -> dict[str, str]:
        in_scope = ""
        if self.route_in_scope is True:
            in_scope = "1"
        elif self.route_in_scope is False:
            in_scope = "0"
        return {
            "target": self.target[:80],
            "target_ip": (self.target_ip or "")[:64],
            "reachability": self.reachability.value,
            "interface": self.selected_interface or "",
            "source": self.source_address or "",
            "route": self.selected_route or "",
            "tunnel": self.tunnel_token(),
            "tunnel_hint": self.tunnel_hint[:32],
            "diagnostic": self.diagnostic[:160],
            "available": "1" if self.available else "0",
            "route_in_scope": in_scope,
            "platform": self.platform[:24],
            "digest": self.digest(),
        }

    @classmethod
    def unavailable(
        cls, target: str, *, diagnostic: str = "", platform: str = "unknown"
    ) -> NetworkContext:
        return cls(
            target=target,
            reachability=ReachabilityStatus.UNKNOWN,
            diagnostic=diagnostic or "network information unavailable",
            platform=platform,
            available=False,
        )
