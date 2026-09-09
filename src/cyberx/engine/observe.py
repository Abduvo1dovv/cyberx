"""Read-only network observation and locator evidence ingest. Not World Model facts."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urlsplit

from cyberx.domain.enums import ReachabilityStatus, TimelineKind
from cyberx.domain.errors import (
    DomainValidationError,
    LocatorRejected,
    MissionStateError,
    ScopeViolationError,
    TargetValidationError,
)
from cyberx.domain.models.network import NetworkContext
from cyberx.network.resolver import NetworkResolver
from cyberx.ports.events import DomainEvent, EventSink, EventType, emit_safe
from cyberx.ports.execution import ExecutionContext


class NetworkCycle:
    def __init__(
        self,
        resolver: NetworkResolver,
        events: EventSink,
        *,
        append_event: Callable[[str, TimelineKind, str], None],
        mark_unreachable: Callable[[str, str], None],
    ) -> None:
        self._network = resolver
        self._events = events
        self._append_event = append_event
        self._mark_unreachable = mark_unreachable
        self._last: dict[str, NetworkContext] = {}

    def last(self, mission_id: str) -> NetworkContext | None:
        return self._last.get(mission_id)

    def observe(
        self, mission_id: str, target: Any, scope: Any, *, emit: bool = True
    ) -> NetworkContext:
        token = target_token(target)
        resolved = list(getattr(target, "resolved_ipv4", None) or [])
        resolved.extend(getattr(target, "resolved_ipv6", None) or [])
        try:
            net = self._network.resolve(token, scope=scope, resolved_ips=resolved)
        except (OSError, TimeoutError, ValueError, RuntimeError):
            net = NetworkContext.unavailable(token, diagnostic="network observe failed")
        prev = self._last.get(mission_id)
        self._last[mission_id] = net
        changed = prev is None or prev.digest() != net.digest()
        blocking = net.reachability.value in {"ROUTE_MISSING", "UNREACHABLE", "BLOCKED"}
        if emit and net.reachability is ReachabilityStatus.UNREACHABLE and (net.target_ip or token):
            try:
                self._mark_unreachable(mission_id, net.target_ip or token)
            except (
                LocatorRejected,
                MissionStateError,
                DomainValidationError,
                TargetValidationError,
            ):
                pass
        if emit and changed:
            msg = (
                f"network {net.reachability.value}"
                + (f" via {net.selected_interface}" if net.selected_interface else "")
                + (f" src={net.source_address}" if net.source_address else "")
                + (f" route={net.selected_route}" if net.selected_route else "")
                + f" digest={net.digest()}"
            )
            if blocking and net.diagnostic:
                msg = f"{msg}; {net.diagnostic}"
            self._append_event(mission_id, TimelineKind.NETWORK, msg[:1000])
            emit_safe(
                self._events,
                DomainEvent(
                    event_type=EventType.NETWORK_OBSERVED,
                    mission_id=mission_id,
                    payload={
                        "reachability": net.reachability.value,
                        "interface": net.selected_interface or "",
                        "route": net.selected_route or "",
                        "source": net.source_address or "",
                        "digest": net.digest(),
                    },
                ),
            )
        return net


def ingest_locator_evidence(
    observe: Callable[..., Any],
    mission_id: str,
    evidence: Sequence[Any],
) -> None:
    for item in evidence:
        preview = getattr(item, "claim_preview", None) or {}
        pred = str(preview.get("predicate") or "")
        obj = preview.get("object")
        locators: list[str] = []
        if pred == "dns.record" and isinstance(obj, dict):
            rtype = str(obj.get("type") or "").upper()
            if rtype in {"A", "AAAA"}:
                value = str(obj.get("value") or "")
                if value:
                    locators.append(value)
        elif pred == "host.address":
            if isinstance(obj, str):
                locators.append(obj)
            elif isinstance(obj, dict):
                value = str(obj.get("value") or obj.get("ip") or "")
                if value:
                    locators.append(value)
        for locator in locators:
            try:
                observe(
                    mission_id,
                    locator,
                    source="dns" if pred == "dns.record" else "recon",
                    evidence_ids=[item.evidence_id],
                )
            except (
                LocatorRejected,
                DomainValidationError,
                TargetValidationError,
                ScopeViolationError,
            ):
                continue


def execution_context(candidate: Any, net: NetworkContext) -> ExecutionContext:
    return ExecutionContext(
        mission_id=candidate.target.asset_id or "pending",
        action_id="pending",
        timeout_s=int(getattr(candidate, "timeout_s", 30) or 30),
        stub=False,
        source_interface=net.selected_interface,
        source_address=net.source_address,
        route_cidr=net.selected_route,
        reachability=net.reachability.value,
        likely_tunnel=net.likely_tunnel,
        network_diagnostic=net.diagnostic[:200],
    )


def unavailable_event(adapter_name: str) -> str:
    token = (adapter_name or "").lower()
    if "nmap" in token:
        return "nmap unavailable"
    if "directory" in token:
        return "directory enumeration transport unavailable"
    if "http" in token or "tech" in token or "endpoint" in token:
        return "HTTP transport unavailable"
    if "dns" in token or "subdomain" in token:
        return "DNS resolver unavailable"
    return f"adapter unavailable: {adapter_name}"


def target_token(target: Any) -> str:
    current = getattr(target, "current_locator", None)
    if current:
        return str(current)
    kind = getattr(getattr(target, "kind", None), "value", "")
    if kind == "url":
        host = getattr(target, "normalized", "") or ""
        if "://" in host:
            return urlsplit(host).hostname or host
        return host
    return str(getattr(target, "normalized", "") or getattr(target, "raw_input", "") or "")
