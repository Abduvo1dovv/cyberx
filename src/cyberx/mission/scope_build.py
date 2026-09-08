"""Default scope construction and validation (SPEC §2.3, §4.2)."""

from __future__ import annotations

import ipaddress

from cyberx.domain.enums import ALLOWED_PROTOCOLS, MissionMode, TargetKind
from cyberx.domain.errors import ScopeValidationError
from cyberx.domain.identity import (
    IdentityError,
    is_subdomain_of,
    normalize_cidr,
    normalize_fqdn,
)
from cyberx.domain.models.mission import Scope, Target
from cyberx.mission.target_parse import RFC1918_10, ParsedTarget

ASSESSMENT_DEFAULT_PORTS = (80, 443, 8080, 8443)
DEFAULT_PROTOCOLS = ("tcp", "http", "https", "dns")


class ScopeOverrides:
    __slots__ = (
        "allowed_targets",
        "allowed_networks",
        "allowed_ports",
        "allowed_protocols",
        "excluded_targets",
        "excluded_networks",
        "excluded_ports",
        "allow_subdomains",
        "time_window_start",
        "time_window_end",
    )

    def __init__(
        self,
        *,
        allowed_targets: list[str] | None = None,
        allowed_networks: list[str] | None = None,
        allowed_ports: list[int] | None = None,
        allowed_protocols: list[str] | None = None,
        excluded_targets: list[str] | None = None,
        excluded_networks: list[str] | None = None,
        excluded_ports: list[int] | None = None,
        allow_subdomains: bool | None = None,
        time_window_start=None,
        time_window_end=None,
    ) -> None:
        self.allowed_targets = allowed_targets
        self.allowed_networks = allowed_networks
        self.allowed_ports = allowed_ports
        self.allowed_protocols = allowed_protocols
        self.excluded_targets = excluded_targets
        self.excluded_networks = excluded_networks
        self.excluded_ports = excluded_ports
        self.allow_subdomains = allow_subdomains
        self.time_window_start = time_window_start
        self.time_window_end = time_window_end


def _normalize_protocol_list(values: list[str]) -> list[str]:
    out: list[str] = []
    for item in values:
        proto = item.strip().lower()
        if proto not in ALLOWED_PROTOCOLS:
            raise ScopeValidationError(f"unsupported protocol: {item}")
        if proto not in out:
            out.append(proto)
    return out


def _cidr_prefix_ok(cidr: str, mode: MissionMode) -> None:
    network = ipaddress.ip_network(cidr, strict=False)
    if mode is MissionMode.AUTHORIZED_ASSESSMENT and network.prefixlen < 16:
        raise ScopeValidationError("assessment CIDR may not be larger than /16")
    if mode in (MissionMode.CTF, MissionMode.LAB) and network.prefixlen < 8:
        raise ScopeValidationError("CTF/lab CIDR may not be larger than /8")


def target_allow_entries(parsed: ParsedTarget) -> tuple[list[str], list[str]]:
    """(allowed_targets, allowed_networks) derived from the Target."""
    if parsed.kind is TargetKind.CIDR:
        return [], [parsed.normalized]
    if parsed.kind is TargetKind.URL:
        entries = [parsed.host or parsed.normalized, parsed.normalized]
        return entries, []
    return [parsed.normalized], []


def apply_target_to_lists(
    allowed_targets: list[str],
    allowed_networks: list[str],
    parsed: ParsedTarget,
) -> tuple[list[str], list[str]]:
    t_add, n_add = target_allow_entries(parsed)
    targets = list(allowed_targets)
    nets = list(allowed_networks)
    for item in t_add:
        if item not in targets:
            targets.append(item)
    for item in n_add:
        if item not in nets:
            nets.append(item)
    return targets, nets


def validate_scope_values(
    *,
    mode: MissionMode,
    allowed_targets: list[str],
    allowed_networks: list[str],
    allowed_protocols: list[str],
    excluded_targets: list[str],
    excluded_networks: list[str],
    parsed: ParsedTarget | None = None,
) -> None:
    if not allowed_targets and not allowed_networks:
        raise ScopeValidationError("scope needs allowed_targets or allowed_networks")
    if not allowed_protocols:
        raise ScopeValidationError("allowed_protocols must be non-empty")
    for net in allowed_networks + excluded_networks:
        try:
            normalized = normalize_cidr(net)
        except IdentityError as exc:
            raise ScopeValidationError(str(exc)) from exc
        if net in allowed_networks:
            _cidr_prefix_ok(normalized, mode)
    if parsed is not None:
        if target_is_excluded(
            parsed,
            excluded_targets=excluded_targets,
            excluded_networks=excluded_networks,
        ):
            raise ScopeValidationError("target itself is excluded from scope")
        if not target_is_allowed(
            parsed,
            allowed_targets=allowed_targets,
            allowed_networks=allowed_networks,
            allow_subdomains=True,
        ):
            raise ScopeValidationError("scope must include the mission target")
        if mode is MissionMode.AUTHORIZED_ASSESSMENT and parsed.kind in (
            TargetKind.IPV4,
            TargetKind.CIDR,
        ):
            _assert_assessment_10(parsed, allowed_targets, allowed_networks)


def _assert_assessment_10(
    parsed: ParsedTarget,
    allowed_targets: list[str],
    allowed_networks: list[str],
) -> None:
    """10/8 is denied for assessment unless the address sits in explicit scope."""
    try:
        if parsed.kind is TargetKind.IPV4:
            addr = ipaddress.ip_address(parsed.normalized)
            if addr not in RFC1918_10:
                return
            if parsed.normalized in allowed_targets:
                return
            for net in allowed_networks:
                if addr in ipaddress.ip_network(net, strict=False):
                    return
            raise ScopeValidationError(
                "10.0.0.0/8 is denied for authorized_assessment unless in explicit scope"
            )
        if parsed.kind is TargetKind.CIDR:
            net = ipaddress.ip_network(parsed.normalized, strict=False)
            if net.overlaps(RFC1918_10) and parsed.normalized not in allowed_networks:
                raise ScopeValidationError(
                    "10.0.0.0/8 is denied for authorized_assessment unless in explicit scope"
                )
    except ValueError:
        return


def target_is_excluded(
    parsed: ParsedTarget,
    *,
    excluded_targets: list[str],
    excluded_networks: list[str],
) -> bool:
    locators = {parsed.normalized}
    if parsed.host:
        locators.add(parsed.host)
    excluded_n = {normalize_fqdn(x) if not _looks_ip(x) else x for x in excluded_targets}
    for loc in locators:
        key = loc.lower()
        if key in excluded_n or loc in excluded_targets:
            return True
        if _looks_ip(loc):
            addr = ipaddress.ip_address(loc)
            for net in excluded_networks:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True
        if parsed.kind is TargetKind.CIDR:
            me = ipaddress.ip_network(parsed.normalized, strict=False)
            for net in excluded_networks:
                if me.overlaps(ipaddress.ip_network(net, strict=False)):
                    return True
    return False


def target_is_allowed(
    parsed: ParsedTarget,
    *,
    allowed_targets: list[str],
    allowed_networks: list[str],
    allow_subdomains: bool,
) -> bool:
    if parsed.kind is TargetKind.CIDR:
        return parsed.normalized in allowed_networks
    if parsed.kind in (TargetKind.IPV4, TargetKind.IPV6) or (
        parsed.host and _looks_ip(parsed.host)
    ):
        if parsed.kind in (TargetKind.IPV4, TargetKind.IPV6):
            addr_s = parsed.normalized
        else:
            addr_s = parsed.host

        if addr_s in allowed_targets:
            return True
        addr = ipaddress.ip_address(addr_s)
        return any(addr in ipaddress.ip_network(net, strict=False) for net in allowed_networks)
    name = parsed.host or parsed.normalized
    name_n = normalize_fqdn(name)
    allowed_names = [
        normalize_fqdn(t) for t in allowed_targets if not _looks_ip(t) and "/" not in t
    ]

    if name_n in allowed_names or parsed.normalized in allowed_targets:
        return True
    if allow_subdomains:
        return any(is_subdomain_of(name_n, parent) for parent in allowed_names)
    return False


def _looks_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def default_ports(mode: MissionMode, override: list[int] | None) -> list[int]:
    if override is not None:
        return list(override)
    if mode is MissionMode.AUTHORIZED_ASSESSMENT:
        return list(ASSESSMENT_DEFAULT_PORTS)
    return []


def build_scope_fields(
    parsed: ParsedTarget,
    mode: MissionMode,
    overrides: ScopeOverrides | None,
) -> dict:
    overrides = overrides or ScopeOverrides()
    allowed_targets = list(overrides.allowed_targets or [])
    allowed_networks = []
    for net in overrides.allowed_networks or []:
        allowed_networks.append(normalize_cidr(net))
    allowed_targets, allowed_networks = apply_target_to_lists(
        allowed_targets, allowed_networks, parsed
    )
    protocols = _normalize_protocol_list(list(overrides.allowed_protocols or DEFAULT_PROTOCOLS))
    validate_scope_values(
        mode=mode,
        allowed_targets=allowed_targets,
        allowed_networks=allowed_networks,
        allowed_protocols=protocols,
        excluded_targets=list(overrides.excluded_targets or []),
        excluded_networks=list(overrides.excluded_networks or []),
        parsed=parsed,
    )
    return {
        "allowed_targets": allowed_targets,
        "allowed_networks": allowed_networks,
        "allowed_ports": default_ports(mode, overrides.allowed_ports),
        "allowed_protocols": protocols,
        "excluded_targets": list(overrides.excluded_targets or []),
        "excluded_networks": [normalize_cidr(n) for n in (overrides.excluded_networks or [])],
        "excluded_ports": list(overrides.excluded_ports or []),
        "allow_subdomains": (
            True if overrides.allow_subdomains is None else overrides.allow_subdomains
        ),
        "time_window_start": overrides.time_window_start,
        "time_window_end": overrides.time_window_end,
    }


def ensure_scope_includes_target(scope: Scope, target: Target, parsed: ParsedTarget) -> Scope:
    targets, nets = apply_target_to_lists(
        list(scope.allowed_targets), list(scope.allowed_networks), parsed
    )
    if targets == scope.allowed_targets and nets == scope.allowed_networks:
        return scope
    return scope.model_copy(update={"allowed_targets": targets, "allowed_networks": nets})
