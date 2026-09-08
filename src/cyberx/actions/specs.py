"""Closed v1 ActionSpec registry data. No tool implementations."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from cyberx.actions.params import (
    DirectoryEnumerationParams,
    DnsEnumerationParams,
    EndpointDiscoveryParams,
    HttpProbeParams,
    NetworkDiscoveryParams,
    PortScanParams,
    ServiceEnumerationParams,
    SubdomainEnumerationParams,
    TechnologyDetectionParams,
)
from cyberx.domain.enums import V1_ACTION_TYPES, MissionMode, Risk


class ActionSpec(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid", frozen=True)

    action_type: str
    summary: str
    parameter_schema: type[BaseModel]
    prerequisites_gap_kinds: tuple[str, ...]
    produces_predicates: tuple[str, ...]
    risk: Risk
    cost: float
    default_timeout_s: int
    max_timeout_s: int
    max_attempts: int = 2
    allowed_modes: tuple[MissionMode, ...]
    adapter_name: str
    enabled: bool = True


_ALL_MODES = (
    MissionMode.CTF,
    MissionMode.LAB,
    MissionMode.AUTHORIZED_ASSESSMENT,
)

V1_SPECS: tuple[ActionSpec, ...] = (
    ActionSpec(
        action_type="network_discovery",
        summary="Identify live hosts in an in-scope network",
        parameter_schema=NetworkDiscoveryParams,
        prerequisites_gap_kinds=(),
        produces_predicates=("host.alive", "host.address"),
        risk=Risk.LOW,
        cost=0.4,
        default_timeout_s=120,
        max_timeout_s=180,
        allowed_modes=_ALL_MODES,
        adapter_name="nmap_adapter",
    ),
    ActionSpec(
        action_type="port_scan",
        summary="Discover port states on a host",
        parameter_schema=PortScanParams,
        prerequisites_gap_kinds=("host.ports_unknown",),
        produces_predicates=("port.state",),
        risk=Risk.LOW,
        cost=0.5,
        default_timeout_s=180,
        max_timeout_s=300,
        allowed_modes=_ALL_MODES,
        adapter_name="nmap_adapter",
    ),
    ActionSpec(
        action_type="service_enumeration",
        summary="Fingerprint services on open ports",
        parameter_schema=ServiceEnumerationParams,
        prerequisites_gap_kinds=("port.service_unknown",),
        produces_predicates=(
            "service.name",
            "service.product",
            "service.version",
            "service.banner",
        ),
        risk=Risk.LOW,
        cost=0.5,
        default_timeout_s=180,
        max_timeout_s=300,
        allowed_modes=_ALL_MODES,
        adapter_name="nmap_adapter",
    ),
    ActionSpec(
        action_type="http_probe",
        summary="Request HTTP(S) and record status/title/redirects",
        parameter_schema=HttpProbeParams,
        prerequisites_gap_kinds=("service.http_unprobed",),
        produces_predicates=(
            "http.status",
            "http.title",
            "http.redirect",
            "url.seen",
            "endpoint.seen",
        ),
        risk=Risk.INFO,
        cost=0.2,
        default_timeout_s=30,
        max_timeout_s=60,
        allowed_modes=_ALL_MODES,
        adapter_name="http_adapter",
    ),
    ActionSpec(
        action_type="technology_detection",
        summary="Fingerprint web/app technologies",
        parameter_schema=TechnologyDetectionParams,
        prerequisites_gap_kinds=("url.tech_unknown",),
        produces_predicates=("http.tech", "http.header"),
        risk=Risk.INFO,
        cost=0.2,
        default_timeout_s=45,
        max_timeout_s=90,
        allowed_modes=_ALL_MODES,
        adapter_name="tech_adapter",
    ),
    ActionSpec(
        action_type="dns_enumeration",
        summary="Resolve and collect DNS records in scope",
        parameter_schema=DnsEnumerationParams,
        prerequisites_gap_kinds=("host.unresolved",),
        produces_predicates=("dns.record", "host.address", "host.hostname"),
        risk=Risk.INFO,
        cost=0.2,
        default_timeout_s=30,
        max_timeout_s=60,
        allowed_modes=_ALL_MODES,
        adapter_name="dns_adapter",
    ),
    ActionSpec(
        action_type="subdomain_enumeration",
        summary="Discover in-scope subdomains",
        parameter_schema=SubdomainEnumerationParams,
        prerequisites_gap_kinds=("domain.subdomains_unknown",),
        produces_predicates=("dns.subdomain",),
        risk=Risk.LOW,
        cost=0.4,
        default_timeout_s=120,
        max_timeout_s=180,
        allowed_modes=_ALL_MODES,
        adapter_name="subdomain_adapter",
    ),
    ActionSpec(
        action_type="directory_enumeration",
        summary="Discover paths on an HTTP service",
        parameter_schema=DirectoryEnumerationParams,
        prerequisites_gap_kinds=("service.directories_unknown",),
        produces_predicates=("url.seen", "http.status"),
        risk=Risk.MEDIUM,
        cost=0.6,
        default_timeout_s=120,
        max_timeout_s=180,
        allowed_modes=_ALL_MODES,
        adapter_name="directory_adapter",
    ),
    ActionSpec(
        action_type="endpoint_discovery",
        summary="Extract links/forms/parameters from probed pages",
        parameter_schema=EndpointDiscoveryParams,
        prerequisites_gap_kinds=("endpoint.params_unknown",),
        produces_predicates=("endpoint.seen", "param.seen", "auth.seen", "url.seen"),
        risk=Risk.INFO,
        cost=0.3,
        default_timeout_s=30,
        max_timeout_s=60,
        allowed_modes=_ALL_MODES,
        adapter_name="endpoint_adapter",
    ),
)


def assert_v1_closed() -> None:
    types = tuple(spec.action_type for spec in V1_SPECS)
    if types != V1_ACTION_TYPES:
        raise RuntimeError("v1 catalog drifted from SPEC")
    for spec in V1_SPECS:
        if spec.risk is Risk.MEDIUM and spec.cost > 1:
            raise RuntimeError("invalid spec")
