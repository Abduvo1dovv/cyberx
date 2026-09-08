"""GapDetector — recomputes the closed v1 gap set after every apply (SPEC §3.10)."""

from __future__ import annotations

from typing import Any

from cyberx.domain.enums import (
    GAP_KINDS,
    AddressType,
    EpistemicStatus,
    PortState,
)
from cyberx.domain.errors import InvalidWorldDelta
from cyberx.domain.ids import PREFIX_GAP, new_id
from cyberx.domain.models.assets import Domain, Endpoint, Host, Port, Service, UrlAsset
from cyberx.domain.models.evidence import KnowledgeGap
from cyberx.world.importance import asset_importance

_LIVE = {
    EpistemicStatus.KNOWN,
    EpistemicStatus.SUPPORTED,
    EpistemicStatus.CONFIRMED,
}

PRIORITIES = {
    "host.unresolved": 0.95,
    "host.ports_unknown": 0.90,
    "port.service_unknown": 0.80,
    "service.http_unprobed": 0.75,
    "domain.subdomains_unknown": 0.70,
    "service.directories_unknown": 0.60,
    "url.tech_unknown": 0.55,
    "endpoint.params_unknown": 0.40,
}

_HTTP_NAMES = frozenset({"http", "https", "http-alt", "http-proxy", "ssl/http", "https-alt"})


def require_gap_kind(kind: str) -> str:
    if kind not in GAP_KINDS:
        raise InvalidWorldDelta(f"unknown gap kind: {kind}")
    return kind


class GapDetector:
    def recompute(self, world: Any) -> None:
        desired: dict[tuple[str, str], KnowledgeGap] = {}
        claims = list(world.iter_claims_raw())
        live = [c for c in claims if c.epistemic_status in _LIVE]
        key_of = world.asset_key_by_id

        def open_gap(kind: str, subject_id: str | None, detail: str, subject_key: str) -> None:
            require_gap_kind(kind)
            token = (kind, subject_key)
            if token in desired:
                return
            asset = world.peek_asset_by_id(subject_id) if subject_id else None
            importance = asset_importance(asset, world) if asset is not None else 0.5
            desired[token] = KnowledgeGap(
                gap_id=new_id(PREFIX_GAP),
                kind=kind,
                subject_id=subject_id,
                detail=detail,
                priority=min(1.0, PRIORITIES[kind] * (0.75 + 0.25 * importance)),
                closed=False,
            )

        hosts = [a for a in world.iter_assets_raw() if isinstance(a, Host)]
        ports = [a for a in world.iter_assets_raw() if isinstance(a, Port)]
        services = [a for a in world.iter_assets_raw() if isinstance(a, Service)]
        urls = [a for a in world.iter_assets_raw() if isinstance(a, UrlAsset)]
        endpoints = [a for a in world.iter_assets_raw() if isinstance(a, Endpoint)]
        domains = [a for a in world.iter_assets_raw() if isinstance(a, Domain)]

        ports_by_host: dict[str, list[Port]] = {}
        for port in ports:
            ports_by_host.setdefault(port.host_id, []).append(port)
        svc_by_port: dict[str, list[Service]] = {}
        for svc in services:
            svc_by_port.setdefault(svc.port_id, []).append(svc)
        url_by_host_name: dict[str, list[UrlAsset]] = {}
        for url in urls:
            url_by_host_name.setdefault(url.host, []).append(url)

        def has_claim(subject_id: str, predicate: str) -> bool:
            return any(c.subject_id == subject_id and c.predicate == predicate for c in live)

        for host in hosts:
            if host.out_of_scope or "alias" in host.labels:
                continue
            host_key = host.canonical_key
            unresolved = host.address_type is AddressType.NAME and not (host.ipv4 or host.ipv6)
            if unresolved and not has_claim(host.asset_id, "host.address"):
                open_gap(
                    "host.unresolved",
                    host.asset_id,
                    "hostname has no resolved address",
                    host_key,
                )
            host_ports = ports_by_host.get(host.asset_id, [])
            has_port_state = any(
                c.predicate == "port.state"
                and key_of(c.subject_id) is not None
                and key_of(c.subject_id).startswith("port:" + host_key)
                for c in live
            )
            if not host_ports and not has_port_state:
                open_gap(
                    "host.ports_unknown",
                    host.asset_id,
                    "no port states observed",
                    host_key,
                )

        for port in ports:
            if port.out_of_scope or port.state is not PortState.OPEN:
                continue
            svcs = svc_by_port.get(port.asset_id, [])
            named = [s for s in svcs if s.name and s.name != "unknown"]
            if not named and not has_claim(port.asset_id, "service.name"):
                # service.name claims sit on the service asset, not the port
                svc_named = any(
                    c.predicate == "service.name"
                    and key_of(c.subject_id) == f"svc:{port.canonical_key}"
                    for c in live
                )
                if not svc_named:
                    open_gap(
                        "port.service_unknown",
                        port.asset_id,
                        "open port has no service name",
                        port.canonical_key,
                    )

        for svc in services:
            if svc.out_of_scope:
                continue
            if svc.name not in _HTTP_NAMES:
                continue
            port = world.peek_asset_by_id(svc.port_id)
            host = None
            if isinstance(port, Port):
                host = world.peek_asset_by_id(port.host_id)
            host_name = None
            if isinstance(host, Host):
                host_name = host.ipv4 or host.ipv6 or host.hostname
            probed = False
            if host_name:
                for url in url_by_host_name.get(host_name, []):
                    if url.port == (port.number if isinstance(port, Port) else url.port):
                        if has_claim(url.asset_id, "http.status") or has_claim(
                            url.asset_id, "url.seen"
                        ):
                            probed = True
                            break
            if not probed:
                open_gap(
                    "service.http_unprobed",
                    svc.asset_id,
                    "http service has no http probe",
                    svc.canonical_key,
                )
            extra_paths = []
            if host_name:
                extra_paths = [
                    u for u in url_by_host_name.get(host_name, []) if u.path not in {"", "/"}
                ]
            if not extra_paths:
                open_gap(
                    "service.directories_unknown",
                    svc.asset_id,
                    "no directory paths observed",
                    svc.canonical_key,
                )

        for url in urls:
            if url.out_of_scope:
                continue
            probed = has_claim(url.asset_id, "http.status")
            if not probed:
                continue
            tech_hit = any(
                c.subject_id == url.asset_id and c.predicate == "http.tech" for c in live
            )
            child_tech = any(
                getattr(a, "parent_asset_id", None) == url.asset_id and a.kind.value == "technology"
                for a in world.iter_assets_raw()
            )
            if not tech_hit and not child_tech:
                open_gap(
                    "url.tech_unknown",
                    url.asset_id,
                    "url has no technology fingerprint",
                    url.canonical_key,
                )

        for domain in domains:
            if domain.out_of_scope:
                continue
            children = [
                a
                for a in world.iter_assets_raw()
                if getattr(a, "domain_id", None) == domain.asset_id
            ]
            sub_claim = any(
                c.predicate == "dns.subdomain" and c.subject_id == domain.asset_id for c in live
            )
            if not children and not sub_claim:
                open_gap(
                    "domain.subdomains_unknown",
                    domain.asset_id,
                    "domain has no subdomains",
                    domain.canonical_key,
                )

        for endpoint in endpoints:
            if endpoint.out_of_scope:
                continue
            params = [
                a
                for a in world.iter_assets_raw()
                if getattr(a, "endpoint_id", None) == endpoint.asset_id
                and a.kind.value == "parameter"
            ]
            param_claim = any(
                c.predicate == "param.seen" and c.subject_id == endpoint.asset_id for c in live
            )
            if not params and not param_claim:
                open_gap(
                    "endpoint.params_unknown",
                    endpoint.asset_id,
                    "endpoint has no parameters",
                    endpoint.canonical_key,
                )

        world.replace_gaps(desired, live_claims=live)
