"""Deterministic Planner. Catalog-only candidates; no new action types."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from cyberx.actions.catalog import DEFAULT_CATALOG, ActionCatalog
from cyberx.actions.coverage import coverage_key
from cyberx.actions.specs import ActionSpec
from cyberx.brain.dedup import merge_candidates
from cyberx.brain.locators import (
    host_address,
    hosts,
    hosts_for_ip_actions,
    locator_is_obsolete,
    network_blocks_ip,
)
from cyberx.brain.types import CandidateAction
from cyberx.domain.enums import V1_ACTION_TYPES, MissionMode
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.models.actions import ActionTarget
from cyberx.domain.models.context import AssetContext, GapContext, PathContext, ValidationContext
from cyberx.domain.models.findings import BrainContext

GAP_ACTIONS: dict[str, tuple[str, ...]] = {
    "host.unresolved": ("dns_enumeration",),
    "host.ports_unknown": ("port_scan",),
    "port.service_unknown": ("service_enumeration",),
    "service.http_unprobed": ("http_probe",),
    "url.tech_unknown": ("technology_detection",),
    "domain.subdomains_unknown": ("subdomain_enumeration",),
    "service.directories_unknown": ("directory_enumeration",),
    "endpoint.params_unknown": ("endpoint_discovery",),
}

HTTP_PORTS = {80, 443, 8080, 8443}
HTTPS_PORTS = {443, 8443}

IP_GATED_ACTIONS = frozenset(
    {
        "network_discovery",
        "port_scan",
        "service_enumeration",
        "http_probe",
        "technology_detection",
        "directory_enumeration",
        "endpoint_discovery",
    }
)


def _index(ctx: BrainContext) -> dict[str, AssetContext]:
    out: dict[str, AssetContext] = {}
    for row in ctx.top_assets:
        if row.id:
            out[row.id] = row
        if row.key:
            out[row.key] = row
    return out


def _ports(ctx: BrainContext) -> list[AssetContext]:
    return [row for row in ctx.top_assets if row.kind == "port"]


def _services(ctx: BrainContext) -> list[AssetContext]:
    return [row for row in ctx.top_assets if row.kind == "service"]


def _urls(ctx: BrainContext) -> list[AssetContext]:
    return [row for row in ctx.top_assets if row.kind == "url"]


def _domains(ctx: BrainContext) -> list[AssetContext]:
    return [row for row in ctx.top_assets if row.kind == "domain"]


def _networks(ctx: BrainContext) -> list[AssetContext]:
    return [row for row in ctx.top_assets if row.kind == "network"]


def _http_url(host: str, port: int) -> str:
    scheme = "https" if port in HTTPS_PORTS else "http"
    return f"{scheme}://{host}:{port}/"


class Planner:
    def __init__(self, catalog: ActionCatalog | None = None) -> None:
        self._catalog = catalog or DEFAULT_CATALOG

    def propose(
        self, ctx: BrainContext, catalog: ActionCatalog | None = None
    ) -> list[CandidateAction]:
        cat = catalog or self._catalog
        covered: set[str] = set(ctx.coverage_keys)
        mode = _parse_mode(ctx.mode)
        out: list[CandidateAction] = []
        assets = _index(ctx)

        if not hosts(ctx):
            for net in _networks(ctx):
                cand = self._make(
                    cat,
                    "network_discovery",
                    ActionTarget(canonical_locator=net.address or ""),
                    {"network": net.address or ""},
                    reason="no hosts discovered",
                    gap_kind="host.unresolved",
                    covered=covered,
                    mode=mode,
                    source="planner",
                )
                if cand:
                    out.append(cand)

        for gap in ctx.gaps:
            types = GAP_ACTIONS.get(gap.kind, ())
            subject = assets.get(gap.subject_id) or assets.get(gap.subject_key)
            for action_type in types:
                built = self._from_gap(cat, ctx, action_type, gap, subject, assets)
                out.extend(built)

        out.extend(self._http_from_open_ports(cat, ctx, covered, mode))
        out.extend(self._dns_from_domains(cat, ctx, covered, mode))
        out.extend(self._from_validation(cat, ctx, covered, mode))
        out.extend(self._from_paths(cat, ctx, covered, mode))

        out = [cand for cand in out if cand.coverage_key not in covered]
        out = merge_candidates(out)
        unresolved = any(gap.kind == "host.unresolved" for gap in ctx.gaps)
        if unresolved:
            out = [cand for cand in out if cand.action_type != "subdomain_enumeration"]
        if network_blocks_ip(ctx):
            out = [cand for cand in out if cand.action_type not in IP_GATED_ACTIONS]
        return out

    def _from_gap(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        action_type: str,
        gap: GapContext,
        subject: AssetContext | None,
        assets: dict[str, AssetContext],
    ) -> list[CandidateAction]:
        mode = _parse_mode(ctx.mode)
        kind = gap.kind
        reason = f"gap={kind}"
        prereq = [kind]
        target: ActionTarget | None = None
        params: dict[str, Any] = {}

        if action_type == "port_scan":
            host = subject if subject and subject.kind == "host" else None
            live = hosts_for_ip_actions(ctx)
            if host is None and live:
                host = live[0]
            if host is None:
                return []
            address = host_address(host)
            if locator_is_obsolete(ctx, address):
                return []
            target = ActionTarget(asset_id=host.id or None, canonical_locator=address)
            params = {
                "host_id": host.id,
                "address": address,
                "ports": "top1000",
                "protocol": "tcp",
            }
        elif action_type == "dns_enumeration":
            if subject and subject.kind == "domain":
                fqdn = subject.fqdn
                if not fqdn:
                    return []
                target = ActionTarget(asset_id=subject.id or None, canonical_locator=fqdn)
                params = {"fqdn": fqdn}
            else:
                host = subject if subject else (hosts(ctx)[0] if hosts(ctx) else None)
                fqdn = (host.address if host else "") or (host.key.split(":")[-1] if host else "")
                if not fqdn:
                    return []
                target = ActionTarget(
                    asset_id=(host.id if host else None) or None, canonical_locator=fqdn
                )
                params = {"fqdn": fqdn}
        elif action_type == "service_enumeration":
            host = _host_for_port(ctx, subject, assets)
            if host is None:
                return []
            address = host_address(host)
            if locator_is_obsolete(ctx, address):
                return []
            port_num = None
            if subject and subject.kind == "port" and subject.number:
                port_num = int(subject.number)
            target = ActionTarget(asset_id=host.id or None, canonical_locator=address)
            params = {"host_id": host.id}
            if port_num:
                params["port"] = port_num
        elif action_type == "http_probe":
            built = self._http_probe_params(ctx, subject, assets)
            if built is None:
                return []
            target, params = built
        elif action_type == "technology_detection":
            url = _pick_url(ctx, subject)
            if url is None:
                return []
            locator = url.url
            target = ActionTarget(asset_id=url.id or None, canonical_locator=locator)
            params = {"url_id": url.id, "url": locator}
        elif action_type == "directory_enumeration":
            url = _pick_url(ctx, subject)
            if url is None:
                url = _url_from_service(ctx)
            if url is None:
                return []
            locator = url.url
            target = ActionTarget(asset_id=url.id or None, canonical_locator=locator)
            params = {"url_id": url.id, "url": locator, "wordlist": "small"}
            if not params.get("url_id"):
                params.pop("url_id", None)
        elif action_type == "endpoint_discovery":
            url = _probed_page(ctx)
            if url is None:
                url = _pick_url(ctx, None)
            if url is None:
                return []
            locator = url.url
            if not url.id:
                return []
            target = ActionTarget(asset_id=url.id or None, canonical_locator=locator)
            params = {"url_id": url.id, "url": locator}
        elif action_type == "subdomain_enumeration":
            domain = subject if subject and subject.kind == "domain" else None
            if domain is None and _domains(ctx):
                domain = _domains(ctx)[0]
            if domain is None:
                return []
            fqdn = domain.fqdn
            target = ActionTarget(asset_id=domain.id or None, canonical_locator=fqdn)
            params = {"domain_id": domain.id, "fqdn": fqdn, "wordlist": "default"}
        elif action_type == "network_discovery":
            nets = _networks(ctx)
            if not nets:
                return []
            cidr = nets[0].address
            target = ActionTarget(canonical_locator=cidr)
            params = {"network": cidr}
        else:
            return []

        if target is None:
            return []
        cand = self._make(
            cat,
            action_type,
            target,
            params,
            reason=reason,
            gap_kind=kind,
            gap_subject=gap.subject_id,
            prerequisites=prereq,
            covered=set(),
            mode=mode,
            source="planner",
        )
        return [cand] if cand else []

    def _http_probe_params(
        self,
        ctx: BrainContext,
        subject: AssetContext | None,
        assets: dict[str, AssetContext],
    ) -> tuple[ActionTarget, dict[str, Any]] | None:
        url = _pick_url(ctx, subject)
        if url is not None:
            locator = url.url
            return (
                ActionTarget(asset_id=url.id or None, canonical_locator=locator),
                {"url": locator},
            )
        host, port = _http_host_port(ctx, subject, assets)
        if host is None or port is None:
            return None
        address = host_address(host)
        if locator_is_obsolete(ctx, address):
            return None
        locator = _http_url(address, port)
        scheme = "https" if port in HTTPS_PORTS else "http"
        return (
            ActionTarget(asset_id=host.id or None, canonical_locator=locator),
            {"host_id": host.id, "port": port, "scheme": scheme, "url": locator},
        )

    def _http_from_open_ports(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        covered: set[str],
        mode: MissionMode,
    ) -> list[CandidateAction]:
        out: list[CandidateAction] = []
        assets = _index(ctx)
        existing_urls = {(url.host, url.port) for url in _urls(ctx)}
        for port in _ports(ctx):
            if port.state != "open":
                continue
            try:
                number = int(port.number or "0")
            except ValueError:
                continue
            if number not in HTTP_PORTS:
                continue
            host = assets.get(port.host_id)
            if host is None:
                continue
            address = host_address(host)
            if locator_is_obsolete(ctx, address):
                continue
            if (address, str(number)) in existing_urls:
                continue
            locator = _http_url(address, number)
            scheme = "https" if number in HTTPS_PORTS else "http"
            cand = self._make(
                cat,
                "http_probe",
                ActionTarget(asset_id=host.id or None, canonical_locator=locator),
                {
                    "host_id": host.id,
                    "port": number,
                    "scheme": scheme,
                    "url": locator,
                },
                reason="gap=service.http_unprobed",
                gap_kind="service.http_unprobed",
                prerequisites=["service.http_unprobed", "port.service_unknown"],
                covered=covered,
                mode=mode,
                source="planner",
            )
            if cand:
                out.append(cand)
        return out

    def _dns_from_domains(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        covered: set[str],
        mode: MissionMode,
    ) -> list[CandidateAction]:
        has_record = any(claim.predicate == "dns.record" for claim in ctx.claims)
        if has_record:
            return []
        out: list[CandidateAction] = []
        for domain in _domains(ctx):
            fqdn = domain.fqdn
            if not fqdn:
                continue
            cand = self._make(
                cat,
                "dns_enumeration",
                ActionTarget(asset_id=domain.id or None, canonical_locator=fqdn),
                {"fqdn": fqdn},
                reason="domain has no dns records",
                gap_kind="domain.subdomains_unknown",
                prerequisites=[],
                covered=covered,
                mode=mode,
                source="planner",
            )
            if cand:
                out.append(cand)
        return out

    def _from_validation(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        covered: set[str],
        mode: MissionMode,
    ) -> list[CandidateAction]:
        out: list[CandidateAction] = []
        for row in ctx.validation_candidates:
            if row.status != "proposed":
                continue
            action_type = row.action
            if action_type not in V1_ACTION_TYPES:
                continue
            if action_type == "endpoint_discovery" and (
                any(asset.kind == "endpoint" for asset in ctx.top_assets)
                or any(claim.predicate == "endpoint.seen" for claim in ctx.claims)
            ):
                continue
            locator = row.locator or row.url
            if not locator:
                continue
            if locator_is_obsolete(ctx, locator):
                continue
            params = _params_from_validation(action_type, row, locator)
            if params is None:
                continue
            target = ActionTarget(
                asset_id=row.asset_id or None,
                canonical_locator=locator,
            )
            cand = self._make(
                cat,
                action_type,
                target,
                params,
                reason=row.reason or "validation candidate",
                gap_kind="",
                prerequisites=list(cat.get(action_type).prerequisites_gap_kinds)
                if cat.get(action_type)
                else [],
                covered=covered,
                mode=mode,
                gap_subject=row.finding_id,
                source="validation",
            )
            if cand is None:
                continue
            cand = cand.model_copy(update={"expected_information_gain": 0.65})
            out.append(cand)
        return out

    def _from_paths(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        covered: set[str],
        mode: MissionMode,
    ) -> list[CandidateAction]:
        out: list[CandidateAction] = []
        for row in ctx.investigation_paths:
            if row.oos == "1":
                continue
            action_type = row.action
            if action_type not in V1_ACTION_TYPES:
                continue
            if action_type == "endpoint_discovery" and (
                any(asset.kind == "endpoint" for asset in ctx.top_assets)
                or any(claim.predicate == "endpoint.seen" for claim in ctx.claims)
            ):
                continue
            locator = row.locator or row.url or row.fqdn
            if not locator:
                continue
            if locator_is_obsolete(ctx, locator):
                continue
            params = _params_from_path(action_type, row, locator)
            if params is None:
                continue
            target = ActionTarget(
                asset_id=row.asset_id or row.host_id or row.url_id or None,
                canonical_locator=locator,
            )
            cand = self._make(
                cat,
                action_type,
                target,
                params,
                reason=row.questions or row.labels or "investigation path",
                gap_kind="",
                prerequisites=list(cat.get(action_type).prerequisites_gap_kinds)
                if cat.get(action_type)
                else [],
                covered=covered,
                mode=mode,
                gap_subject=row.id,
                source="path",
            )
            if cand is None:
                continue
            cand = cand.model_copy(update={"expected_information_gain": 0.62})
            out.append(cand)
        return out

    def _make(
        self,
        cat: ActionCatalog,
        action_type: str,
        target: ActionTarget,
        params: dict[str, Any],
        *,
        reason: str,
        gap_kind: str,
        covered: set[str],
        mode: MissionMode,
        gap_subject: str = "",
        prerequisites: list[str] | None = None,
        source: str = "planner",
    ) -> CandidateAction | None:
        spec = cat.get(action_type)
        if spec is None or not spec.enabled:
            return None
        if mode not in spec.allowed_modes:
            return None
        if action_type not in V1_ACTION_TYPES:
            return None
        clean = _validate_params(spec, params)
        if clean is None:
            return None
        key = coverage_key(action_type, target, clean)
        if key in covered:
            return None
        prereq = list(prerequisites or spec.prerequisites_gap_kinds)
        return CandidateAction(
            action_type=action_type,
            target=target,
            parameters=clean,
            coverage_key=key,
            reason=reason,
            gap_kind=gap_kind,
            gap_subject=gap_subject,
            prerequisites=prereq,
            expected_information_gain=0.8,
            risk=spec.risk.value,
            cost=spec.cost,
            catalog_index=list(V1_ACTION_TYPES).index(action_type),
            timeout_s=spec.default_timeout_s,
            source=source,
        )


def _validate_params(spec: ActionSpec, params: dict[str, Any]) -> dict[str, Any] | None:
    try:
        parsed = spec.parameter_schema.model_validate(params)
    except (ValidationError, DomainValidationError):
        return None
    return parsed.model_dump()


def _params_from_validation(
    action_type: str, row: ValidationContext | PathContext, locator: str
) -> dict[str, Any] | None:
    if action_type == "http_probe":
        return {"url": row.url or locator}
    if action_type == "technology_detection":
        params: dict[str, Any] = {"url": row.url or locator}
        if row.url_id:
            params["url_id"] = row.url_id
        return params
    if action_type == "endpoint_discovery":
        params = {"url": row.url or locator}
        if row.url_id:
            params["url_id"] = row.url_id
        return params
    if action_type == "service_enumeration":
        host_id = row.host_id
        if not host_id:
            return None
        params = {"host_id": host_id}
        if row.port:
            try:
                params["port"] = int(row.port)
            except ValueError:
                return None
        return params
    return None


def _params_from_path(action_type: str, row: PathContext, locator: str) -> dict[str, Any] | None:
    shared = _params_from_validation(action_type, row, locator)
    if shared is not None:
        return shared
    if action_type == "port_scan":
        host_id = row.host_id or row.asset_id
        if not host_id:
            return None
        return {
            "host_id": host_id,
            "address": locator,
            "ports": "top1000",
            "protocol": "tcp",
        }
    if action_type == "dns_enumeration":
        fqdn = row.fqdn or locator
        if not fqdn:
            return None
        return {"fqdn": fqdn}
    if action_type == "subdomain_enumeration":
        domain_id = row.domain_id or row.asset_id
        fqdn = row.fqdn or locator
        if not domain_id or not fqdn:
            return None
        return {"domain_id": domain_id, "fqdn": fqdn, "wordlist": "default"}
    if action_type == "directory_enumeration":
        params: dict[str, Any] = {"url": row.url or locator, "wordlist": "small"}
        if row.url_id:
            params["url_id"] = row.url_id
        return params
    return None


def _parse_mode(value: str) -> MissionMode:
    try:
        return MissionMode(value)
    except ValueError:
        return MissionMode.CTF


def _host_for_port(
    ctx: BrainContext,
    subject: AssetContext | None,
    assets: dict[str, AssetContext],
) -> AssetContext | None:
    if subject and subject.kind == "host":
        return subject
    if subject and subject.kind == "port":
        host = assets.get(subject.host_id)
        if host:
            return host
    live = hosts(ctx)
    return live[0] if live else None


def _pick_url(ctx: BrainContext, subject: AssetContext | None) -> AssetContext | None:
    if subject and subject.kind == "url":
        return subject
    if subject and subject.kind == "endpoint":
        key = subject.url
        for url in _urls(ctx):
            if url.key == key or url.url == key:
                return url
    urls = _urls(ctx)
    if not urls:
        return None
    rooted = [url for url in urls if url.path in {"", "/"}]
    return rooted[0] if rooted else urls[0]


def _probed_page(ctx: BrainContext) -> AssetContext | None:
    probed = [url for url in _urls(ctx) if url.http_status and url.http_status not in {"", "0"}]
    if not probed:
        return None
    rooted = [url for url in probed if url.path in {"", "/"}]
    return rooted[0] if rooted else probed[0]


def _url_from_service(ctx: BrainContext) -> AssetContext | None:
    urls = _urls(ctx)
    return urls[0] if urls else None


def _http_host_port(
    ctx: BrainContext,
    subject: AssetContext | None,
    assets: dict[str, AssetContext],
) -> tuple[AssetContext | None, int | None]:
    live = hosts(ctx)
    if subject and subject.kind == "port":
        host = assets.get(subject.host_id)
        try:
            number = int(subject.number or "0")
        except ValueError:
            number = 0
        return host, number or None
    if subject and subject.kind == "service":
        for port in _ports(ctx):
            if port.id == subject.port_id:
                host = assets.get(port.host_id)
                return host, int(port.number or "80")
        host = live[0] if live else None
        return host, 80
    host = live[0] if live else None
    for port in _ports(ctx):
        if port.state == "open":
            try:
                number = int(port.number or "0")
            except ValueError:
                continue
            if number in HTTP_PORTS:
                return host, number
    return host, None
