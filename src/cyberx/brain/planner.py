"""Deterministic Planner. Catalog-only candidates; no new action types."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from cyberx.actions.catalog import DEFAULT_CATALOG, ActionCatalog
from cyberx.actions.coverage import coverage_key
from cyberx.actions.specs import ActionSpec
from cyberx.brain.types import CandidateAction
from cyberx.domain.enums import V1_ACTION_TYPES, MissionMode
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.models.actions import ActionTarget
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
_BLOCKING_REACHABILITY = frozenset({"ROUTE_MISSING", "UNREACHABLE", "BLOCKED"})


def _index(ctx: BrainContext) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for row in ctx.top_assets:
        if row.get("id"):
            out[row["id"]] = row
        if row.get("key"):
            out[row["key"]] = row
    return out


def _hosts(ctx: BrainContext) -> list[dict[str, str]]:
    return [r for r in ctx.top_assets if r.get("kind") == "host"]


def _obsolete_locators(ctx: BrainContext) -> set[str]:
    ident = ctx.target_identity or {}
    current = ident.get("current") or ""
    tokens = [p for p in (ident.get("historical") or "").split(",") if p]
    out = {p for p in tokens if p != current}
    previous = ident.get("previous") or ""
    if previous and previous != current:
        out.add(previous)
    return out


def _hosts_for_ip_actions(ctx: BrainContext) -> list[dict[str, str]]:
    obsolete = _obsolete_locators(ctx)
    current = (ctx.target_identity or {}).get("current") or ctx.network.get("target_ip") or ""
    live: list[dict[str, str]] = []
    for host in _hosts(ctx):
        labels = host.get("labels") or ""
        if "historical" in labels.split(","):
            continue
        addr = _host_address(host)
        if addr in obsolete:
            continue
        live.append(host)
    if current:
        matching = [h for h in live if _host_address(h) == current]
        if matching:
            return matching
    return live


def _locator_obsolete(ctx: BrainContext, locator: str) -> bool:
    if not locator:
        return False
    return locator in _obsolete_locators(ctx)


def _ports(ctx: BrainContext) -> list[dict[str, str]]:
    return [r for r in ctx.top_assets if r.get("kind") == "port"]


def _services(ctx: BrainContext) -> list[dict[str, str]]:
    return [r for r in ctx.top_assets if r.get("kind") == "service"]


def _urls(ctx: BrainContext) -> list[dict[str, str]]:
    return [r for r in ctx.top_assets if r.get("kind") == "url"]


def _domains(ctx: BrainContext) -> list[dict[str, str]]:
    return [r for r in ctx.top_assets if r.get("kind") == "domain"]


def _networks(ctx: BrainContext) -> list[dict[str, str]]:
    return [r for r in ctx.top_assets if r.get("kind") == "network"]


def _host_address(host: dict[str, str]) -> str:
    return host.get("address") or host.get("key", "").split(":")[-1]


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
        seen_keys: set[str] = set(ctx.coverage_keys)
        mode = _parse_mode(ctx.mode)
        out: list[CandidateAction] = []
        assets = _index(ctx)

        if not _hosts(ctx):
            for net in _networks(ctx):
                cand = self._make(
                    cat,
                    "network_discovery",
                    ActionTarget(canonical_locator=net.get("address") or ""),
                    {"network": net.get("address") or ""},
                    reason="no hosts discovered",
                    gap_kind="host.unresolved",
                    seen_keys=seen_keys,
                    mode=mode,
                )
                if cand:
                    out.append(cand)

        for gap in ctx.gaps:
            kind = gap.get("kind") or ""
            types = GAP_ACTIONS.get(kind, ())
            subject = assets.get(gap.get("subject_id") or "") or assets.get(
                gap.get("subject_key") or ""
            )
            for action_type in types:
                built = self._from_gap(cat, ctx, action_type, gap, subject, assets)
                for cand in built:
                    if cand.coverage_key in seen_keys:
                        continue
                    seen_keys.add(cand.coverage_key)
                    out.append(cand)

        for extra in self._http_from_open_ports(cat, ctx, seen_keys, mode):
            out.append(extra)
            seen_keys.add(extra.coverage_key)

        for extra in self._dns_from_domains(cat, ctx, seen_keys, mode):
            out.append(extra)
            seen_keys.add(extra.coverage_key)

        for extra in self._from_validation(cat, ctx, seen_keys, mode):
            out.append(extra)
            seen_keys.add(extra.coverage_key)

        for extra in self._from_paths(cat, ctx, seen_keys, mode):
            out.append(extra)
            seen_keys.add(extra.coverage_key)

        unresolved = any(g.get("kind") == "host.unresolved" for g in ctx.gaps)
        if unresolved:
            out = [c for c in out if c.action_type != "subdomain_enumeration"]
        if _network_blocks_ip(ctx):
            out = [c for c in out if c.action_type not in IP_GATED_ACTIONS]
        return out

    def _from_gap(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        action_type: str,
        gap: dict[str, str],
        subject: dict[str, str] | None,
        assets: dict[str, dict[str, str]],
    ) -> list[CandidateAction]:
        mode = _parse_mode(ctx.mode)
        kind = gap.get("kind") or ""
        reason = f"gap={kind}"
        prereq = [kind]
        target: ActionTarget | None = None
        params: dict[str, Any] = {}

        if action_type == "port_scan":
            host = subject if subject and subject.get("kind") == "host" else None
            if host is None and _hosts_for_ip_actions(ctx):
                host = _hosts_for_ip_actions(ctx)[0]
            if host is None:
                return []
            address = _host_address(host)
            if _locator_obsolete(ctx, address):
                return []
            target = ActionTarget(asset_id=host.get("id") or None, canonical_locator=address)
            params = {
                "host_id": host["id"],
                "address": address,
                "ports": "top1000",
                "protocol": "tcp",
            }
        elif action_type == "dns_enumeration":
            if subject and subject.get("kind") == "domain":
                fqdn = subject.get("fqdn") or ""
                if not fqdn:
                    return []
                target = ActionTarget(asset_id=subject.get("id") or None, canonical_locator=fqdn)
                params = {"fqdn": fqdn}
            else:
                host = subject if subject else (_hosts(ctx)[0] if _hosts(ctx) else None)
                fqdn = (host or {}).get("address") or (host or {}).get("key", "").split(":")[-1]
                if not fqdn:
                    return []
                target = ActionTarget(
                    asset_id=(host or {}).get("id") or None, canonical_locator=fqdn
                )
                params = {"fqdn": fqdn}
        elif action_type == "service_enumeration":
            host = _host_for_port(ctx, subject, assets)
            if host is None:
                return []
            address = _host_address(host)
            if _locator_obsolete(ctx, address):
                return []
            port_num = None
            if subject and subject.get("kind") == "port" and subject.get("number"):
                port_num = int(subject["number"])
            target = ActionTarget(asset_id=host.get("id") or None, canonical_locator=address)
            params = {"host_id": host["id"]}
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
            locator = url.get("url") or ""
            target = ActionTarget(asset_id=url.get("id") or None, canonical_locator=locator)
            params = {"url_id": url["id"], "url": locator}
        elif action_type == "directory_enumeration":
            url = _pick_url(ctx, subject)
            if url is None:
                url = _url_from_service(ctx, subject, assets)
            if url is None:
                return []
            locator = url.get("url") or ""
            target = ActionTarget(asset_id=url.get("id") or None, canonical_locator=locator)
            params = {"url_id": url.get("id"), "url": locator, "wordlist": "small"}
            if not params.get("url_id"):
                params.pop("url_id", None)
        elif action_type == "endpoint_discovery":
            url = _probed_page(ctx)
            if url is None:
                url = _pick_url(ctx, None)
            if url is None:
                return []
            locator = url.get("url") or ""
            if not url.get("id"):
                return []
            target = ActionTarget(asset_id=url.get("id") or None, canonical_locator=locator)
            params = {"url_id": url["id"], "url": locator}
        elif action_type == "subdomain_enumeration":
            domain = subject if subject and subject.get("kind") == "domain" else None
            if domain is None and _domains(ctx):
                domain = _domains(ctx)[0]
            if domain is None:
                return []
            fqdn = domain.get("fqdn") or ""
            target = ActionTarget(asset_id=domain.get("id") or None, canonical_locator=fqdn)
            params = {"domain_id": domain["id"], "fqdn": fqdn, "wordlist": "default"}
        elif action_type == "network_discovery":
            nets = _networks(ctx)
            if not nets:
                return []
            cidr = nets[0].get("address") or ""
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
            gap_subject=gap.get("subject_id") or "",
            prerequisites=prereq,
            seen_keys=set(),
            mode=mode,
        )
        return [cand] if cand else []

    def _http_probe_params(
        self,
        ctx: BrainContext,
        subject: dict[str, str] | None,
        assets: dict[str, dict[str, str]],
    ) -> tuple[ActionTarget, dict[str, Any]] | None:
        url = _pick_url(ctx, subject)
        if url is not None:
            locator = url.get("url") or ""
            return (
                ActionTarget(asset_id=url.get("id") or None, canonical_locator=locator),
                {"url": locator},
            )
        host, port = _http_host_port(ctx, subject, assets)
        if host is None or port is None:
            return None
        address = _host_address(host)
        if _locator_obsolete(ctx, address):
            return None
        locator = _http_url(address, port)
        scheme = "https" if port in HTTPS_PORTS else "http"
        return (
            ActionTarget(asset_id=host.get("id") or None, canonical_locator=locator),
            {"host_id": host["id"], "port": port, "scheme": scheme, "url": locator},
        )

    def _http_from_open_ports(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        seen_keys: set[str],
        mode: MissionMode,
    ) -> list[CandidateAction]:
        out: list[CandidateAction] = []
        assets = _index(ctx)
        existing_urls = {(u.get("host"), u.get("port")) for u in _urls(ctx)}
        for port in _ports(ctx):
            if port.get("state") != "open":
                continue
            try:
                number = int(port.get("number") or "0")
            except ValueError:
                continue
            if number not in HTTP_PORTS:
                continue
            host = assets.get(port.get("host_id") or "")
            if host is None:
                continue
            address = _host_address(host)
            if _locator_obsolete(ctx, address):
                continue
            if (address, str(number)) in existing_urls:
                continue
            locator = _http_url(address, number)
            scheme = "https" if number in HTTPS_PORTS else "http"
            cand = self._make(
                cat,
                "http_probe",
                ActionTarget(asset_id=host.get("id") or None, canonical_locator=locator),
                {
                    "host_id": host["id"],
                    "port": number,
                    "scheme": scheme,
                    "url": locator,
                },
                reason="gap=service.http_unprobed",
                gap_kind="service.http_unprobed",
                prerequisites=["service.http_unprobed", "port.service_unknown"],
                seen_keys=seen_keys,
                mode=mode,
            )
            if cand:
                out.append(cand)
                seen_keys.add(cand.coverage_key)
        return out

    def _dns_from_domains(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        seen_keys: set[str],
        mode: MissionMode,
    ) -> list[CandidateAction]:
        has_record = any(c.get("predicate") == "dns.record" for c in ctx.claims)
        if has_record:
            return []
        out: list[CandidateAction] = []
        for domain in _domains(ctx):
            fqdn = domain.get("fqdn") or ""
            if not fqdn:
                continue
            cand = self._make(
                cat,
                "dns_enumeration",
                ActionTarget(asset_id=domain.get("id") or None, canonical_locator=fqdn),
                {"fqdn": fqdn},
                reason="domain has no dns records",
                gap_kind="domain.subdomains_unknown",
                prerequisites=[],
                seen_keys=seen_keys,
                mode=mode,
            )
            if cand:
                out.append(cand)
        return out

    def _from_validation(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        seen_keys: set[str],
        mode: MissionMode,
    ) -> list[CandidateAction]:
        out: list[CandidateAction] = []
        for row in ctx.validation_candidates:
            if row.get("status") != "proposed":
                continue
            action_type = row.get("action") or ""
            if action_type not in V1_ACTION_TYPES:
                continue
            if action_type == "endpoint_discovery" and (
                any(a.get("kind") == "endpoint" for a in ctx.top_assets)
                or any(c.get("predicate") == "endpoint.seen" for c in ctx.claims)
            ):
                continue
            locator = row.get("locator") or row.get("url") or ""
            if not locator:
                continue
            if _locator_obsolete(ctx, locator):
                continue
            params = _params_from_validation(action_type, row, locator)
            if params is None:
                continue
            target = ActionTarget(
                asset_id=row.get("asset_id") or None,
                canonical_locator=locator,
            )
            cand = self._make(
                cat,
                action_type,
                target,
                params,
                reason=row.get("reason") or "validation candidate",
                gap_kind="",
                prerequisites=list(cat.get(action_type).prerequisites_gap_kinds)
                if cat.get(action_type)
                else [],
                seen_keys=seen_keys,
                mode=mode,
                gap_subject=row.get("finding_id") or "",
            )
            if cand is None:
                continue
            cand = cand.model_copy(update={"expected_information_gain": 0.65})
            out.append(cand)
            seen_keys.add(cand.coverage_key)
        return out

    def _from_paths(
        self,
        cat: ActionCatalog,
        ctx: BrainContext,
        seen_keys: set[str],
        mode: MissionMode,
    ) -> list[CandidateAction]:
        out: list[CandidateAction] = []
        for row in ctx.investigation_paths:
            if row.get("oos") == "1":
                continue
            action_type = row.get("action") or ""
            if action_type not in V1_ACTION_TYPES:
                continue
            if action_type == "endpoint_discovery" and (
                any(a.get("kind") == "endpoint" for a in ctx.top_assets)
                or any(c.get("predicate") == "endpoint.seen" for c in ctx.claims)
            ):
                continue
            locator = row.get("locator") or row.get("url") or row.get("fqdn") or ""
            if not locator:
                continue
            if _locator_obsolete(ctx, locator):
                continue
            params = _params_from_path(action_type, row, locator)
            if params is None:
                continue
            target = ActionTarget(
                asset_id=row.get("asset_id") or row.get("host_id") or row.get("url_id") or None,
                canonical_locator=locator,
            )
            cand = self._make(
                cat,
                action_type,
                target,
                params,
                reason=row.get("questions") or row.get("labels") or "investigation path",
                gap_kind="",
                prerequisites=list(cat.get(action_type).prerequisites_gap_kinds)
                if cat.get(action_type)
                else [],
                seen_keys=seen_keys,
                mode=mode,
                gap_subject=row.get("id") or "",
            )
            if cand is None:
                continue
            cand = cand.model_copy(update={"expected_information_gain": 0.62})
            out.append(cand)
            seen_keys.add(cand.coverage_key)
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
        seen_keys: set[str],
        mode: MissionMode,
        gap_subject: str = "",
        prerequisites: list[str] | None = None,
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
        if key in seen_keys:
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
        )


def _network_blocks_ip(ctx: BrainContext) -> bool:
    net = ctx.network or {}
    return net.get("reachability") in _BLOCKING_REACHABILITY


def _validate_params(spec: ActionSpec, params: dict[str, Any]) -> dict[str, Any] | None:
    try:
        parsed = spec.parameter_schema.model_validate(params)
    except (ValidationError, DomainValidationError):
        return None
    return parsed.model_dump()


def _params_from_validation(
    action_type: str, row: dict[str, str], locator: str
) -> dict[str, Any] | None:
    if action_type == "http_probe":
        return {"url": row.get("url") or locator}
    if action_type == "technology_detection":
        params: dict[str, Any] = {"url": row.get("url") or locator}
        if row.get("url_id"):
            params["url_id"] = row["url_id"]
        return params
    if action_type == "endpoint_discovery":
        params = {"url": row.get("url") or locator}
        if row.get("url_id"):
            params["url_id"] = row["url_id"]
        return params
    if action_type == "service_enumeration":
        host_id = row.get("host_id") or ""
        if not host_id:
            return None
        params = {"host_id": host_id}
        if row.get("port"):
            try:
                params["port"] = int(row["port"])
            except ValueError:
                return None
        return params
    return None


def _params_from_path(action_type: str, row: dict[str, str], locator: str) -> dict[str, Any] | None:
    shared = _params_from_validation(action_type, row, locator)
    if shared is not None:
        return shared
    if action_type == "port_scan":
        host_id = row.get("host_id") or row.get("asset_id") or ""
        if not host_id:
            return None
        return {
            "host_id": host_id,
            "address": locator,
            "ports": "top1000",
            "protocol": "tcp",
        }
    if action_type == "dns_enumeration":
        fqdn = row.get("fqdn") or locator
        if not fqdn:
            return None
        return {"fqdn": fqdn}
    if action_type == "subdomain_enumeration":
        domain_id = row.get("domain_id") or row.get("asset_id") or ""
        fqdn = row.get("fqdn") or locator
        if not domain_id or not fqdn:
            return None
        return {"domain_id": domain_id, "fqdn": fqdn, "wordlist": "default"}
    if action_type == "directory_enumeration":
        params: dict[str, Any] = {"url": row.get("url") or locator, "wordlist": "small"}
        if row.get("url_id"):
            params["url_id"] = row["url_id"]
        return params
    return None


def _parse_mode(value: str) -> MissionMode:
    try:
        return MissionMode(value)
    except ValueError:
        return MissionMode.CTF


def _host_for_port(
    ctx: BrainContext,
    subject: dict[str, str] | None,
    assets: dict[str, dict[str, str]],
) -> dict[str, str] | None:
    if subject and subject.get("kind") == "host":
        return subject
    if subject and subject.get("kind") == "port":
        host = assets.get(subject.get("host_id") or "")
        if host:
            return host
    return _hosts(ctx)[0] if _hosts(ctx) else None


def _pick_url(ctx: BrainContext, subject: dict[str, str] | None) -> dict[str, str] | None:
    if subject and subject.get("kind") == "url":
        return subject
    if subject and subject.get("kind") == "endpoint":
        key = subject.get("url") or ""
        for url in _urls(ctx):
            if url.get("key") == key or url.get("url") == key:
                return url
    urls = _urls(ctx)
    if not urls:
        return None
    rooted = [u for u in urls if u.get("path") in {"", "/"}]
    return rooted[0] if rooted else urls[0]


def _probed_page(ctx: BrainContext) -> dict[str, str] | None:
    probed = [
        u for u in _urls(ctx) if u.get("http_status") and u.get("http_status") not in {"", "0"}
    ]
    if not probed:
        return None
    rooted = [u for u in probed if u.get("path") in {"", "/"}]
    return rooted[0] if rooted else probed[0]


def _url_from_service(
    ctx: BrainContext,
    subject: dict[str, str] | None,
    assets: dict[str, dict[str, str]],
) -> dict[str, str] | None:
    del subject, assets
    return _urls(ctx)[0] if _urls(ctx) else None


def _http_host_port(
    ctx: BrainContext,
    subject: dict[str, str] | None,
    assets: dict[str, dict[str, str]],
) -> tuple[dict[str, str] | None, int | None]:
    if subject and subject.get("kind") == "port":
        host = assets.get(subject.get("host_id") or "")
        try:
            number = int(subject.get("number") or "0")
        except ValueError:
            number = 0
        return host, number or None
    if subject and subject.get("kind") == "service":
        for port in _ports(ctx):
            if port.get("id") == subject.get("port_id"):
                host = assets.get(port.get("host_id") or "")
                return host, int(port.get("number") or "80")
        host = _hosts(ctx)[0] if _hosts(ctx) else None
        return host, 80
    host = _hosts(ctx)[0] if _hosts(ctx) else None
    for port in _ports(ctx):
        if port.get("state") == "open":
            try:
                number = int(port.get("number") or "0")
            except ValueError:
                continue
            if number in HTTP_PORTS:
                return host, number
    return host, None
