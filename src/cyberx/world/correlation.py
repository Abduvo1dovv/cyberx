"""Deterministic CorrelationEngine (SPEC §7.3, §3.8). No AI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from cyberx.domain.enums import (
    AddressType,
    AssetKind,
    AuthSurfaceKind,
    EpistemicStatus,
    HttpMethod,
    ParamLocation,
    PortState,
    SubdomainSource,
    TechSource,
    TransportProtocol,
)
from cyberx.domain.errors import IdentityError, WorldModelError
from cyberx.domain.identity import (
    auth_key,
    host_key_name,
    iface_key,
    param_key,
    product_slug,
    tech_key,
)
from cyberx.domain.ids import (
    PREFIX_AUTH,
    PREFIX_DOMAIN,
    PREFIX_ENDPOINT,
    PREFIX_HOST,
    PREFIX_INTERFACE,
    PREFIX_PARAMETER,
    PREFIX_PORT,
    PREFIX_SERVICE,
    PREFIX_SUBDOMAIN,
    PREFIX_TECH,
    PREFIX_URL,
    new_id,
)
from cyberx.domain.models.assets import (
    Asset,
    AuthenticationSurface,
    Domain,
    Endpoint,
    Host,
    NetworkInterface,
    Parameter,
    Port,
    Service,
    Subdomain,
    Technology,
    UrlAsset,
)
from cyberx.domain.models.evidence import Evidence
from cyberx.domain.time import utcnow
from cyberx.world.keys import SubjectRef, parent_domain_fqdn, parse_subject_hint


class AssetLookup(Protocol):
    def peek_asset(self, canonical_key: str) -> Asset | None: ...


class ScopeGate(Protocol):
    def out_of_scope(self, canonical_key: str) -> bool: ...


@dataclass
class BoundEvidence:
    evidence: Evidence
    predicate: str
    object: Any
    subject: SubjectRef
    assets: list[Asset] = field(default_factory=list)
    subject_asset: Asset | None = None
    mapped: bool = True
    out_of_scope: bool = False


class CorrelationEngine:
    """Map subject_hint → canonical assets. get_or_create under the mission lock."""

    def correlate(
        self,
        evidence: Evidence,
        lookup: AssetLookup,
        *,
        scope_gate: ScopeGate | None = None,
        now: datetime | None = None,
    ) -> BoundEvidence:
        preview = evidence.claim_preview or {}
        predicate = str(preview.get("predicate") or "")
        obj = preview.get("object")
        hint = str(preview.get("subject_hint") or "")
        mapped = bool(preview.get("mapped", True))
        try:
            subject = parse_subject_hint(hint)
        except IdentityError as exc:
            raise WorldModelError(f"unparseable subject_hint: {hint}") from exc
        moment = now or utcnow()
        pending: dict[str, Asset] = {}
        assets = self._chain(
            subject,
            evidence.mission_id,
            moment,
            lookup,
            pending,
            scope_gate,
            predicate=predicate,
            obj=obj,
        )
        assets.extend(
            self._extras(
                predicate,
                obj,
                subject,
                evidence.mission_id,
                moment,
                lookup,
                pending,
                scope_gate,
            )
        )
        subject_asset = pending.get(subject.canonical_key)
        oos = any(a.out_of_scope for a in assets)
        return BoundEvidence(
            evidence=evidence,
            predicate=predicate,
            object=obj,
            subject=subject,
            assets=assets,
            subject_asset=subject_asset,
            mapped=mapped,
            out_of_scope=oos,
        )

    def _resolve(
        self,
        key: str,
        factory,
        lookup: AssetLookup,
        pending: dict[str, Asset],
    ) -> Asset:
        if key in pending:
            return pending[key]
        existing = lookup.peek_asset(key)
        if existing is not None:
            pending[key] = existing
            return existing
        asset = factory()
        pending[key] = asset
        return asset

    def _oos(self, key: str, gate: ScopeGate | None) -> bool:
        if gate is None:
            return False
        return bool(gate.out_of_scope(key))

    def _chain(
        self,
        ref: SubjectRef,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
        *,
        predicate: str,
        obj: Any,
    ) -> list[Asset]:
        order: list[Asset] = []

        def add(asset: Asset) -> Asset:
            if asset.canonical_key not in {a.canonical_key for a in order}:
                order.append(asset)
            return asset

        host: Host | None = None
        if ref.host_key:
            host = self._host(ref, mission_id, now, lookup, pending, gate)
            add(host)
            iface = self._iface(host, mission_id, now, lookup, pending, gate)
            if iface is not None:
                add(iface)

        if ref.kind is AssetKind.PORT or ref.port_key:
            if host is None and ref.host_key:
                host = self._host(ref, mission_id, now, lookup, pending, gate)
                add(host)
            if ref.port_key and host is not None:
                add(self._port(ref, host, mission_id, now, lookup, pending, gate))

        if ref.kind is AssetKind.SERVICE or ref.service_key:
            port_asset = pending.get(ref.port_key or "")
            if isinstance(port_asset, Port):
                add(self._service(ref, port_asset, mission_id, now, lookup, pending, gate))

        if ref.domain_key:
            add(self._domain(ref, mission_id, now, lookup, pending, gate))

        if ref.kind is AssetKind.SUBDOMAIN:
            domain = pending.get(ref.domain_key or "")
            if isinstance(domain, Domain):
                add(self._subdomain(ref, domain, mission_id, now, lookup, pending, gate))

        if ref.url_key or ref.kind is AssetKind.URL:
            add(self._url(ref, mission_id, now, lookup, pending, gate, host))

        if ref.kind is AssetKind.ENDPOINT or ref.endpoint_key:
            url_asset = pending.get(ref.url_key or "")
            if isinstance(url_asset, UrlAsset) and ref.endpoint_key:
                add(self._endpoint(ref, url_asset, mission_id, now, lookup, pending, gate))

        if ref.kind is AssetKind.PARAMETER and ref.param_name:
            ep = pending.get(ref.endpoint_key or "")
            if isinstance(ep, Endpoint):
                add(self._parameter(ref, ep, mission_id, now, lookup, pending, gate))

        if ref.kind is AssetKind.AUTH_SURFACE:
            add(self._auth(ref, mission_id, now, lookup, pending, gate))

        if ref.kind is AssetKind.TECHNOLOGY and ref.parent_canonical:
            parent = pending.get(ref.parent_canonical)
            if parent is None and ref.url_key:
                parent = pending.get(ref.url_key)
            if parent is not None:
                add(self._tech(ref, parent, mission_id, now, lookup, pending, gate))

        if ref.kind is AssetKind.HOST and host is not None:
            add(host)

        if predicate == "host.hostname" and isinstance(obj, str) and host is not None:
            alias = self._alias_name_host(obj, host, mission_id, now, lookup, pending, gate)
            if alias is not None:
                add(alias)

        return order

    def _extras(
        self,
        predicate: str,
        obj: Any,
        ref: SubjectRef,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> list[Asset]:
        extra: list[Asset] = []
        if predicate == "http.tech" and isinstance(obj, dict):
            parent = pending.get(ref.canonical_key)
            if parent is None and ref.url_key:
                parent = pending.get(ref.url_key)
            if parent is not None:
                product = str(obj.get("product") or "")
                version = obj.get("version")
                version_s = str(version) if version else None
                if product:
                    tref = SubjectRef(
                        kind=AssetKind.TECHNOLOGY,
                        canonical_key=tech_key(parent.canonical_key, product, version_s),
                        parent_canonical=parent.canonical_key,
                        product=product_slug(product),
                        version=version_s,
                    )
                    extra.append(self._tech(tref, parent, mission_id, now, lookup, pending, gate))
        if predicate == "param.seen":
            ep = pending.get(ref.canonical_key)
            if isinstance(ep, Endpoint) and isinstance(obj, dict):
                name = str(obj.get("name") or "")
                location = str(obj.get("location") or "query")
                if name:
                    pref = SubjectRef(
                        kind=AssetKind.PARAMETER,
                        canonical_key=param_key(ep.canonical_key, location, name),
                        endpoint_key=ep.canonical_key,
                        param_name=name,
                        param_location=location,
                        parent_canonical=ep.canonical_key,
                    )
                    extra.append(self._parameter(pref, ep, mission_id, now, lookup, pending, gate))
        if predicate == "auth.seen":
            kind = str(obj) if not isinstance(obj, dict) else str(obj.get("kind") or obj)
            parent = pending.get(ref.canonical_key)
            if parent is not None and kind:
                aref = SubjectRef(
                    kind=AssetKind.AUTH_SURFACE,
                    canonical_key=auth_key(parent.canonical_key, kind),
                    auth_kind=kind,
                    endpoint_key=parent.canonical_key
                    if parent.canonical_key.startswith("ep:")
                    else None,
                    url_key=parent.canonical_key
                    if parent.canonical_key.startswith("url:")
                    else None,
                    parent_canonical=parent.canonical_key,
                )
                extra.append(self._auth(aref, mission_id, now, lookup, pending, gate))
        if predicate == "service.product" and isinstance(obj, str):
            parent = pending.get(ref.canonical_key)
            if isinstance(parent, Service):
                tref = SubjectRef(
                    kind=AssetKind.TECHNOLOGY,
                    canonical_key=tech_key(parent.canonical_key, obj, None),
                    parent_canonical=parent.canonical_key,
                    product=product_slug(obj),
                )
                extra.append(self._tech(tref, parent, mission_id, now, lookup, pending, gate))
        return extra

    def _host(
        self,
        ref: SubjectRef,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> Host:
        key = ref.host_key or ref.canonical_key

        def factory() -> Host:
            if ref.ipv4:
                addr_type, ipv4, ipv6, hostname = AddressType.IPV4, ref.ipv4, None, None
                display = ref.ipv4
            elif ref.ipv6:
                addr_type, ipv4, ipv6, hostname = AddressType.IPV6, None, ref.ipv6, None
                display = ref.ipv6
            else:
                addr_type = AddressType.NAME
                ipv4, ipv6, hostname = None, None, ref.hostname or ref.host
                display = hostname or key
            return Host(
                asset_id=new_id(PREFIX_HOST),
                mission_id=mission_id,
                kind=AssetKind.HOST,
                canonical_key=key,
                display_name=display or key,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.KNOWN,
                address_type=addr_type,
                ipv4=ipv4,
                ipv6=ipv6,
                hostname=hostname,
                out_of_scope=self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, Host):
            raise WorldModelError(f"expected Host at {key}")
        return asset

    def _iface(
        self,
        host: Host,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> NetworkInterface | None:
        ip = host.ipv4 or host.ipv6
        if not ip:
            return None
        key = iface_key(host.canonical_key, ip)

        def factory() -> NetworkInterface:
            return NetworkInterface(
                asset_id=new_id(PREFIX_INTERFACE),
                mission_id=mission_id,
                kind=AssetKind.INTERFACE,
                canonical_key=key,
                display_name=ip,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=host.epistemic_status,
                host_id=host.asset_id,
                ip=ip,
                family=4 if host.ipv4 else 6,
                host_canonical=host.canonical_key,
                parent_asset_id=host.asset_id,
                out_of_scope=host.out_of_scope or self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        return asset if isinstance(asset, NetworkInterface) else None

    def _port(
        self,
        ref: SubjectRef,
        host: Host,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> Port:
        key = ref.port_key or ref.canonical_key
        proto = ref.protocol or "tcp"
        number = ref.number or 0

        def factory() -> Port:
            return Port(
                asset_id=new_id(PREFIX_PORT),
                mission_id=mission_id,
                kind=AssetKind.PORT,
                canonical_key=key,
                display_name=f"{number}/{proto}",
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.KNOWN,
                host_id=host.asset_id,
                protocol=TransportProtocol(proto),
                number=number,
                state=PortState.UNKNOWN,
                host_canonical=host.canonical_key,
                parent_asset_id=host.asset_id,
                out_of_scope=host.out_of_scope or self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, Port):
            raise WorldModelError(f"expected Port at {key}")
        return asset

    def _service(
        self,
        ref: SubjectRef,
        port: Port,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> Service:
        key = ref.service_key or ref.canonical_key

        def factory() -> Service:
            return Service(
                asset_id=new_id(PREFIX_SERVICE),
                mission_id=mission_id,
                kind=AssetKind.SERVICE,
                canonical_key=key,
                display_name="unknown",
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.KNOWN,
                port_id=port.asset_id,
                name="unknown",
                port_canonical=port.canonical_key,
                parent_asset_id=port.asset_id,
                out_of_scope=port.out_of_scope or self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, Service):
            raise WorldModelError(f"expected Service at {key}")
        return asset

    def _domain(
        self,
        ref: SubjectRef,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> Domain:
        key = ref.domain_key or ref.canonical_key
        fqdn = ref.fqdn
        if ref.kind is AssetKind.SUBDOMAIN:
            fqdn = parent_domain_fqdn(ref.fqdn or "")

        def factory() -> Domain:
            return Domain(
                asset_id=new_id(PREFIX_DOMAIN),
                mission_id=mission_id,
                kind=AssetKind.DOMAIN,
                canonical_key=key,
                display_name=fqdn or key,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.KNOWN,
                fqdn=fqdn or key.split(":", 1)[-1],
                out_of_scope=self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, Domain):
            raise WorldModelError(f"expected Domain at {key}")
        return asset

    def _subdomain(
        self,
        ref: SubjectRef,
        domain: Domain,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> Subdomain:
        key = ref.canonical_key

        def factory() -> Subdomain:
            return Subdomain(
                asset_id=new_id(PREFIX_SUBDOMAIN),
                mission_id=mission_id,
                kind=AssetKind.SUBDOMAIN,
                canonical_key=key,
                display_name=ref.fqdn or key,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.KNOWN,
                fqdn=ref.fqdn or "",
                domain_id=domain.asset_id,
                domain_fqdn=domain.fqdn,
                source=SubdomainSource.ENUM,
                parent_asset_id=domain.asset_id,
                out_of_scope=domain.out_of_scope or self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, Subdomain):
            raise WorldModelError(f"expected Subdomain at {key}")
        return asset

    def _url(
        self,
        ref: SubjectRef,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
        host: Host | None,
    ) -> UrlAsset:
        key = ref.url_key or ref.canonical_key
        scheme = ref.scheme or "http"
        host_s = ref.host or (host.display_name if host else "")
        port_n = ref.port_number or (443 if scheme == "https" else 80)
        path = ref.path or "/"

        def factory() -> UrlAsset:
            return UrlAsset(
                asset_id=new_id(PREFIX_URL),
                mission_id=mission_id,
                kind=AssetKind.URL,
                canonical_key=key,
                display_name=f"{scheme}://{host_s}{path}",
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.KNOWN,
                scheme=scheme,
                host=host_s,
                port=port_n,
                path=path,
                parent_asset_id=host.asset_id if host else None,
                out_of_scope=(host.out_of_scope if host else False) or self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, UrlAsset):
            raise WorldModelError(f"expected UrlAsset at {key}")
        return asset

    def _endpoint(
        self,
        ref: SubjectRef,
        url_asset: UrlAsset,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> Endpoint:
        key = ref.endpoint_key or ref.canonical_key
        method = ref.method or "GET"

        def factory() -> Endpoint:
            return Endpoint(
                asset_id=new_id(PREFIX_ENDPOINT),
                mission_id=mission_id,
                kind=AssetKind.ENDPOINT,
                canonical_key=key,
                display_name=f"{method} {url_asset.display_name}",
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.KNOWN,
                url_id=url_asset.asset_id,
                method=HttpMethod(method),
                url_canonical=url_asset.canonical_key,
                parent_asset_id=url_asset.asset_id,
                out_of_scope=url_asset.out_of_scope or self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, Endpoint):
            raise WorldModelError(f"expected Endpoint at {key}")
        return asset

    def _parameter(
        self,
        ref: SubjectRef,
        endpoint: Endpoint,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> Parameter:
        location = ref.param_location or "query"
        name = ref.param_name or "id"
        key = param_key(endpoint.canonical_key, location, name)

        def factory() -> Parameter:
            loc = location if location in {p.value for p in ParamLocation} else "query"
            return Parameter(
                asset_id=new_id(PREFIX_PARAMETER),
                mission_id=mission_id,
                kind=AssetKind.PARAMETER,
                canonical_key=key,
                display_name=name,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.KNOWN,
                endpoint_id=endpoint.asset_id,
                name=name,
                location=ParamLocation(loc),
                endpoint_canonical=endpoint.canonical_key,
                parent_asset_id=endpoint.asset_id,
                out_of_scope=endpoint.out_of_scope or self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, Parameter):
            raise WorldModelError(f"expected Parameter at {key}")
        return asset

    def _auth(
        self,
        ref: SubjectRef,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> AuthenticationSurface:
        kind_raw = ref.auth_kind or "unknown"
        try:
            kind = AuthSurfaceKind(kind_raw)
        except ValueError:
            kind = AuthSurfaceKind.UNKNOWN
        parent_key = ref.parent_canonical or ref.endpoint_key or ref.url_key or ""
        parent = pending.get(parent_key) if parent_key else None
        key = auth_key(parent_key or "unknown", kind.value)

        def factory() -> AuthenticationSurface:
            endpoint_id = None
            url_id = None
            if isinstance(parent, Endpoint):
                endpoint_id = parent.asset_id
            if isinstance(parent, UrlAsset):
                url_id = parent.asset_id
            if endpoint_id is None and url_id is None and isinstance(parent, Asset):
                if parent.canonical_key.startswith("ep:"):
                    endpoint_id = parent.asset_id
                else:
                    url_id = parent.asset_id
            return AuthenticationSurface(
                asset_id=new_id(PREFIX_AUTH),
                mission_id=mission_id,
                kind=AssetKind.AUTH_SURFACE,
                canonical_key=key,
                display_name=kind.value,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.KNOWN,
                auth_kind=kind,
                endpoint_id=endpoint_id,
                url_id=url_id,
                endpoint_canonical=parent_key or (parent.canonical_key if parent else "url:"),
                parent_asset_id=parent.asset_id if parent else None,
                out_of_scope=(parent.out_of_scope if parent else False) or self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, AuthenticationSurface):
            raise WorldModelError(f"expected AuthenticationSurface at {key}")
        return asset

    def _tech(
        self,
        ref: SubjectRef,
        parent: Asset,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> Technology:
        product = ref.product or "unknown"
        version = ref.version
        key = tech_key(parent.canonical_key, product, version)

        def factory() -> Technology:
            return Technology(
                asset_id=new_id(PREFIX_TECH),
                mission_id=mission_id,
                kind=AssetKind.TECHNOLOGY,
                canonical_key=key,
                display_name=product if not version else f"{product}/{version}",
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=EpistemicStatus.SUPPORTED,
                parent_asset_id=parent.asset_id,
                product=product,
                version=version,
                source=TechSource.HEADER,
                parent_canonical=parent.canonical_key,
                out_of_scope=parent.out_of_scope or self._oos(key, gate),
            )

        asset = self._resolve(key, factory, lookup, pending)
        if not isinstance(asset, Technology):
            raise WorldModelError(f"expected Technology at {key}")
        return asset

    def _alias_name_host(
        self,
        hostname: str,
        ip_host: Host,
        mission_id: str,
        now: datetime,
        lookup: AssetLookup,
        pending: dict[str, Asset],
        gate: ScopeGate | None,
    ) -> Host | None:
        try:
            name_key = host_key_name(hostname)
        except IdentityError:
            return None
        existing = lookup.peek_asset(name_key) or pending.get(name_key)
        if existing is None or not isinstance(existing, Host):
            return None
        if existing.canonical_key == ip_host.canonical_key:
            return None
        if "alias" in existing.labels and existing.parent_asset_id:
            pending[name_key] = existing
            return existing
        labels = list(dict.fromkeys([*existing.labels, "alias"]))
        aliased = existing.model_copy(
            update={
                "labels": labels,
                "parent_asset_id": ip_host.asset_id,
                "last_seen_at": now,
            }
        )
        pending[name_key] = aliased
        return aliased
