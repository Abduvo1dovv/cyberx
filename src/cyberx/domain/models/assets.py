"""Asset graph entities."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator, model_validator

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
from cyberx.domain.errors import DomainValidationError, IdentityError
from cyberx.domain.identity import (
    auth_key,
    domain_key,
    endpoint_key,
    host_key_ipv4,
    host_key_ipv6,
    host_key_name,
    iface_key,
    is_secret_shaped_name,
    is_secret_shaped_value,
    is_subdomain_of,
    normalize_fqdn,
    normalize_ip,
    param_key,
    port_key,
    service_key,
    subdomain_key,
    tech_key,
    url_key,
)
from cyberx.domain.ids import (
    PREFIX_AUTH,
    PREFIX_DOMAIN,
    PREFIX_ENDPOINT,
    PREFIX_HOST,
    PREFIX_INTERFACE,
    PREFIX_MISSION,
    PREFIX_PARAMETER,
    PREFIX_PORT,
    PREFIX_SERVICE,
    PREFIX_SUBDOMAIN,
    PREFIX_TECH,
    PREFIX_URL,
    require_id,
)
from cyberx.domain.models.common import DomainModel


class Asset(DomainModel):
    asset_id: str
    mission_id: str
    kind: AssetKind
    canonical_key: str
    display_name: str
    first_seen_at: datetime
    last_seen_at: datetime
    epistemic_status: EpistemicStatus
    parent_asset_id: str | None = None
    labels: list[str] = Field(default_factory=list)
    out_of_scope: bool = False

    @field_validator("mission_id")
    @classmethod
    def _mid(cls, value: str) -> str:
        return require_id(value, PREFIX_MISSION)

    @field_validator("canonical_key")
    @classmethod
    def _key(cls, value: str) -> str:
        if not value or ":" not in value:
            raise IdentityError("canonical_key must come from the identity layer")
        return value


class Host(Asset):
    kind: AssetKind = AssetKind.HOST
    address_type: AddressType
    ipv4: str | None = None
    ipv6: str | None = None
    hostname: str | None = None
    os_family: str | None = None
    os_hint: str | None = None

    @field_validator("asset_id")
    @classmethod
    def _hid(cls, value: str) -> str:
        return require_id(value, PREFIX_HOST)

    @model_validator(mode="after")
    def _identity(self) -> Host:
        if self.kind is not AssetKind.HOST:
            raise DomainValidationError("Host.kind must be host")
        if self.address_type is AddressType.IPV4:
            if not self.ipv4:
                raise DomainValidationError("ipv4 required")
            expected = host_key_ipv4(self.ipv4)
        elif self.address_type is AddressType.IPV6:
            if not self.ipv6:
                raise DomainValidationError("ipv6 required")
            expected = host_key_ipv6(self.ipv6)
        else:
            if not self.hostname:
                raise DomainValidationError("hostname required")
            expected = host_key_name(self.hostname)
        if self.canonical_key != expected:
            raise IdentityError("Host.canonical_key must be produced by identity")
        return self


class NetworkInterface(Asset):
    kind: AssetKind = AssetKind.INTERFACE
    host_id: str
    ip: str
    family: int
    mac: str | None = None
    iface_name: str | None = None
    rdns: str | None = None
    host_canonical: str

    @field_validator("asset_id")
    @classmethod
    def _iid(cls, value: str) -> str:
        return require_id(value, PREFIX_INTERFACE)

    @field_validator("host_id")
    @classmethod
    def _host(cls, value: str) -> str:
        return require_id(value, PREFIX_HOST)

    @model_validator(mode="after")
    def _identity(self) -> NetworkInterface:
        if self.family not in (4, 6):
            raise DomainValidationError("family must be 4 or 6")
        expected = iface_key(self.host_canonical, self.ip)
        if self.canonical_key != expected:
            raise IdentityError("NetworkInterface.canonical_key must be produced by identity")
        return self


class Port(Asset):
    kind: AssetKind = AssetKind.PORT
    host_id: str
    protocol: TransportProtocol
    number: int = Field(ge=1, le=65535)
    state: PortState
    reason: str | None = Field(default=None, max_length=64)
    host_canonical: str

    @field_validator("asset_id")
    @classmethod
    def _pid(cls, value: str) -> str:
        return require_id(value, PREFIX_PORT)

    @model_validator(mode="after")
    def _identity(self) -> Port:
        expected = port_key(self.host_canonical, self.protocol.value, self.number)
        if self.canonical_key != expected:
            raise IdentityError("Port.canonical_key must be produced by identity")
        return self


class Service(Asset):
    kind: AssetKind = AssetKind.SERVICE
    port_id: str
    name: str
    product: str | None = None
    version: str | None = None
    banner: str | None = Field(default=None, max_length=256)
    tunnel: str | None = None
    port_canonical: str

    @field_validator("asset_id")
    @classmethod
    def _sid(cls, value: str) -> str:
        return require_id(value, PREFIX_SERVICE)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return value.lower()

    @model_validator(mode="after")
    def _identity(self) -> Service:
        expected = service_key(self.port_canonical)
        if self.canonical_key != expected:
            raise IdentityError("Service.canonical_key must be produced by identity")
        if self.tunnel not in (None, "ssl", "none"):
            raise DomainValidationError("tunnel must be ssl or none")
        return self


class Technology(Asset):
    kind: AssetKind = AssetKind.TECHNOLOGY
    parent_asset_id: str
    product: str
    version: str | None = None
    cpe: str | None = None
    source: TechSource | None = None
    parent_canonical: str

    @field_validator("asset_id")
    @classmethod
    def _tid(cls, value: str) -> str:
        return require_id(value, PREFIX_TECH)

    @model_validator(mode="after")
    def _identity(self) -> Technology:
        expected = tech_key(self.parent_canonical, self.product, self.version)
        if self.canonical_key != expected:
            raise IdentityError("Technology.canonical_key must be produced by identity")
        return self


class Domain(Asset):
    kind: AssetKind = AssetKind.DOMAIN
    fqdn: str

    @field_validator("asset_id")
    @classmethod
    def _did(cls, value: str) -> str:
        return require_id(value, PREFIX_DOMAIN)

    @model_validator(mode="after")
    def _identity(self) -> Domain:
        expected = domain_key(self.fqdn)
        if self.canonical_key != expected:
            raise IdentityError("Domain.canonical_key must be produced by identity")
        self.fqdn = normalize_fqdn(self.fqdn)
        return self


class Subdomain(Asset):
    kind: AssetKind = AssetKind.SUBDOMAIN
    fqdn: str
    domain_id: str
    domain_fqdn: str
    source: SubdomainSource | None = None

    @field_validator("asset_id")
    @classmethod
    def _sid(cls, value: str) -> str:
        return require_id(value, PREFIX_SUBDOMAIN)

    @field_validator("domain_id")
    @classmethod
    def _dom(cls, value: str) -> str:
        return require_id(value, PREFIX_DOMAIN)

    @model_validator(mode="after")
    def _identity(self) -> Subdomain:
        expected = subdomain_key(self.fqdn)
        if self.canonical_key != expected:
            raise IdentityError("Subdomain.canonical_key must be produced by identity")
        if not is_subdomain_of(self.fqdn, self.domain_fqdn):
            raise DomainValidationError("subdomain must sit under parent domain")
        return self


class UrlAsset(Asset):
    kind: AssetKind = AssetKind.URL
    scheme: str
    host: str
    port: int = Field(ge=1, le=65535)
    path: str
    query_template: str | None = None
    status_code: int | None = None
    title: str | None = Field(default=None, max_length=128)
    content_type: str | None = None

    @field_validator("asset_id")
    @classmethod
    def _uid(cls, value: str) -> str:
        return require_id(value, PREFIX_URL)

    @model_validator(mode="after")
    def _identity(self) -> UrlAsset:
        expected = url_key(self.scheme, self.host, self.port, self.path)
        if self.canonical_key != expected:
            raise IdentityError("UrlAsset.canonical_key must be produced by identity")
        return self


class Endpoint(Asset):
    kind: AssetKind = AssetKind.ENDPOINT
    url_id: str
    method: HttpMethod
    url_canonical: str
    last_status: int | None = None
    content_length: int | None = None
    auth_required: bool = False

    @field_validator("asset_id")
    @classmethod
    def _eid(cls, value: str) -> str:
        return require_id(value, PREFIX_ENDPOINT)

    @model_validator(mode="after")
    def _identity(self) -> Endpoint:
        expected = endpoint_key(self.method.value, self.url_canonical)
        if self.canonical_key != expected:
            raise IdentityError("Endpoint.canonical_key must be produced by identity")
        return self


class Parameter(Asset):
    kind: AssetKind = AssetKind.PARAMETER
    endpoint_id: str
    name: str
    location: ParamLocation
    endpoint_canonical: str
    example_seen: str | None = None
    redacted: bool = False

    @field_validator("asset_id")
    @classmethod
    def _pid(cls, value: str) -> str:
        return require_id(value, PREFIX_PARAMETER)

    @model_validator(mode="after")
    def _identity(self) -> Parameter:
        expected = param_key(self.endpoint_canonical, self.location.value, self.name)
        if self.canonical_key != expected:
            raise IdentityError("Parameter.canonical_key must be produced by identity")
        if is_secret_shaped_name(self.name) or is_secret_shaped_value(self.example_seen):
            self.redacted = True
            self.example_seen = None
        return self


class AuthenticationSurface(Asset):
    kind: AssetKind = AssetKind.AUTH_SURFACE
    auth_kind: AuthSurfaceKind
    endpoint_id: str | None = None
    url_id: str | None = None
    endpoint_canonical: str
    form_fields: list[str] = Field(default_factory=list)
    realm: str | None = None

    @field_validator("asset_id")
    @classmethod
    def _aid(cls, value: str) -> str:
        return require_id(value, PREFIX_AUTH)

    @model_validator(mode="after")
    def _identity(self) -> AuthenticationSurface:
        if not self.endpoint_id and not self.url_id:
            raise DomainValidationError("AuthenticationSurface needs endpoint_id or url_id")
        expected = auth_key(self.endpoint_canonical, self.auth_kind.value)
        if self.canonical_key != expected:
            raise IdentityError("AuthenticationSurface.canonical_key must be produced by identity")
        return self


def require_normalized_ip(ip: str) -> str:
    return normalize_ip(ip)
