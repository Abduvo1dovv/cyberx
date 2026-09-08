"""Pydantic parameter schemas for the nine v1 action types."""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cyberx.domain.errors import DomainValidationError, IdentityError
from cyberx.domain.identity import normalize_cidr, parse_http_url, validate_fqdn
from cyberx.domain.ids import (
    PREFIX_DOMAIN,
    PREFIX_HOST,
    PREFIX_SERVICE,
    PREFIX_URL,
    is_valid_id,
)


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NetworkDiscoveryParams(_Params):
    network: str

    @model_validator(mode="after")
    def _cidr(self) -> NetworkDiscoveryParams:
        try:
            self.network = normalize_cidr(self.network)
            ipaddress.ip_network(self.network, strict=False)
        except Exception as exc:
            raise DomainValidationError("network must be a CIDR") from exc
        return self


class PortScanParams(_Params):
    host_id: str | None = None
    address: str | None = None
    ports: str = "top1000"
    port_list: list[int] | None = None
    protocol: str = "tcp"

    @model_validator(mode="after")
    def _need_host(self) -> PortScanParams:
        if not self.host_id and not self.address:
            raise DomainValidationError("port_scan requires host_id or address")
        if self.host_id and not is_valid_id(self.host_id, PREFIX_HOST):
            raise DomainValidationError("host_id must be a host ULID")
        if self.ports not in {"top100", "top1000", "specified"}:
            raise DomainValidationError("ports must be top100, top1000, or specified")
        if self.ports == "specified":
            if not self.port_list:
                raise DomainValidationError("specified ports require port_list")
            for port in self.port_list:
                if port < 1 or port > 65535:
                    raise DomainValidationError(f"invalid port: {port}")
        if self.protocol not in {"tcp", "udp"}:
            raise DomainValidationError("protocol must be tcp or udp")
        return self


class ServiceEnumerationParams(_Params):
    host_id: str
    port: int | None = Field(default=None, ge=1, le=65535)

    @model_validator(mode="after")
    def _host(self) -> ServiceEnumerationParams:
        if not is_valid_id(self.host_id, PREFIX_HOST):
            raise DomainValidationError("host_id must be a host ULID")
        return self


class HttpProbeParams(_Params):
    url: str | None = None
    host_id: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    scheme: str | None = None

    @model_validator(mode="after")
    def _locator(self) -> HttpProbeParams:
        if self.url:
            try:
                parse_http_url(self.url)
            except IdentityError as exc:
                raise DomainValidationError(str(exc)) from exc
            return self
        if self.host_id and not is_valid_id(self.host_id, PREFIX_HOST):
            raise DomainValidationError("host_id must be a host ULID")
        if self.host_id and self.port and self.scheme in {"http", "https"}:
            return self
        raise DomainValidationError("http_probe requires url or (host_id, port, scheme)")


class TechnologyDetectionParams(_Params):
    url_id: str | None = None
    service_id: str | None = None
    url: str | None = None

    @model_validator(mode="after")
    def _need(self) -> TechnologyDetectionParams:
        if self.url:
            try:
                parse_http_url(self.url)
            except IdentityError as exc:
                raise DomainValidationError(str(exc)) from exc
        if self.url_id and not is_valid_id(self.url_id, PREFIX_URL):
            raise DomainValidationError("url_id must be a url ULID")
        if self.service_id and not is_valid_id(self.service_id, PREFIX_SERVICE):
            raise DomainValidationError("service_id must be a service ULID")
        if not self.url_id and not self.service_id and not self.url:
            raise DomainValidationError("technology_detection requires url_id, service_id, or url")
        return self


class DnsEnumerationParams(_Params):
    fqdn: str

    @model_validator(mode="after")
    def _fqdn(self) -> DnsEnumerationParams:
        self.fqdn = validate_fqdn(self.fqdn, allow_single_label=True)
        return self


class SubdomainEnumerationParams(_Params):
    domain_id: str | None = None
    fqdn: str | None = None
    wordlist: str = "default"

    @model_validator(mode="after")
    def _need(self) -> SubdomainEnumerationParams:
        if not self.domain_id and not self.fqdn:
            raise DomainValidationError("subdomain_enumeration requires domain_id or fqdn")
        if self.wordlist != "default":
            raise DomainValidationError("v1 subdomain wordlist must be 'default'")
        if self.domain_id and not is_valid_id(self.domain_id, PREFIX_DOMAIN):
            raise DomainValidationError("domain_id must be a domain ULID")
        if self.fqdn:
            self.fqdn = validate_fqdn(self.fqdn, allow_single_label=False)
        return self


class DirectoryEnumerationParams(_Params):
    url_id: str | None = None
    url: str | None = None
    wordlist: str = "small"

    @model_validator(mode="after")
    def _need(self) -> DirectoryEnumerationParams:
        if not self.url_id and not self.url:
            raise DomainValidationError("directory_enumeration requires url_id or url")
        if self.wordlist != "small":
            raise DomainValidationError("v1 directory wordlist must be 'small'")
        if self.url_id and not is_valid_id(self.url_id, PREFIX_URL):
            raise DomainValidationError("url_id must be a url ULID")
        if self.url:
            try:
                parse_http_url(self.url)
            except IdentityError as exc:
                raise DomainValidationError(str(exc)) from exc
        return self


class EndpointDiscoveryParams(_Params):
    url_id: str | None = None
    url: str | None = None

    @model_validator(mode="after")
    def _need(self) -> EndpointDiscoveryParams:
        if not self.url_id and not self.url:
            raise DomainValidationError("endpoint_discovery requires url_id or url")
        if self.url_id and not is_valid_id(self.url_id, PREFIX_URL):
            raise DomainValidationError("url_id must be a url ULID")
        if self.url:
            try:
                parse_http_url(self.url)
            except IdentityError as exc:
                raise DomainValidationError(str(exc)) from exc
        return self
