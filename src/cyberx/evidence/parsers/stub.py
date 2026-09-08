"""Stub JSON dispatcher. Same observation shapes as native parsers. No tools."""

from __future__ import annotations

from typing import Any

from cyberx.domain.errors import IdentityError, ParseError
from cyberx.domain.identity import port_key, service_key
from cyberx.domain.models.evidence import Observation
from cyberx.evidence.parsers.base import emit, host_subject, load_json_object
from cyberx.evidence.parsers.directory import observations_from_directory_payload
from cyberx.evidence.parsers.dns import observations_from_dns_payload
from cyberx.evidence.parsers.endpoint import observations_from_endpoint_payload
from cyberx.evidence.parsers.http_probe import observations_from_http_payload
from cyberx.evidence.parsers.tech import observations_from_tech_payload
from cyberx.ports.execution import RawArtifact

PARSER_ID = "stub"


class StubParser:
    parser_id = PARSER_ID
    action_types: tuple[str, ...] = (
        "network_discovery",
        "port_scan",
        "service_enumeration",
        "http_probe",
        "technology_detection",
        "dns_enumeration",
        "subdomain_enumeration",
        "directory_enumeration",
        "endpoint_discovery",
    )
    produces: tuple[str, ...] = (
        "host.alive",
        "host.address",
        "port.state",
        "service.name",
        "service.product",
        "http.status",
        "http.title",
        "http.header",
        "http.tech",
        "dns.record",
        "dns.subdomain",
        "url.seen",
        "endpoint.seen",
        "param.seen",
        "auth.seen",
    )

    def parse(self, artifact: RawArtifact) -> list[Observation]:
        data = load_json_object(artifact)
        return observations_from_stub_payload(data, artifact)


def observations_from_stub_payload(
    data: dict[str, Any], artifact: RawArtifact
) -> list[Observation]:
    action_type = str(data.get("action_type") or "")
    dispatch = {
        "network_discovery": _hosts,
        "port_scan": _ports,
        "service_enumeration": _services,
        "http_probe": observations_from_http_payload,
        "technology_detection": observations_from_tech_payload,
        "dns_enumeration": observations_from_dns_payload,
        "subdomain_enumeration": observations_from_dns_payload,
        "directory_enumeration": observations_from_directory_payload,
        "endpoint_discovery": observations_from_endpoint_payload,
    }
    rows: list[Observation]
    if action_type in dispatch:
        rows = dispatch[action_type](data, artifact)
    elif "hosts" in data:
        rows = _hosts(data, artifact)
    elif "ports" in data:
        rows = _ports(data, artifact)
    elif "services" in data:
        rows = _services(data, artifact)
    elif "technologies" in data:
        rows = observations_from_tech_payload(data, artifact)
    elif "records" in data or "subdomains" in data:
        rows = observations_from_dns_payload(data, artifact)
    elif "paths" in data:
        rows = observations_from_directory_payload(data, artifact)
    elif "endpoints" in data or "html" in data:
        rows = observations_from_endpoint_payload(data, artifact)
    elif "status" in data:
        rows = observations_from_http_payload(data, artifact)
    else:
        raise ParseError("unrecognized stub payload", code="unknown_stub_shape")
    return [row.model_copy(update={"parser_id": PARSER_ID}) for row in rows]


def _target_host(data: dict[str, Any], artifact: RawArtifact) -> str | None:
    locator = data.get("target") or artifact.source_locator
    if not isinstance(locator, str) or not locator.strip():
        return None
    text = locator.strip()
    if "://" in text:
        from cyberx.domain.identity import parse_http_url

        try:
            _scheme, host, _port, _path = parse_http_url(text)
            return host
        except IdentityError:
            return None
    return text


def _hosts(data: dict[str, Any], artifact: RawArtifact) -> list[Observation]:
    out: list[Observation] = []
    for item in data.get("hosts") or []:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not isinstance(ip, str):
            continue
        try:
            subject = host_subject(ip)
        except IdentityError:
            continue
        alive = bool(item.get("alive", True))
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="host.alive",
                obj=alive,
                subject_hint=subject,
            )
        )
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="host.address",
                obj=ip,
                subject_hint=subject,
            )
        )
    return out


def _ports(data: dict[str, Any], artifact: RawArtifact) -> list[Observation]:
    host = _target_host(data, artifact)
    if not host:
        raise ParseError("port_scan stub missing target host", code="missing_target")
    try:
        host_c = host_subject(host)
    except IdentityError as exc:
        raise ParseError(str(exc), code="invalid_target") from exc
    out: list[Observation] = []
    for item in data.get("ports") or []:
        if not isinstance(item, dict):
            continue
        try:
            number = int(item.get("number"))
        except (TypeError, ValueError):
            continue
        protocol = str(item.get("protocol") or "tcp").lower()
        state = str(item.get("state") or "unknown")
        try:
            pkey = port_key(host_c, protocol, number)
        except IdentityError:
            continue
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="port.state",
                obj=state,
                subject_hint=pkey,
                extra={"protocol": protocol, "number": number},
            )
        )
    return out


def _services(data: dict[str, Any], artifact: RawArtifact) -> list[Observation]:
    host = _target_host(data, artifact)
    if not host:
        raise ParseError("service_enumeration stub missing target host", code="missing_target")
    try:
        host_c = host_subject(host)
    except IdentityError as exc:
        raise ParseError(str(exc), code="invalid_target") from exc
    out: list[Observation] = []
    for item in data.get("services") or []:
        if not isinstance(item, dict):
            continue
        try:
            number = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        protocol = str(item.get("protocol") or "tcp").lower()
        try:
            pkey = port_key(host_c, protocol, number)
            skey = service_key(pkey)
        except IdentityError:
            continue
        name = item.get("name")
        if isinstance(name, str) and name:
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="service.name",
                    obj=name.lower(),
                    subject_hint=skey,
                )
            )
        product = item.get("product")
        if isinstance(product, str) and product:
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="service.product",
                    obj=product,
                    subject_hint=skey,
                )
            )
    return out
