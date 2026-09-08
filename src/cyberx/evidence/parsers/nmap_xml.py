"""Nmap XML parser. Pure function. No network, no process execution.

Stdlib ElementTree is used because defusedxml is not a project dependency.
Input is local adapter output. DTD ENTITY / SYSTEM / PUBLIC subsets are rejected
before parse. Nmap's empty doctype declaration is stripped.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from cyberx.domain.errors import IdentityError, ParseError
from cyberx.domain.identity import port_key, service_key
from cyberx.domain.models.evidence import Observation
from cyberx.evidence.parsers.base import MAX_BANNER, clip, emit, host_subject, read_artifact_bytes
from cyberx.ports.execution import RawArtifact

PARSER_ID = "nmap_xml"

try:
    from defusedxml.ElementTree import fromstring as _xml_fromstring
except ImportError:  # pragma: no cover - optional
    _xml_fromstring = ET.fromstring

_EMPTY_DOCTYPE = re.compile(rb"<!DOCTYPE\s+nmaprun\s*>", re.IGNORECASE)
_STYLESHEET = re.compile(rb"<\?xml-stylesheet[^?]*\?>", re.IGNORECASE)


def _tag(element: ET.Element) -> str:
    return element.tag.split("}")[-1]


class NmapXmlParser:
    parser_id = PARSER_ID
    produces: tuple[str, ...] = (
        "host.alive",
        "host.address",
        "host.hostname",
        "port.state",
        "service.name",
        "service.product",
        "service.version",
        "service.banner",
    )

    def parse(self, artifact: RawArtifact) -> list[Observation]:
        raw = read_artifact_bytes(artifact)
        sanitized = _sanitize(raw)
        try:
            root = _xml_fromstring(sanitized)
        except ET.ParseError as exc:
            raise ParseError(f"invalid xml: {exc}", code="invalid_xml") from exc
        if _tag(root) != "nmaprun":
            raise ParseError("xml root must be nmaprun", code="invalid_xml")
        observations: list[Observation] = []
        for host in root.iter():
            if _tag(host) != "host" or host is root:
                continue
            observations.extend(_parse_host(host, artifact))
        return observations


def _sanitize(raw: bytes) -> bytes:
    _reject_unsafe(raw)
    text = _EMPTY_DOCTYPE.sub(b"", raw, count=1)
    text = _STYLESHEET.sub(b"", text, count=1)
    return text


def _reject_unsafe(raw: bytes) -> None:
    head = raw[:8192]
    upper = head.upper()
    if b"<!ENTITY" in upper:
        raise ParseError("XML DTD/ENTITY is not allowed", code="unsafe_xml")
    if b"<!DOCTYPE" in upper:
        if b"SYSTEM" in upper or b"PUBLIC" in upper or b"[" in head:
            raise ParseError("XML DTD/ENTITY is not allowed", code="unsafe_xml")


def _parse_host(host: ET.Element, artifact: RawArtifact) -> list[Observation]:
    ipv4 = None
    ipv6 = None
    hostnames: list[str] = []
    alive = True
    for child in list(host):
        name = _tag(child)
        if name == "status":
            alive = (child.attrib.get("state") or "up").lower() == "up"
        elif name == "address":
            addr = child.attrib.get("addr")
            kind = (child.attrib.get("addrtype") or "").lower()
            if not addr:
                continue
            if kind == "ipv6":
                ipv6 = addr
            elif kind in {"ipv4", ""}:
                ipv4 = ipv4 or addr
        elif name == "hostnames":
            for hn in child:
                if _tag(hn) == "hostname" and hn.attrib.get("name"):
                    hostnames.append(hn.attrib["name"])
    address = ipv4 or ipv6
    if not address:
        return []
    try:
        subject = host_subject(address)
    except IdentityError:
        return []
    out: list[Observation] = [
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="host.alive",
            obj=alive,
            subject_hint=subject,
        ),
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="host.address",
            obj=address,
            subject_hint=subject,
        ),
    ]
    for hostname in hostnames:
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="host.hostname",
                obj=hostname.lower().rstrip("."),
                subject_hint=subject,
            )
        )
    ports_el = next((c for c in host if _tag(c) == "ports"), None)
    if ports_el is None:
        return out
    for port_el in ports_el:
        if _tag(port_el) != "port":
            continue
        out.extend(_parse_port(port_el, artifact, subject))
    return out


def _parse_port(
    port_el: ET.Element, artifact: RawArtifact, host_canonical: str
) -> list[Observation]:
    protocol = (port_el.attrib.get("protocol") or "tcp").lower()
    try:
        number = int(port_el.attrib.get("portid") or "0")
    except ValueError:
        return []
    if protocol not in {"tcp", "udp"} or number < 1 or number > 65535:
        return []
    try:
        pkey = port_key(host_canonical, protocol, number)
    except IdentityError:
        return []
    state_el = next((c for c in port_el if _tag(c) == "state"), None)
    state = (state_el.attrib.get("state") if state_el is not None else "unknown") or "unknown"
    reason = state_el.attrib.get("reason") if state_el is not None else None
    extra = {"protocol": protocol, "number": number}
    if reason:
        extra["reason"] = clip(reason, 64)
    out = [
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="port.state",
            obj=state,
            subject_hint=pkey,
            extra=extra,
        )
    ]
    service_el = next((c for c in port_el if _tag(c) == "service"), None)
    if service_el is None:
        return out
    skey = service_key(pkey)
    name = (service_el.attrib.get("name") or "").lower()
    product = service_el.attrib.get("product")
    version = service_el.attrib.get("version")
    banner = service_el.attrib.get("extrainfo") or service_el.attrib.get("servicefp")
    if name:
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="service.name",
                obj=name,
                subject_hint=skey,
            )
        )
    if product:
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="service.product",
                obj=product,
                subject_hint=skey,
            )
        )
    if version:
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="service.version",
                obj=version,
                subject_hint=skey,
            )
        )
    if banner:
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="service.banner",
                obj=clip(banner, MAX_BANNER),
                subject_hint=skey,
            )
        )
    return out
