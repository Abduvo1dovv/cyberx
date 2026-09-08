"""Build a ScopeSubject from a validated Action."""

from __future__ import annotations

import ipaddress

from cyberx.domain.errors import IdentityError
from cyberx.domain.identity import parse_http_url
from cyberx.domain.models.actions import Action, ScopeSubject


def _looks_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _looks_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def _add_locator(subject: ScopeSubject, locator: str) -> None:
    if _looks_cidr(locator):
        subject.cidrs.append(locator)
    elif _looks_ip(locator):
        subject.ips.append(locator)
    elif locator.startswith("http://") or locator.startswith("https://"):
        try:
            scheme, host, port, _path = parse_http_url(locator)
        except IdentityError:
            subject.fqdns.append(locator)
            return
        subject.url = locator
        subject.schemes.append(scheme)
        subject.ports.append(port)
        if _looks_ip(host):
            subject.ips.append(host)
        else:
            subject.fqdns.append(host)
    else:
        subject.fqdns.append(locator)


def subject_from_action(action: Action) -> ScopeSubject:
    subject = ScopeSubject()
    locator = action.target.canonical_locator
    if locator:
        _add_locator(subject, locator)

    params = action.parameters
    atype = action.action_type

    if atype == "network_discovery" and params.get("network"):
        _add_locator(subject, str(params["network"]))
        subject.protocol = "tcp"

    if atype == "port_scan":
        proto = str(params.get("protocol") or "tcp")
        subject.protocol = proto
        if params.get("address"):
            _add_locator(subject, str(params["address"]))
        if params.get("ports") == "specified":
            for port in params.get("port_list") or []:
                subject.ports.append(int(port))

    if atype == "service_enumeration" and params.get("port"):
        subject.ports.append(int(params["port"]))
        subject.protocol = "tcp"

    if atype == "http_probe":
        if params.get("url"):
            _add_locator(subject, str(params["url"]))
        if params.get("scheme"):
            subject.schemes.append(str(params["scheme"]))
            subject.protocol = str(params["scheme"])
        if params.get("port"):
            subject.ports.append(int(params["port"]))

    if atype in ("technology_detection", "directory_enumeration", "endpoint_discovery"):
        if params.get("url"):
            _add_locator(subject, str(params["url"]))
        subject.protocol = subject.protocol or "http"

    if atype in ("dns_enumeration", "subdomain_enumeration"):
        if params.get("fqdn"):
            _add_locator(subject, str(params["fqdn"]))
        subject.protocol = "dns"

    if not subject.protocol:
        default_proto = {
            "http_probe": "http",
            "technology_detection": "http",
            "directory_enumeration": "http",
            "endpoint_discovery": "http",
            "dns_enumeration": "dns",
            "subdomain_enumeration": "dns",
            "port_scan": "tcp",
            "service_enumeration": "tcp",
            "network_discovery": "tcp",
        }
        subject.protocol = default_proto.get(atype)

    # de-dup
    subject.ips = list(dict.fromkeys(subject.ips))
    subject.fqdns = list(dict.fromkeys(subject.fqdns))
    subject.cidrs = list(dict.fromkeys(subject.cidrs))
    subject.ports = list(dict.fromkeys(subject.ports))
    subject.schemes = list(dict.fromkeys(subject.schemes))
    return subject
