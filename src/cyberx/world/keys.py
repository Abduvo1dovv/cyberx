"""Parse canonical subject hints. Identity functions remain the only key builders."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from cyberx.domain.enums import AssetKind, HttpMethod
from cyberx.domain.errors import IdentityError
from cyberx.domain.identity import (
    domain_key,
    endpoint_key,
    host_key_ipv4,
    host_key_ipv6,
    host_key_name,
    normalize_fqdn,
    normalize_ip,
    parse_http_url,
    port_key,
    service_key,
    subdomain_key,
    url_key,
    validate_fqdn,
)


@dataclass(frozen=True)
class SubjectRef:
    kind: AssetKind
    canonical_key: str
    host_key: str | None = None
    port_key: str | None = None
    service_key: str | None = None
    url_key: str | None = None
    endpoint_key: str | None = None
    domain_key: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    hostname: str | None = None
    protocol: str | None = None
    number: int | None = None
    scheme: str | None = None
    host: str | None = None
    path: str | None = None
    port_number: int | None = None
    method: str | None = None
    fqdn: str | None = None
    product: str | None = None
    version: str | None = None
    param_name: str | None = None
    param_location: str | None = None
    auth_kind: str | None = None
    parent_canonical: str | None = None


def object_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def parent_domain_fqdn(fqdn: str) -> str:
    labels = normalize_fqdn(fqdn).split(".")
    if len(labels) < 2:
        raise IdentityError("cannot infer parent domain")
    if len(labels) == 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def parse_subject_hint(hint: str) -> SubjectRef:
    text = (hint or "").strip()
    if not text or ":" not in text and "." not in text:
        if text:
            return _fallback(text)
        raise IdentityError("empty subject_hint")
    if text.startswith("param:"):
        return _parse_param(text)
    if text.startswith("auth:"):
        return _parse_auth(text)
    if text.startswith("tech:"):
        return _parse_tech(text)
    if text.startswith("iface:"):
        return _parse_iface(text)
    if text.startswith("ep:"):
        return _parse_endpoint(text)
    if text.startswith("svc:"):
        return _parse_service(text)
    if text.startswith("port:"):
        return _parse_port(text)
    if text.startswith("subdomain:"):
        return _parse_subdomain(text)
    if text.startswith("domain:"):
        return _parse_domain(text)
    if text.startswith("url:"):
        return _parse_url(text)
    if text.startswith("host:"):
        return _parse_host(text)
    return _fallback(text)


def _parse_host(text: str) -> SubjectRef:
    if text.startswith("host:ipv4:"):
        ip = text[len("host:ipv4:") :]
        key = host_key_ipv4(ip)
        return SubjectRef(
            kind=AssetKind.HOST,
            canonical_key=key,
            host_key=key,
            ipv4=normalize_ip(ip),
        )
    if text.startswith("host:ipv6:"):
        ip = text[len("host:ipv6:") :]
        key = host_key_ipv6(ip)
        return SubjectRef(
            kind=AssetKind.HOST,
            canonical_key=key,
            host_key=key,
            ipv6=normalize_ip(ip),
        )
    if text.startswith("host:name:"):
        name = text[len("host:name:") :]
        key = host_key_name(name)
        return SubjectRef(
            kind=AssetKind.HOST,
            canonical_key=key,
            host_key=key,
            hostname=validate_fqdn(name),
        )
    raise IdentityError(f"unparseable host key: {text}")


def _split_port_inner(inner: str) -> tuple[str, str, int]:
    for proto in ("tcp", "udp"):
        token = f":{proto}:"
        idx = inner.rfind(token)
        if idx == -1:
            continue
        host_c = inner[:idx]
        num_s = inner[idx + len(token) :]
        if not host_c.startswith("host:"):
            continue
        try:
            number = int(num_s)
        except ValueError as exc:
            raise IdentityError(f"invalid port number in {inner}") from exc
        return host_c, proto, number
    raise IdentityError(f"unparseable port key: {inner}")


def _parse_port(text: str) -> SubjectRef:
    inner = text[len("port:") :]
    host_c, proto, number = _split_port_inner(inner)
    host_ref = _parse_host(host_c)
    key = port_key(host_c, proto, number)
    return SubjectRef(
        kind=AssetKind.PORT,
        canonical_key=key,
        host_key=host_c,
        port_key=key,
        protocol=proto,
        number=number,
        ipv4=host_ref.ipv4,
        ipv6=host_ref.ipv6,
        hostname=host_ref.hostname,
    )


def _parse_service(text: str) -> SubjectRef:
    port_c = text[len("svc:") :]
    port_ref = _parse_port(port_c)
    key = service_key(port_c)
    return SubjectRef(
        kind=AssetKind.SERVICE,
        canonical_key=key,
        host_key=port_ref.host_key,
        port_key=port_c,
        service_key=key,
        protocol=port_ref.protocol,
        number=port_ref.number,
        ipv4=port_ref.ipv4,
        ipv6=port_ref.ipv6,
        hostname=port_ref.hostname,
    )


def _parse_url(text: str) -> SubjectRef:
    raw = text[len("url:") :] if text.startswith("url:") else text
    scheme, host, port, path = parse_http_url(raw)
    key = url_key(scheme, host, port, path)
    host_ref = _host_from_locator(host)
    return SubjectRef(
        kind=AssetKind.URL,
        canonical_key=key,
        url_key=key,
        host_key=host_ref.canonical_key,
        scheme=scheme,
        host=host,
        path=path,
        port_number=port,
        ipv4=host_ref.ipv4,
        ipv6=host_ref.ipv6,
        hostname=host_ref.hostname,
    )


def _parse_endpoint(text: str) -> SubjectRef:
    rest = text[len("ep:") :]
    method, _, url_part = rest.partition(":")
    method_u = method.upper()
    if method_u not in {m.value for m in HttpMethod}:
        raise IdentityError(f"invalid HTTP method: {method}")
    url_ref = _parse_url(url_part)
    key = endpoint_key(method_u, url_ref.canonical_key)
    return SubjectRef(
        kind=AssetKind.ENDPOINT,
        canonical_key=key,
        endpoint_key=key,
        url_key=url_ref.canonical_key,
        host_key=url_ref.host_key,
        method=method_u,
        scheme=url_ref.scheme,
        host=url_ref.host,
        path=url_ref.path,
        port_number=url_ref.port_number,
        ipv4=url_ref.ipv4,
        ipv6=url_ref.ipv6,
        hostname=url_ref.hostname,
    )


def _parse_domain(text: str) -> SubjectRef:
    fqdn = text[len("domain:") :]
    key = domain_key(fqdn)
    return SubjectRef(
        kind=AssetKind.DOMAIN,
        canonical_key=key,
        domain_key=key,
        fqdn=normalize_fqdn(fqdn),
    )


def _parse_subdomain(text: str) -> SubjectRef:
    fqdn = text[len("subdomain:") :]
    key = subdomain_key(fqdn)
    parent = parent_domain_fqdn(fqdn)
    dkey = domain_key(parent)
    return SubjectRef(
        kind=AssetKind.SUBDOMAIN,
        canonical_key=key,
        domain_key=dkey,
        fqdn=normalize_fqdn(fqdn),
        parent_canonical=dkey,
        hostname=normalize_fqdn(fqdn),
    )


def _parse_tech(text: str) -> SubjectRef:
    rest = text[len("tech:") :]
    parent, _, tail = _rsplit2(rest)
    # tail is slug:version; parent still includes kind prefix
    slug, _, version = tail.rpartition(":")
    if not slug:
        slug, version = tail, "-"
    parent_key = parent
    return SubjectRef(
        kind=AssetKind.TECHNOLOGY,
        canonical_key=text if text.startswith("tech:") else f"tech:{parent}:{slug}:{version}",
        parent_canonical=parent_key,
        product=slug,
        version=None if version in {"", "-"} else version,
        url_key=parent_key if parent_key.startswith("url:") else None,
        service_key=parent_key if parent_key.startswith("svc:") else None,
    )


def _parse_param(text: str) -> SubjectRef:
    rest = text[len("param:") :]
    head, location, name = _rsplit2_parts(rest)
    ep_ref = parse_subject_hint(head) if head.startswith("ep:") else None
    return SubjectRef(
        kind=AssetKind.PARAMETER,
        canonical_key=text,
        endpoint_key=head if head.startswith("ep:") else None,
        url_key=ep_ref.url_key if ep_ref else None,
        host_key=ep_ref.host_key if ep_ref else None,
        param_location=location,
        param_name=name,
        parent_canonical=head,
        method=ep_ref.method if ep_ref else None,
    )


def _parse_auth(text: str) -> SubjectRef:
    rest = text[len("auth:") :]
    parent, _, kind = rest.rpartition(":")
    parent_ref = parse_subject_hint(parent) if parent else None
    return SubjectRef(
        kind=AssetKind.AUTH_SURFACE,
        canonical_key=text,
        auth_kind=kind,
        endpoint_key=parent if parent.startswith("ep:") else None,
        url_key=parent
        if parent.startswith("url:")
        else (parent_ref.url_key if parent_ref else None),
        host_key=parent_ref.host_key if parent_ref else None,
        parent_canonical=parent,
        method=parent_ref.method if parent_ref else None,
    )


def _parse_iface(text: str) -> SubjectRef:
    rest = text[len("iface:") :]
    # host canonical starts with host:; IP is the suffix after that key
    if rest.startswith("host:ipv4:"):
        # iface:host:ipv4:A.B.C.D:A.B.C.D
        body = rest[len("host:ipv4:") :]
        ip_tail = body.rsplit(":", 1)
        if len(ip_tail) != 2:
            raise IdentityError(f"unparseable iface key: {text}")
        host_c = "host:ipv4:" + ip_tail[0]
        ip = ip_tail[1]
        host_ref = _parse_host(host_c)
        return SubjectRef(
            kind=AssetKind.INTERFACE,
            canonical_key=text,
            host_key=host_c,
            ipv4=host_ref.ipv4 or ip,
            parent_canonical=host_c,
        )
    if rest.startswith("host:ipv6:"):
        host_ref = _parse_host_from_iface_v6(rest)
        return SubjectRef(
            kind=AssetKind.INTERFACE,
            canonical_key=text,
            host_key=host_ref.canonical_key,
            ipv6=host_ref.ipv6,
            parent_canonical=host_ref.canonical_key,
        )
    raise IdentityError(f"unparseable iface key: {text}")


def _parse_host_from_iface_v6(rest: str) -> SubjectRef:
    # rest = host:ipv6:<compressed>: <same ip>
    body = rest[len("host:ipv6:") :]
    # split at the last occurrence of a second IPv6 is ambiguous; use host parse
    # by reconstructing host:ipv6: + all-but-last-colon-group is wrong for v6.
    # Identity writes iface:{host_canonical}:{ip} with the same compressed IP.
    # Find a prefix that parses as a host key.
    parts = body.split(":")
    for i in range(len(parts) - 1, 0, -1):
        candidate = "host:ipv6:" + ":".join(parts[:i])
        try:
            return _parse_host(candidate)
        except IdentityError:
            continue
    raise IdentityError(f"unparseable ipv6 iface: {rest}")


def _host_from_locator(host: str) -> SubjectRef:
    try:
        key = host_key_ipv4(host)
        return SubjectRef(
            kind=AssetKind.HOST, canonical_key=key, host_key=key, ipv4=normalize_ip(host)
        )
    except IdentityError:
        pass
    try:
        key = host_key_ipv6(host)
        return SubjectRef(
            kind=AssetKind.HOST, canonical_key=key, host_key=key, ipv6=normalize_ip(host)
        )
    except IdentityError:
        key = host_key_name(host)
        return SubjectRef(
            kind=AssetKind.HOST,
            canonical_key=key,
            host_key=key,
            hostname=validate_fqdn(host),
        )


def _fallback(text: str) -> SubjectRef:
    if "://" in text:
        return _parse_url(text if text.startswith("url:") else f"url:{text}")
    try:
        return _parse_host(f"host:ipv4:{text}")
    except IdentityError:
        pass
    try:
        return _parse_host(f"host:ipv6:{text}")
    except IdentityError:
        pass
    try:
        if "." in text:
            return _parse_domain(f"domain:{text}")
    except IdentityError:
        pass
    return _parse_host(f"host:name:{text}")


def _rsplit2(text: str) -> tuple[str, str, str]:
    """Split 'parent:slug:version' from the right into (parent, sep, slug:version)."""
    left, sep, version = text.rpartition(":")
    parent, sep2, slug = left.rpartition(":")
    if not sep or not sep2:
        raise IdentityError(f"unparseable tech key body: {text}")
    return parent, ":", f"{slug}:{version}"


def _rsplit2_parts(text: str) -> tuple[str, str, str]:
    head, _, name = text.rpartition(":")
    parent, _, location = head.rpartition(":")
    if not parent or not location or not name:
        raise IdentityError(f"unparseable param key: {text}")
    return parent, location, name
