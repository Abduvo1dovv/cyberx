"""Canonical keys — the only legal way to build asset identities."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

from cyberx.domain.errors import IdentityError

_PRODUCT_SLUG = re.compile("[^a-z0-9]+")
_LDH_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SECRET_NAME = re.compile(r"(pass|pwd|secret|token|key|session|cookie|auth|jwt)", re.IGNORECASE)
_JWTISH = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def normalize_ipv4(ip: str) -> str:
    try:
        return str(ipaddress.IPv4Address(ip.strip()))
    except ipaddress.AddressValueError as exc:
        raise IdentityError(f"invalid IPv4: {ip}") from exc


def normalize_ipv6(ip: str) -> str:
    try:
        return str(ipaddress.IPv6Address(ip.strip()).compressed)
    except ipaddress.AddressValueError as exc:
        raise IdentityError(f"invalid IPv6: {ip}") from exc


def normalize_ip(ip: str) -> str:
    text = ip.strip()
    try:
        return normalize_ipv4(text)
    except IdentityError:
        return normalize_ipv6(text)


def normalize_fqdn(name: str) -> str:
    return name.strip().rstrip(".").lower()


def validate_fqdn(name: str, *, allow_single_label: bool = True) -> str:
    fqdn = normalize_fqdn(name)
    if not fqdn or len(fqdn) > 253:
        raise IdentityError("invalid hostname length")
    labels = fqdn.split(".")
    if not allow_single_label and len(labels) < 2:
        raise IdentityError("domain requires at least two labels")
    for label in labels:
        if not _LDH_LABEL.match(label):
            raise IdentityError(f"invalid LDH label: {label}")
    return fqdn


def normalize_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise IdentityError(f"invalid CIDR: {value}") from exc
    return str(network)


def product_slug(product: str) -> str:
    slug = _PRODUCT_SLUG.sub("-", product.lower()).strip("-")
    if not slug:
        raise IdentityError("empty product slug")
    return slug


def normalize_url_path(path: str) -> str:
    raw = path or "/"
    decoded = unquote(raw)
    if ".." in decoded or "%2e" in raw.lower():
        raise IdentityError("dot-dot path rejected")
    decoded = decoded.split("?")[0].split("#")[0]
    while "//" in decoded:
        decoded = decoded.replace("//", "/")
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    if decoded != "/" and decoded.endswith("/"):
        decoded = decoded.rstrip("/")
    return decoded or "/"


def parse_http_url(raw: str) -> tuple[str, str, int, str]:
    """Return (scheme, host, port, path). Host is lowercased / compressed IP."""
    parts = urlsplit(raw.strip())
    if parts.scheme not in ("http", "https"):
        raise IdentityError("only http/https URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise IdentityError("credentials-in-url")
    if parts.hostname is None:
        raise IdentityError("URL missing host")
    scheme = parts.scheme.lower()
    host = parts.hostname
    try:
        host = normalize_ip(host)
    except IdentityError:
        host = validate_fqdn(host)
    port = parts.port or (443 if scheme == "https" else 80)
    path = normalize_url_path(parts.path or "/")
    return scheme, host, port, path


def host_key_ipv4(ip: str) -> str:
    return f"host:ipv4:{normalize_ipv4(ip)}"


def host_key_ipv6(ip: str) -> str:
    return f"host:ipv6:{normalize_ipv6(ip)}"


def host_key_name(fqdn: str) -> str:
    return f"host:name:{validate_fqdn(fqdn)}"


def iface_key(host_canonical: str, ip: str) -> str:
    return f"iface:{host_canonical}:{normalize_ip(ip)}"


def port_key(host_canonical: str, protocol: str, number: int) -> str:
    if protocol not in ("tcp", "udp"):
        raise IdentityError(f"invalid port protocol: {protocol}")
    if number < 1 or number > 65535:
        raise IdentityError(f"invalid port number: {number}")
    return f"port:{host_canonical}:{protocol}:{number}"


def service_key(port_canonical: str) -> str:
    if not port_canonical.startswith("port:"):
        raise IdentityError("service key requires a port canonical key")
    return f"svc:{port_canonical}"


def tech_key(parent_canonical: str, product: str, version: str | None = None) -> str:
    ver = version or "-"
    return f"tech:{parent_canonical}:{product_slug(product)}:{ver}"


def domain_key(fqdn: str) -> str:
    return f"domain:{validate_fqdn(fqdn, allow_single_label=False)}"


def subdomain_key(fqdn: str) -> str:
    return f"subdomain:{validate_fqdn(fqdn, allow_single_label=False)}"


def url_key(scheme: str, host: str, port: int, path: str) -> str:
    if scheme not in ("http", "https"):
        raise IdentityError("url key scheme must be http or https")
    path_n = normalize_url_path(path)
    try:
        host_n = normalize_ip(host)
    except IdentityError:
        host_n = validate_fqdn(host)
    return f"url:{scheme}://{host_n}:{port}{path_n}"


def url_key_from_string(raw: str) -> str:
    scheme, host, port, path = parse_http_url(raw)
    return url_key(scheme, host, port, path)


def endpoint_key(method: str, url_canonical: str) -> str:
    if not url_canonical.startswith("url:"):
        raise IdentityError("endpoint key requires a url canonical key")
    return f"ep:{method.upper()}:{url_canonical}"


def param_key(endpoint_canonical: str, location: str, name: str) -> str:
    return f"param:{endpoint_canonical}:{location}:{name.lower()}"


def auth_key(endpoint_canonical: str, kind: str) -> str:
    return f"auth:{endpoint_canonical}:{kind}"


def is_secret_shaped_name(name: str) -> bool:
    return bool(_SECRET_NAME.search(name))


def is_secret_shaped_value(value: str | None) -> bool:
    if not value:
        return False
    text = value.strip()
    if _JWTISH.match(text):
        return True
    if "BEGIN " in text and "PRIVATE KEY" in text:
        return True
    if "BEGIN CERTIFICATE" in text:
        return True
    return False


def is_subdomain_of(fqdn: str, parent: str) -> bool:
    child = normalize_fqdn(fqdn)
    root = normalize_fqdn(parent)
    return child == root or child.endswith("." + root)


def target_identity_key(kind: str, normalized: str, *, host: str | None = None) -> str:
    """Stable mission-target identity. Name/domain beat a raw IP locator."""
    token = (kind or "").lower()
    name = host or normalized
    if token in {"hostname", "domain"}:
        return f"identity:name:{validate_fqdn(normalized, allow_single_label=True)}"
    if token == "url":
        subject = name or normalized
        try:
            ip = normalize_ip(subject)
            family = "ipv6" if ":" in ip else "ipv4"
            return f"identity:{family}:{ip}"
        except IdentityError:
            try:
                return f"identity:name:{validate_fqdn(subject, allow_single_label=True)}"
            except IdentityError:
                return f"identity:url:{normalized.lower()[:200]}"
    if token == "ipv4":
        return f"identity:ipv4:{normalize_ipv4(normalized)}"
    if token == "ipv6":
        return f"identity:ipv6:{normalize_ipv6(normalized)}"
    if token == "cidr":
        return f"identity:cidr:{normalize_cidr(normalized)}"
    return f"identity:raw:{normalized.lower()[:200]}"


def parse_locator(raw: str) -> tuple[str, str]:
    """Return (kind, canonical locator). kind is ipv4, ipv6, hostname, or cidr."""
    text = (raw or "").strip()
    if not text:
        raise IdentityError("empty locator")
    if "://" in text:
        _scheme, host, _port, _path = parse_http_url(text)
        return parse_locator(host)
    if "/" in text:
        try:
            return "cidr", normalize_cidr(text)
        except IdentityError:
            pass
    try:
        return "ipv4", normalize_ipv4(text)
    except IdentityError:
        pass
    try:
        return "ipv6", normalize_ipv6(text)
    except IdentityError:
        pass
    return "hostname", validate_fqdn(text, allow_single_label=True)


def address_family(raw: str | None) -> str:
    """Classify a locator as ipv4, ipv6, or hostname. Never raises."""
    text = (raw or "").strip()
    if not text:
        return "hostname"
    if "://" in text:
        try:
            _scheme, host, _port, _path = parse_http_url(text)
            return address_family(host)
        except IdentityError:
            return "hostname"
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
            return "ipv4" if network.version == 4 else "ipv6"
        except ValueError:
            text = text.split("/", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return "hostname"
    return "ipv4" if addr.version == 4 else "ipv6"


def is_ipv6_link_local(raw: str | None) -> bool:
    try:
        addr = ipaddress.ip_address((raw or "").strip())
    except ValueError:
        return False
    return addr.version == 6 and bool(addr.is_link_local)
