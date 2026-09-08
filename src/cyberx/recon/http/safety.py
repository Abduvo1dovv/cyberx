"""HTTP destination checks. Fail closed. No fetching."""

from __future__ import annotations

import ipaddress

from cyberx.domain.errors import DomainValidationError, IdentityError
from cyberx.domain.identity import is_subdomain_of, normalize_fqdn, parse_http_url
from cyberx.ports.execution import ExecutionContext

_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.internal",
        "fd00:ec2::254",
    }
)
_FORBIDDEN_URL_CHARS = set(" \t\n\r;|`$(){}<>\\\"'")


def canonical_url(raw: str) -> str:
    scheme, host, port, path = parse_http_url(raw)
    default = 443 if scheme == "https" else 80
    netloc = host if port == default else f"{host}:{port}"
    return f"{scheme}://{netloc}{path}"


def validate_http_url(raw: str) -> str:
    if raw is None or not str(raw).strip():
        raise DomainValidationError("http url is empty")
    text = str(raw).strip()
    if any(ch in _FORBIDDEN_URL_CHARS for ch in text):
        raise DomainValidationError("http url contains forbidden characters")
    if text.startswith("-"):
        raise DomainValidationError("http url must not start with -")
    try:
        scheme, host, _port, _path = parse_http_url(text)
    except IdentityError as exc:
        raise DomainValidationError(str(exc)) from exc
    if is_blocked_ssrf(host):
        raise DomainValidationError("http url destination is blocked")
    if scheme not in {"http", "https"}:
        raise DomainValidationError("only http/https URLs are supported")
    return canonical_url(text)


def is_blocked_ssrf(host: str) -> bool:
    lowered = host.lower().rstrip(".")
    if lowered in _METADATA_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_multicast:
        return True
    if str(ip) == "169.254.169.254":
        return True
    return False


def host_in_allowlist(host: str, ctx: ExecutionContext) -> bool:
    if host in ctx.excluded_targets:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        name = normalize_fqdn(host)
        excluded = [normalize_fqdn(t) for t in ctx.excluded_targets if _not_ip(t)]
        if name in excluded:
            return False
        allowed = [normalize_fqdn(t) for t in ctx.allowed_targets if _not_ip(t)]
        if name in allowed:
            return True
        if ctx.allow_subdomains and any(is_subdomain_of(name, parent) for parent in allowed):
            return True
        return False
    if str(addr) in ctx.excluded_targets or host in ctx.excluded_targets:
        return False
    for net in ctx.excluded_networks:
        if addr in ipaddress.ip_network(net, strict=False):
            return False
    if host in ctx.allowed_targets or str(addr) in ctx.allowed_targets:
        return True
    for net in ctx.allowed_networks:
        if addr in ipaddress.ip_network(net, strict=False):
            return True
    return False


def destination_allowed(
    url: str,
    *,
    origin_host: str,
    ctx: ExecutionContext,
) -> bool:
    try:
        scheme, host, _port, _path = parse_http_url(url)
    except IdentityError:
        return False
    if is_blocked_ssrf(host):
        return False
    allowed_protos = {p.lower() for p in ctx.allowed_protocols} if ctx.allowed_protocols else set()
    if allowed_protos and scheme not in allowed_protos:
        return False
    if ctx.allowed_targets or ctx.allowed_networks:
        return host_in_allowlist(host, ctx)
    return host == origin_host


def _not_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return True
