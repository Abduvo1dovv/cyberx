"""Target normalization and validation (SPEC §2.2)."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from cyberx.domain.enums import MissionMode, TargetKind
from cyberx.domain.errors import TargetValidationError
from cyberx.domain.identity import (
    IdentityError,
    normalize_cidr,
    normalize_ipv4,
    normalize_ipv6,
    parse_http_url,
    validate_fqdn,
)

_LOOPBACK = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)
_LINK_LOCAL = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
)
_MULTICAST = (
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
)
RFC1918_10 = ipaddress.ip_network("10.0.0.0/8")


class ParsedTarget:
    __slots__ = ("kind", "normalized", "url_scheme", "url_port", "url_path", "host")

    def __init__(
        self,
        kind: TargetKind,
        normalized: str,
        *,
        url_scheme: str | None = None,
        url_port: int | None = None,
        url_path: str | None = None,
        host: str | None = None,
    ) -> None:
        self.kind = kind
        self.normalized = normalized
        self.url_scheme = url_scheme
        self.url_port = url_port
        self.url_path = url_path
        self.host = host


def _in_any(addr: ipaddress._BaseAddress, nets: tuple[ipaddress._BaseNetwork, ...]) -> bool:
    return any(addr in net for net in nets)


def classify_address_restrictions(
    addr: ipaddress._BaseAddress,
    *,
    mode: MissionMode,
    allow_special: bool,
) -> None:
    if _in_any(addr, _LOOPBACK) or _in_any(addr, _LINK_LOCAL) or _in_any(addr, _MULTICAST):
        if mode is MissionMode.AUTHORIZED_ASSESSMENT or not allow_special:
            raise TargetValidationError(
                "loopback, link-local, and multicast targets are denied by default"
            )
    if addr in RFC1918_10 and mode is MissionMode.AUTHORIZED_ASSESSMENT:
        # Allowed only when explicit scope will include the address; caller checks scope.
        return


def parse_target(
    raw_input: str,
    *,
    mode: MissionMode,
    allow_special: bool = False,
) -> ParsedTarget:
    raw = (raw_input or "").strip()
    if not raw:
        raise TargetValidationError("target must not be empty")

    if "://" in raw or raw.lower().startswith("http:") or raw.lower().startswith("https:"):
        parts = urlsplit(raw)
        if parts.username is not None or parts.password is not None:
            raise TargetValidationError("credentials-in-url")
        try:
            scheme, host, port, path = parse_http_url(raw)
        except IdentityError as exc:
            raise TargetValidationError(str(exc)) from exc
        try:
            addr = ipaddress.ip_address(host)
            classify_address_restrictions(addr, mode=mode, allow_special=allow_special)
        except ValueError:
            pass
        return ParsedTarget(
            TargetKind.URL,
            f"{scheme}://{host}:{port}{path}",
            url_scheme=scheme,
            url_port=port,
            url_path=path,
            host=host,
        )

    if "/" in raw:
        try:
            cidr = normalize_cidr(raw)
            network = ipaddress.ip_network(cidr, strict=False)
        except (IdentityError, ValueError) as exc:
            raise TargetValidationError(f"invalid CIDR: {raw}") from exc
        if network.num_addresses == 1:
            # still a cidr kind if user typed /32 explicitly
            pass
        addr = network.network_address
        classify_address_restrictions(addr, mode=mode, allow_special=allow_special)
        if (
            network.version == 4
            and network.prefixlen < 8
            and mode is not MissionMode.AUTHORIZED_ASSESSMENT
        ):
            raise TargetValidationError("CTF/lab CIDR may not be larger than /8")

        if mode is MissionMode.AUTHORIZED_ASSESSMENT and network.prefixlen < 16:
            raise TargetValidationError("assessment CIDR may not be larger than /16")
        if mode in (MissionMode.CTF, MissionMode.LAB) and network.prefixlen < 8:
            raise TargetValidationError("CTF/lab CIDR may not be larger than /8")
        return ParsedTarget(TargetKind.CIDR, cidr, host=str(addr))

    try:
        ip = normalize_ipv4(raw)
        addr = ipaddress.IPv4Address(ip)
        classify_address_restrictions(addr, mode=mode, allow_special=allow_special)
        return ParsedTarget(TargetKind.IPV4, ip, host=ip)
    except (IdentityError, TargetValidationError) as exc:
        if isinstance(exc, TargetValidationError):
            raise
    except Exception:
        pass

    try:
        ip = normalize_ipv6(raw)
        addr = ipaddress.IPv6Address(ip)
        classify_address_restrictions(addr, mode=mode, allow_special=allow_special)
        return ParsedTarget(TargetKind.IPV6, ip, host=ip)
    except TargetValidationError:
        raise
    except Exception:
        pass

    try:
        fqdn = validate_fqdn(raw, allow_single_label=True)
    except IdentityError as exc:
        raise TargetValidationError(f"invalid target: {raw}") from exc
    kind = TargetKind.DOMAIN if "." in fqdn else TargetKind.HOSTNAME
    if kind is TargetKind.DOMAIN:
        # two-or-more labels: treat as domain (DNS zone). More labels still domain
        # if the operator typed a FQDN host we still seed as domain+host later.
        labels = fqdn.split(".")
        if len(labels) >= 3:
            kind = TargetKind.HOSTNAME
    return ParsedTarget(kind, fqdn, host=fqdn)
