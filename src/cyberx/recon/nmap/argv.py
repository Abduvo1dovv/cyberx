"""Deterministic Nmap argv construction. No process execution."""

from __future__ import annotations

import ipaddress
import re

from pydantic import ValidationError

from cyberx.actions.params import (
    NetworkDiscoveryParams,
    PortScanParams,
    ServiceEnumerationParams,
)
from cyberx.domain.errors import DomainValidationError, IdentityError
from cyberx.domain.identity import address_family, is_ipv6_link_local, normalize_cidr, validate_fqdn
from cyberx.domain.models.actions import Action

NMAP_ACTION_TYPES: tuple[str, ...] = (
    "network_discovery",
    "port_scan",
    "service_enumeration",
)

# Conservative v1 flag set. Operator/AI cannot add to this list.
_SAFE_BASE = ("-n", "-Pn", "--max-retries")
_FORBIDDEN_TARGET_CHARS = set(" \t\n\r;|&$`(){}[]<>\"'\\*?#,=!@%")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,15}$")


def target_family(raw: str | None) -> str:
    """ipv4 | ipv6 | hostname. Hostnames default to IPv4 mode in v1 CTF."""
    return address_family(raw)


def family_args(family: str) -> list[str]:
    """Force nmap address family so dual-stack interfaces cannot bind the other."""
    if family == "ipv6":
        return ["-6"]
    return ["-4"]


def bind_args(
    source_interface: str | None,
    source_address: str | None = None,
    *,
    family: str = "ipv4",
) -> list[str]:
    """Optional nmap -e only. Never automatic -S. Never IPv6 link-local.

    IPv4 CTF scans use interface selection (`-e`) plus `-4`. Explicit `-S`
    caused privilege/bind failures and is not required when routing is correct.
    A provided source_address is validated then ignored so callers cannot
    accidentally bind fe80:: on an IPv4 target.
    """
    del family
    out: list[str] = []
    if source_interface:
        name = str(source_interface).strip()
        if not _IFACE_RE.match(name) or name.startswith("-"):
            raise DomainValidationError("invalid source interface")
        out.extend(["-e", name])
    if source_address:
        try:
            addr = ipaddress.ip_address(str(source_address).strip())
        except ValueError as exc:
            raise DomainValidationError("invalid source address") from exc
        if is_ipv6_link_local(str(addr)):
            return out
    return out


def drop_source_address(argv: list[str]) -> list[str]:
    """Remove -S <addr> only. Keep -e. Never from AI argv."""
    out: list[str] = []
    skip = False
    for token in argv:
        if skip:
            skip = False
            continue
        if token == "-S":
            skip = True
            continue
        out.append(token)
    return out


def drop_interface(argv: list[str]) -> list[str]:
    """Remove -e <iface> only. Keep family flags. Documented OS-routing fallback."""
    out: list[str] = []
    skip = False
    for token in argv:
        if skip:
            skip = False
            continue
        if token == "-e":
            skip = True
            continue
        out.append(token)
    return out


def safe_target(raw: str | None) -> str:
    """Validate a host/CIDR/name token. Rejects flag-like and shell-like values."""
    if raw is None or not str(raw).strip():
        raise DomainValidationError("nmap target is empty")
    text = str(raw).strip()
    if text.startswith("-"):
        raise DomainValidationError("nmap target must not start with -")
    if any(ch in _FORBIDDEN_TARGET_CHARS for ch in text):
        raise DomainValidationError("nmap target contains forbidden characters")
    if "/" in text:
        try:
            return normalize_cidr(text)
        except (IdentityError, ValueError) as exc:
            raise DomainValidationError("nmap target is not a valid CIDR") from exc
    try:
        addr = ipaddress.ip_address(text)
        return str(addr)
    except ValueError:
        pass
    if _IPV4_RE.match(text):
        raise DomainValidationError("nmap target is not a valid IPv4 address")
    try:
        return validate_fqdn(text, allow_single_label=True)
    except IdentityError as exc:
        raise DomainValidationError("nmap target is not a valid host") from exc


def _port_args(params: PortScanParams) -> list[str]:
    if params.ports == "top100":
        return ["--top-ports", "100"]
    if params.ports == "top1000":
        return ["--top-ports", "1000"]
    ports = params.port_list or []
    if not ports:
        raise DomainValidationError("specified ports require port_list")
    cleaned: list[int] = []
    for port in ports:
        if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
            raise DomainValidationError(f"invalid port: {port}")
        cleaned.append(port)
    unique = ",".join(str(p) for p in sorted(set(cleaned)))
    return ["-p", unique]


def _host_timeout_token(timeout_s: int) -> str:
    seconds = max(1, int(timeout_s))
    return f"{seconds}s"


def _refuse_link_local(argv: list[str]) -> None:
    for token in argv:
        if is_ipv6_link_local(token):
            raise DomainValidationError("refusing IPv6 link-local nmap bind")


def build_nmap_argv(
    action: Action,
    *,
    binary: str = "nmap",
    xml_path: str,
    timeout_s: int,
    max_retries: int = 1,
    source_interface: str | None = None,
    source_address: str | None = None,
) -> list[str]:
    """Return a closed argv list. Never concatenates a shell string."""
    if action.action_type not in NMAP_ACTION_TYPES:
        raise DomainValidationError(f"nmap adapter does not run {action.action_type}")
    if not binary or binary.startswith("-"):
        raise DomainValidationError("invalid nmap binary")
    if not xml_path or xml_path.startswith("-"):
        raise DomainValidationError("invalid nmap xml path")
    retries = str(max(0, min(int(max_retries), 2)))
    host_timeout = _host_timeout_token(timeout_s)

    if action.action_type == "port_scan":
        try:
            params = PortScanParams.model_validate(action.parameters)
        except ValidationError as exc:
            raise DomainValidationError("invalid port_scan parameters") from exc
        target = safe_target(params.address or action.target.canonical_locator)
        family = target_family(target)
        scan = ["-sU"] if params.protocol == "udp" else ["-sT"]
        argv = [
            binary,
            *family_args(family),
            *bind_args(source_interface, source_address, family=family),
            "-n",
            "-Pn",
            "--max-retries",
            retries,
            *scan,
            *_port_args(params),
            "-oX",
            xml_path,
            "--host-timeout",
            host_timeout,
            target,
        ]
        _refuse_link_local(argv)
        return argv

    if action.action_type == "service_enumeration":
        try:
            params = ServiceEnumerationParams.model_validate(action.parameters)
        except ValidationError as exc:
            raise DomainValidationError("invalid service_enumeration parameters") from exc
        target = safe_target(action.target.canonical_locator)
        family = target_family(target)
        port_args = ["-p", str(params.port)] if params.port is not None else ["--top-ports", "100"]
        argv = [
            binary,
            *family_args(family),
            *bind_args(source_interface, source_address, family=family),
            "-n",
            "-Pn",
            "--max-retries",
            retries,
            "-sV",
            "-sT",
            *port_args,
            "-oX",
            xml_path,
            "--host-timeout",
            host_timeout,
            target,
        ]
        _refuse_link_local(argv)
        return argv

    try:
        params = NetworkDiscoveryParams.model_validate(action.parameters)
    except ValidationError as exc:
        raise DomainValidationError("invalid network_discovery parameters") from exc
    target = safe_target(params.network)
    family = target_family(target)
    argv = [
        binary,
        *family_args(family),
        *bind_args(source_interface, source_address, family=family),
        "-n",
        "--max-retries",
        retries,
        "-sn",
        "-oX",
        xml_path,
        "--host-timeout",
        host_timeout,
        target,
    ]
    _refuse_link_local(argv)
    return argv


# referenced so ruff does not drop the constant
_ = _SAFE_BASE
