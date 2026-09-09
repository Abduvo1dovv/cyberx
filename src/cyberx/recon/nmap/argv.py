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
from cyberx.domain.identity import normalize_cidr, validate_fqdn
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


def bind_args(source_interface: str | None, source_address: str | None) -> list[str]:
    """Optional nmap -e/-S. Only modeled, validated values. Never from AI argv."""
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
        out.extend(["-S", str(addr)])
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
    bind = bind_args(source_interface, source_address)

    if action.action_type == "port_scan":
        try:
            params = PortScanParams.model_validate(action.parameters)
        except ValidationError as exc:
            raise DomainValidationError("invalid port_scan parameters") from exc
        target = safe_target(params.address or action.target.canonical_locator)
        scan = ["-sU"] if params.protocol == "udp" else ["-sT"]
        return [
            binary,
            *bind,
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

    if action.action_type == "service_enumeration":
        try:
            params = ServiceEnumerationParams.model_validate(action.parameters)
        except ValidationError as exc:
            raise DomainValidationError("invalid service_enumeration parameters") from exc
        target = safe_target(action.target.canonical_locator)
        port_args = ["-p", str(params.port)] if params.port is not None else ["--top-ports", "100"]
        return [
            binary,
            *bind,
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

    try:
        params = NetworkDiscoveryParams.model_validate(action.parameters)
    except ValidationError as exc:
        raise DomainValidationError("invalid network_discovery parameters") from exc
    target = safe_target(params.network)
    return [
        binary,
        *bind,
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


# referenced so ruff does not drop the constant
_ = _SAFE_BASE
