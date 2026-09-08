"""Map recon signals to EXISTING catalog actions. No new action types."""

from __future__ import annotations

from typing import Any

from cyberx.actions.coverage import coverage_key
from cyberx.domain.enums import V1_ACTION_TYPES, FindingKind
from cyberx.domain.models.actions import ActionTarget
from cyberx.domain.models.assets import (
    AuthenticationSurface,
    Endpoint,
    Host,
    Port,
    Service,
    Technology,
    UrlAsset,
)
from cyberx.domain.models.findings import Finding

HTTP_PORTS = frozenset({80, 443, 8080, 8443})
HTTPS_PORTS = frozenset({443, 8443})

# candidate_type, action, expected predicates
_SIGNAL_MAP: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "auth_surface": (
        "authentication_surface",
        "endpoint_discovery",
        ("auth.seen", "endpoint.seen"),
    ),
    "admin_surface": ("interesting_path", "http_probe", ("http.status",)),
    "api_surface": ("interesting_path", "http_probe", ("http.status",)),
    "backup_looking_path": ("interesting_path", "http_probe", ("http.status",)),
    "upload_surface": ("interesting_path", "http_probe", ("http.status",)),
    "debug_surface": ("interesting_path", "http_probe", ("http.status",)),
    "internal_surface": ("interesting_path", "http_probe", ("http.status",)),
    "management_surface": ("interesting_path", "http_probe", ("http.status",)),
    "interesting_endpoint": ("interesting_path", "endpoint_discovery", ("endpoint.seen",)),
    "directory_listing": ("interesting_path", "http_probe", ("http.status",)),
    "unusual_status": ("unusual_http", "http_probe", ("http.status",)),
    "unusual_redirect": ("redirect_behavior", "http_probe", ("http.redirect", "http.status")),
    "tech_observed": (
        "technology_fingerprint",
        "technology_detection",
        ("http.tech", "service.version"),
    ),
    "version_disclosure": (
        "technology_fingerprint",
        "technology_detection",
        ("http.tech", "service.version"),
    ),
    "unusual_service": (
        "service_fingerprint",
        "service_enumeration",
        ("service.name", "service.version"),
    ),
}

UNSAFE_CANDIDATE_TYPES = frozenset(
    {
        "sql_injection",
        "xss",
        "ssrf",
        "rce",
        "file_upload_exploit",
        "command_injection",
        "auth_bypass",
        "credential_attack",
        "brute_force",
        "exploit",
        "validate",
    }
)


def mapping_for(finding: Finding, asset: Any | None) -> tuple[str, str, tuple[str, ...]] | None:
    if finding.kind is FindingKind.OUT_OF_SCOPE_OBSERVATION:
        return None
    signal = finding.signal or finding.kind.value
    if signal in UNSAFE_CANDIDATE_TYPES:
        return None
    if signal in _SIGNAL_MAP:
        return _SIGNAL_MAP[signal]
    if signal in {"exposed_service", "open_port"}:
        if isinstance(asset, Port) and asset.number in HTTP_PORTS:
            return ("http_surface", "http_probe", ("http.status",))
        return None
    if finding.kind is FindingKind.AUTH_SURFACE:
        return _SIGNAL_MAP["auth_surface"]
    if finding.kind is FindingKind.TECHNOLOGY:
        return _SIGNAL_MAP["tech_observed"]
    if finding.kind is FindingKind.URL:
        return ("http_surface", "http_probe", ("http.status",))
    return None


def locator_from_asset(asset: Any | None) -> str:
    if asset is None:
        return ""
    if isinstance(asset, UrlAsset):
        return f"{asset.scheme}://{asset.host}:{asset.port}{asset.path or '/'}"
    if isinstance(asset, Endpoint):
        raw = asset.url_canonical
        return raw[4:] if raw.startswith("url:") else raw
    if isinstance(asset, AuthenticationSurface):
        raw = asset.endpoint_canonical
        if raw.startswith("url:"):
            return raw[4:]
        if "url:" in raw:
            return raw.split("url:", 1)[1]
        return raw
    if isinstance(asset, Technology):
        parent = asset.parent_canonical or ""
        if parent.startswith("url:"):
            return parent[4:]
        return parent
    if isinstance(asset, Host):
        return asset.ipv4 or asset.ipv6 or asset.hostname or ""
    if isinstance(asset, Port):
        return asset.host_canonical.split(":")[-1] if asset.host_canonical else ""
    if isinstance(asset, Service):
        return asset.port_canonical
    return getattr(asset, "canonical_key", "") or ""


def build_action(
    action_type: str,
    *,
    finding: Finding,
    asset: Any | None,
    world: Any,
) -> tuple[str, dict[str, Any], str] | None:
    """Return (locator, parameters, coverage_key) or None if not legally constructible."""
    if action_type not in V1_ACTION_TYPES:
        return None
    locator = locator_from_asset(asset)
    params: dict[str, Any] = {}
    if action_type == "http_probe":
        url = _http_url(asset, world, locator)
        if not url:
            return None
        locator = url
        params = {"url": url}
    elif action_type == "technology_detection":
        url = _http_url(asset, world, locator)
        if not url:
            return None
        locator = url
        params = {"url": url}
        url_id = _url_id(asset)
        if url_id:
            params["url_id"] = url_id
    elif action_type == "endpoint_discovery":
        url = _http_url(asset, world, locator)
        if not url:
            return None
        locator = url
        params = {"url": url}
        url_id = _url_id(asset)
        if url_id:
            params["url_id"] = url_id
    elif action_type == "service_enumeration":
        host_id, port_num, address = _host_port(asset, world)
        if not host_id:
            return None
        locator = address or locator
        params = {"host_id": host_id}
        if port_num:
            params["port"] = port_num
    else:
        return None
    target = ActionTarget(
        asset_id=getattr(asset, "asset_id", None) if asset is not None else None,
        canonical_locator=locator,
    )
    key = coverage_key(action_type, target, params)
    return locator, params, key


def _http_url(asset: Any | None, world: Any, locator: str) -> str:
    if locator.startswith("http://") or locator.startswith("https://"):
        return locator
    if isinstance(asset, Port):
        host = world.peek_asset_by_id(asset.host_id) if world is not None else None
        address = ""
        if isinstance(host, Host):
            address = host.ipv4 or host.ipv6 or host.hostname or ""
        if not address:
            address = locator
        if not address:
            return ""
        scheme = "https" if asset.number in HTTPS_PORTS else "http"
        return f"{scheme}://{address}:{asset.number}/"
    return ""


def _url_id(asset: Any | None) -> str:
    if isinstance(asset, UrlAsset):
        return asset.asset_id
    if isinstance(asset, Endpoint):
        return asset.url_id
    if isinstance(asset, AuthenticationSurface):
        return asset.url_id or ""
    return ""


def _host_port(asset: Any | None, world: Any) -> tuple[str, int | None, str]:
    if isinstance(asset, Port):
        host = world.peek_asset_by_id(asset.host_id) if world is not None else None
        address = ""
        if isinstance(host, Host):
            address = host.ipv4 or host.ipv6 or host.hostname or ""
        return asset.host_id, asset.number, address
    if isinstance(asset, Service) and world is not None:
        port = world.peek_asset_by_id(asset.port_id)
        if isinstance(port, Port):
            return _host_port(port, world)
    if isinstance(asset, Host):
        address = asset.ipv4 or asset.ipv6 or asset.hostname or ""
        return asset.asset_id, None, address
    return "", None, ""
