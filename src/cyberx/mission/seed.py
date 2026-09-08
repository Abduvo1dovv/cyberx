"""Confirm-time seed assets (SPEC §4.3). Full World Model apply is M6."""

from __future__ import annotations

from datetime import datetime

from cyberx.domain.enums import AddressType, AssetKind, EpistemicStatus, TargetKind
from cyberx.domain.errors import IdentityError
from cyberx.domain.identity import (
    domain_key,
    host_key_ipv4,
    host_key_ipv6,
    host_key_name,
    parse_locator,
    url_key_from_string,
    validate_fqdn,
)
from cyberx.domain.ids import PREFIX_DOMAIN, PREFIX_HOST, PREFIX_URL, new_id
from cyberx.domain.models.assets import Asset, Domain, Host, UrlAsset
from cyberx.domain.models.mission import Target
from cyberx.mission.target_parse import ParsedTarget


def _identity_labels(target: Target) -> list[str]:
    key = target.canonical_identity or ""
    labels = []
    if key:
        labels.append(key)
    labels.append("current_locator")
    return labels


def seed_assets_for_target(
    mission_id: str,
    target: Target,
    parsed: ParsedTarget,
    now: datetime,
) -> list[Asset]:
    status = EpistemicStatus.KNOWN
    assets: list[Asset] = []
    labels = _identity_labels(target)
    if target.kind is TargetKind.IPV4:
        assets.append(
            Host(
                asset_id=new_id(PREFIX_HOST),
                mission_id=mission_id,
                kind=AssetKind.HOST,
                canonical_key=host_key_ipv4(target.normalized),
                display_name=target.normalized,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=status,
                address_type=AddressType.IPV4,
                ipv4=target.normalized,
                labels=labels,
            )
        )
    elif target.kind is TargetKind.IPV6:
        assets.append(
            Host(
                asset_id=new_id(PREFIX_HOST),
                mission_id=mission_id,
                kind=AssetKind.HOST,
                canonical_key=host_key_ipv6(target.normalized),
                display_name=target.normalized,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=status,
                address_type=AddressType.IPV6,
                ipv6=target.normalized,
                labels=labels,
            )
        )
    elif target.kind is TargetKind.CIDR:
        # CIDR seeds no host until network_discovery; nothing extra.
        pass
    elif target.kind is TargetKind.HOSTNAME:
        assets.append(
            Host(
                asset_id=new_id(PREFIX_HOST),
                mission_id=mission_id,
                kind=AssetKind.HOST,
                canonical_key=host_key_name(target.normalized),
                display_name=target.normalized,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=status,
                address_type=AddressType.NAME,
                hostname=target.normalized,
                labels=labels,
            )
        )
        if "." in target.normalized:
            try:
                parent = ".".join(validate_fqdn(target.normalized).split(".")[-2:])
                assets.append(
                    Domain(
                        asset_id=new_id(PREFIX_DOMAIN),
                        mission_id=mission_id,
                        kind=AssetKind.DOMAIN,
                        canonical_key=domain_key(parent),
                        display_name=parent,
                        first_seen_at=now,
                        last_seen_at=now,
                        epistemic_status=status,
                        fqdn=parent,
                    )
                )
            except Exception:
                pass
    elif target.kind is TargetKind.DOMAIN:
        assets.append(
            Domain(
                asset_id=new_id(PREFIX_DOMAIN),
                mission_id=mission_id,
                kind=AssetKind.DOMAIN,
                canonical_key=domain_key(target.normalized),
                display_name=target.normalized,
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=status,
                fqdn=target.normalized,
                labels=labels,
            )
        )
    elif target.kind is TargetKind.URL:
        key = url_key_from_string(
            f"{target.url_scheme}://{parsed.host}:{target.url_port}{target.url_path}"
        )
        assets.append(
            UrlAsset(
                asset_id=new_id(PREFIX_URL),
                mission_id=mission_id,
                kind=AssetKind.URL,
                canonical_key=key,
                display_name=f"{target.url_scheme}://{parsed.host}{target.url_path}",
                first_seen_at=now,
                last_seen_at=now,
                epistemic_status=status,
                scheme=target.url_scheme or "http",
                host=parsed.host or target.normalized,
                port=target.url_port or 80,
                path=target.url_path or "/",
                labels=labels,
            )
        )
    return assets


def host_for_locator(
    mission_id: str,
    locator: str,
    now: datetime,
    *,
    labels: list[str] | None = None,
) -> Host | None:
    """Host asset for an IP/name locator. None for CIDR."""
    try:
        kind, canonical = parse_locator(locator)
    except IdentityError:
        return None
    tags = list(labels or [])
    if kind == "ipv4":
        return Host(
            asset_id=new_id(PREFIX_HOST),
            mission_id=mission_id,
            kind=AssetKind.HOST,
            canonical_key=host_key_ipv4(canonical),
            display_name=canonical,
            first_seen_at=now,
            last_seen_at=now,
            epistemic_status=EpistemicStatus.KNOWN,
            address_type=AddressType.IPV4,
            ipv4=canonical,
            labels=tags,
        )
    if kind == "ipv6":
        return Host(
            asset_id=new_id(PREFIX_HOST),
            mission_id=mission_id,
            kind=AssetKind.HOST,
            canonical_key=host_key_ipv6(canonical),
            display_name=canonical,
            first_seen_at=now,
            last_seen_at=now,
            epistemic_status=EpistemicStatus.KNOWN,
            address_type=AddressType.IPV6,
            ipv6=canonical,
            labels=tags,
        )
    if kind in {"hostname", "domain"}:
        return Host(
            asset_id=new_id(PREFIX_HOST),
            mission_id=mission_id,
            kind=AssetKind.HOST,
            canonical_key=host_key_name(canonical),
            display_name=canonical,
            first_seen_at=now,
            last_seen_at=now,
            epistemic_status=EpistemicStatus.KNOWN,
            address_type=AddressType.NAME,
            hostname=canonical,
            labels=tags,
        )
    return None
