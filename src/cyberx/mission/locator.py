"""Target identity vs observed locators. No I/O. Never expands Scope."""

from __future__ import annotations

from datetime import datetime

from cyberx.domain.enums import LocatorStatus, TargetKind
from cyberx.domain.errors import IdentityError, LocatorRejected
from cyberx.domain.identity import parse_locator, target_identity_key
from cyberx.domain.models.mission import ObservedLocator, Scope, Target
from cyberx.mission.scope_build import target_is_allowed, target_is_excluded
from cyberx.mission.target_parse import ParsedTarget, parse_target

OPERATOR_ACTORS = frozenset({"operator"})


def initial_locator(parsed: ParsedTarget) -> tuple[str, str]:
    """Canonical (kind, locator) the operator pointed at."""
    if parsed.kind is TargetKind.URL:
        host = parsed.host or parsed.normalized
        try:
            return parse_locator(host)
        except IdentityError:
            return "hostname", host
    if parsed.kind is TargetKind.CIDR:
        return "cidr", parsed.normalized
    if parsed.kind is TargetKind.IPV4:
        return "ipv4", parsed.normalized
    if parsed.kind is TargetKind.IPV6:
        return "ipv6", parsed.normalized
    if parsed.kind is TargetKind.DOMAIN:
        return "domain", parsed.normalized
    return "hostname", parsed.normalized


def seed_identity_fields(parsed: ParsedTarget, now: datetime) -> dict:
    kind, locator = initial_locator(parsed)
    identity = target_identity_key(parsed.kind.value, parsed.normalized, host=parsed.host)
    record = ObservedLocator(
        locator=locator,
        kind=kind,
        status=LocatorStatus.CURRENT,
        first_seen_at=now,
        last_seen_at=now,
        source="operator",
    )
    return {
        "canonical_identity": identity,
        "current_locator": locator,
        "locator_history": [record],
        "last_observed_at": now,
    }


def compact_identity(target: Target) -> dict[str, str]:
    historical = target.historical_locators()
    return {
        "identity": target.identity_key(),
        "kind": target.kind.value,
        "current": target.current_locator or target.normalized,
        "previous": target.previous_locator() or "",
        "historical": ",".join(historical[:8]),
        "normalized": target.normalized,
    }


def locator_in_scope(
    locator: str,
    scope: Scope,
    *,
    mode,
    allow_special: bool = True,
) -> bool:
    try:
        parsed = parse_target(locator, mode=mode, allow_special=allow_special)
    except Exception:
        return False
    if target_is_excluded(
        parsed,
        excluded_targets=scope.excluded_targets,
        excluded_networks=scope.excluded_networks,
    ):
        return False
    return target_is_allowed(
        parsed,
        allowed_targets=scope.allowed_targets,
        allowed_networks=scope.allowed_networks,
        allow_subdomains=scope.allow_subdomains,
    )


def observe_locator(
    target: Target,
    raw: str,
    *,
    now: datetime,
    source: str = "recon",
    evidence_ids: list[str] | None = None,
) -> Target:
    """Record an observed address. Never promotes it to current."""
    kind, locator = parse_locator(raw)
    history = [item.model_copy(deep=True) for item in target.locator_history]
    found = False
    for idx, item in enumerate(history):
        if item.locator == locator:
            ids = list(dict.fromkeys([*item.evidence_ids, *(evidence_ids or [])]))
            history[idx] = item.model_copy(
                update={
                    "last_seen_at": now,
                    "evidence_ids": ids,
                }
            )
            found = True
            break
    if not found:
        history.append(
            ObservedLocator(
                locator=locator,
                kind=kind,
                status=LocatorStatus.OBSERVED,
                first_seen_at=now,
                last_seen_at=now,
                source=source,
                evidence_ids=list(evidence_ids or []),
            )
        )
    resolved_v4 = list(target.resolved_ipv4)
    resolved_v6 = list(target.resolved_ipv6)
    if kind == "ipv4" and locator not in resolved_v4:
        resolved_v4.append(locator)
    if kind == "ipv6" and locator not in resolved_v6:
        resolved_v6.append(locator)
    return target.model_copy(
        update={
            "locator_history": history,
            "last_observed_at": now,
            "resolved_ipv4": resolved_v4,
            "resolved_ipv6": resolved_v6,
        }
    )


def mark_locator_unreachable(target: Target, raw: str, *, now: datetime) -> Target:
    """Note that a locator failed routing. Does not invalidate target identity."""
    try:
        _kind, locator = parse_locator(raw)
    except IdentityError:
        locator = (raw or "").strip()
    if not locator:
        return target
    history = [item.model_copy(deep=True) for item in target.locator_history]
    changed = False
    for idx, item in enumerate(history):
        if item.locator != locator:
            continue
        if item.status is LocatorStatus.CURRENT:
            history[idx] = item.model_copy(
                update={"last_seen_at": now, "status": LocatorStatus.UNREACHABLE}
            )
        else:
            history[idx] = item.model_copy(
                update={
                    "last_seen_at": now,
                    "status": LocatorStatus.UNREACHABLE
                    if item.status is not LocatorStatus.HISTORICAL
                    else item.status,
                }
            )
        changed = True
        break
    if not changed:
        return target
    current = target.current_locator
    if current == locator:
        # Keep current_locator so Brain still knows what we *intend* to reach.
        current = locator
    return target.model_copy(update={"locator_history": history, "last_observed_at": now})


def confirm_locator(
    target: Target,
    scope: Scope,
    raw: str,
    *,
    now: datetime,
    actor: str,
    mode,
    allow_special: bool = True,
) -> Target:
    """Operator-only promotion of an in-scope locator to current."""
    if actor not in OPERATOR_ACTORS:
        raise LocatorRejected("AI cannot change the mission target locator")
    try:
        kind, locator = parse_locator(raw)
    except IdentityError as exc:
        raise LocatorRejected(f"invalid locator: {raw}") from exc
    if not locator_in_scope(locator, scope, mode=mode, allow_special=allow_special):
        raise LocatorRejected("locator is outside frozen mission scope")
    if target.current_locator == locator:
        return observe_locator(target, locator, now=now, source="operator")

    previous = target.current_locator
    history = [item.model_copy(deep=True) for item in target.locator_history]
    seen = False
    for idx, item in enumerate(history):
        if item.locator == locator:
            history[idx] = item.model_copy(
                update={
                    "status": LocatorStatus.CURRENT,
                    "last_seen_at": now,
                    "source": "operator",
                }
            )
            seen = True
        elif previous and item.locator == previous:
            history[idx] = item.model_copy(
                update={"status": LocatorStatus.HISTORICAL, "last_seen_at": now}
            )
    if not seen:
        history.append(
            ObservedLocator(
                locator=locator,
                kind=kind,
                status=LocatorStatus.CURRENT,
                first_seen_at=now,
                last_seen_at=now,
                source="operator",
            )
        )
    resolved_v4 = list(target.resolved_ipv4)
    resolved_v6 = list(target.resolved_ipv6)
    if kind == "ipv4" and locator not in resolved_v4:
        resolved_v4.append(locator)
    if kind == "ipv6" and locator not in resolved_v6:
        resolved_v6.append(locator)
    return target.model_copy(
        update={
            "current_locator": locator,
            "locator_history": history,
            "last_observed_at": now,
            "resolved_ipv4": resolved_v4,
            "resolved_ipv6": resolved_v6,
        }
    )
