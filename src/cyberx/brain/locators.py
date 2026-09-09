"""Current vs historical vs out-of-scope locator selection.

Historical / stale locators are not action targets. Out-of-scope hosts are
skipped. New locators require operator confirmation before they become current.
"""

from __future__ import annotations

from cyberx.domain.models.context import AssetContext
from cyberx.domain.models.findings import BrainContext

_BLOCKING_REACHABILITY = frozenset({"ROUTE_MISSING", "UNREACHABLE", "BLOCKED"})


def current_locator(ctx: BrainContext) -> str:
    ident = ctx.target_identity
    return ident.current or ctx.network.target_ip or ctx.network.current_locator or ""


def historical_locators(ctx: BrainContext) -> set[str]:
    ident = ctx.target_identity
    tokens = [part for part in ident.historical.split(",") if part]
    previous = ident.previous
    if previous:
        tokens.append(previous)
    return set(tokens)


def obsolete_locators(ctx: BrainContext) -> set[str]:
    """Locators that must not receive new IP-gated actions."""
    current = current_locator(ctx)
    return {token for token in historical_locators(ctx) if token != current}


def locator_is_obsolete(ctx: BrainContext, locator: str) -> bool:
    if not locator:
        return False
    return locator in obsolete_locators(ctx)


def hosts(ctx: BrainContext) -> list[AssetContext]:
    return [row for row in ctx.top_assets if row.kind == "host"]


def host_address(host: AssetContext) -> str:
    return host.address or host.key.split(":")[-1]


def hosts_for_ip_actions(ctx: BrainContext) -> list[AssetContext]:
    """Only current, in-scope, non-historical hosts may be IP-gated action targets."""
    obsolete = obsolete_locators(ctx)
    current = current_locator(ctx)
    live: list[AssetContext] = []
    for host in hosts(ctx):
        labels = host.labels.split(",") if host.labels else []
        if "historical" in labels:
            continue
        if host.oos == "1":
            continue
        addr = host_address(host)
        if addr in obsolete:
            continue
        live.append(host)
    if current:
        matching = [item for item in live if host_address(item) == current]
        if matching:
            return matching
    return live


def network_blocks_ip(ctx: BrainContext) -> bool:
    return ctx.network.reachability in _BLOCKING_REACHABILITY
