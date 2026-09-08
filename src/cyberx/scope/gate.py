"""World-model scope gate. Marks discovered assets out of scope without expanding scope."""

from __future__ import annotations

import ipaddress
import re

from cyberx.domain.identity import normalize_fqdn
from cyberx.domain.models.mission import Scope
from cyberx.scope.checker import ScopeChecker

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


class MissionScopeGate:
    """ScopeGate protocol. Hosts/ports not in the frozen allowlist are out_of_scope."""

    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self._checker = ScopeChecker()

    def out_of_scope(self, canonical_key: str) -> bool:
        address = _address_from_key(canonical_key)
        if address is None:
            return False
        try:
            ipaddress.ip_address(address)
            decision = self._checker._check_ip(address, self._scope)
            return not decision.allowed
        except ValueError:
            decision = self._checker._check_fqdn(address, self._scope)
            return not decision.allowed


def _address_from_key(key: str) -> str | None:
    if key.startswith("host:ipv4:"):
        return key[len("host:ipv4:") :]
    if key.startswith("host:ipv6:"):
        return key[len("host:ipv6:") :]
    if key.startswith("host:name:"):
        return key[len("host:name:") :]
    if key.startswith("domain:"):
        return key[len("domain:") :]
    if key.startswith("subdomain:"):
        return key[len("subdomain:") :]
    match = _IPV4.search(key)
    if match:
        return match.group(1)
    if ":name:" in key:
        rest = key.split(":name:", 1)[1]
        return rest.split(":")[0]
    try:
        normalize_fqdn(key)
    except Exception:
        return None
    return None
