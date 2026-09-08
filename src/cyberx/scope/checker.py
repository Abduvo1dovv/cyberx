"""ScopeChecker — deterministic allow/deny (SPEC §4.8)."""

from __future__ import annotations

import ipaddress
from datetime import datetime

from cyberx.domain.enums import PolicyVerdict
from cyberx.domain.identity import is_subdomain_of, normalize_fqdn
from cyberx.domain.models.actions import Action, PolicyDecision, ScopeSubject
from cyberx.domain.models.mission import Scope
from cyberx.domain.time import utcnow
from cyberx.scope.subject import subject_from_action


def _deny(code: str, message: str = "") -> PolicyDecision:
    return PolicyDecision(verdict=PolicyVerdict.DENY, reason_code=code, message=message or code)


def _allow() -> PolicyDecision:
    return PolicyDecision(verdict=PolicyVerdict.ALLOW, reason_code="allow", message="in scope")


def _looks_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class ScopeChecker:
    def check(
        self,
        action: Action,
        scope: Scope,
        now: datetime | None = None,
        subject: ScopeSubject | None = None,
    ) -> PolicyDecision:
        if not scope.frozen:
            return _deny("scope_not_frozen")
        moment = now or utcnow()
        if scope.time_window_start and moment < scope.time_window_start:
            return _deny("out_of_time_window")
        if scope.time_window_end and moment > scope.time_window_end:
            return _deny("out_of_time_window")

        subj = subject or subject_from_action(action)
        for ip in subj.ips:
            decision = self._check_ip(ip, scope)
            if not decision.allowed:
                return decision
        for fqdn in subj.fqdns:
            decision = self._check_fqdn(fqdn, scope)
            if not decision.allowed:
                return decision
        for cidr in subj.cidrs:
            decision = self._check_cidr(cidr, scope)
            if not decision.allowed:
                return decision
        for port in subj.ports:
            decision = self._check_port(port, scope)
            if not decision.allowed:
                return decision
        proto_decision = self._check_protocol(action.action_type, subj, scope)
        if not proto_decision.allowed:
            return proto_decision
        if subj.url and not (subj.ips or subj.fqdns):
            return _deny("not_in_allowlist", "URL host could not be scoped")
        if not (subj.ips or subj.fqdns or subj.cidrs):
            # asset_id-only target: still require the canonical locator for v1
            if action.target.canonical_locator:
                return _deny("not_in_allowlist")
            # host_id without locator is accepted at scope layer only if no locators
            # to check; engine/world will bind later. Fail closed if action type
            # requires a network locator.
            if (
                action.action_type
                in {
                    "network_discovery",
                    "dns_enumeration",
                    "http_probe",
                    "directory_enumeration",
                }
                and not action.target.canonical_locator
            ):
                if action.action_type == "http_probe" and action.parameters.get("url"):
                    return _deny("not_in_allowlist")
                if action.action_type == "network_discovery":
                    return _deny("not_in_allowlist", "network_discovery requires a CIDR")
        return _allow()

    def _check_ip(self, ip: str, scope: Scope) -> PolicyDecision:
        addr = ipaddress.ip_address(ip)
        if ip in scope.excluded_targets or str(addr) in scope.excluded_targets:
            return _deny("excluded")
        for net in scope.excluded_networks:
            if addr in ipaddress.ip_network(net, strict=False):
                return _deny("excluded")
        if ip in scope.allowed_targets or str(addr) in scope.allowed_targets:
            return _allow()
        for net in scope.allowed_networks:
            if addr in ipaddress.ip_network(net, strict=False):
                return _allow()
        return _deny("not_in_allowlist", f"IP {ip} not in scope")

    def _check_fqdn(self, fqdn: str, scope: Scope) -> PolicyDecision:
        name = normalize_fqdn(fqdn)
        excluded = [normalize_fqdn(t) for t in scope.excluded_targets if not _looks_ip(t)]
        if name in excluded:
            return _deny("excluded")
        allowed = [normalize_fqdn(t) for t in scope.allowed_targets if not _looks_ip(t)]
        if name in allowed:
            return _allow()
        if scope.allow_subdomains and any(is_subdomain_of(name, parent) for parent in allowed):
            return _allow()
        return _deny("not_in_allowlist", f"name {fqdn} not in scope")

    def _check_cidr(self, cidr: str, scope: Scope) -> PolicyDecision:
        network = ipaddress.ip_network(cidr, strict=False)
        for excluded in scope.excluded_networks:
            if network.overlaps(ipaddress.ip_network(excluded, strict=False)):
                return _deny("excluded")
        # SPEC: network_discovery CIDR must equal an allowed_network
        allowed = {str(ipaddress.ip_network(n, strict=False)) for n in scope.allowed_networks}
        if str(network) in allowed:
            return _allow()
        return _deny("not_in_allowlist", f"CIDR {cidr} is not an allowed_network")

    def _check_port(self, port: int, scope: Scope) -> PolicyDecision:
        if port in scope.excluded_ports:
            return _deny("excluded")
        if scope.allowed_ports and port not in scope.allowed_ports:
            return _deny("port_not_allowed")
        return _allow()

    def _check_protocol(
        self, action_type: str, subject: ScopeSubject, scope: Scope
    ) -> PolicyDecision:
        allowed = {p.lower() for p in scope.allowed_protocols}
        if action_type == "http_probe":
            schemes = subject.schemes or (
                [subject.protocol] if subject.protocol in {"http", "https"} else []
            )
            if not schemes:
                if "http" not in allowed and "https" not in allowed:
                    return _deny("protocol_not_allowed")
            else:
                for scheme in schemes:
                    if scheme not in allowed:
                        return _deny("protocol_not_allowed")
            return _allow()
        if action_type in {
            "technology_detection",
            "directory_enumeration",
            "endpoint_discovery",
        }:
            if "http" not in allowed and "https" not in allowed:
                return _deny("protocol_not_allowed")
            return _allow()
        if action_type in {"dns_enumeration", "subdomain_enumeration"}:
            if "dns" not in allowed:
                return _deny("protocol_not_allowed")
            return _allow()
        if action_type == "port_scan":
            proto = subject.protocol or "tcp"
            if proto not in allowed:
                return _deny("protocol_not_allowed")
            return _allow()
        if subject.protocol and subject.protocol not in allowed:
            # tcp implied for network_discovery / service_enumeration
            if subject.protocol == "tcp" and "tcp" not in allowed:
                return _deny("protocol_not_allowed")
        return _allow()
