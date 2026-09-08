"""PolicyEngine — fail closed. Does not execute tools."""

from __future__ import annotations

from datetime import datetime

from cyberx.actions.catalog import DEFAULT_CATALOG, ActionCatalog
from cyberx.actions.validator import ActionValidator
from cyberx.domain.enums import (
    FORBIDDEN_ACTION_MARKERS,
    ActionStatus,
    MissionStatus,
    PolicyVerdict,
)
from cyberx.domain.errors import ActionRejected
from cyberx.domain.identity import is_secret_shaped_name, is_secret_shaped_value
from cyberx.domain.models.actions import Action, ActionRequest, PolicyDecision
from cyberx.domain.models.mission import Mission, Scope
from cyberx.scope.checker import ScopeChecker
from cyberx.scope.subject import subject_from_action


def _deny(code: str, message: str = "") -> PolicyDecision:
    return PolicyDecision(verdict=PolicyVerdict.DENY, reason_code=code, message=message or code)


def _allow(message: str = "authorized") -> PolicyDecision:
    return PolicyDecision(verdict=PolicyVerdict.ALLOW, reason_code="allow", message=message)


class PolicyEngine:
    def __init__(
        self,
        catalog: ActionCatalog | None = None,
        *,
        validator: ActionValidator | None = None,
        scope_checker: ScopeChecker | None = None,
    ) -> None:
        self._catalog = catalog or DEFAULT_CATALOG
        self._validator = validator or ActionValidator(self._catalog)
        self._scope = scope_checker or ScopeChecker()

    def authorize(
        self,
        action: Action | ActionRequest,
        mission: Mission,
        scope: Scope,
        now: datetime | None = None,
    ) -> PolicyDecision:
        """Authorize or deny. Never executes. Never mutates scope or mission."""
        if isinstance(action, ActionRequest):
            try:
                action = self._validator.validate(action)
            except ActionRejected as exc:
                return _deny(exc.reason_code, exc.message)

        marker_hit = [m for m in FORBIDDEN_ACTION_MARKERS if m in action.action_type.lower()]
        if marker_hit:
            return _deny("forbidden_action_kind", f"v1 hard-denies {marker_hit}")

        spec = self._catalog.get(action.action_type)
        if spec is None or not spec.enabled:
            return _deny("unknown_action", f"unknown action type: {action.action_type}")

        if mission.status is not MissionStatus.RUNNING:
            return _deny("mission_not_running", f"mission is {mission.status.value}")

        if mission.mode not in spec.allowed_modes:
            return _deny("mode_not_allowed")

        if action.timeout_s > spec.max_timeout_s:
            return _deny("timeout_exceeded")

        if spec.prerequisites_gap_kinds and not action.prerequisites:
            return _deny("missing_prerequisites")

        try:
            spec.parameter_schema.model_validate(action.parameters)
        except Exception as exc:
            return _deny("malformed_action", str(exc))

        if action.action_type == "port_scan":
            ports_mode = action.parameters.get("ports")
            if scope.allowed_ports and ports_mode in {"top100", "top1000"}:
                return _deny(
                    "port_not_allowed",
                    "restricted port set requires ports=specified",
                )
            if action.parameters.get("protocol") == "udp" and "udp" not in {
                p.lower() for p in scope.allowed_protocols
            }:
                return _deny("protocol_not_allowed")

        if action.action_type == "subdomain_enumeration" and not scope.allow_subdomains:
            return _deny("not_in_allowlist", "subdomain enumeration disabled by scope")

        if action.action_type == "network_discovery":
            if not scope.allowed_networks:
                return _deny("not_in_allowlist", "network_discovery requires allowed_networks")

        scoped = self._scope.check(action, scope, now=now, subject=subject_from_action(action))
        if not scoped.allowed:
            return scoped

        if action.status in {ActionStatus.REJECTED, ActionStatus.DENIED, ActionStatus.CANCELLED}:
            return _deny("malformed_action", f"action status is {action.status.value}")

        for key, raw in action.parameters.items():
            if is_secret_shaped_name(str(key)):
                return _deny("forbidden_action_kind", "credential parameters are forbidden")
            if isinstance(raw, str) and is_secret_shaped_value(raw):
                return _deny("forbidden_action_kind", "secret-shaped values are forbidden")
        method = str(action.parameters.get("method") or "").upper()
        if method in {"POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"}:
            return _deny("forbidden_action_kind", "unsafe HTTP method")

        return _allow()
