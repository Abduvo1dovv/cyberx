"""Coherent error hierarchy for logging, TUI, and API layers."""

from __future__ import annotations

from typing import Any


class CyberxError(Exception):
    """Base error. `category` classifies the failure for callers."""

    category = "generic"

    def __init__(
        self,
        message: str = "",
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or type(self).__name__
        self.details = details or {}


class DomainValidationError(CyberxError):
    category = "domain_validation"


class IdentityError(DomainValidationError):
    """Canonical key / locator construction failed."""


class TargetValidationError(DomainValidationError):
    """Target raw_input could not be normalized."""


class ScopeViolationError(CyberxError):
    category = "scope_violation"


class ScopeValidationError(ScopeViolationError, DomainValidationError):
    """Scope failed validation (create/update time)."""

    category = "scope_violation"


class ScopeFrozenError(ScopeViolationError):
    """Attempt to mutate a frozen scope."""


class LocatorRejected(ScopeValidationError):
    """New locator denied (out of scope, AI actor, or illegal state)."""

    category = "scope_violation"


class MissionStateError(CyberxError):
    category = "mission_state"


class IllegalMissionTransition(MissionStateError):
    """Mission state machine rejected the transition."""

    def __init__(self, current: str, dest: str) -> None:
        self.current = current
        self.dest = dest
        super().__init__(
            f"illegal mission transition {current} -> {dest}",
            code="illegal_transition",
            details={"current": current, "dest": dest},
        )


class MissionNotFound(MissionStateError):
    def __init__(self, mission_id: str) -> None:
        self.mission_id = mission_id
        super().__init__(
            f"mission not found: {mission_id}",
            code="mission_not_found",
            details={"mission_id": mission_id},
        )


class ActionValidationError(CyberxError):
    category = "action_validation"


class ActionValidationIssue:
    __slots__ = ("field", "code", "message")

    def __init__(self, field: str, code: str, message: str) -> None:
        self.field = field
        self.code = code
        self.message = message

    def as_dict(self) -> dict[str, str]:
        return {"field": self.field, "code": self.code, "message": self.message}


class ActionRejected(ActionValidationError):
    """Unknown or malformed action failed closed. Constructor kept stable for M0–M2."""

    def __init__(
        self,
        reason_code: str,
        message: str = "",
        issues: list[ActionValidationIssue] | None = None,
    ) -> None:
        self.reason_code = reason_code
        self.issues = tuple(issues or ())
        text = message or reason_code
        super().__init__(
            text,
            code=reason_code,
            details={"issues": [i.as_dict() for i in self.issues]},
        )
        self.message = text


class PolicyDeniedError(CyberxError):
    category = "policy_denial"

    def __init__(self, reason_code: str, message: str = "", *, details: dict | None = None) -> None:
        self.reason_code = reason_code
        super().__init__(message or reason_code, code=reason_code, details=details)
        self.message = message or reason_code


class AdapterError(CyberxError):
    category = "adapter_failure"


class AdapterUnavailable(AdapterError):
    def __init__(self, adapter_name: str) -> None:
        self.adapter_name = adapter_name
        super().__init__(
            f"adapter unavailable: {adapter_name}",
            code="adapter_unavailable",
            details={"adapter": adapter_name},
        )


class ExecutionError(CyberxError):
    category = "execution_failure"


class ExecutionBypassError(ExecutionError):
    """Raised if code tries to run an action without a policy Allow."""

    def __init__(self, message: str = "executor cannot bypass policy") -> None:
        super().__init__(message, code="policy_bypass")


class StorageError(CyberxError):
    category = "storage_failure"


class ConfigurationError(CyberxError):
    category = "configuration_failure"


class ParseError(CyberxError):
    """Malformed or unsafe artifact; parsers fail closed."""

    category = "parse_failure"

    def __init__(
        self, message: str, *, code: str = "malformed_artifact", details: dict | None = None
    ) -> None:
        super().__init__(message, code=code, details=details)


class WorldModelError(CyberxError):
    """Projection, correlation, or apply failed. Facts were not invented."""

    category = "world_model"


class InvalidWorldDelta(WorldModelError):
    """A WorldDelta violated evidence rules or the closed kind catalog."""

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message, code="invalid_world_delta", details=details)
