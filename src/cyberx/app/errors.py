"""Operator-facing error messages. TUI must not print tracebacks."""

from __future__ import annotations

from cyberx.domain.errors import (
    ActionRejected,
    AdapterUnavailable,
    ConfigurationError,
    CyberxError,
    DomainValidationError,
    ExecutionError,
    IllegalMissionTransition,
    LocatorRejected,
    MissionNotFound,
    MissionStateError,
    PolicyDeniedError,
    ScopeFrozenError,
    ScopeValidationError,
    StorageError,
    TargetValidationError,
)


class OperatorError(Exception):
    """Application-level operator error. Not a domain type."""

    def __init__(self, message: str, *, code: str = "operator") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def tool_unavailable_message(adapter_name: str) -> str:
    token = (adapter_name or "").lower()
    if "nmap" in token:
        return "nmap unavailable"
    if "directory" in token:
        return "directory enumeration transport unavailable"
    if "http" in token or "tech" in token or "endpoint" in token:
        return "HTTP transport unavailable"
    if "dns" in token or "subdomain" in token:
        return "DNS resolver unavailable"
    return f"tool unavailable: {adapter_name}"


def operator_message(exc: BaseException) -> str:
    if isinstance(exc, OperatorError):
        return exc.message
    if isinstance(exc, TargetValidationError):
        return f"Invalid target. {exc.message}"
    if isinstance(exc, ScopeFrozenError):
        return "Scope is frozen after confirmation and cannot be changed."
    if isinstance(exc, LocatorRejected):
        return f"Locator change denied. {exc.message}"
    if isinstance(exc, ScopeValidationError):
        return f"Scope rejected. {exc.message}"
    if isinstance(exc, IllegalMissionTransition):
        return f"That command is not valid in the current mission state ({exc.current})."
    if isinstance(exc, MissionNotFound):
        return "Mission not found."
    if isinstance(exc, MissionStateError):
        return f"Mission state error. {exc.message}"
    if isinstance(exc, PolicyDeniedError):
        return f"Policy denied the action. {exc.message}"
    if isinstance(exc, StorageError):
        return f"Storage error. {exc.message}"
    if isinstance(exc, AdapterUnavailable):
        return tool_unavailable_message(exc.adapter_name)
    if isinstance(exc, ActionRejected):
        return f"Action rejected. {exc.message}"
    if isinstance(exc, ConfigurationError):
        return f"Invalid configuration. {exc.message}"
    if isinstance(exc, ExecutionError):
        return f"Executor error. {exc.message}"
    if isinstance(exc, DomainValidationError):
        return f"Invalid input. {exc.message}"
    if isinstance(exc, CyberxError):
        return exc.message or exc.code
    return "An unexpected error occurred. Details were recorded in the event log."
