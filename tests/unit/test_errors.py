from __future__ import annotations

from cyberx.app.errors import operator_message, tool_unavailable_message
from cyberx.domain.errors import (
    ActionRejected,
    AdapterError,
    AdapterUnavailable,
    ConfigurationError,
    CyberxError,
    DomainValidationError,
    ExecutionBypassError,
    ExecutionError,
    IllegalMissionTransition,
    InvalidWorldDelta,
    MissionStateError,
    ParseError,
    PolicyDeniedError,
    ScopeFrozenError,
    ScopeValidationError,
    ScopeViolationError,
    StorageError,
    WorldModelError,
)


def test_error_categories() -> None:
    assert DomainValidationError("x").category == "domain_validation"
    assert IllegalMissionTransition("CREATED", "RUNNING").category == "mission_state"
    assert isinstance(IllegalMissionTransition("CREATED", "RUNNING"), MissionStateError)
    assert ScopeFrozenError("frozen").category == "scope_violation"
    assert isinstance(ScopeValidationError("bad"), ScopeViolationError)
    assert ActionRejected("unknown_action").category == "action_validation"
    assert PolicyDeniedError("not_in_allowlist").category == "policy_denial"
    assert AdapterError("down").category == "adapter_failure"
    assert ExecutionError("boom").category == "execution_failure"
    assert StorageError("io").category == "storage_failure"
    assert ConfigurationError("env").category == "configuration_failure"
    assert ParseError("bad xml").category == "parse_failure"
    assert WorldModelError("no").category == "world_model"
    assert InvalidWorldDelta("bad delta").category == "world_model"
    assert isinstance(InvalidWorldDelta("bad delta"), WorldModelError)


def test_all_errors_are_cyberx_error() -> None:
    err = ActionRejected("malformed_action", "bad params")
    assert isinstance(err, CyberxError)
    assert err.reason_code == "malformed_action"
    assert err.code == "malformed_action"


def test_bypass_and_unavailable_categories() -> None:
    bypass = ExecutionBypassError()
    assert isinstance(bypass, ExecutionError)
    assert bypass.category == "execution_failure"
    assert bypass.code == "policy_bypass"
    missing = AdapterUnavailable("nmap_adapter")
    assert isinstance(missing, AdapterError)
    assert missing.category == "adapter_failure"
    assert missing.adapter_name == "nmap_adapter"
    assert tool_unavailable_message("nmap_adapter") == "nmap unavailable"
    assert operator_message(missing) == "nmap unavailable"
    assert operator_message(AdapterUnavailable("http_adapter")) == "HTTP transport unavailable"
