"""Deterministic coverage_key (SPEC §5.2) and blocking status."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cyberx.domain.models.actions import ActionTarget

# Skip re-proposal. `attempted` is not blocking — retries remain (SPEC §9.3).
BLOCKING_COVERAGE = frozenset(
    {
        "completed",
        "denied",
        "rejected",
        "running",
        "failed",
        "unavailable",
    }
)
RETRYABLE_ERROR_CODES = frozenset(
    {
        "timeout",
        "adapter_crash",
        "empty_output",
        "process_error",
    }
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def canonical_target_str(target: ActionTarget) -> str:
    if target.canonical_locator:
        return target.canonical_locator
    if target.asset_id:
        return target.asset_id
    return ""


def coverage_key(action_type: str, target: ActionTarget, parameters: dict[str, Any]) -> str:
    material = action_type + canonical_target_str(target) + canonical_json(parameters)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def coverage_status(value: str | None) -> str:
    return (value or "").split(":")[0].strip().lower()


def is_blocking_coverage(status: str | None) -> bool:
    return coverage_status(status) in BLOCKING_COVERAGE


def blocking_coverage_keys(coverage: dict[str, str] | None) -> list[str]:
    rows = coverage or {}
    return sorted(key for key, status in rows.items() if is_blocking_coverage(status))


def is_retryable_error(code: str | None) -> bool:
    return (code or "") in RETRYABLE_ERROR_CODES


def next_failure_coverage(previous: str | None, error_code: str | None) -> str:
    """First retryable miss → attempted. Exhausted or non-retryable → failed."""
    prev = coverage_status(previous)
    if is_retryable_error(error_code) and prev not in {"attempted", "failed"}:
        return "attempted"
    return "failed"


def attempt_display(previous: str | None, *, max_attempts: int = 2) -> tuple[int, str, bool]:
    """Return (attempt_number, 'n/max', retryable_after_this)."""
    prev = coverage_status(previous)
    number = 2 if prev == "attempted" else 1
    remaining = number < max_attempts
    return number, f"{number}/{max_attempts}", remaining


def format_action_event(
    action_type: str,
    status: str,
    *,
    reason: str = "",
    attempt: str = "",
    retryable: str = "",
    target: str = "",
    family: str = "",
    interface: str = "",
    source: str = "",
    route: str = "",
) -> str:
    bits = [action_type, status or "unknown"]
    if reason:
        bits.append(f"reason={reason}")
    if attempt:
        bits.append(f"attempt={attempt}")
    if retryable:
        bits.append(f"retryable={retryable}")
    if target:
        bits.append(f"target={target}")
    if family:
        bits.append(f"family={family}")
    if interface:
        bits.append(f"interface={interface}")
    if source:
        bits.append(f"source={source}")
    if route:
        bits.append(f"route={route}")
    return " ".join(bits)[:1000]


def parse_action_event(message: str) -> dict[str, str] | None:
    parts = (message or "").split()
    if len(parts) < 2:
        return None
    fields: dict[str, str] = {}
    for token in parts[2:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return {
        "action_type": parts[0],
        "status": parts[1],
        "reason": fields.get("reason", ""),
        "attempt": fields.get("attempt", ""),
        "retryable": fields.get("retryable", "NO"),
        "target": fields.get("target", ""),
        "family": fields.get("family", ""),
        "interface": fields.get("interface", ""),
        "source": fields.get("source", ""),
        "route": fields.get("route", ""),
    }
