"""Deterministic coverage_key (SPEC §5.2)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cyberx.domain.models.actions import ActionTarget


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
