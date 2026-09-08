"""Safe validation rules. v2 adds rules behind this protocol; v1 is recon-only."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from cyberx.domain.enums import FindingKind
from cyberx.domain.models.findings import Finding
from cyberx.validation.mappings import UNSAFE_CANDIDATE_TYPES, mapping_for

Draft = dict[str, Any]


class ValidationRule(Protocol):
    """Extension point for v2 protocol-specific validation. Must not execute."""

    candidate_type: str

    def consider(self, finding: Finding, world: Any) -> Draft | None:
        """Return a draft mapping or None. Never returns exploit types."""
        ...


def default_rule(finding: Finding, world: Any) -> Draft | None:
    asset = None
    if finding.asset_ids and world is not None:
        asset = world.peek_asset_by_id(finding.asset_ids[0])
    mapped = mapping_for(finding, asset)
    if mapped is None:
        return None
    candidate_type, action, expected = mapped
    if candidate_type in UNSAFE_CANDIDATE_TYPES:
        return None
    if finding.kind is FindingKind.OUT_OF_SCOPE_OBSERVATION:
        return None
    if getattr(asset, "out_of_scope", False):
        return None
    return {
        "candidate_type": candidate_type,
        "action": action,
        "expected": expected,
        "asset": asset,
        "reason": _reason(candidate_type, finding),
    }


def _reason(candidate_type: str, finding: Finding) -> str:
    titles = {
        "http_surface": "Confirm HTTP surface with a canonical in-scope probe",
        "interesting_path": "Re-observe interesting path with an in-scope HTTP probe",
        "unusual_http": "Clarify unusual HTTP behavior with a safe GET probe",
        "redirect_behavior": "Re-observe in-scope redirect with existing HTTP probe rules",
        "technology_fingerprint": "Obtain stronger technology evidence from existing detection",
        "authentication_surface": "Confirm authentication surface shape without credentials",
        "service_fingerprint": "Confirm service fingerprint with non-invasive enumeration",
    }
    base = titles.get(candidate_type, "Investigate recon signal with a catalogued action")
    detail = finding.signal or finding.kind.value
    return f"{base} ({detail})"


SAFE_RULES: tuple[Callable[[Finding, Any], Draft | None], ...] = (default_rule,)
