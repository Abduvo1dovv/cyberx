"""Epistemic status + confidence updates (SPEC §3.5–3.6)."""

from __future__ import annotations

from cyberx.domain.confidence import apply_contradicting, apply_supporting
from cyberx.domain.enums import EpistemicStatus
from cyberx.domain.models.evidence import Evidence

HIGH_DIRECT_PREDICATES = frozenset(
    {
        "port.state",
        "http.status",
        "dns.record",
        "url.seen",
        "host.alive",
    }
)

FINGERPRINT_PREDICATES = frozenset(
    {
        "service.product",
        "service.version",
        "service.banner",
        "http.tech",
    }
)

_AI_PARSERS = frozenset({"ai", "llm", "hypothesis"})

_RANK = {
    EpistemicStatus.UNKNOWN: 0,
    EpistemicStatus.SUSPECTED: 1,
    EpistemicStatus.KNOWN: 2,
    EpistemicStatus.SUPPORTED: 3,
    EpistemicStatus.CONFIRMED: 4,
    EpistemicStatus.INVALIDATED: -1,
}


def is_ai_parser(parser_id: str) -> bool:
    return parser_id.lower() in _AI_PARSERS


def status_from_reliability(predicate: str, reliability: float) -> EpistemicStatus:
    """Single-observation table in SPEC §3.6."""
    r = reliability
    if r >= 0.90 and predicate in HIGH_DIRECT_PREDICATES:
        return EpistemicStatus.CONFIRMED
    if r >= 0.70:
        return EpistemicStatus.KNOWN
    if r >= 0.40:
        if predicate in FINGERPRINT_PREDICATES:
            return EpistemicStatus.SUPPORTED
        return EpistemicStatus.SUSPECTED
    return EpistemicStatus.SUSPECTED


def is_independent(first: Evidence, second: Evidence) -> bool:
    """Independent = different tool_run_id and (parser_id or action_type)."""
    if first.tool_run_id == second.tool_run_id:
        return False
    if first.parser_id != second.parser_id:
        return True
    action_a = (first.claim_preview or {}).get("action_type")
    action_b = (second.claim_preview or {}).get("action_type")
    if (
        isinstance(action_a, str)
        and isinstance(action_b, str)
        and action_a
        and action_b
        and action_a != action_b
    ):
        return True
    return False


def has_independent_pair(items: list[Evidence]) -> bool:
    for i, left in enumerate(items):
        for right in items[i + 1 :]:
            if is_independent(left, right):
                return True
    return False


def status_after_support(
    predicate: str,
    confidence: float,
    evidences: list[Evidence],
    *,
    open_contradiction: bool,
) -> EpistemicStatus:
    if not evidences:
        return EpistemicStatus.UNKNOWN
    independent = has_independent_pair(evidences)
    if independent and confidence >= 0.80 and not open_contradiction:
        return EpistemicStatus.CONFIRMED
    max_r = max(item.reliability for item in evidences)
    base = status_from_reliability(predicate, max_r)
    if independent and confidence >= 0.70:
        if _RANK[base] >= _RANK[EpistemicStatus.SUPPORTED]:
            return base
        return EpistemicStatus.SUPPORTED
    return base


def apply_support(confidence: float, reliability: float) -> float:
    return apply_supporting(confidence, reliability)


def apply_contradiction(confidence: float, reliability: float) -> tuple[float, bool]:
    return apply_contradicting(confidence, reliability)


def max_status(left: EpistemicStatus, right: EpistemicStatus) -> EpistemicStatus:
    if _RANK[left] >= _RANK[right]:
        return left
    return right
