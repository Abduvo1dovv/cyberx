"""Candidate uniqueness: one executable action per coverage_key."""

from __future__ import annotations

from cyberx.brain.types import CandidateAction

# Planner proposes first; path/validation may overlap the same coverage_key.
_SOURCE_RANK = {"planner": 0, "path": 1, "validation": 2}


def merge_candidates(candidates: list[CandidateAction]) -> list[CandidateAction]:
    """Deterministic merge. ActionScorer remains the scoring authority.

    Same coverage_key → one executable candidate, merged reasons, highest gain.
    Source metadata is preserved as a comma-separated set.
    """
    grouped: dict[str, CandidateAction] = {}
    order: list[str] = []
    for cand in candidates:
        key = cand.coverage_key
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = cand
            order.append(key)
            continue
        grouped[key] = _merge_pair(existing, cand)
    return [grouped[key] for key in order]


def _merge_pair(left: CandidateAction, right: CandidateAction) -> CandidateAction:
    keep = left
    other = right
    if right.expected_information_gain > left.expected_information_gain:
        keep, other = right, left
    elif right.expected_information_gain == left.expected_information_gain:
        if _source_rank(right.source) < _source_rank(left.source):
            keep, other = right, left
    reasons = _merge_text(keep.reason, other.reason)
    sources = _merge_text(keep.source, other.source, sep=",")
    return keep.model_copy(update={"reason": reasons, "source": sources})


def _source_rank(source: str) -> int:
    first = source.split(",")[0].strip() if source else "planner"
    return _SOURCE_RANK.get(first, 9)


def _merge_text(left: str, right: str, *, sep: str = "; ") -> str:
    parts: list[str] = []
    seen: set[str] = set()
    for raw in (left, right):
        for token in raw.split(sep if sep != "," else ","):
            item = token.strip()
            if not item or item in seen:
                continue
            seen.add(item)
            parts.append(item)
    joiner = "," if sep == "," else sep
    return joiner.join(parts)[:500]
