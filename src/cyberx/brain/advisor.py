"""When to call AI, and how to merge advisory output. Never executes."""

from __future__ import annotations

from collections.abc import Sequence

from cyberx.ai.protocol import HypothesisDraft, IntelligenceProvider, ScoreAdvice
from cyberx.ai.validate import DELTA_LIMIT
from cyberx.brain.types import CandidateAction, HypothesisDelta, ScoredAction
from cyberx.domain.confidence import clamp01
from cyberx.domain.models.findings import BrainContext

_TRIVIAL_GAPS = {
    "host.ports_unknown",
    "host.unresolved",
    "target.route_missing",
    "target.unreachable",
    "target.blocked",
}


def is_trivial(ctx: BrainContext) -> bool:
    if ctx.top_findings or ctx.investigation_paths or ctx.validation_candidates:
        return False
    kinds = {g.get("kind") or "" for g in ctx.gaps}
    kinds.discard("")
    if not kinds:
        return True
    return kinds <= _TRIVIAL_GAPS


def want_hypotheses(ctx: BrainContext) -> bool:
    if is_trivial(ctx):
        return False
    return bool(ctx.top_findings or ctx.gaps)


def want_advice(scored: Sequence[ScoredAction], ctx: BrainContext) -> bool:
    if is_trivial(ctx):
        return False
    eligible = [item for item in scored if not item.rejected]
    if len(eligible) < 2:
        return False
    eligible.sort(key=lambda item: -item.score)
    close = abs(eligible[0].score - eligible[1].score) <= 0.12
    if close:
        return True
    return bool(ctx.top_findings or ctx.investigation_paths or len(ctx.gaps) >= 2)


def drafts_to_deltas(drafts: Sequence[HypothesisDraft], ctx: BrainContext) -> list[HypothesisDelta]:
    del ctx
    out: list[HypothesisDelta] = []
    for item in drafts:
        subject = item.related_canonical_keys[0] if item.related_canonical_keys else ""
        out.append(
            HypothesisDelta(
                op="create",
                statement=item.statement[:500],
                confidence=min(0.4, max(0.0, item.confidence)),
                rationale=(item.rationale or "ai suggestion")[:500],
                subject_id=subject if subject.startswith("hst_") else "",
                source="ai",
            )
        )
    return out


def apply_score_advice(
    scored: list[ScoredAction], advice: Sequence[ScoreAdvice]
) -> list[ScoredAction]:
    by_key = {item.coverage_key: item for item in advice}
    out: list[ScoredAction] = []
    for item in scored:
        hint = by_key.get(item.candidate.coverage_key)
        if hint is None or item.rejected:
            out.append(item)
            continue
        delta = max(-DELTA_LIMIT, min(DELTA_LIMIT, hint.delta))
        out.append(item.model_copy(update={"score": clamp01(item.score + delta)}))
    return out


class AiAdvisor:
    def __init__(self, provider: IntelligenceProvider) -> None:
        self._provider = provider

    def enhance_hypotheses(
        self, ctx: BrainContext, deltas: list[HypothesisDelta]
    ) -> list[HypothesisDelta]:
        if not want_hypotheses(ctx):
            return deltas
        drafts = self._provider.hypothesize(ctx)
        extra = drafts_to_deltas(drafts, ctx)
        return list(deltas) + extra

    def enhance_scores(
        self,
        ctx: BrainContext,
        candidates: Sequence[CandidateAction],
        scored: list[ScoredAction],
    ) -> list[ScoredAction]:
        if not want_advice(scored, ctx):
            return scored
        advice = self._provider.advise_scores(candidates, ctx)
        return apply_score_advice(scored, advice)
