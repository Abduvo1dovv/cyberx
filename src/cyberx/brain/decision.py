"""DecisionEngine — pick top legal candidate or STOP (SPEC §8.2, §15.6)."""

from __future__ import annotations

from cyberx.brain.locators import network_blocks_ip
from cyberx.brain.types import Decision, ScoredAction
from cyberx.domain.ids import PREFIX_DECISION, new_id
from cyberx.domain.models.findings import BrainContext
from cyberx.domain.time import utcnow

MIN_SCORE = 0.15


class DecisionEngine:
    def select(
        self,
        scored: list[ScoredAction],
        ctx: BrainContext,
        *,
        min_score: float | None = None,
    ) -> Decision:
        threshold = ctx_min(ctx, min_score)
        rejected = [
            {
                "action_type": s.candidate.action_type,
                "coverage_key": s.candidate.coverage_key,
                "reason": s.reject_reason or "below_min_score",
            }
            for s in scored
            if s.rejected or s.score < threshold
        ]
        eligible = [s for s in scored if (not s.rejected) and s.score >= threshold]
        eligible.sort(
            key=lambda s: (
                -s.score,
                s.factors.get("risk", 1.0),
                s.factors.get("cost", 1.0),
                s.candidate.catalog_index,
            )
        )
        scores = [
            {
                "action_type": s.candidate.action_type,
                "score": f"{s.score:.4f}",
                "novelty": f"{s.factors.get('novelty', 0):.1f}",
                "coverage_key": s.candidate.coverage_key[:16],
            }
            for s in scored
        ]
        if not eligible:
            reason = "no_actions"
            if not ctx.gaps:
                reason = "objectives_met"
            extra = ""
            if network_blocks_ip(ctx):
                extra = f" reachability={ctx.network.reachability}"
            return Decision(
                decision_id=new_id(PREFIX_DECISION),
                kind="stop",
                rejected=rejected,
                rationale="stop no legal action above min score" + extra,
                scores=scores,
                context_revision=ctx.revision,
                created_at=utcnow(),
                stop_reason=reason,
            )
        top = eligible[0]
        cand = top.candidate
        locator = cand.target.canonical_locator or cand.gap_subject or ""
        rationale = (
            f"gap={cand.gap_kind or 'none'} host={locator} "
            f"score={top.score:.2f} gain={top.factors.get('information_gain', 0):.2f} "
            f"novelty={top.factors.get('novelty', 0):.1f}"
        )
        return Decision(
            decision_id=new_id(PREFIX_DECISION),
            kind="act",
            action=cand,
            rejected=rejected,
            rationale=rationale,
            scores=scores,
            context_revision=ctx.revision,
            created_at=utcnow(),
        )


def ctx_min(ctx: BrainContext, override: float | None) -> float:
    del ctx
    if override is None:
        return MIN_SCORE
    return override
