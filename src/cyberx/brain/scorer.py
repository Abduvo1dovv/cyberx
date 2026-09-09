"""ActionScorer — exact SPEC §15.6 formula. AI advice is applied after this scorer."""

from __future__ import annotations

from cyberx.actions.scoring import RISK_VALUE, ScoreFactors, compute_score
from cyberx.brain.types import CandidateAction, ScoredAction, factors_as_dict
from cyberx.domain.confidence import clamp01
from cyberx.domain.enums import Risk
from cyberx.domain.models.findings import BrainContext

MIN_SCORE = 0.15


class ActionScorer:
    def score(self, candidates: list[CandidateAction], ctx: BrainContext) -> list[ScoredAction]:
        seen = set(ctx.coverage_keys)
        open_kinds = {gap.kind for gap in ctx.gaps}
        sibling_failed = any(row.status == "failed" for row in ctx.recent_results)
        out: list[ScoredAction] = []
        for cand in candidates:
            novelty = 0.0 if cand.coverage_key in seen else 1.0
            related = cand.gap_kind in open_kinds or any(
                p in open_kinds for p in cand.prerequisites
            )
            if cand.action_type == "http_probe" and any(
                asset.kind == "port" and asset.state == "open" for asset in ctx.top_assets
            ):
                related = True
            if _validation_hit(cand, ctx):
                related = True
            readiness = 1.0 if related or not cand.prerequisites else 0.0
            if cand.action_type == "network_discovery":
                readiness = 1.0
                related = True
            gain_base = cand.expected_information_gain
            information_gain = gain_base * (1.0 if related else 0.1)
            relevance = 1.0 if related else 0.4
            evidence_strength = 1.0 if ctx.asset_counts.get("host") or related else 0.0
            if cand.action_type == "network_discovery":
                evidence_strength = 1.0
            intel = _intel_for(cand, ctx)
            if intel > 0:
                relevance = clamp01(max(relevance, 0.7 * relevance + 0.3 * intel))
                information_gain = clamp01(
                    max(information_gain, 0.85 * information_gain + 0.15 * intel)
                )
            p_useful = 0.3 if sibling_failed else 0.7
            try:
                risk_enum = Risk(cand.risk)
            except ValueError:
                risk_enum = Risk.LOW
            factors = ScoreFactors(
                mission_relevance=relevance,
                information_gain=information_gain,
                evidence_strength=evidence_strength,
                p_useful=p_useful,
                novelty=novelty,
                dependency_readiness=readiness,
                cost=cand.cost,
                risk=RISK_VALUE[risk_enum],
            )
            value = compute_score(factors)
            rejected = novelty == 0.0 or readiness == 0.0
            reason = ""
            if novelty == 0.0:
                reason = "novelty_zero"
            elif readiness == 0.0:
                reason = "not_ready"
            out.append(
                ScoredAction(
                    candidate=cand,
                    score=value,
                    factors=factors_as_dict(factors),
                    rejected=rejected,
                    reject_reason=reason,
                )
            )
        return out


def _intel_for(cand: CandidateAction, ctx: BrainContext) -> float:
    best = 0.0
    locator = cand.target.canonical_locator or ""
    asset_id = cand.target.asset_id or ""
    for row in ctx.investigations:
        try:
            pri = float(row.priority or 0)
        except ValueError:
            pri = 0.0
        if asset_id and row.asset_id == asset_id:
            best = max(best, pri)
        elif locator and locator in (row.asset or ""):
            best = max(best, pri)
    for row in ctx.validation_candidates:
        if row.status != "proposed":
            continue
        try:
            pri = float(row.priority or 0)
        except ValueError:
            pri = 0.0
        if row.coverage_key and row.coverage_key == cand.coverage_key:
            best = max(best, pri)
        elif row.action == cand.action_type and locator and locator == row.locator:
            best = max(best, pri)
    for row in ctx.investigation_paths:
        if row.oos == "1":
            continue
        try:
            pri = float(row.priority or 0)
        except ValueError:
            pri = 0.0
        if row.action != cand.action_type:
            continue
        path_locator = row.locator
        if path_locator and (
            path_locator == locator or locator in path_locator or path_locator in locator
        ):
            best = max(best, pri)
        elif asset_id and (row.asset_id == asset_id or row.host_id == asset_id):
            best = max(best, pri)
    return clamp01(best)


def _validation_hit(cand: CandidateAction, ctx: BrainContext) -> bool:
    locator = cand.target.canonical_locator or ""
    for row in ctx.validation_candidates:
        if row.status != "proposed":
            continue
        if row.coverage_key and row.coverage_key == cand.coverage_key:
            return True
        if row.action == cand.action_type and locator and locator == row.locator:
            return True
    for row in ctx.investigation_paths:
        if row.oos == "1":
            continue
        if row.action != cand.action_type:
            continue
        path_locator = row.locator
        if path_locator and locator and (path_locator == locator or locator in path_locator):
            return True
    return False
