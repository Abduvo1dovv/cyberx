"""Brain facade. Reads context, returns a Decision. Never executes tools."""

from __future__ import annotations

from cyberx.actions.catalog import DEFAULT_CATALOG, ActionCatalog
from cyberx.ai.none import NoneProvider
from cyberx.ai.protocol import IntelligenceProvider
from cyberx.brain.advisor import AiAdvisor
from cyberx.brain.context import BrainContextBuilder, context_hash
from cyberx.brain.decision import DecisionEngine
from cyberx.brain.hypotheses import HypothesisEngine
from cyberx.brain.planner import Planner
from cyberx.brain.scorer import ActionScorer
from cyberx.brain.types import Decision, HypothesisDelta
from cyberx.domain.models.findings import BrainContext


class Brain:
    def __init__(
        self,
        *,
        catalog: ActionCatalog | None = None,
        planner: Planner | None = None,
        scorer: ActionScorer | None = None,
        decision: DecisionEngine | None = None,
        hypotheses: HypothesisEngine | None = None,
        builder: BrainContextBuilder | None = None,
        provider: IntelligenceProvider | None = None,
    ) -> None:
        self.catalog = catalog or DEFAULT_CATALOG
        self.planner = planner or Planner(self.catalog)
        self.scorer = scorer or ActionScorer()
        self.decisions = decision or DecisionEngine()
        self.hypotheses = hypotheses or HypothesisEngine()
        self.builder = builder or BrainContextBuilder()
        self._provider = provider or NoneProvider()
        self._advisor = AiAdvisor(self._provider)

    def revise_hypotheses(self, ctx: BrainContext) -> list[HypothesisDelta]:
        deltas = self.hypotheses.revise(ctx)
        return self._advisor.enhance_hypotheses(ctx, deltas)

    def decide(
        self,
        ctx: BrainContext,
        catalog: ActionCatalog | None = None,
        *,
        min_score: float | None = None,
    ) -> Decision:
        cat = catalog or self.catalog
        candidates = self.planner.propose(ctx, cat)
        scored = self.scorer.score(candidates, ctx)
        scored = self._advisor.enhance_scores(ctx, candidates, scored)
        decision = self.decisions.select(scored, ctx, min_score=min_score)
        return decision.model_copy(update={"context_hash": context_hash(ctx)})

    def ai_status(self) -> dict[str, str | int | bool]:
        provider = self._provider
        name = getattr(provider, "name", "none")
        available = bool(getattr(provider, "available", False)) and name != "none"
        if name == "none":
            status = "DISABLED"
            reason = "provider not configured"
        elif not getattr(provider, "available", False):
            status = "DISABLED"
            reason = getattr(provider, "status_reason", "provider not configured")
        else:
            status = "AVAILABLE"
            reason = getattr(provider, "status_reason", "ok")
        return {
            "provider": name,
            "status": status,
            "reason": reason,
            "calls": int(getattr(provider, "calls", 0) or 0),
            "budget": int(getattr(provider, "budget", 0) or 0),
            "model": str(getattr(provider, "model", "") or ""),
            "available": available,
        }
