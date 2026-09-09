"""Apply Brain hypothesis deltas to the World Model. Never writes claims."""

from __future__ import annotations

from cyberx.brain.hypotheses import core_statement
from cyberx.brain.types import HypothesisDelta
from cyberx.domain.confidence import AI_HYPOTHESIS_CONFIDENCE_CAP
from cyberx.domain.enums import HypothesisSource, HypothesisStatus
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import PREFIX_HYPOTHESIS, new_id
from cyberx.domain.models.findings import Hypothesis
from cyberx.domain.time import utcnow
from cyberx.world.model import InMemoryWorldModel


def apply_hypothesis_deltas(
    world: InMemoryWorldModel, mission_id: str, deltas: list[HypothesisDelta]
) -> None:
    existing = {h.statement: h for h in world.get_hypotheses()}
    existing_core = {core_statement(h.statement) for h in world.get_hypotheses()}
    existing_gaps = {gid for hyp in world.get_hypotheses() for gid in hyp.related_gap_ids if gid}
    for delta in deltas:
        if delta.op == "create" and delta.statement not in existing:
            if core_statement(delta.statement) in existing_core:
                continue
            if delta.gap_id and delta.gap_id in existing_gaps:
                continue
            source = HypothesisSource.AI if delta.source == "ai" else HypothesisSource.HEURISTIC
            confidence = delta.confidence
            if source is HypothesisSource.AI:
                confidence = min(AI_HYPOTHESIS_CONFIDENCE_CAP, confidence)
            try:
                hyp = Hypothesis(
                    hypothesis_id=new_id(PREFIX_HYPOTHESIS),
                    mission_id=mission_id,
                    statement=delta.statement,
                    status=HypothesisStatus.OPEN,
                    confidence=confidence,
                    created_at=utcnow(),
                    rationale=delta.rationale,
                    related_asset_ids=[delta.subject_id] if delta.subject_id else [],
                    related_gap_ids=[delta.gap_id] if delta.gap_id else [],
                    source=source,
                )
            except DomainValidationError:
                continue
            world.record_hypothesis(hyp)
            existing[delta.statement] = hyp
            existing_core.add(core_statement(delta.statement))
            if delta.gap_id:
                existing_gaps.add(delta.gap_id)
        elif delta.op == "support":
            for hyp in world.get_hypotheses():
                if hyp.statement == delta.statement or (
                    delta.hypothesis_id and hyp.hypothesis_id == delta.hypothesis_id
                ):
                    raised = min(1.0, hyp.confidence + 0.15)
                    if hyp.source is HypothesisSource.AI:
                        raised = min(AI_HYPOTHESIS_CONFIDENCE_CAP, raised)
                    try:
                        world.record_hypothesis(
                            hyp.model_copy(
                                update={
                                    "status": HypothesisStatus.SUPPORTED,
                                    "confidence": raised,
                                    "rationale": delta.rationale or hyp.rationale,
                                }
                            )
                        )
                    except DomainValidationError:
                        continue
        elif delta.op == "retire":
            for hyp in world.get_hypotheses():
                if hyp.statement == delta.statement or (
                    delta.hypothesis_id and hyp.hypothesis_id == delta.hypothesis_id
                ):
                    try:
                        world.record_hypothesis(
                            hyp.model_copy(update={"status": HypothesisStatus.RETIRED})
                        )
                    except DomainValidationError:
                        continue
