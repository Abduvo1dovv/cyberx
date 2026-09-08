"""WorldProjector: BoundEvidence → WorldDelta[]. Never invents facts."""

from __future__ import annotations

from cyberx.domain.enums import OBSERVATION_PREDICATES, EpistemicStatus
from cyberx.domain.errors import WorldModelError
from cyberx.domain.ids import PREFIX_CLAIM, new_id
from cyberx.domain.models.evidence import Claim
from cyberx.domain.time import utcnow
from cyberx.world.correlation import BoundEvidence
from cyberx.world.delta import WorldDelta, upsert_asset_delta, upsert_claim_delta
from cyberx.world.status import is_ai_parser, status_from_reliability


class WorldProjector:
    def project(self, bound: BoundEvidence) -> list[WorldDelta]:
        evidence = bound.evidence
        if is_ai_parser(evidence.parser_id):
            raise WorldModelError("AI cannot create World Model facts")
        if not bound.mapped or bound.predicate not in OBSERVATION_PREDICATES:
            return []
        if bound.subject_asset is None:
            return []
        deltas: list[WorldDelta] = []
        seen: set[str] = set()
        for asset in bound.assets:
            if asset.canonical_key in seen:
                continue
            seen.add(asset.canonical_key)
            deltas.append(upsert_asset_delta(asset, evidence_id=evidence.evidence_id))
        now = utcnow()
        status = status_from_reliability(bound.predicate, evidence.reliability)
        claim = Claim(
            claim_id=new_id(PREFIX_CLAIM),
            subject_id=bound.subject_asset.asset_id,
            predicate=bound.predicate,
            object=bound.object,
            epistemic_status=status,
            confidence=evidence.reliability,
            evidence_ids=[evidence.evidence_id],
            contradiction_ids=[],
            created_at=now,
            updated_at=now,
        )
        if status is EpistemicStatus.UNKNOWN:
            raise WorldModelError("projector refused a claim with UNKNOWN status")
        deltas.append(upsert_claim_delta(claim))
        return deltas
