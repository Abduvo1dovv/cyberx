"""Typed WorldDelta kinds (SPEC §7.4). Not a free-form patch."""

from __future__ import annotations

from typing import Any

from pydantic import field_validator

from cyberx.domain.enums import StrEnum
from cyberx.domain.errors import InvalidWorldDelta
from cyberx.domain.ids import PREFIX_CLAIM, PREFIX_EVIDENCE, PREFIX_GAP, is_valid_id
from cyberx.domain.models.assets import Asset
from cyberx.domain.models.common import DomainModel
from cyberx.domain.models.evidence import Claim, KnowledgeGap


class WorldDeltaKind(StrEnum):
    UPSERT_ASSET = "upsert_asset"
    UPSERT_CLAIM = "upsert_claim"
    INVALIDATE_CLAIM = "invalidate_claim"
    CLOSE_GAP = "close_gap"
    OPEN_GAP = "open_gap"
    COVERAGE_ADD = "coverage_add"


class WorldDelta(DomainModel):
    """Application-level change. Claim deltas always carry evidence."""

    kind: WorldDeltaKind
    evidence_id: str | None = None
    asset: Any = None
    claim: Claim | None = None
    claim_id: str | None = None
    gap: KnowledgeGap | None = None
    gap_id: str | None = None
    coverage_key: str | None = None
    coverage_status: str | None = None

    @field_validator("evidence_id")
    @classmethod
    def _eid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not is_valid_id(value, PREFIX_EVIDENCE):
            raise InvalidWorldDelta(f"invalid evidence_id: {value}")
        return value

    def check(self) -> None:
        """Fail closed if the payload does not match the kind."""
        if self.kind is WorldDeltaKind.UPSERT_ASSET:
            if self.asset is None or not isinstance(self.asset, Asset):
                raise InvalidWorldDelta("upsert_asset requires an Asset payload")
            return
        if self.kind is WorldDeltaKind.UPSERT_CLAIM:
            if self.claim is None:
                raise InvalidWorldDelta("upsert_claim requires a Claim")
            if not self.claim.evidence_ids:
                raise InvalidWorldDelta("claim without evidence_ids is invalid")
            return
        if self.kind is WorldDeltaKind.INVALIDATE_CLAIM:
            if not self.claim_id or not is_valid_id(self.claim_id, PREFIX_CLAIM):
                raise InvalidWorldDelta("invalidate_claim requires a claim_id")
            return
        if self.kind is WorldDeltaKind.OPEN_GAP:
            if self.gap is None:
                raise InvalidWorldDelta("open_gap requires a KnowledgeGap")
            return
        if self.kind is WorldDeltaKind.CLOSE_GAP:
            if not self.gap_id or not is_valid_id(self.gap_id, PREFIX_GAP):
                raise InvalidWorldDelta("close_gap requires a gap_id")
            return
        if self.kind is WorldDeltaKind.COVERAGE_ADD:
            if not self.coverage_key:
                raise InvalidWorldDelta("coverage_add requires coverage_key")
            return
        raise InvalidWorldDelta(f"unknown WorldDelta kind: {self.kind}")


def upsert_asset_delta(asset: Asset, *, evidence_id: str | None = None) -> WorldDelta:
    return WorldDelta(kind=WorldDeltaKind.UPSERT_ASSET, asset=asset, evidence_id=evidence_id)


def upsert_claim_delta(claim: Claim) -> WorldDelta:
    eid = claim.evidence_ids[0] if claim.evidence_ids else None
    return WorldDelta(kind=WorldDeltaKind.UPSERT_CLAIM, claim=claim, evidence_id=eid)


def invalidate_claim_delta(claim_id: str, *, evidence_id: str | None = None) -> WorldDelta:
    return WorldDelta(
        kind=WorldDeltaKind.INVALIDATE_CLAIM,
        claim_id=claim_id,
        evidence_id=evidence_id,
    )


def open_gap_delta(gap: KnowledgeGap) -> WorldDelta:
    return WorldDelta(kind=WorldDeltaKind.OPEN_GAP, gap=gap)


def close_gap_delta(gap_id: str) -> WorldDelta:
    return WorldDelta(kind=WorldDeltaKind.CLOSE_GAP, gap_id=gap_id)


def coverage_add_delta(coverage_key: str, status: str = "completed") -> WorldDelta:
    return WorldDelta(
        kind=WorldDeltaKind.COVERAGE_ADD,
        coverage_key=coverage_key,
        coverage_status=status,
    )
