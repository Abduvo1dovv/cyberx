"""ValidationEngine — proposes safe questions. Never executes."""

from __future__ import annotations

import hashlib
from typing import Any

from cyberx.domain.enums import FindingKind, FindingStatus, ValidationStatus
from cyberx.domain.ids import PREFIX_VALIDATION, generate_ulid
from cyberx.domain.models.findings import Finding
from cyberx.domain.models.validation import ValidationCandidate
from cyberx.domain.time import utcnow
from cyberx.validation.mappings import UNSAFE_CANDIDATE_TYPES, build_action
from cyberx.validation.rules import SAFE_RULES
from cyberx.world.priority import investigation_priority

# These questions are answered by existing evidence; do not recrawl.
_CONFIRM_WITHOUT_RERUN = frozenset({"authentication_surface"})


class ValidationEngine:
    """Deterministic, fail-closed. Maps recon signals to catalogued recon actions."""

    def evaluate(self, world: Any) -> list[ValidationCandidate]:
        coverage = _coverage_keys(world)
        claims = _live_claims(world)
        hypotheses = list(world.get_hypotheses()) if hasattr(world, "get_hypotheses") else []
        now = utcnow()
        out: list[ValidationCandidate] = []
        seen: set[str] = set()
        mission_id = getattr(world, "mission_id", "")
        for finding in world.get_findings():
            drafts = []
            for rule in SAFE_RULES:
                draft = rule(finding, world)
                if draft:
                    drafts.append(draft)
            if not drafts:
                if (
                    finding.kind is FindingKind.OUT_OF_SCOPE_OBSERVATION
                    or (finding.signal or "") in UNSAFE_CANDIDATE_TYPES
                ):
                    cand = _rejected(
                        mission_id,
                        finding,
                        reason=(
                            "out-of-scope observation is not validated"
                            if finding.kind is FindingKind.OUT_OF_SCOPE_OBSERVATION
                            else "unsupported validation rejected"
                        ),
                        now=now,
                    )
                    if cand.identity_key not in seen:
                        seen.add(cand.identity_key)
                        out.append(cand)
                continue
            for draft in drafts:
                cand = _from_draft(
                    world,
                    finding,
                    draft,
                    coverage=coverage,
                    claims=claims,
                    hypotheses=hypotheses,
                    now=now,
                )
                if cand.identity_key in seen:
                    continue
                seen.add(cand.identity_key)
                out.append(cand)
        out.sort(key=lambda c: (-c.priority, c.candidate_type, c.identity_key))
        return out

    def sync_findings(self, world: Any, candidates: list[ValidationCandidate]) -> None:
        if not hasattr(world, "put_finding"):
            return
        by_finding: dict[str, ValidationCandidate] = {}
        for cand in candidates:
            if cand.finding_id and cand.finding_id not in by_finding:
                by_finding[cand.finding_id] = cand
        for finding in world.get_findings():
            cand = by_finding.get(finding.finding_id)
            if cand is None:
                continue
            count = finding.validation_count
            if cand.status in {
                ValidationStatus.SUPPORTED,
                ValidationStatus.INCONCLUSIVE,
            }:
                count = max(count, finding.observation_count, 1)
            world.put_finding(
                finding.model_copy(
                    update={
                        "validation_state": cand.status.value,
                        "validation_count": count,
                        "last_validation_result": cand.status.value,
                    }
                )
            )


def _from_draft(
    world: Any,
    finding: Finding,
    draft: dict[str, Any],
    *,
    coverage: set[str],
    claims: list[Any],
    hypotheses: list[Any],
    now: Any,
) -> ValidationCandidate:
    candidate_type = str(draft.get("candidate_type") or "")
    action = str(draft.get("action") or "")
    expected = tuple(draft.get("expected") or ())
    asset = draft.get("asset")
    reason = str(draft.get("reason") or "investigate recon signal")
    if candidate_type in UNSAFE_CANDIDATE_TYPES:
        return _rejected(
            world.mission_id, finding, reason="unsupported validation rejected", now=now
        )
    if finding.status is FindingStatus.INVALIDATED:
        status = ValidationStatus.EXPIRED
        built = None
    else:
        built = build_action(action, finding=finding, asset=asset, world=world)
        status = ValidationStatus.PROPOSED
    locator = ""
    params: dict[str, Any] = {}
    key = ""
    if built is None:
        if status is not ValidationStatus.EXPIRED:
            status = ValidationStatus.REJECTED
            reason = "no legal catalog action mapping"
    else:
        locator, params, key = built
        expected_hit = _expected_present(claims, finding.asset_ids, expected)
        if key in coverage:
            if expected_hit:
                status = ValidationStatus.SUPPORTED
                reason = "coverage satisfied and expected evidence present"
            else:
                status = ValidationStatus.INCONCLUSIVE
                reason = "coverage satisfied but evidence is inconclusive"
            if (
                finding.validation_count > 0
                and finding.observation_count > finding.validation_count
                and status is ValidationStatus.INCONCLUSIVE
            ):
                status = ValidationStatus.PROPOSED
                reason = "evidence changed; revalidation proposed"
        elif expected_hit and candidate_type in _CONFIRM_WITHOUT_RERUN:
            status = ValidationStatus.SUPPORTED
            reason = "expected evidence already present; no additional probe"
    identity = "|".join(
        [
            candidate_type,
            finding.identity_key or finding.finding_id,
            action,
            locator,
        ]
    )
    hyp_id = _hypothesis_id(hypotheses, finding)
    asset = draft.get("asset")
    priority = investigation_priority(finding, asset=asset, world=world)
    return ValidationCandidate(
        validation_id=_deterministic_id(identity),
        mission_id=finding.mission_id,
        candidate_type=candidate_type or "unsupported",
        identity_key=identity[:400],
        status=status,
        reason=reason[:500],
        finding_id=finding.finding_id,
        asset_ids=list(finding.asset_ids),
        hypothesis_id=hyp_id,
        mapped_action_type=action if built is not None else "",
        coverage_key=key,
        locator=locator,
        parameters=params,
        expected_predicates=list(expected),
        evidence_ids=list(finding.evidence_ids),
        current_confidence=finding.confidence,
        priority=priority,
        created_at=now,
        updated_at=now,
        source="heuristic",
    )


def _rejected(mission_id: str, finding: Finding, reason: str, now: Any) -> ValidationCandidate:
    identity = f"rejected|{finding.identity_key or finding.finding_id}|{reason}"
    return ValidationCandidate(
        validation_id=_deterministic_id(identity),
        mission_id=finding.mission_id or mission_id,
        candidate_type="unsupported",
        identity_key=identity[:400],
        status=ValidationStatus.REJECTED,
        reason=reason[:500],
        finding_id=finding.finding_id,
        asset_ids=list(finding.asset_ids),
        evidence_ids=list(finding.evidence_ids),
        current_confidence=finding.confidence,
        priority=0.0,
        created_at=now,
        updated_at=now,
        source="heuristic",
    )


def _deterministic_id(material: str) -> str:
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    return PREFIX_VALIDATION + generate_ulid(timestamp_ms=0, randomness=digest[:10])


def _coverage_keys(world: Any) -> set[str]:
    if hasattr(world, "get_coverage"):
        cov = world.get_coverage()
        return set(cov) if isinstance(cov, dict) else set(cov)
    cov = getattr(world, "coverage", {})
    return set(cov) if isinstance(cov, dict) else set(cov or ())


def _live_claims(world: Any) -> list[Any]:
    if hasattr(world, "get_claims"):
        try:
            return list(world.get_claims(include_invalidated=False))
        except TypeError:
            return [
                c
                for c in world.get_claims()
                if getattr(getattr(c, "epistemic_status", None), "value", "") != "INVALIDATED"
            ]
    return list(getattr(world, "claims", ()) or ())


def _expected_present(claims: list[Any], asset_ids: list[str], expected: tuple[str, ...]) -> bool:
    if not expected:
        return False
    wanted = set(asset_ids)
    predicates = {c.predicate for c in claims if getattr(c, "subject_id", None) in wanted}
    if any(item in predicates for item in expected):
        return True
    all_predicates = {c.predicate for c in claims}
    return any(item in all_predicates for item in expected)


def _hypothesis_id(hypotheses: list[Any], finding: Finding) -> str | None:
    finding_assets = set(finding.asset_ids)
    needle = (finding.signal or finding.kind.value).replace("_", " ")
    for hyp in hypotheses:
        related = set(getattr(hyp, "related_asset_ids", ()) or ())
        if related & finding_assets:
            return hyp.hypothesis_id
        statement = (getattr(hyp, "statement", "") or "").lower()
        if needle and needle in statement:
            return hyp.hypothesis_id
    return None
