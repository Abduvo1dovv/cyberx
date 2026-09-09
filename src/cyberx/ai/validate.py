"""Validate Grok output against catalog, context, and score bounds."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence

from pydantic import ValidationError

from cyberx.ai.protocol import HypothesisDraft, ScoreAdvice
from cyberx.ai.schemas import (
    AdviceResponse,
    ExplanationResponse,
    HypothesesResponse,
    ReportSectionResponse,
)
from cyberx.domain.enums import FORBIDDEN_ACTION_MARKERS, V1_ACTION_TYPES
from cyberx.domain.models.findings import BrainContext

DELTA_LIMIT = 0.1
_SHELL = ("&&", "`", "$(", " | ")
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def parse_json_object(raw: str) -> dict | None:
    text = raw.strip()
    text = _FENCE.sub("", text).strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    return value


def validate_hypotheses(raw: dict, ctx: BrainContext) -> list[HypothesisDraft]:
    try:
        parsed = HypothesesResponse.model_validate(raw)
    except ValidationError:
        return []
    known = _known_keys(ctx)
    out: list[HypothesisDraft] = []
    for item in parsed.hypotheses[:8]:
        statement = item.statement.strip()
        if not statement or _unsafe(statement) or _unsafe(item.rationale):
            continue
        if item.evidence_ids:
            continue
        related = [k for k in item.related_canonical_keys if k in known]
        if item.related_canonical_keys and not related:
            continue
        if any(_forbidden_type(t) for t in item.suggested_action_types):
            continue
        types = [
            t
            for t in item.suggested_action_types
            if t in V1_ACTION_TYPES and not _forbidden_type(t)
        ]
        conf = item.confidence
        if conf < 0.0 or conf > 0.4:
            conf = min(0.4, max(0.0, conf))
        out.append(
            HypothesisDraft(
                statement=statement[:500],
                rationale=(item.rationale or "")[:500],
                related_canonical_keys=related,
                suggested_action_types=types,
                confidence=conf,
                evidence_ids=[],
            )
        )
    return out


def validate_advice(raw: dict, candidates: Sequence[object]) -> list[ScoreAdvice]:
    try:
        parsed = AdviceResponse.model_validate(raw)
    except ValidationError:
        return []
    keys = {str(getattr(c, "coverage_key", "") or "") for c in candidates}
    keys.discard("")
    out: list[ScoreAdvice] = []
    for item in parsed.advice:
        if item.coverage_key not in keys:
            continue
        if _unsafe(item.comment):
            continue
        if item.delta > DELTA_LIMIT or item.delta < -DELTA_LIMIT:
            continue
        out.append(
            ScoreAdvice(
                coverage_key=item.coverage_key,
                delta=item.delta,
                comment=(item.comment or "")[:200],
            )
        )
    return out


def validate_explanation(raw: dict) -> str:
    try:
        parsed = ExplanationResponse.model_validate(raw)
    except ValidationError:
        return ""
    parts = [
        parsed.explanation.strip(),
        parsed.why_it_matters.strip(),
    ]
    if parsed.supporting_evidence:
        parts.append("Evidence: " + "; ".join(parsed.supporting_evidence[:6]))
    if parsed.unknowns:
        parts.append("Unknown: " + "; ".join(parsed.unknowns[:6]))
    text = "\n".join(p for p in parts if p)
    if _unsafe(text):
        return ""
    return text[:2000]


def validate_report_section(raw: dict) -> str:
    try:
        parsed = ReportSectionResponse.model_validate(raw)
    except ValidationError:
        return ""
    text = parsed.section.strip()
    if _unsafe(text):
        return ""
    if parsed.uncertain and text:
        text = text + "\n(uncertain — AI prose, not a fact)"
    return text[:4000]


def _known_keys(ctx: BrainContext) -> set[str]:
    out: set[str] = set()
    for row in ctx.top_assets:
        if row.id:
            out.add(row.id)
        if row.key:
            out.add(row.key)
    return out


def _forbidden_type(action_type: str) -> bool:
    lowered = action_type.lower()
    return any(marker in lowered for marker in FORBIDDEN_ACTION_MARKERS)


def _unsafe(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    if any(marker in text for marker in _SHELL):
        return True
    if any(marker in lowered for marker in FORBIDDEN_ACTION_MARKERS):
        return True
    return False
