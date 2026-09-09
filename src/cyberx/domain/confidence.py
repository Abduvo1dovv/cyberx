"""Confidence in [0, 1] and SPEC §3.5 update formulas."""

from __future__ import annotations

from cyberx.domain.errors import DomainValidationError

# AI-proposed hypotheses are advisory. They must not become high-confidence
# facts without later non-AI evidence. This is an epistemic safety boundary,
# not a scoring knob. SPEC §3 / §8.4 / §11.
AI_HYPOTHESIS_CONFIDENCE_CAP = 0.4


def validate_confidence(value: float, *, field: str = "confidence") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainValidationError(f"{field} must be a number")
    number = float(value)
    if number < 0.0 or number > 1.0:
        raise DomainValidationError(f"{field} must be in [0.0, 1.0], got {number}")
    return number


def clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return float(value)


def apply_supporting(confidence: float, reliability: float) -> float:
    """c := 1 - (1 - c) * (1 - r). Non-AI evidence may raise confidence above the AI cap."""
    c = validate_confidence(confidence)
    r = validate_confidence(reliability, field="reliability")
    return clamp01(1.0 - (1.0 - c) * (1.0 - r))


def apply_contradicting(confidence: float, reliability: float) -> tuple[float, bool]:
    """Return (new_confidence, invalidated)."""
    c = validate_confidence(confidence)
    r = validate_confidence(reliability, field="reliability")
    if r >= c:
        return r, True
    return clamp01(c * (1.0 - 0.5 * r)), False
