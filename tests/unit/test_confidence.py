from __future__ import annotations

import pytest

from cyberx.domain.confidence import apply_contradicting, apply_supporting, validate_confidence
from cyberx.domain.errors import DomainValidationError


def test_confidence_range() -> None:
    assert validate_confidence(0.0) == 0.0
    assert validate_confidence(1.0) == 1.0
    with pytest.raises(DomainValidationError):
        validate_confidence(-0.01)
    with pytest.raises(DomainValidationError):
        validate_confidence(1.01)
    with pytest.raises(DomainValidationError):
        validate_confidence(True)  # type: ignore[arg-type]


def test_supporting_formula() -> None:
    assert apply_supporting(0.0, 0.95) == pytest.approx(0.95)
    # 1 - (1-0.5)*(1-0.5) = 0.75
    assert apply_supporting(0.5, 0.5) == pytest.approx(0.75)


def test_contradicting_invalidates_when_r_ge_c() -> None:
    c, invalidated = apply_contradicting(0.4, 0.9)
    assert invalidated is True
    assert c == pytest.approx(0.9)
    c2, invalidated2 = apply_contradicting(0.8, 0.2)
    assert invalidated2 is False
    assert c2 == pytest.approx(0.8 * (1 - 0.5 * 0.2))
