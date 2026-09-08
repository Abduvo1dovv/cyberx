from __future__ import annotations

import pytest

from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import (
    PREFIX_MISSION,
    generate_ulid,
    is_valid_id,
    new_id,
    require_id,
)
from cyberx.domain.time import UTC, utcnow


def test_new_id_prefix_and_ulid_shape() -> None:
    value = new_id(PREFIX_MISSION)
    assert value.startswith("mis_")
    assert is_valid_id(value, PREFIX_MISSION)
    assert len(value) == 4 + 26


def test_ulid_is_deterministic_with_fixed_entropy() -> None:
    ulid = generate_ulid(timestamp_ms=1_700_000_000_000, randomness=b"\x01" * 10)
    again = generate_ulid(timestamp_ms=1_700_000_000_000, randomness=b"\x01" * 10)
    assert ulid == again
    assert len(ulid) == 26


def test_unknown_prefix_rejected() -> None:
    with pytest.raises(DomainValidationError):
        new_id("exp_")


def test_require_id_rejects_garbage() -> None:
    with pytest.raises(DomainValidationError):
        require_id("not-an-id", PREFIX_MISSION)


def test_utcnow_is_timezone_aware() -> None:
    now = utcnow()
    assert now.tzinfo is not None
    assert now.tzinfo == UTC
