"""UTC clock helpers."""

from __future__ import annotations

from datetime import datetime, timezone

from cyberx.domain.errors import DomainValidationError

UTC = timezone.utc


def utcnow() -> datetime:
    return datetime.now(UTC)


def require_utc(value: datetime, *, field: str = "timestamp") -> datetime:
    if value.tzinfo is None:
        raise DomainValidationError(f"{field} must be timezone-aware UTC")
    converted = value.astimezone(UTC)
    return converted
