"""Shared pydantic configuration."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from cyberx.domain.time import require_utc


class DomainModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="after")
    @classmethod
    def _utc_datetimes(cls, value: object) -> object:
        if isinstance(value, datetime):
            return require_utc(value)
        return value
