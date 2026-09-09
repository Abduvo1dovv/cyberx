"""Typed events and the EventSink / EventReader ports."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any, Protocol

from pydantic import Field

from cyberx.domain.enums import StrEnum
from cyberx.domain.ids import PREFIX_TIMELINE, new_id
from cyberx.domain.models.common import DomainModel
from cyberx.domain.time import utcnow


class EventType(StrEnum):
    MISSION_STATUS = "mission.status"
    ACTION_VALIDATED = "action.validated"
    ACTION_REJECTED = "action.rejected"
    POLICY_DECISION = "policy.decision"
    ACTION_STARTED = "action.started"
    ACTION_COMPLETED = "action.completed"
    ACTION_FAILED = "action.failed"
    EXECUTION_DENIED = "execution.denied"
    NMAP_STARTED = "nmap.started"
    NMAP_COMPLETED = "nmap.completed"
    NMAP_FAILED = "nmap.failed"
    NMAP_UNAVAILABLE = "nmap.unavailable"
    PARSE_COMPLETED = "parse.completed"
    PARSE_FAILED = "parse.failed"
    HTTP_STARTED = "http.started"
    HTTP_COMPLETED = "http.completed"
    HTTP_FAILED = "http.failed"
    HTTP_REDIRECT_BLOCKED = "http.redirect_blocked"
    DNS_STARTED = "dns.started"
    DNS_COMPLETED = "dns.completed"
    DNS_FAILED = "dns.failed"
    DIRECTORY_STARTED = "directory.started"
    DIRECTORY_COMPLETED = "directory.completed"
    DIRECTORY_FAILED = "directory.failed"
    NETWORK_OBSERVED = "network.observed"
    LOCATOR_CONFIRMED = "locator.confirmed"
    AI_REQUESTED = "ai.requested"
    AI_COMPLETED = "ai.completed"
    AI_FAILED = "ai.failed"
    AI_REJECTED = "ai.rejected"
    AI_FALLBACK = "ai.fallback"


class DomainEvent(DomainModel):
    event_id: str = Field(default_factory=lambda: new_id(PREFIX_TIMELINE))
    event_type: EventType
    mission_id: str | None = None
    at: datetime = Field(default_factory=utcnow)
    payload: dict[str, Any] = Field(default_factory=dict)


class EventSink(Protocol):
    def emit(self, event: DomainEvent) -> None: ...


class EventReader(Protocol):
    def iter_recent(self, *, after: int = 0, limit: int = 100) -> Iterator[DomainEvent]: ...

    def emitted_count(self) -> int: ...


class EventLog(EventSink, EventReader, Protocol):
    """Minimum emit + read capability. Engine must not inspect sink internals."""


class NullEventSink:
    def emit(self, event: DomainEvent) -> None:
        return None

    def iter_recent(self, *, after: int = 0, limit: int = 100) -> Iterator[DomainEvent]:
        del after, limit
        return iter(())

    def emitted_count(self) -> int:
        return 0


def emit_safe(sink: EventSink | None, event: DomainEvent) -> None:
    if sink is None:
        return
    sink.emit(event)
