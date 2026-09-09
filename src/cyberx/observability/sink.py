"""In-memory event sink for tests and the M4 execution path."""

from __future__ import annotations

from collections.abc import Iterator

from cyberx.ports.events import DomainEvent, EventType, NullEventSink, emit_safe

__all__ = ["InMemoryEventSink", "NullEventSink", "emit_safe"]


class InMemoryEventSink:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []

    def emit(self, event: DomainEvent) -> None:
        self.events.append(event)

    def of_type(self, event_type: EventType) -> list[DomainEvent]:
        return [e for e in self.events if e.event_type is event_type]

    def iter_recent(self, *, after: int = 0, limit: int = 100) -> Iterator[DomainEvent]:
        start = max(0, after)
        end = start + max(0, limit)
        return iter(self.events[start:end])

    def emitted_count(self) -> int:
        return len(self.events)
