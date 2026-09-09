"""Stable ports (extension points). Infrastructure implements these.

Application code depends on these contracts, not on nmap/httpx/sqlite/AI SDKs.
"""

from cyberx.ports.events import (
    DomainEvent,
    EventLog,
    EventReader,
    EventSink,
    EventType,
    NullEventSink,
    emit_safe,
)
from cyberx.ports.evidence import EvidenceParser
from cyberx.ports.execution import (
    ActionExecutor,
    AuthorizedAction,
    ExecutionContext,
    RawArtifact,
    ToolAdapter,
)
from cyberx.ports.storage import EnginePersistence

__all__ = [
    "ActionExecutor",
    "AuthorizedAction",
    "DomainEvent",
    "EnginePersistence",
    "EventLog",
    "EventReader",
    "EventSink",
    "EventType",
    "EvidenceParser",
    "ExecutionContext",
    "NullEventSink",
    "RawArtifact",
    "ToolAdapter",
    "emit_safe",
]
