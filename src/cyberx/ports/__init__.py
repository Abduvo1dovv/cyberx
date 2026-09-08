"""Stable ports (extension points). Infrastructure implements these.

Application code depends on these contracts, not on nmap/httpx/sqlite/AI SDKs.
"""

from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe
from cyberx.ports.evidence import EvidenceParser
from cyberx.ports.execution import (
    ActionExecutor,
    AuthorizedAction,
    ExecutionContext,
    RawArtifact,
    ToolAdapter,
)

__all__ = [
    "ActionExecutor",
    "AuthorizedAction",
    "DomainEvent",
    "EventSink",
    "EventType",
    "EvidenceParser",
    "ExecutionContext",
    "NullEventSink",
    "RawArtifact",
    "ToolAdapter",
    "emit_safe",
]
