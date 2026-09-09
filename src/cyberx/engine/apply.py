"""Result processing: verify/parse artifact, persist evidence, apply World Model.

Not a second sequencer. MissionEngine calls this after a completed tool run.
"""

from __future__ import annotations

from collections.abc import Callable

from cyberx.domain.enums import TimelineKind
from cyberx.domain.errors import ParseError
from cyberx.engine.observe import ingest_locator_evidence
from cyberx.engine.persist import CyclePersistence
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.ports.events import DomainEvent, EventSink, EventType, emit_safe
from cyberx.ports.execution import RawArtifact
from cyberx.world.model import InMemoryWorldModel


def apply_completed_artifact(
    *,
    pipeline: EvidencePipeline,
    persist: CyclePersistence,
    events: EventSink,
    append_event: Callable[[str, TimelineKind, str], None],
    observe_locator: Callable[..., object],
    world: InMemoryWorldModel,
    mission_id: str,
    action_type: str,
    coverage_key: str,
    artifact: RawArtifact,
) -> tuple[int, str, bool]:
    """Returns (evidence_added, exec_status, parsed_ok). Fail-closed on parse/integrity."""
    try:
        _obs, evidence = pipeline.normalize(artifact)
    except ParseError as exc:
        emit_safe(
            events,
            DomainEvent(
                event_type=EventType.PARSE_FAILED,
                mission_id=mission_id,
                payload={"action_type": action_type, "code": exc.code},
            ),
        )
        append_event(mission_id, TimelineKind.ERROR, f"parse failed: {exc.code}")
        world.record_coverage(coverage_key, "failed")
        return 0, "failed", False

    emit_safe(
        events,
        DomainEvent(
            event_type=EventType.PARSE_COMPLETED,
            mission_id=mission_id,
            payload={
                "action_type": action_type,
                "observation_count": len(_obs),
                "evidence_count": len(evidence),
            },
        ),
    )
    persist.save_evidence(artifact, _obs, evidence)
    added = 0
    for item in evidence:
        world.apply_evidence(item)
        added += 1
    ingest_locator_evidence(observe_locator, mission_id, evidence)
    world.record_coverage(coverage_key, "completed")
    return added, "completed", True
