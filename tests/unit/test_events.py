from __future__ import annotations

from tests.conftest import create_cmd

from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.ports.events import EventType


def test_mission_emits_typed_status_events() -> None:
    sink = InMemoryEventSink()
    service = MissionService(InMemoryMissionStore(), events=sink)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    kinds = [e.event_type for e in sink.events]
    assert EventType.MISSION_STATUS in kinds
    assert all(isinstance(e.payload, dict) for e in sink.events)
    assert all(e.event_id.startswith("tl_") for e in sink.events)
