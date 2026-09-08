"""Adaptivity golden: new evidence changes the next action. Not a fixed pipeline."""

from __future__ import annotations

from tests.conftest import create_cmd

from cyberx.engine.loop import MissionEngine
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.storage.sqlite import SqliteStore


def test_synthetic_world_evolves_through_distinct_actions(tmp_path) -> None:
    store = SqliteStore(tmp_path / "cyberx.db", data_dir=tmp_path)
    service = MissionService(store)
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(service, store=store)
    seen: list[str] = []
    for _ in range(6):
        report = engine.run_one_cycle(mission.mission_id)
        if report.completed or report.paused:
            break
        if report.selected_action_type:
            seen.append(report.selected_action_type)
    assert len(seen) >= 3
    assert seen[0] == "port_scan"
    assert seen[1] != seen[0]
    assert len(set(seen)) >= 3
    # A fixed pipeline would be the same sequence even without evidence;
    # coverage must have grown with each selected type.
    world = engine.world(mission.mission_id)
    assert world.get_open_ports()
    assert world.get_coverage()
    assert len(world.get_coverage()) >= 3
    store.close()


def test_in_memory_engine_is_adaptive() -> None:
    service = MissionService(InMemoryMissionStore())
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    engine = MissionEngine(service)
    r1 = engine.run_one_cycle(mission.mission_id)
    r2 = engine.run_one_cycle(mission.mission_id)
    r3 = engine.run_one_cycle(mission.mission_id)
    assert r1.selected_action_type != r2.selected_action_type
    assert r2.evidence_added > 0
    # third cycle still useful or stopping because gaps closed — not repeating cycle 1
    if not r3.completed:
        assert r3.selected_action_type != r1.selected_action_type
    world = engine.world(mission.mission_id)
    assert world.revision > 1
    kinds = {g.kind for g in world.get_gaps() if not g.closed}
    assert "host.ports_unknown" not in kinds
