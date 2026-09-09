"""Engine persistence adapter. Talks only to EnginePersistence — never sqlite3."""

from __future__ import annotations

from collections.abc import Sequence

from cyberx.domain.errors import StorageError, WorldModelError
from cyberx.domain.models.actions import Action, ActionResult, ToolRun
from cyberx.domain.models.evidence import Evidence, Observation
from cyberx.domain.models.findings import TimelineEvent
from cyberx.ports.execution import RawArtifact
from cyberx.ports.storage import EnginePersistence
from cyberx.world.model import InMemoryWorldModel


class CyclePersistence:
    """No-op when store is None (in-memory missions). Typed when a store is attached."""

    def __init__(self, store: EnginePersistence | None) -> None:
        if store is not None and not isinstance(store, EnginePersistence):
            store = None
        self._store = store

    def enabled(self) -> bool:
        return self._store is not None

    def resume_world(self, mission_id: str) -> InMemoryWorldModel | None:
        store = self._store
        if store is None:
            return None
        try:
            world = store.resume_world(mission_id)
        except (StorageError, WorldModelError):
            return None
        if not isinstance(world, InMemoryWorldModel):
            return None
        return world

    def runtime(self, mission_id: str) -> tuple[int, int, int, int]:
        store = self._store
        if store is None:
            return 0, 0, 0, 0
        return store.get_runtime(mission_id)

    def save_execution(self, action: Action, tool_run: ToolRun, result: ActionResult) -> None:
        store = self._store
        if store is None:
            return
        with store.transaction():
            store.save_action(action)
            store.save_tool_run(tool_run)
            store.save_result(result)

    def save_evidence(
        self,
        artifact: RawArtifact,
        observations: Sequence[Observation],
        evidence: Sequence[Evidence],
    ) -> None:
        store = self._store
        if store is None:
            return
        with store.transaction():
            store.put(artifact)
            for item in observations:
                store.insert_observation(item)
            for item in evidence:
                store.insert_evidence(item)

    def append_timeline(self, event: TimelineEvent) -> None:
        store = self._store
        if store is None:
            return
        store.append_timeline(event)

    def save_trace(self, mission_id: str, iteration: int, payload: str) -> None:
        store = self._store
        if store is None:
            return
        store.save_decision_trace(mission_id, iteration, payload)

    def persist_cycle(
        self,
        mission_id: str,
        world: InMemoryWorldModel,
        consecutive_failures: int,
        stall_cycles: int,
    ) -> None:
        store = self._store
        if store is None:
            return
        with store.transaction():
            store.persist_world(world)
            store.save_runtime(
                mission_id,
                consecutive_failures,
                stall_cycles,
                world.revision,
                len(list(world.get_recent_evidence(limit=10000))),
            )
