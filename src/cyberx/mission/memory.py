"""In-memory MissionStore for tests and the M0–M2 foundation."""

from __future__ import annotations

from cyberx.domain.errors import MissionNotFound
from cyberx.domain.models.mission import Mission
from cyberx.mission.ports import MissionBundle


class InMemoryMissionStore:
    def __init__(self) -> None:
        self._items: dict[str, MissionBundle] = {}

    def save(self, bundle: MissionBundle) -> None:
        self._items[bundle.mission.mission_id] = bundle

    def get(self, mission_id: str) -> MissionBundle:
        try:
            return self._items[mission_id]
        except KeyError as exc:
            raise MissionNotFound(mission_id) from exc

    def list_missions(self) -> list[Mission]:
        items = list(self._items.values())
        items.sort(key=lambda b: b.mission.created_at, reverse=True)
        return [b.mission for b in items]
