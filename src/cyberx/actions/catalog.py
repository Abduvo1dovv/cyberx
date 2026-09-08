"""Closed ActionCatalog. No public register() — AI cannot add types."""

from __future__ import annotations

from types import MappingProxyType

from cyberx.actions.specs import V1_SPECS, ActionSpec, assert_v1_closed
from cyberx.domain.enums import V1_ACTION_TYPES


class ActionCatalog:
    def __init__(self) -> None:
        assert_v1_closed()
        self._specs = MappingProxyType({spec.action_type: spec for spec in V1_SPECS})

    def get(self, action_type: str) -> ActionSpec | None:
        return self._specs.get(action_type)

    def all(self) -> tuple[ActionSpec, ...]:
        return tuple(self._specs[name] for name in V1_ACTION_TYPES)

    def is_registered(self, action_type: str) -> bool:
        return action_type in self._specs

    def types(self) -> tuple[str, ...]:
        return V1_ACTION_TYPES


DEFAULT_CATALOG = ActionCatalog()
