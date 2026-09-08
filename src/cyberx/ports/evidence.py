"""EvidenceParser port. Implementations land in M5; this contract is stable now."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from cyberx.domain.models.evidence import Observation
from cyberx.ports.execution import RawArtifact


class EvidenceParser(Protocol):
    parser_id: str
    produces: tuple[str, ...]

    def parse(self, artifact: RawArtifact) -> Sequence[Observation]: ...
