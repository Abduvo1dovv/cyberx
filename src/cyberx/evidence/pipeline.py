"""Thin normalizer: artifact → Observation[] → Evidence[]. No World Model apply."""

from __future__ import annotations

from cyberx.domain.models.evidence import Evidence, Observation
from cyberx.evidence.factory import EvidenceFactory
from cyberx.evidence.registry import ParserRegistry, default_registry
from cyberx.ports.execution import RawArtifact


class EvidencePipeline:
    """Parse artifacts then wrap Observations as Evidence. No World Model apply."""

    def __init__(
        self,
        registry: ParserRegistry | None = None,
        factory: EvidenceFactory | None = None,
    ) -> None:
        self._registry = registry or default_registry()
        self._factory = factory or EvidenceFactory()

    def parse(self, artifact: RawArtifact) -> list[Observation]:
        return self._registry.parse(artifact)

    def wrap(self, observations: list[Observation], artifact: RawArtifact) -> list[Evidence]:
        return self._factory.wrap_all(observations, artifact)

    def normalize(self, artifact: RawArtifact) -> tuple[list[Observation], list[Evidence]]:
        observations = self.parse(artifact)
        return observations, self.wrap(observations, artifact)
