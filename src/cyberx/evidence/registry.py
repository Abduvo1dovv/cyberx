"""Closed parser registry. Unknown adapters fail closed. No public register()."""

from __future__ import annotations

from types import MappingProxyType

from cyberx.domain.errors import ParseError
from cyberx.domain.models.evidence import Observation
from cyberx.evidence.parsers import V1_PARSERS
from cyberx.ports.evidence import EvidenceParser
from cyberx.ports.execution import RawArtifact

_ADAPTER_TO_PARSER = {
    "nmap_adapter": "nmap_xml",
    "http_adapter": "http_probe",
    "dns_adapter": "dns",
    "subdomain_adapter": "dns",
    "directory_adapter": "directory",
    "tech_adapter": "tech",
    "endpoint_adapter": "endpoint",
    "stub_adapter": "stub",
}

# `seed` is confirm-time operator evidence (SPEC §4.3), not a tool parser.
LEGAL_PARSER_IDS = frozenset(p.parser_id for p in V1_PARSERS) | {"seed"}


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers = MappingProxyType({p.parser_id: p for p in V1_PARSERS})

    def get(self, parser_id: str) -> EvidenceParser | None:
        return self._parsers.get(parser_id)

    def ids(self) -> tuple[str, ...]:
        return tuple(self._parsers.keys())

    def parser_id_for_adapter(self, adapter_name: str) -> str | None:
        return _ADAPTER_TO_PARSER.get(adapter_name)

    def for_artifact(self, artifact: RawArtifact) -> EvidenceParser:
        parser_id = _ADAPTER_TO_PARSER.get(artifact.adapter_name)
        media = (artifact.media_type or "").lower()
        if parser_id is None:
            if "xml" in media:
                parser_id = "nmap_xml"
            elif "html" in media:
                parser_id = "endpoint"
            else:
                raise ParseError(
                    f"no parser for adapter {artifact.adapter_name!r}",
                    code="unknown_parser",
                )
        parser = self.get(parser_id)
        if parser is None:
            raise ParseError(f"parser not registered: {parser_id}", code="unknown_parser")
        return parser

    def parse(self, artifact: RawArtifact) -> list[Observation]:
        parser = self.for_artifact(artifact)
        return list(parser.parse(artifact))


def default_registry() -> ParserRegistry:
    return ParserRegistry()
