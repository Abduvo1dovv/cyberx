"""EvidenceFactory.wrap — Observations become Evidence. Does not apply World Model."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import PREFIX_EVIDENCE, new_id
from cyberx.domain.models.evidence import Evidence, Observation
from cyberx.domain.time import utcnow
from cyberx.evidence.registry import LEGAL_PARSER_IDS
from cyberx.ports.execution import RawArtifact

_AI_PARSERS = frozenset({"ai", "llm", "hypothesis"})

# SPEC §3.4 reliability table (predicate defaults). Directory 404 is special-cased.
_RELIABILITY: dict[str, float] = {
    "host.alive": 0.95,
    "host.address": 0.90,
    "host.hostname": 0.85,
    "port.state": 0.95,
    "service.name": 0.85,
    "service.product": 0.60,
    "service.version": 0.60,
    "service.banner": 0.60,
    "http.status": 0.90,
    "http.title": 0.85,
    "http.header": 0.55,
    "http.redirect": 0.90,
    "http.body_hash": 0.90,
    "http.tech": 0.55,
    "dns.record": 0.90,
    "dns.subdomain": 0.80,
    "url.seen": 0.85,
    "endpoint.seen": 0.85,
    "param.seen": 0.80,
    "auth.seen": 0.85,
}


def reliability_for(observation: Observation) -> float:
    if not observation.mapped:
        return 0.0
    if observation.predicate == "port.state":
        state = str(observation.object or "").lower()
        if state == "filtered":
            return 0.70
        return 0.95
    if observation.predicate == "http.tech":
        source = ""
        if isinstance(observation.object, dict):
            source = str(observation.object.get("source") or "")
        if source in {"body", "cookie", "behavior"}:
            return 0.50
        return 0.55
    if observation.predicate == "url.seen":
        status = observation.extra.get("status")
        if status == 404:
            return 0.40
        if status in {200, 401, 403}:
            return 0.85
    return _RELIABILITY.get(observation.predicate, 0.50)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


class EvidenceFactory:
    def wrap(self, observation: Observation, artifact: RawArtifact) -> Evidence:
        parser_id = observation.parser_id
        if parser_id.lower() in _AI_PARSERS:
            raise DomainValidationError("AI cannot create Evidence")
        if parser_id not in LEGAL_PARSER_IDS:
            raise DomainValidationError(f"parser_id not in registry: {parser_id}")
        if observation.mission_id != artifact.mission_id:
            raise DomainValidationError("observation.mission_id must match artifact.mission_id")
        preview = {
            "predicate": observation.predicate,
            "object": observation.object,
            "subject_hint": observation.subject_hint,
            "mapped": observation.mapped,
        }
        digest = hashlib.sha256(_canonical(preview).encode("utf-8")).hexdigest()
        return Evidence(
            evidence_id=new_id(PREFIX_EVIDENCE),
            mission_id=observation.mission_id,
            observation_id=observation.observation_id,
            artifact_id=artifact.artifact_id,
            tool_run_id=artifact.tool_run_id,
            parser_id=parser_id,
            claim_preview=preview,
            reliability=reliability_for(observation),
            created_at=utcnow(),
            hash=digest,
        )

    def wrap_all(self, observations: list[Observation], artifact: RawArtifact) -> list[Evidence]:
        return [self.wrap(item, artifact) for item in observations]
