"""RawArtifact integrity. Corruption must not become World Model facts."""

from __future__ import annotations

import hashlib

from cyberx.config import ActionLimits
from cyberx.domain.errors import ParseError
from cyberx.evidence.parsers.base import read_artifact_bytes
from cyberx.ports.execution import RawArtifact


def verify_raw_artifact(artifact: RawArtifact, *, max_bytes: int | None = None) -> bytes:
    """Fail closed: hash/size/path mismatches never parse into observations."""
    if artifact.truncated and not artifact.body and not artifact.path:
        raise ParseError("truncated artifact has no body", code="artifact_truncated_empty")
    limit = max_bytes if max_bytes is not None else ActionLimits().max_artifact_bytes
    raw = read_artifact_bytes(artifact)
    if len(raw) > limit:
        raise ParseError("artifact exceeds size bound", code="artifact_too_large")
    digest = hashlib.sha256(raw).hexdigest()
    if (artifact.sha256 or "").lower() != digest:
        raise ParseError("artifact hash mismatch", code="artifact_hash_mismatch")
    if not artifact.truncated and artifact.byte_size != len(raw):
        raise ParseError("artifact size mismatch", code="artifact_size_mismatch")
    if artifact.truncated and not raw:
        raise ParseError("truncated artifact has no body", code="artifact_truncated_empty")
    return raw
