"""Shared parser helpers. The only allowed I/O is reading artifact.path."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberx.domain.errors import ParseError
from cyberx.domain.ids import PREFIX_OBSERVATION, new_id
from cyberx.domain.models.evidence import Observation
from cyberx.domain.time import utcnow
from cyberx.evidence.redactor import DEFAULT_REDACTOR
from cyberx.ports.execution import RawArtifact

MAX_BANNER = 256
MAX_TITLE = 128


def read_artifact_bytes(artifact: RawArtifact) -> bytes:
    if artifact.body:
        return artifact.body
    if artifact.path:
        try:
            return Path(artifact.path).read_bytes()
        except OSError as exc:
            raise ParseError(
                f"cannot read artifact path: {artifact.path}",
                code="artifact_unreadable",
            ) from exc
    raise ParseError("artifact has no body or path", code="empty_artifact")


def decode_utf8(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("artifact is not valid utf-8", code="invalid_encoding") from exc


def load_json_object(artifact: RawArtifact) -> dict[str, Any]:
    raw = read_artifact_bytes(artifact)
    try:
        data = json.loads(decode_utf8(raw))
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid json: {exc}", code="invalid_json") from exc
    if not isinstance(data, dict):
        raise ParseError("json artifact must be an object", code="invalid_json")
    return data


def require_mission_id(artifact: RawArtifact) -> str:
    mission_id = (artifact.mission_id or "").strip()
    if not mission_id:
        raise ParseError("artifact.mission_id is required", code="missing_mission")
    return mission_id


def clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit]


def emit(
    *,
    artifact: RawArtifact,
    parser_id: str,
    predicate: str,
    obj: Any,
    subject_hint: str,
    extra: dict[str, Any] | None = None,
) -> Observation:
    cleaned = DEFAULT_REDACTOR.redact(obj)
    extra_clean = DEFAULT_REDACTOR.redact(extra or {})
    if isinstance(cleaned, str):
        cleaned = clip(cleaned, 4000)
    return Observation(
        observation_id=new_id(PREFIX_OBSERVATION),
        mission_id=require_mission_id(artifact),
        parser_id=parser_id,
        predicate=predicate,
        object=cleaned,
        subject_hint=subject_hint,
        created_at=utcnow(),
        extra=extra_clean if isinstance(extra_clean, dict) else {},
    )


def host_subject(address: str) -> str:
    from cyberx.domain.errors import IdentityError
    from cyberx.domain.identity import host_key_ipv4, host_key_ipv6, host_key_name

    try:
        return host_key_ipv4(address)
    except IdentityError:
        try:
            return host_key_ipv6(address)
        except IdentityError:
            return host_key_name(address)


def coerce_http_base(locator: str | None) -> str | None:
    if not locator:
        return None
    text = locator.strip()
    if text.startswith("http://") or text.startswith("https://"):
        return text
    if "://" in text:
        return None
    return f"http://{text}/"


def resolve_http_url(raw: str, base: str | None = None) -> tuple[str, str, int, str]:
    from urllib.parse import urljoin

    from cyberx.domain.identity import parse_http_url

    candidate = raw.strip()
    if base and not candidate.startswith("http://") and not candidate.startswith("https://"):
        candidate = urljoin(base if base.endswith("/") else base + "/", candidate)
    return parse_http_url(candidate)
