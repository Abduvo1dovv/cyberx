"""Directory enumeration JSON parser. Does not crawl."""

from __future__ import annotations

from typing import Any

from cyberx.domain.errors import IdentityError, ParseError
from cyberx.domain.identity import url_key
from cyberx.domain.models.evidence import Observation
from cyberx.evidence.parsers.base import (
    coerce_http_base,
    emit,
    load_json_object,
    resolve_http_url,
)
from cyberx.ports.execution import RawArtifact

PARSER_ID = "directory"


class DirectoryParser:
    parser_id = PARSER_ID
    produces: tuple[str, ...] = ("url.seen", "http.status")

    def parse(self, artifact: RawArtifact) -> list[Observation]:
        return observations_from_directory_payload(load_json_object(artifact), artifact)


def observations_from_directory_payload(
    data: dict[str, Any], artifact: RawArtifact
) -> list[Observation]:
    raw_base = (
        data.get("base_url") or data.get("url") or data.get("target") or artifact.source_locator
    )
    base = coerce_http_base(str(raw_base) if raw_base else None)
    if not base:
        raise ParseError("directory artifact missing base url", code="missing_url")
    if data.get("wildcard_detected") and not data.get("paths"):
        ukey = _key_or_none(base, base)
        if ukey is None:
            return []
        return [
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="url.seen",
                obj=ukey,
                subject_hint=ukey,
                extra={"wildcard_detected": True},
            )
        ]
    paths = data.get("paths") or []
    if not isinstance(paths, list):
        raise ParseError("directory paths must be a list", code="invalid_json")
    out: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for item in paths:
        if isinstance(item, str):
            path, status = item, None
            extra_src: dict[str, Any] = {}
        elif isinstance(item, dict):
            path, status = item.get("path") or item.get("url"), item.get("status")
            extra_src = item
        else:
            continue
        if not isinstance(path, str) or not path.strip():
            continue
        try:
            scheme, host, port, npath = resolve_http_url(path.strip(), base=base)
            ukey = url_key(scheme, host, port, npath)
        except IdentityError:
            continue
        extra: dict[str, Any] = {}
        if isinstance(status, int):
            extra["status"] = status
        if extra_src.get("classification"):
            extra["classification"] = str(extra_src["classification"])
        if extra_src.get("content_type"):
            extra["content_type"] = str(extra_src["content_type"])[:80]
        if extra_src.get("title"):
            extra["title"] = str(extra_src["title"])[:128]
        if extra_src.get("wildcard_detected"):
            extra["wildcard_detected"] = True
        marker = (ukey, "url.seen")
        if marker not in seen:
            seen.add(marker)
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="url.seen",
                    obj=ukey,
                    subject_hint=ukey,
                    extra=extra,
                )
            )
        if isinstance(status, int) and (ukey, "http.status") not in seen:
            seen.add((ukey, "http.status"))
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="http.status",
                    obj=status,
                    subject_hint=ukey,
                )
            )
        redirect = extra_src.get("redirect")
        if isinstance(redirect, str) and redirect.strip() and not extra_src.get("out_of_scope"):
            try:
                scheme, host, port, npath = resolve_http_url(redirect.strip(), base=base)
                rkey = url_key(scheme, host, port, npath)
            except IdentityError:
                continue
            if (rkey, "url.seen") in seen:
                continue
            seen.add((rkey, "url.seen"))
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="url.seen",
                    obj=rkey,
                    subject_hint=rkey,
                    extra={"via": "redirect"},
                )
            )
    return out


def _key_or_none(path: str, base: str) -> str | None:
    try:
        scheme, host, port, npath = resolve_http_url(path, base=base)
        return url_key(scheme, host, port, npath)
    except IdentityError:
        return None
