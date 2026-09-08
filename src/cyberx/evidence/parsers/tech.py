"""Technology detection JSON parser."""

from __future__ import annotations

from typing import Any

from cyberx.domain.errors import IdentityError, ParseError
from cyberx.domain.identity import product_slug, url_key
from cyberx.domain.models.evidence import Observation
from cyberx.evidence.parsers.base import coerce_http_base, emit, load_json_object, resolve_http_url
from cyberx.evidence.parsers.fingerprints import detect_technologies
from cyberx.ports.execution import RawArtifact

PARSER_ID = "tech"


class TechnologyParser:
    parser_id = PARSER_ID
    produces: tuple[str, ...] = ("http.tech", "http.header")

    def parse(self, artifact: RawArtifact) -> list[Observation]:
        return observations_from_tech_payload(load_json_object(artifact), artifact)


def observations_from_tech_payload(
    data: dict[str, Any], artifact: RawArtifact
) -> list[Observation]:
    raw_url = (
        data.get("url") or data.get("final_url") or data.get("target") or artifact.source_locator
    )
    base = coerce_http_base(str(raw_url) if raw_url else None)
    if not base:
        raise ParseError("technology artifact missing url", code="missing_url")
    try:
        scheme, host, port, path = resolve_http_url(base)
        ukey = url_key(scheme, host, port, path)
    except IdentityError as exc:
        raise ParseError(str(exc), code="invalid_url") from exc
    out: list[Observation] = []
    techs = data.get("technologies") or []
    if not isinstance(techs, list):
        raise ParseError("technologies must be a list", code="invalid_json")
    headers = data.get("headers") or {}
    body = data.get("body") if isinstance(data.get("body"), str) else ""
    if not techs:
        techs = detect_technologies(headers if isinstance(headers, dict) else {}, body)
    for item in techs:
        if not isinstance(item, dict):
            continue
        product = item.get("product")
        if not isinstance(product, str) or not product.strip():
            continue
        try:
            slug = product_slug(product)
        except IdentityError:
            continue
        payload = {
            "product": slug,
            "source": item.get("source") or "header",
        }
        if item.get("version"):
            payload["version"] = str(item["version"])
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="http.tech",
                obj=payload,
                subject_hint=ukey,
            )
        )
    if isinstance(headers, dict):
        for name, value in headers.items():
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="http.header",
                    obj={"name": str(name).lower(), "value": "" if value is None else str(value)},
                    subject_hint=ukey,
                )
            )
    return out
