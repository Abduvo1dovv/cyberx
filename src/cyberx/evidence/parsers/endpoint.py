"""Endpoint discovery parser: JSON payloads or stored HTML. No crawling."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from cyberx.domain.enums import AuthSurfaceKind, HttpMethod
from cyberx.domain.errors import IdentityError, ParseError
from cyberx.domain.identity import (
    endpoint_key,
    is_secret_shaped_name,
    parse_http_url,
    url_key,
)
from cyberx.domain.models.evidence import Observation
from cyberx.evidence.parsers.base import (
    coerce_http_base,
    decode_utf8,
    emit,
    load_json_object,
    read_artifact_bytes,
    resolve_http_url,
)
from cyberx.ports.execution import RawArtifact

PARSER_ID = "endpoint"
_MAX_URLS = 25
_SKIP_SCHEMES = ("javascript:", "data:", "mailto:", "tel:", "blob:")
_AUTH_FIELD_NAMES = frozenset({"password", "passwd", "pass", "pwd", "secret"})


class EndpointParser:
    parser_id = PARSER_ID
    produces: tuple[str, ...] = ("endpoint.seen", "param.seen", "auth.seen", "url.seen")

    def parse(self, artifact: RawArtifact) -> list[Observation]:
        media = (artifact.media_type or "").lower()
        raw = read_artifact_bytes(artifact)
        text = decode_utf8(raw)
        if "html" in media or _looks_html(text):
            return observations_from_html(text, artifact)
        try:
            data = load_json_object(artifact)
        except ParseError:
            if _looks_html(text):
                return observations_from_html(text, artifact)
            raise
        html = data.get("html")
        if not isinstance(html, str):
            body = data.get("body")
            html = body if isinstance(body, str) else None
        if isinstance(html, str) and _looks_html(html):
            return observations_from_html(html, artifact, data=data)
        return observations_from_endpoint_payload(data, artifact)


def observations_from_endpoint_payload(
    data: dict[str, Any], artifact: RawArtifact
) -> list[Observation]:
    raw_base = (
        data.get("url") or data.get("base_url") or data.get("target") or artifact.source_locator
    )
    base = coerce_http_base(str(raw_base) if raw_base else None)
    if not base:
        raise ParseError("endpoint artifact missing url", code="missing_url")
    out: list[Observation] = []
    seen = 0
    endpoints = data.get("endpoints") or []
    if not isinstance(endpoints, list):
        raise ParseError("endpoints must be a list", code="invalid_json")
    for item in endpoints:
        if seen >= _MAX_URLS:
            break
        if not isinstance(item, dict):
            continue
        method = str(item.get("method") or "GET").upper()
        if method not in {m.value for m in HttpMethod}:
            continue
        path = item.get("path") or item.get("url") or "/"
        if not isinstance(path, str):
            continue
        try:
            scheme, host, port, npath = resolve_http_url(path, base=base)
            ukey = url_key(scheme, host, port, npath)
        except IdentityError:
            continue
        seen += 1
        out.extend(_endpoint_obs(artifact, ukey, method))
        params = item.get("params") or []
        if isinstance(params, list):
            for param in params:
                out.extend(_param_obs(artifact, ukey, method, param))
        if item.get("auth"):
            kind = str(item.get("auth"))
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="auth.seen",
                    obj=kind,
                    subject_hint=endpoint_key(method, ukey),
                )
            )
    return out


def observations_from_html(
    html: str, artifact: RawArtifact, data: dict[str, Any] | None = None
) -> list[Observation]:
    raw_base = None
    if data:
        raw_base = (
            data.get("final_url") or data.get("url") or data.get("base_url") or data.get("target")
        )
    raw_base = raw_base or artifact.source_locator
    base = coerce_http_base(str(raw_base) if raw_base else None)
    extractor = _HtmlExtractor()
    try:
        extractor.feed(html)
        extractor.close()
    except Exception:
        extractor = _HtmlExtractor()
    if extractor.base_href:
        if base:
            base = urljoin(base, extractor.base_href)
        else:
            base = coerce_http_base(extractor.base_href)
    if not base:
        raise ParseError("html endpoint artifact missing base url", code="missing_url")
    try:
        base_scheme, base_host, _base_port, _base_path = parse_http_url(base)
    except IdentityError as exc:
        raise ParseError(str(exc), code="invalid_url") from exc

    out: list[Observation] = []
    seen_keys: list[str] = []

    def _accept(raw_href: str, method: str) -> str | None:
        if _skip_scheme(raw_href):
            return None
        try:
            scheme, host, port, path = resolve_http_url(raw_href, base=base)
        except IdentityError:
            return None
        if host != base_host or scheme != base_scheme:
            return None
        ukey = url_key(scheme, host, port, path)
        token = f"{method}:{ukey}"
        if token in seen_keys:
            return None
        if len(seen_keys) >= _MAX_URLS:
            return None
        seen_keys.append(token)
        return ukey

    for href in extractor.links:
        ukey = _accept(href, "GET")
        if ukey:
            out.extend(_endpoint_obs(artifact, ukey, "GET"))
            for name in _query_names(href):
                out.extend(_param_obs(artifact, ukey, "GET", {"name": name, "location": "query"}))
    for form in extractor.forms:
        method = form["method"]
        ukey = _accept(form["action"] or "/", method)
        if not ukey:
            continue
        out.extend(_endpoint_obs(artifact, ukey, method))
        location = "query" if method == "GET" else "body"
        if _is_auth_form(form):
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="auth.seen",
                    obj=AuthSurfaceKind.HTTP_FORM.value,
                    subject_hint=endpoint_key(method, ukey),
                )
            )
        for field in form["fields"]:
            payload = {
                "name": field["name"],
                "location": location,
                "input_type": field.get("type") or "",
            }
            out.extend(_param_obs(artifact, ukey, method, payload))
    return out


def _endpoint_obs(artifact: RawArtifact, ukey: str, method: str) -> list[Observation]:
    return [
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="url.seen",
            obj=ukey,
            subject_hint=ukey,
        ),
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="endpoint.seen",
            obj={"method": method, "url": ukey},
            subject_hint=endpoint_key(method, ukey),
        ),
    ]


def _param_obs(artifact: RawArtifact, ukey: str, method: str, param: Any) -> list[Observation]:
    extra: dict[str, Any] = {}
    if isinstance(param, str):
        name, location = param, "query"
    elif isinstance(param, dict):
        name, location = param.get("name"), param.get("location") or "query"
        if param.get("input_type"):
            extra["input_type"] = str(param["input_type"])[:32]
    else:
        return []
    if not isinstance(name, str) or not name.strip():
        return []
    location_s = str(location)
    payload: dict[str, Any] = {
        "name": name.strip(),
        "location": location_s,
        "redacted": is_secret_shaped_name(name),
    }
    ekey = endpoint_key(method, ukey)
    return [
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="param.seen",
            obj=payload,
            subject_hint=ekey,
            extra=extra or None,
        )
    ]


def _skip_scheme(raw_href: str) -> bool:
    lowered = raw_href.strip().lower()
    return any(lowered.startswith(s) for s in _SKIP_SCHEMES)


def _query_names(href: str) -> list[str]:
    try:
        query = urlsplit(urljoin("http://placeholder.local/", href)).query
    except Exception:
        return []
    names: list[str] = []
    seen: set[str] = set()
    for key, _value in parse_qsl(query, keep_blank_values=True):
        if not key or key in seen:
            continue
        seen.add(key)
        names.append(key)
    return names


def _is_auth_form(form: dict[str, Any]) -> bool:
    for field in form.get("fields") or []:
        name = str(field.get("name") or "").lower()
        ftype = str(field.get("type") or "").lower()
        if ftype == "password":
            return True
        if name in _AUTH_FIELD_NAMES or is_secret_shaped_name(name):
            return True
    return False


def _looks_html(text: str) -> bool:
    stripped = text.lstrip().lower()
    if stripped.startswith("{") or stripped.startswith("["):
        return False
    return (
        stripped.startswith("<!doctype html")
        or stripped.startswith("<html")
        or "<form" in stripped[:4000]
        or "<a href" in stripped[:4000]
        or "<title" in stripped[:4000]
    )


class _HtmlExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and ad.get("href"):
            self.base_href = ad["href"]
        elif tag == "a" and ad.get("href"):
            self.links.append(ad["href"])
        elif tag == "form":
            method = (ad.get("method") or "GET").upper()
            if method not in {m.value for m in HttpMethod}:
                method = "GET"
            self._form = {
                "action": ad.get("action") or "",
                "method": method,
                "fields": [],
            }
            self.forms.append(self._form)
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            name = ad.get("name")
            if name:
                self._form["fields"].append({"name": name, "type": (ad.get("type") or tag).lower()})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
