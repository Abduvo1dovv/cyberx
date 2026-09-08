"""HTTP probe JSON parser. No network."""

from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

from cyberx.domain.enums import HttpMethod
from cyberx.domain.errors import IdentityError, ParseError
from cyberx.domain.identity import endpoint_key, url_key
from cyberx.domain.models.evidence import Observation
from cyberx.evidence.parsers.base import (
    MAX_TITLE,
    clip,
    coerce_http_base,
    emit,
    load_json_object,
    resolve_http_url,
)
from cyberx.evidence.redactor import DEFAULT_REDACTOR, REDACTED
from cyberx.ports.execution import RawArtifact

PARSER_ID = "http_probe"
_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
_SKIP_SCHEMES = ("javascript:", "data:", "mailto:", "tel:", "blob:")
_MAX_LINKS = 25


class HttpProbeParser:
    parser_id = PARSER_ID
    produces: tuple[str, ...] = (
        "http.status",
        "http.title",
        "http.header",
        "http.redirect",
        "http.body_hash",
        "url.seen",
        "endpoint.seen",
        "auth.seen",
    )

    def parse(self, artifact: RawArtifact) -> list[Observation]:
        return observations_from_http_payload(load_json_object(artifact), artifact)


def observations_from_http_payload(
    data: dict[str, Any], artifact: RawArtifact
) -> list[Observation]:
    raw_url = data.get("url") or data.get("target") or artifact.source_locator
    base = coerce_http_base(str(raw_url) if raw_url else None)
    if not base:
        raise ParseError("http probe artifact missing url", code="missing_url")
    try:
        scheme, host, port, path = resolve_http_url(base)
    except IdentityError as exc:
        raise ParseError(str(exc), code="invalid_url") from exc
    ukey = url_key(scheme, host, port, path)
    if "status" not in data:
        raise ParseError("http probe artifact missing status", code="missing_status")
    try:
        status = int(data["status"])
    except (TypeError, ValueError) as exc:
        raise ParseError("http status must be an integer", code="invalid_status") from exc

    extra_url: dict[str, Any] = {"status": status}
    tls = data.get("tls")
    if isinstance(tls, dict) and tls.get("enabled"):
        extra_url["tls"] = True
        if tls.get("version"):
            extra_url["tls_version"] = str(tls["version"])[:16]

    out: list[Observation] = [
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="url.seen",
            obj=ukey,
            subject_hint=ukey,
            extra=extra_url,
        ),
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="http.status",
            obj=status,
            subject_hint=ukey,
        ),
        emit(
            artifact=artifact,
            parser_id=PARSER_ID,
            predicate="endpoint.seen",
            obj={"method": "GET", "url": ukey},
            subject_hint=endpoint_key("GET", ukey),
            extra={"status": status},
        ),
    ]
    title = data.get("title")
    if not (isinstance(title, str) and title.strip()):
        body = data.get("body")
        if isinstance(body, str):
            title = _title_from_html(body)
    if isinstance(title, str) and title.strip():
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="http.title",
                obj=clip(_strip_tags(title.strip()), MAX_TITLE),
                subject_hint=ukey,
            )
        )
    headers = data.get("headers") or {}
    if isinstance(headers, dict):
        for name, value in headers.items():
            header_name = str(name)
            header_value = "" if value is None else str(value)
            redacted_value, _refs = DEFAULT_REDACTOR.redact_header(header_name, header_value)
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="http.header",
                    obj={"name": header_name.lower(), "value": redacted_value},
                    subject_hint=ukey,
                )
            )
            if header_name.lower() == "server" and redacted_value != REDACTED:
                product = redacted_value.split("/")[0].strip()
                if product:
                    out.append(
                        emit(
                            artifact=artifact,
                            parser_id=PARSER_ID,
                            predicate="http.tech",
                            obj={"product": product, "source": "header"},
                            subject_hint=ukey,
                        )
                    )
            if header_name.lower() == "www-authenticate":
                kind = "unknown"
                low = header_value.lower()
                if low.startswith("basic"):
                    kind = "http_basic"
                elif "bearer" in low:
                    kind = "http_bearer_challenge"
                out.append(
                    emit(
                        artifact=artifact,
                        parser_id=PARSER_ID,
                        predicate="auth.seen",
                        obj=kind,
                        subject_hint=ukey,
                    )
                )
    redirect = data.get("redirect")
    if isinstance(redirect, str) and redirect.strip():
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="http.redirect",
                obj=redirect.strip(),
                subject_hint=ukey,
            )
        )
    body_hash = data.get("body_hash")
    body = data.get("body")
    if isinstance(body, str) and not body_hash:
        body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    if isinstance(body_hash, str) and body_hash:
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="http.body_hash",
                obj=body_hash,
                subject_hint=ukey,
            )
        )
    if isinstance(body, str) and _looks_html(body):
        out.extend(_html_surface(body, artifact, base, host, scheme))
    return out


def _title_from_html(html: str) -> str | None:
    match = _TITLE_RE.search(html)
    if not match:
        return None
    return _strip_tags(match.group(1)).strip() or None


def _strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text).replace("\n", " ").strip()


def _looks_html(text: str) -> bool:
    low = text.lower()
    return "<html" in low or "<title" in low or "<body" in low or "<form" in low


def _html_surface(
    html: str,
    artifact: RawArtifact,
    base: str,
    base_host: str,
    base_scheme: str,
) -> list[Observation]:
    extractor = _ProbeHtml()
    try:
        extractor.feed(html)
        extractor.close()
    except Exception:
        return []
    out: list[Observation] = []
    seen: list[str] = []

    def accept(raw_href: str, method: str) -> str | None:
        if any(raw_href.lower().startswith(s) for s in _SKIP_SCHEMES):
            return None
        try:
            scheme, host, port, path = resolve_http_url(raw_href, base=base)
        except IdentityError:
            return None
        if host != base_host or scheme != base_scheme:
            return None
        ukey = url_key(scheme, host, port, path)
        token = f"{method}:{ukey}"
        if token in seen or len(seen) >= _MAX_LINKS:
            return None
        seen.append(token)
        return ukey

    for href in extractor.links:
        ukey = accept(href, "GET")
        if not ukey:
            continue
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="url.seen",
                obj=ukey,
                subject_hint=ukey,
            )
        )
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="endpoint.seen",
                obj={"method": "GET", "url": ukey},
                subject_hint=endpoint_key("GET", ukey),
            )
        )
    for form in extractor.forms:
        method = form["method"]
        action = form["action"] or "/"
        ukey = accept(urljoin(base, action), method)
        if not ukey:
            continue
        out.append(
            emit(
                artifact=artifact,
                parser_id=PARSER_ID,
                predicate="endpoint.seen",
                obj={"method": method, "url": ukey},
                subject_hint=endpoint_key(method, ukey),
            )
        )
        if form["fields"]:
            out.append(
                emit(
                    artifact=artifact,
                    parser_id=PARSER_ID,
                    predicate="auth.seen",
                    obj="http_form",
                    subject_hint=endpoint_key(method, ukey),
                )
            )
    return out


class _ProbeHtml(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and ad.get("href"):
            self.links.append(ad["href"])
        elif tag == "form":
            method = (ad.get("method") or "GET").upper()
            if method not in {m.value for m in HttpMethod}:
                method = "GET"
            self._form = {"action": ad.get("action") or "", "method": method, "fields": []}
            self.forms.append(self._form)
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            if ad.get("name"):
                self._form["fields"].append(ad["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
