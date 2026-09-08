"""HTTP/HTTPS ToolAdapter. GET only. No World Model, no arbitrary headers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyberx.domain.errors import DomainValidationError
from cyberx.domain.identity import parse_http_url
from cyberx.domain.ids import PREFIX_ARTIFACT, PREFIX_TOOL_RUN, new_id
from cyberx.domain.models.actions import Action
from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe
from cyberx.ports.execution import ExecutionContext, RawArtifact
from cyberx.recon.http.request import (
    HTTP_ACTION_TYPES,
    build_http_argv,
    prepare_get,
    resolve_redirect,
    url_from_action,
)
from cyberx.recon.http.safety import destination_allowed
from cyberx.recon.http.transport import HttpRawResponse, StdlibTransport

SAFE_HEADERS = frozenset(
    {
        "server",
        "content-type",
        "content-length",
        "location",
        "www-authenticate",
        "x-powered-by",
        "x-generator",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
        "allow",
        "date",
        "etag",
        "cache-control",
        "x-aspnet-version",
        "x-drupal-cache",
        "retry-after",
    }
)
REDACT_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
)


@dataclass
class HttpCallMeta:
    timed_out: bool = False
    error: str | None = None
    status: int | None = None
    exit_code: int = 0


class HttpAdapter:
    name = "http_adapter"
    action_types: tuple[str, ...] = ("http_probe",)

    def __init__(
        self,
        *,
        transport: Any | None = None,
        events: EventSink | None = None,
        max_body_bytes: int = 524288,
        max_redirects: int = 3,
        tls_verify: bool = True,
        user_agent: str = "CyberX/1.0",
        available: bool | None = True,
    ) -> None:
        self._transport = transport or StdlibTransport()
        self._events = events or NullEventSink()
        self._max_body = max_body_bytes
        self._max_redirects = max(0, min(int(max_redirects), 3))
        self._tls_verify = tls_verify
        self._user_agent = user_agent
        self._forced_available = available
        self._last_argv: list[str] = []
        self._last_result: HttpCallMeta | None = None

    def is_available(self) -> bool:
        if self._forced_available is not None:
            return self._forced_available
        return True

    def build_argv(self, action: Action) -> list[str]:
        argv = build_http_argv(action)
        self._last_argv = argv
        return argv

    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact:
        allowed = action.action_type in self.action_types or action.action_type in HTTP_ACTION_TYPES
        if not allowed:
            raise DomainValidationError(f"http adapter does not run {action.action_type}")
        start_url = url_from_action(action)
        origin_host = parse_http_url(start_url)[1]
        if not destination_allowed(start_url, origin_host=origin_host, ctx=ctx):
            if ctx.allowed_targets or ctx.allowed_networks:
                self._last_result = HttpCallMeta(error="out_of_scope", exit_code=1)
                emit_safe(
                    self._events,
                    DomainEvent(
                        event_type=EventType.HTTP_FAILED,
                        mission_id=action.mission_id,
                        payload={"reason": "out_of_scope", "action_id": action.action_id},
                    ),
                )
                return self._artifact(action, ctx, _empty_payload(start_url, error="out_of_scope"))
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.HTTP_STARTED,
                mission_id=action.mission_id,
                payload={"action_id": action.action_id, "action_type": action.action_type},
            ),
        )
        payload = self._probe(start_url, origin_host, ctx)
        meta = self._last_result or HttpCallMeta()
        if meta.timed_out or (meta.error and meta.status is None):
            kind = EventType.HTTP_FAILED
        else:
            kind = EventType.HTTP_COMPLETED
        emit_safe(
            self._events,
            DomainEvent(
                event_type=kind,
                mission_id=action.mission_id,
                payload={
                    "action_id": action.action_id,
                    "status": meta.status,
                    "bytes": len(json.dumps(payload).encode("utf-8")),
                    "error": meta.error,
                },
            ),
        )
        return self._artifact(action, ctx, payload)

    def _probe(self, start_url: str, origin_host: str, ctx: ExecutionContext) -> dict[str, Any]:
        current = start_url
        hops = 0
        redirects: list[dict[str, Any]] = []
        last = HttpRawResponse(url=current, error="empty")
        timeout_s = max(1, int(ctx.timeout_s or 30))
        while hops <= self._max_redirects:
            spec = prepare_get(
                current,
                timeout_s=timeout_s,
                max_body=self._max_body,
                tls_verify=self._tls_verify,
                user_agent=self._user_agent,
            )
            last = self._transport.request(spec)
            if last.timed_out:
                self._last_result = HttpCallMeta(timed_out=True, error="timeout", exit_code=-1)
                return _empty_payload(current, error="timeout")
            if last.error and last.status == 0:
                self._last_result = HttpCallMeta(error=last.error, exit_code=1)
                return _empty_payload(current, error=last.error)
            location = (last.headers or {}).get("location")
            if last.status in {301, 302, 303, 307, 308} and location:
                try:
                    nxt = resolve_redirect(current, location)
                except DomainValidationError:
                    redirects.append(
                        {"from": current, "to": location, "status": last.status, "followed": False}
                    )
                    break
                allowed = destination_allowed(nxt, origin_host=origin_host, ctx=ctx)
                followed = bool(allowed) and hops < self._max_redirects
                redirects.append(
                    {
                        "from": current,
                        "to": nxt,
                        "status": last.status,
                        "followed": followed,
                    }
                )
                if not allowed:
                    emit_safe(
                        self._events,
                        DomainEvent(
                            event_type=EventType.HTTP_REDIRECT_BLOCKED,
                            mission_id=ctx.mission_id,
                            payload={"from": current, "status": last.status},
                        ),
                    )
                    break
                if not followed:
                    break
                hops += 1
                current = nxt
                continue
            break
        self._last_result = HttpCallMeta(status=last.status, exit_code=0)
        return _payload_from_response(start_url, current, last, redirects)

    def _artifact(
        self, action: Action, ctx: ExecutionContext, payload: dict[str, Any]
    ) -> RawArtifact:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        tool_run_id = new_id(PREFIX_TOOL_RUN)
        path = None
        if ctx.workdir:
            art_dir = Path(ctx.workdir) / "artifacts" / tool_run_id
            art_dir.mkdir(parents=True, exist_ok=True)
            dest = art_dir / "response.meta.json"
            dest.write_bytes(raw)
            body = payload.get("body")
            if isinstance(body, str) and body:
                (art_dir / "body.bin").write_bytes(body.encode("utf-8", errors="replace"))
            path = str(dest)
        self._last_argv = ["GET", payload.get("url") or url_from_action(action)]
        locator = payload.get("final_url") or payload.get("url")
        return RawArtifact(
            artifact_id=new_id(PREFIX_ARTIFACT),
            tool_run_id=tool_run_id,
            adapter_name=self.name,
            media_type="application/json",
            sha256=hashlib.sha256(raw).hexdigest(),
            byte_size=len(raw),
            truncated=bool(payload.get("truncated")),
            body=raw,
            path=path,
            mission_id=action.mission_id,
            source_locator=locator if isinstance(locator, str) else action.target.canonical_locator,
        )


def _empty_payload(url: str, *, error: str) -> dict[str, Any]:
    return {
        "url": url,
        "final_url": url,
        "status": 0,
        "headers": {},
        "redirects": [],
        "error": error,
        "body": "",
        "truncated": False,
    }


def _payload_from_response(
    start_url: str,
    final_url: str,
    resp: HttpRawResponse,
    redirects: list[dict[str, Any]],
) -> dict[str, Any]:
    headers = _safe_headers(resp.headers)
    body_text = resp.body.decode("utf-8", errors="replace")
    digest = hashlib.sha256(resp.body).hexdigest() if resp.body else None
    redirect = None
    if redirects:
        redirect = redirects[0].get("to")
    return {
        "url": start_url,
        "final_url": final_url,
        "status": resp.status,
        "method": "GET",
        "headers": headers,
        "content_type": headers.get("content-type"),
        "content_length": len(resp.body),
        "redirect": redirect,
        "redirects": redirects,
        "body": body_text,
        "body_hash": digest,
        "truncated": resp.truncated,
        "tls": {"enabled": resp.tls_enabled, "version": resp.tls_version},
        "error": resp.error,
    }


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        key = str(name).lower()
        if key in REDACT_HEADERS:
            out[key] = "[REDACTED]"
            continue
        if key not in SAFE_HEADERS:
            continue
        out[key] = str(value)[:400]
    return out
