"""directory_enumeration adapter. GET only, depth 1, ≤ 50 names. No World Model."""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from cyberx.actions.params import DirectoryEnumerationParams
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.identity import parse_http_url
from cyberx.domain.ids import PREFIX_ARTIFACT, PREFIX_TOOL_RUN, new_id
from cyberx.domain.models.actions import Action
from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe
from cyberx.ports.execution import ExecutionContext, RawArtifact
from cyberx.recon.http.adapter import HttpCallMeta
from cyberx.recon.http.request import prepare_get, resolve_redirect, url_from_action
from cyberx.recon.http.safety import destination_allowed
from cyberx.recon.http.transport import HttpRawResponse, StdlibTransport
from cyberx.recon.http.wordlist import MAX_DIRECTORY_CANDIDATES, canary_urls, candidate_urls

_TITLE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SUCCESS = frozenset({200, 201, 204, 301, 302, 303, 307, 308})


def classify_status(status: int, *, error: str | None = None, timed_out: bool = False) -> str:
    if timed_out or error == "timeout":
        return "timeout"
    if error:
        return "unavailable"
    if 200 <= status <= 299:
        return "found"
    if status in {301, 302, 303, 307, 308}:
        return "redirect"
    if status == 401:
        return "unauthorized"
    if status == 403:
        return "forbidden"
    if status in {404, 410}:
        return "not_found"
    if 500 <= status <= 599:
        return "server_error"
    return "unavailable"


class DirectoryAdapter:
    name = "directory_adapter"
    action_types: tuple[str, ...] = ("directory_enumeration",)

    def __init__(
        self,
        *,
        transport: Any | None = None,
        events: EventSink | None = None,
        max_body_bytes: int = 65536,
        max_candidates: int = MAX_DIRECTORY_CANDIDATES,
        tls_verify: bool = True,
        user_agent: str = "CyberX/1.0",
        available: bool | None = True,
    ) -> None:
        self._transport = transport or StdlibTransport()
        self._events = events or NullEventSink()
        self._max_body = max(1024, int(max_body_bytes))
        self._max = max(1, min(int(max_candidates), MAX_DIRECTORY_CANDIDATES))
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
        url = url_from_action(action)
        argv = ["GET", url, "wordlist=small", f"limit={self._max}"]
        self._last_argv = argv
        return argv

    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact:
        if action.action_type != "directory_enumeration":
            raise DomainValidationError("directory adapter only runs directory_enumeration")
        DirectoryEnumerationParams.model_validate(action.parameters)
        base = url_from_action(action)
        origin_host = parse_http_url(base)[1]
        self._last_argv = ["GET", base, "wordlist=small", f"limit={self._max}"]
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.DIRECTORY_STARTED,
                mission_id=action.mission_id,
                payload={"action_id": action.action_id, "url": base},
            ),
        )
        if not destination_allowed(base, origin_host=origin_host, ctx=ctx):
            self._last_result = HttpCallMeta(error="out_of_scope", exit_code=1, status=None)
            emit_safe(
                self._events,
                DomainEvent(
                    event_type=EventType.DIRECTORY_FAILED,
                    mission_id=action.mission_id,
                    payload={"reason": "out_of_scope", "url": base},
                ),
            )
            return self._artifact(
                action, ctx, {"base_url": base, "status": "out_of_scope", "paths": []}
            )
        payload = self._enumerate(base, origin_host, ctx)
        meta = self._last_result or HttpCallMeta()
        kind = EventType.DIRECTORY_FAILED if meta.error else EventType.DIRECTORY_COMPLETED
        emit_safe(
            self._events,
            DomainEvent(
                event_type=kind,
                mission_id=action.mission_id,
                payload={
                    "url": base,
                    "paths": len(payload.get("paths") or []),
                    "wildcard": bool(payload.get("wildcard_detected")),
                    "error": meta.error,
                },
            ),
        )
        return self._artifact(action, ctx, payload)

    def _enumerate(self, base: str, origin_host: str, ctx: ExecutionContext) -> dict[str, Any]:
        timeout_s = max(1, int(ctx.timeout_s or 120))
        interval = 0.0
        if ctx.rate_limit_hz and ctx.rate_limit_hz > 0:
            interval = 1.0 / float(ctx.rate_limit_hz)
        canaries = []
        wildcard_fp: tuple[int, str] | None = None
        for path, url in canary_urls(base):
            row, resp = self._hit(url, path, origin_host, ctx, timeout_s)
            canaries.append(row)
            if resp.timed_out:
                self._last_result = HttpCallMeta(timed_out=True, error="timeout", exit_code=-1)
                return {
                    "base_url": base,
                    "status": "timeout",
                    "wildcard_detected": False,
                    "paths": [],
                    "canaries": canaries,
                }
            if resp.error and resp.status == 0:
                self._last_result = HttpCallMeta(error=resp.error, exit_code=1, status=None)
                return {
                    "base_url": base,
                    "status": resp.error,
                    "wildcard_detected": False,
                    "paths": [],
                    "canaries": canaries,
                }
            if interval:
                time.sleep(interval)
        wildcard_fp = _wildcard_fingerprint(canaries)
        if wildcard_fp is not None:
            self._last_result = HttpCallMeta(status=wildcard_fp[0], exit_code=0)
            return {
                "base_url": base,
                "status": "wildcard_detected",
                "wildcard_detected": True,
                "wildcard": {"status": wildcard_fp[0], "body_hash": wildcard_fp[1]},
                "paths": [],
                "canaries": canaries,
                "candidate_count": 0,
            }
        paths: list[dict[str, Any]] = []
        seen: set[str] = set()
        candidates = candidate_urls(base, limit=self._max)
        for path, url in candidates:
            if path in seen:
                continue
            seen.add(path)
            row, resp = self._hit(url, path, origin_host, ctx, timeout_s)
            if resp.timed_out:
                row["classification"] = "timeout"
                paths.append(row)
                self._last_result = HttpCallMeta(timed_out=True, error="timeout", exit_code=-1)
                break
            paths.append(row)
            if interval:
                time.sleep(interval)
        if self._last_result is None or not self._last_result.timed_out:
            self._last_result = HttpCallMeta(status=200, exit_code=0)
        return {
            "base_url": base,
            "status": "ok",
            "wildcard_detected": False,
            "paths": paths,
            "canaries": canaries,
            "candidate_count": len(candidates),
        }

    def _hit(
        self,
        url: str,
        path: str,
        origin_host: str,
        ctx: ExecutionContext,
        timeout_s: int,
    ) -> tuple[dict[str, Any], HttpRawResponse]:
        spec = prepare_get(
            url,
            timeout_s=timeout_s,
            max_body=self._max_body,
            tls_verify=self._tls_verify,
            user_agent=self._user_agent,
        )
        resp = self._transport.request(spec)
        row: dict[str, Any] = {
            "path": path,
            "url": url,
            "status": resp.status,
            "classification": classify_status(
                resp.status, error=resp.error, timed_out=resp.timed_out
            ),
            "size": len(resp.body or b""),
            "content_type": (resp.headers or {}).get("content-type"),
            "body_hash": hashlib.sha256(resp.body).hexdigest() if resp.body else None,
        }
        if resp.timed_out:
            row["error"] = "timeout"
            return row, resp
        if resp.error and resp.status == 0:
            row["error"] = resp.error
            return row, resp
        title = _title_from(resp.body)
        if title:
            row["title"] = title
        location = (resp.headers or {}).get("location")
        if resp.status in {301, 302, 303, 307, 308} and location:
            try:
                nxt = resolve_redirect(url, location)
            except DomainValidationError:
                row["redirect"] = location
                row["out_of_scope"] = True
                row["followed"] = False
                return row, resp
            allowed = destination_allowed(nxt, origin_host=origin_host, ctx=ctx)
            row["redirect"] = nxt
            row["out_of_scope"] = not allowed
            row["followed"] = False
            if not allowed:
                emit_safe(
                    self._events,
                    DomainEvent(
                        event_type=EventType.HTTP_REDIRECT_BLOCKED,
                        mission_id=ctx.mission_id,
                        payload={"from": url, "status": resp.status},
                    ),
                )
        return row, resp

    def _artifact(
        self, action: Action, ctx: ExecutionContext, payload: dict[str, Any]
    ) -> RawArtifact:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        path = None
        if ctx.workdir:
            dest = Path(ctx.workdir) / "artifacts" / "directory.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            path = str(dest)
        return RawArtifact(
            artifact_id=new_id(PREFIX_ARTIFACT),
            tool_run_id=new_id(PREFIX_TOOL_RUN),
            adapter_name=self.name,
            media_type="application/json",
            sha256=hashlib.sha256(raw).hexdigest(),
            byte_size=len(raw),
            body=raw,
            path=path,
            mission_id=action.mission_id,
            source_locator=str(payload.get("base_url") or "") or None,
        )


def _wildcard_fingerprint(canaries: list[dict[str, Any]]) -> tuple[int, str] | None:
    hits: dict[tuple[int, str], int] = {}
    for row in canaries:
        status = int(row.get("status") or 0)
        if status not in _SUCCESS:
            continue
        key = (status, str(row.get("body_hash") or ""))
        hits[key] = hits.get(key, 0) + 1
    for key, count in hits.items():
        if count >= 2:
            return key
    return None


def _title_from(body: bytes) -> str | None:
    if not body:
        return None
    match = _TITLE.search(body.decode("utf-8", errors="replace"))
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:128] or None
