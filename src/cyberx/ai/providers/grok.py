"""Grok IntelligenceProvider. Advisory only. Never executes or writes facts."""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any

from cyberx.ai.prompt import SYSTEM_POLICY, build_messages, serialize_context
from cyberx.ai.protocol import HypothesisDraft, ScoreAdvice
from cyberx.ai.transport import ChatTransport, TransportResult, UrllibChatTransport
from cyberx.ai.validate import (
    parse_json_object,
    validate_advice,
    validate_explanation,
    validate_hypotheses,
    validate_report_section,
)
from cyberx.config import ProviderConfig
from cyberx.domain.models.findings import BrainContext, Finding
from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe


class GrokProvider:
    name = "grok"

    def __init__(
        self,
        settings: ProviderConfig,
        *,
        events: EventSink | None = None,
        transport: ChatTransport | None = None,
    ) -> None:
        self._settings = settings
        self._events = events or NullEventSink()
        self._transport = transport or UrllibChatTransport()
        key = (settings.api_key or "").strip()
        self._key = key
        self.available = bool(key)
        self.status_reason = "ok" if self.available else "missing credentials"
        self.model = settings.model
        self.calls = 0
        self.budget = settings.max_calls_per_mission
        self.last_error: str | None = None
        self.last_latency_ms: int = 0

    def hypothesize(self, ctx: BrainContext) -> list[HypothesisDraft]:
        raw = self._complete("hypothesize", ctx)
        if raw is None:
            return []
        accepted = validate_hypotheses(raw, ctx)
        if not accepted and raw.get("hypotheses"):
            self._reject(ctx.mission_id, "hypothesize", "schema")
        return accepted

    def advise_scores(
        self, candidates: Sequence[object], ctx: BrainContext
    ) -> list[ScoreAdvice]:
        raw = self._complete("advise_scores", ctx, candidates=candidates)
        if raw is None:
            return []
        accepted = validate_advice(raw, candidates)
        if not accepted and raw.get("advice"):
            self._reject(ctx.mission_id, "advise_scores", "coverage_or_range")
        return accepted

    def explain_finding(self, finding: Finding, ctx: BrainContext) -> str:
        raw = self._complete("explain_finding", ctx, finding=finding)
        if raw is None:
            return ""
        text = validate_explanation(raw)
        if not text:
            self._reject(ctx.mission_id, "explain_finding", "schema")
        return text

    def draft_report_section(self, report: object) -> str:
        empty = BrainContext(
            mission_id="mis_01AAAAAAAAAAAAAAAAAAAAAAAA",
            intent="report",
            mode="ctf",
            iteration=0,
            scope_digest="none",
        )
        raw = self._complete("draft_report", empty, report=report)
        if raw is None:
            return ""
        return validate_report_section(raw)

    def _complete(
        self,
        task: str,
        ctx: BrainContext,
        *,
        candidates: Sequence[object] = (),
        finding: Finding | None = None,
        report: object | None = None,
    ) -> dict | None:
        self.last_error = None
        self.last_latency_ms = 0
        if not self.available:
            self.last_error = "missing_credentials"
            return None
        prompt = serialize_context(
            ctx,
            task,
            candidates=candidates,
            finding=finding,
            report=report,
            max_bytes=self._settings.max_prompt_bytes,
        )
        messages = build_messages(task, prompt)
        url = self._settings.base_url.rstrip("/") + "/chat/completions"
        payload: dict[str, Any] = {
            "model": self._settings.model,
            "messages": messages,
            "max_tokens": self._settings.max_output_tokens,
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._key}",
        }
        started = time.monotonic()
        result = self._transport.complete(
            url,
            headers,
            payload,
            timeout_s=float(self._settings.timeout_s),
            max_bytes=self._settings.max_response_bytes,
        )
        self.last_latency_ms = int((time.monotonic() - started) * 1000)
        return self._parse(result, ctx.mission_id, task)

    def _parse(self, result: TransportResult, mission_id: str, task: str) -> dict | None:
        del mission_id, task
        if result.timed_out or result.error == "timeout":
            self.last_error = "timeout"
            return None
        if result.error == "rate_limit" or result.status == 429:
            self.last_error = "rate_limit"
            return None
        if result.status >= 400 or result.error:
            self.last_error = result.error or "unavailable"
            return None
        try:
            envelope = json.loads(result.body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            self.last_error = "invalid_json"
            return None
        content = _message_content(envelope)
        if content is None:
            self.last_error = "invalid_json"
            return None
        parsed = parse_json_object(content)
        if parsed is None:
            self.last_error = "invalid_json"
            return None
        return parsed

    def _reject(self, mission_id: str, task: str, reason: str) -> None:
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.AI_REJECTED,
                mission_id=mission_id,
                payload={
                    "task_type": task,
                    "provider": self.name,
                    "model": self.model,
                    "reason": reason,
                    "validation": "rejected",
                },
            ),
        )

    def __repr__(self) -> str:
        return f"GrokProvider(model={self.model!r}, available={self.available})"


def _message_content(envelope: object) -> str | None:
    if not isinstance(envelope, dict):
        return None
    choices = envelope.get("choices")
    if not isinstance(choices, list) or not choices:
        # allow a bare JSON object as the body for mocked transports
        if "hypotheses" in envelope or "advice" in envelope or "explanation" in envelope:
            return json.dumps(envelope)
        if "section" in envelope:
            return json.dumps(envelope)
        return None
    first = choices[0]
    if not isinstance(first, dict):
        return None
    message = first.get("message") or {}
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if not isinstance(content, str):
        return None
    return content


# referenced so ruff keeps the policy import used by tests via grok module
_ = SYSTEM_POLICY
