"""Call budget, fingerprint cache, and fail-closed wrapping. No execution."""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from cyberx.ai.none import NoneProvider
from cyberx.ai.prompt import request_fingerprint, serialize_context
from cyberx.ai.protocol import HypothesisDraft, IntelligenceProvider, ScoreAdvice
from cyberx.config import ProviderConfig
from cyberx.domain.models.findings import BrainContext, Finding
from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe


class GuardedProvider:
    """Budget + cache + fallback around an IntelligenceProvider."""

    def __init__(
        self,
        inner: IntelligenceProvider,
        settings: ProviderConfig,
        events: EventSink | None = None,
    ) -> None:
        self._inner = inner
        self._settings = settings
        self._events = events or NullEventSink()
        self._cache: dict[str, Any] = {}
        self._mission_calls = 0
        self._cycle_calls = 0
        self._cycle_iteration = -1

    @property
    def name(self) -> str:
        return getattr(self._inner, "name", "none")

    @property
    def available(self) -> bool:
        return bool(getattr(self._inner, "available", False))

    @property
    def status_reason(self) -> str:
        if self.name == "none":
            return "provider not configured"
        if not self.available:
            return getattr(self._inner, "status_reason", "provider not configured")
        if self._mission_calls >= self._settings.max_calls_per_mission:
            return "ai budget exhausted"
        return "ok"

    @property
    def model(self) -> str:
        return getattr(self._inner, "model", self._settings.model)

    @property
    def calls(self) -> int:
        return self._mission_calls

    @property
    def budget(self) -> int:
        return int(self._settings.max_calls_per_mission)

    def hypothesize(self, ctx: BrainContext) -> list[HypothesisDraft]:
        allowed = self._prepare(ctx, "hypothesize")
        if allowed is None:
            return []
        fp, proceed = allowed
        if not proceed:
            cached = self._cache.get(fp)
            return list(cached) if isinstance(cached, list) else []
        result = self._call("hypothesize", fp, lambda: self._inner.hypothesize(ctx), ctx)
        return list(result) if isinstance(result, list) else []

    def advise_scores(self, candidates: Sequence[object], ctx: BrainContext) -> list[ScoreAdvice]:
        extra = ",".join(sorted(str(getattr(c, "coverage_key", "") or "") for c in candidates))
        allowed = self._prepare(ctx, "advise_scores", extra=extra)
        if allowed is None:
            return []
        fp, proceed = allowed
        if not proceed:
            cached = self._cache.get(fp)
            return list(cached) if isinstance(cached, list) else []
        result = self._call(
            "advise_scores",
            fp,
            lambda: self._inner.advise_scores(candidates, ctx),
            ctx,
        )
        return list(result) if isinstance(result, list) else []

    def explain_finding(self, finding: Finding, ctx: BrainContext) -> str:
        allowed = self._prepare(ctx, "explain_finding", extra=finding.finding_id)
        if allowed is None:
            return ""
        fp, proceed = allowed
        if not proceed:
            cached = self._cache.get(fp)
            return str(cached) if cached else ""
        result = self._call(
            "explain_finding",
            fp,
            lambda: self._inner.explain_finding(finding, ctx),
            ctx,
        )
        return str(result) if result else ""

    def draft_report_section(self, report: object) -> str:
        if self.name == "none" or not self.available:
            return ""
        try:
            return self._inner.draft_report_section(report)
        except Exception:
            return ""

    def _prepare(self, ctx: BrainContext, task: str, extra: str = "") -> tuple[str, bool] | None:
        self._sync_cycle(ctx.iteration)
        if self.name == "none":
            return None
        if not self.available:
            self._fallback(ctx.mission_id, task, "missing_credentials")
            return None
        prompt = serialize_context(ctx, task, max_bytes=self._settings.max_prompt_bytes)
        fp = request_fingerprint(
            provider=self.name, model=self.model, task=task + extra, prompt=prompt
        )
        if fp in self._cache:
            return fp, False
        if self._mission_calls >= self._settings.max_calls_per_mission:
            self._fallback(ctx.mission_id, task, "budget")
            return None
        if self._cycle_calls >= self._settings.max_calls_per_cycle:
            self._fallback(ctx.mission_id, task, "budget")
            return None
        return fp, True

    def _call(self, task: str, fp: str, fn: Any, ctx: BrainContext) -> Any:
        self._mission_calls += 1
        self._cycle_calls += 1
        if hasattr(self._inner, "last_error"):
            self._inner.last_error = None
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.AI_REQUESTED,
                mission_id=ctx.mission_id,
                payload={
                    "task_type": task,
                    "provider": self.name,
                    "model": self.model,
                },
            ),
        )
        started = time.monotonic()
        try:
            result = fn()
        except Exception:
            latency_ms = int((time.monotonic() - started) * 1000)
            self._fail(ctx.mission_id, task, "provider_error", latency_ms)
            return [] if task != "explain_finding" else ""
        latency_ms = int((time.monotonic() - started) * 1000)
        err = getattr(self._inner, "last_error", None)
        if err:
            self._fail(ctx.mission_id, task, str(err), latency_ms)
            return [] if task != "explain_finding" else ""
        self._cache[fp] = result
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.AI_COMPLETED,
                mission_id=ctx.mission_id,
                payload={
                    "task_type": task,
                    "provider": self.name,
                    "model": self.model,
                    "latency_ms": latency_ms,
                    "validation": "ok",
                },
            ),
        )
        return result

    def _fail(self, mission_id: str, task: str, reason: str, latency_ms: int) -> None:
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.AI_FAILED,
                mission_id=mission_id,
                payload={
                    "task_type": task,
                    "provider": self.name,
                    "model": self.model,
                    "reason": reason,
                    "latency_ms": latency_ms,
                    "validation": "failed",
                },
            ),
        )
        self._fallback(mission_id, task, reason)

    def _sync_cycle(self, iteration: int) -> None:
        if iteration != self._cycle_iteration:
            self._cycle_iteration = iteration
            self._cycle_calls = 0

    def _fallback(self, mission_id: str, task: str, reason: str) -> None:
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.AI_FALLBACK,
                mission_id=mission_id,
                payload={
                    "task_type": task,
                    "provider": self.name,
                    "model": self.model,
                    "reason": reason,
                },
            ),
        )


def wrap_provider(
    inner: IntelligenceProvider | None,
    settings: ProviderConfig,
    events: EventSink | None = None,
) -> GuardedProvider:
    return GuardedProvider(inner or NoneProvider(), settings, events)
