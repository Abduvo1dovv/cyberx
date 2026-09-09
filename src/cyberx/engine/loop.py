"""MissionEngine adaptive loop. The only sequencer. Brain never executes.

Cycle:
  guard → observe network → snapshot → one BrainContext → revise hypotheses
  → decide → authorize/execute → evidence → persist → report

Hypothesis revisions are applied to the World Model for the next cycle.
The decision phase does not rebuild BrainContext from partially changed state.
"""

from __future__ import annotations

import json

from cyberx.actions.coverage import (
    attempt_display,
    format_action_event,
    is_retryable_error,
    next_failure_coverage,
    parse_action_event,
)
from cyberx.brain.context import BrainContextBuilder, context_hash
from cyberx.brain.facade import Brain
from cyberx.brain.types import CycleReport, Decision, DecisionTrace
from cyberx.domain.enums import (
    ActionResultStatus,
    ActionStatus,
    MissionStatus,
    StopReason,
    TimelineKind,
)
from cyberx.domain.errors import (
    ActionRejected,
    AdapterUnavailable,
    PolicyDeniedError,
)
from cyberx.domain.ids import PREFIX_TIMELINE, new_id
from cyberx.domain.models.actions import ActionRequest
from cyberx.domain.models.findings import TimelineEvent
from cyberx.domain.models.mission import Mission
from cyberx.domain.models.network import NetworkContext
from cyberx.domain.time import utcnow
from cyberx.engine.apply import apply_completed_artifact
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.engine.hypotheses import apply_hypothesis_deltas
from cyberx.engine.observe import (
    NetworkCycle,
    execution_context,
    unavailable_event,
)
from cyberx.engine.persist import CyclePersistence
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.mission.ports import MissionBundle
from cyberx.mission.service import MissionService
from cyberx.network.resolver import NetworkResolver
from cyberx.ports.events import EventLog, NullEventSink
from cyberx.ports.storage import EnginePersistence
from cyberx.scope.gate import MissionScopeGate
from cyberx.validation.engine import ValidationEngine
from cyberx.world.correlation import ScopeGate
from cyberx.world.model import InMemoryWorldModel

TERMINAL = frozenset({MissionStatus.COMPLETED, MissionStatus.STOPPED, MissionStatus.FAILED})
MAX_CONSECUTIVE_FAILURES = 5
PROGRESS_STALL_CYCLES = 3
# Matches ActionLimits.max_attempts (first attempt is 1).
MAX_ACTION_ATTEMPTS = 2


class FrozenScopeGate:
    def __init__(self, out_of_scope_keys: set[str] | None = None) -> None:
        self._keys = out_of_scope_keys or set()

    def out_of_scope(self, canonical_key: str) -> bool:
        return canonical_key in self._keys


class MissionEngine:
    def __init__(
        self,
        service: MissionService,
        *,
        brain: Brain | None = None,
        boundary: ExecutionBoundary | None = None,
        pipeline: EvidencePipeline | None = None,
        store: EnginePersistence | None = None,
        builder: BrainContextBuilder | None = None,
        events: EventLog | None = None,
        network: NetworkResolver | None = None,
    ) -> None:
        self._service = service
        self._brain = brain or Brain()
        self._boundary = boundary or ExecutionBoundary()
        self._pipeline = pipeline or EvidencePipeline()
        self._persist = CyclePersistence(store)
        self._builder = builder or BrainContextBuilder()
        self._events: EventLog = events or NullEventSink()
        self._net = NetworkCycle(
            network or NetworkResolver(),
            self._events,
            append_event=self._append_event,
            mark_unreachable=self._service.mark_locator_unreachable,
        )
        self._worlds: dict[str, InMemoryWorldModel] = {}
        self._failures: dict[str, int] = {}
        self._stalls: dict[str, int] = {}
        self._last_progress: dict[str, tuple[int, int]] = {}
        self._results: dict[str, list] = {}
        self._traces: dict[str, list[DecisionTrace]] = {}
        self._ai_event_cursor = 0
        self._diag: dict[str, dict[str, str]] = {}

    def world(self, mission_id: str) -> InMemoryWorldModel:
        if mission_id not in self._worlds:
            self._worlds[mission_id] = self._load_world(mission_id)
        return self._worlds[mission_id]

    def _load_world(self, mission_id: str) -> InMemoryWorldModel:
        bundle = self._service.get_bundle(mission_id)
        gate: ScopeGate = MissionScopeGate(bundle.scope)
        resumed = self._persist.resume_world(mission_id)
        if resumed is not None:
            fails, stalls, last_rev, last_ev = self._persist.runtime(mission_id)
            self._failures[mission_id] = fails
            self._stalls[mission_id] = stalls
            self._last_progress[mission_id] = (last_rev, last_ev)
            resumed._scope_gate = gate
            self._hydrate_diag(mission_id)
            return resumed
        world = InMemoryWorldModel(mission_id, scope_gate=gate)
        if bundle.seed_assets:
            world.seed_assets(bundle.seed_assets)
        return world

    def run_one_cycle(self, mission_id: str) -> CycleReport:
        bundle = self._service.get_bundle(mission_id)
        mission = bundle.mission
        early = self._guard(mission_id, mission)
        if early is not None:
            return early

        world = self.world(mission_id)
        if world.revision == 0 and bundle.seed_assets:
            world.seed_assets(bundle.seed_assets)

        prev_net = self._net.last(mission_id)
        prev_digest = prev_net.digest() if prev_net is not None else None
        net = self._net.observe(mission_id, bundle.target, bundle.scope)

        validation = ValidationEngine()
        candidates = validation.evaluate(world)
        validation.sync_findings(world, candidates)
        snapshot = world.snapshot()
        ctx = self._builder.build(
            snapshot,
            mission,
            scope=bundle.scope,
            recent_results=self._results.get(mission_id, [])[-5:],
            recent_events=bundle.timeline[-10:],
            validation_candidates=candidates,
            network_context=net,
            target=bundle.target,
            previous_network_digest=prev_digest,
        )
        # Hypothesis work mutates the World Model for the next cycle only.
        hyp_deltas = self._brain.revise_hypotheses(ctx)
        apply_hypothesis_deltas(world, mission_id, hyp_deltas)
        self._flush_ai_timeline(mission_id)
        decision = self._brain.decide(ctx, min_score=mission.min_action_score)
        self._flush_ai_timeline(mission_id)
        trace = DecisionTrace(
            mission_id=mission_id,
            iteration=mission.iteration,
            context_revision=ctx.revision,
            context_hash=context_hash(ctx),
            candidates=decision.scores,
            selected_type=decision.action.action_type if decision.action else None,
            selected_coverage_key=(decision.action.coverage_key if decision.action else None),
            rationale=decision.rationale,
            world_revision=world.revision,
        )

        if decision.kind != "act" or decision.action is None:
            return self._stop_for_decision(mission_id, world, decision, trace)

        return self._act(mission_id, bundle, world, decision, trace, net)

    def _guard(self, mission_id: str, mission: Mission) -> CycleReport | None:
        if mission.status is MissionStatus.PAUSED or mission.pause_requested:
            return self._report(
                mission,
                Decision(
                    decision_id=new_id("dec_"),
                    kind="stop",
                    rationale="paused",
                    stop_reason="operator",
                    context_revision=self.world(mission_id).revision,
                ),
                paused=True,
            )
        if mission.status in TERMINAL:
            return self._report(
                mission,
                Decision(
                    decision_id=new_id("dec_"),
                    kind="stop",
                    rationale=f"mission is {mission.status.value}",
                    stop_reason=mission.stop_reason.value if mission.stop_reason else None,
                    context_revision=self.world(mission_id).revision,
                ),
                completed=True,
                stop_reason=mission.stop_reason.value if mission.stop_reason else None,
            )
        if mission.status is not MissionStatus.RUNNING:
            return self._report(
                mission,
                Decision(
                    decision_id=new_id("dec_"),
                    kind="stop",
                    rationale="mission_not_running",
                    stop_reason="error",
                    context_revision=0,
                ),
                completed=False,
            )
        if mission.iteration >= mission.max_iterations:
            self._service.complete(mission_id, StopReason.MAX_ITERATIONS)
            return self._report(
                self._service.get(mission_id),
                Decision(
                    decision_id=new_id("dec_"),
                    kind="stop",
                    rationale="max iterations",
                    stop_reason="max_iterations",
                    context_revision=self.world(mission_id).revision,
                ),
                completed=True,
                stop_reason="max_iterations",
            )
        if mission.started_at is not None:
            elapsed = (utcnow() - mission.started_at).total_seconds()
            if elapsed >= mission.max_runtime_s:
                self._service.complete(mission_id, StopReason.MAX_RUNTIME)
                return self._report(
                    self._service.get(mission_id),
                    Decision(
                        decision_id=new_id("dec_"),
                        kind="stop",
                        rationale="max runtime",
                        stop_reason="max_runtime",
                        context_revision=self.world(mission_id).revision,
                    ),
                    completed=True,
                    stop_reason="max_runtime",
                )
        return None

    def _stop_for_decision(
        self,
        mission_id: str,
        world: InMemoryWorldModel,
        decision: Decision,
        trace: DecisionTrace,
    ) -> CycleReport:
        reason_token = decision.stop_reason or "no_actions"
        open_gaps = [gap for gap in world.get_gaps() if not gap.closed]
        if reason_token == "no_actions" and open_gaps:
            self._service.bump_iteration(mission_id)
            self._note_progress(mission_id, world, 0)
            if self._stalls.get(mission_id, 0) >= PROGRESS_STALL_CYCLES:
                reason = StopReason.STALLED
                self._service.complete(mission_id, reason)
                trace = trace.model_copy(update={"execution_status": "stalled"})
                self._remember_trace(mission_id, trace)
                self._persist_cycle(mission_id, world, trace=trace)
                return self._report(
                    self._service.get(mission_id),
                    decision,
                    completed=True,
                    stop_reason=reason.value,
                    execution_status="stalled",
                )
            trace = trace.model_copy(update={"execution_status": "deferred"})
            self._remember_trace(mission_id, trace)
            self._persist_cycle(mission_id, world, trace=trace)
            return self._report(
                self._service.get(mission_id),
                decision,
                completed=False,
                execution_status="deferred",
            )
        reason = StopReason(reason_token)
        if self._stalls.get(mission_id, 0) >= PROGRESS_STALL_CYCLES:
            reason = StopReason.STALLED
        self._service.complete(mission_id, reason)
        trace = trace.model_copy(update={"execution_status": "stopped"})
        self._remember_trace(mission_id, trace)
        self._persist_cycle(mission_id, world, trace=trace)
        return self._report(
            self._service.get(mission_id),
            decision,
            completed=True,
            stop_reason=reason.value,
        )

    def _act(
        self,
        mission_id: str,
        bundle: MissionBundle,
        world: InMemoryWorldModel,
        decision: Decision,
        trace: DecisionTrace,
        net: NetworkContext,
    ) -> CycleReport:
        candidate = decision.action
        assert candidate is not None
        mission = bundle.mission
        request = ActionRequest(
            mission_id=mission_id,
            action_type=candidate.action_type,
            target=candidate.target,
            parameters=candidate.parameters,
            reason=candidate.reason[:500],
            timeout_s=candidate.timeout_s,
            prerequisites=candidate.prerequisites,
            expected_information_gain=candidate.expected_information_gain,
        )
        evidence_added = 0
        policy_verdict = None
        exec_status = None
        exec_ctx = execution_context(candidate, net)
        locator = candidate.target.canonical_locator or ""
        try:
            outcome = self._boundary.run(request, mission, bundle.scope, ctx=exec_ctx)
        except PolicyDeniedError as exc:
            policy_verdict = "deny"
            exec_status = "denied"
            world.record_coverage(candidate.coverage_key, ActionStatus.DENIED.value)
            self._append_event(
                mission_id,
                TimelineKind.POLICY,
                f"denied {candidate.action_type}: {exc.reason_code}",
            )
            self._service.bump_iteration(mission_id)
            trace = trace.model_copy(
                update={"policy_verdict": policy_verdict, "execution_status": exec_status}
            )
            self._remember_trace(mission_id, trace)
            self._note_progress(mission_id, world, evidence_added)
            self._persist_cycle(mission_id, world, trace=trace)
            return self._report(
                self._service.get(mission_id),
                decision,
                policy_verdict=policy_verdict,
                execution_status=exec_status,
            )
        except ActionRejected as exc:
            exec_status = "rejected"
            world.record_coverage(candidate.coverage_key, ActionStatus.REJECTED.value)
            self._append_event(
                mission_id,
                TimelineKind.ACTION,
                f"rejected {candidate.action_type}: {exc.reason_code}",
            )
            self._service.bump_iteration(mission_id)
            trace = trace.model_copy(update={"execution_status": exec_status})
            self._remember_trace(mission_id, trace)
            self._persist_cycle(mission_id, world, trace=trace)
            return self._report(
                self._service.get(mission_id),
                decision,
                execution_status=exec_status,
            )
        except AdapterUnavailable as exc:
            return self._unavailable(mission_id, world, decision, candidate, exc)

        policy_verdict = "allow"
        exec_status = outcome.result.status.value
        self._results.setdefault(mission_id, []).append(outcome.result)
        self._persist.save_execution(outcome.action, outcome.tool_run, outcome.result)

        if outcome.result.status is ActionResultStatus.COMPLETED:
            self._failures[mission_id] = 0
            evidence_added, exec_status, parsed_ok = apply_completed_artifact(
                pipeline=self._pipeline,
                persist=self._persist,
                events=self._events,
                append_event=self._append_event,
                observe_locator=self._service.observe_locator,
                world=world,
                mission_id=mission_id,
                action_type=candidate.action_type,
                coverage_key=candidate.coverage_key,
                artifact=outcome.artifact,
            )
            if not parsed_ok:
                self._failures[mission_id] = self._failures.get(mission_id, 0) + 1
                self._remember_diag(
                    mission_id,
                    action_type=candidate.action_type,
                    status=exec_status,
                    reason="invalid_output",
                    previous="",
                    target=locator,
                    retryable=False,
                )
            else:
                self._remember_diag(
                    mission_id,
                    action_type=candidate.action_type,
                    status="completed",
                    reason="",
                    previous="",
                    target=locator,
                    retryable=False,
                )
        else:
            self._failures[mission_id] = self._failures.get(mission_id, 0) + 1
            error_code = outcome.result.error_code or exec_status or "failed"
            previous = world.get_coverage().get(candidate.coverage_key, "")
            status = next_failure_coverage(previous, error_code)
            world.record_coverage(candidate.coverage_key, status)
            retryable = is_retryable_error(error_code) and status == "attempted"
            self._remember_diag(
                mission_id,
                action_type=candidate.action_type,
                status=exec_status or "failed",
                reason=error_code,
                previous=previous,
                target=locator,
                retryable=retryable,
            )
            if self._failures[mission_id] >= MAX_CONSECUTIVE_FAILURES:
                self._service.complete(mission_id, StopReason.TOO_MANY_FAILURES)
                self._persist_cycle(mission_id, world)
                return self._report(
                    self._service.get(mission_id),
                    decision,
                    completed=True,
                    stop_reason="too_many_failures",
                    execution_status=exec_status,
                    evidence_added=evidence_added,
                )

        self._append_event(
            mission_id,
            TimelineKind.ACTION,
            self._action_event(candidate.action_type, exec_status, mission_id),
        )
        self._service.bump_iteration(mission_id)
        self._note_progress(mission_id, world, evidence_added)
        if self._stalls.get(mission_id, 0) >= PROGRESS_STALL_CYCLES:
            self._service.complete(mission_id, StopReason.STALLED)
            self._persist_cycle(mission_id, world, trace=trace)
            return self._report(
                self._service.get(mission_id),
                decision,
                completed=True,
                stop_reason="stalled",
                selected_action_type=candidate.action_type,
                coverage_key=candidate.coverage_key,
                policy_verdict=policy_verdict,
                execution_status=exec_status,
                evidence_added=evidence_added,
            )
        trace = trace.model_copy(
            update={
                "policy_verdict": policy_verdict,
                "execution_status": exec_status,
                "world_revision": world.revision,
            }
        )
        self._remember_trace(mission_id, trace)
        self._persist_cycle(mission_id, world, trace=trace)
        return self._report(
            self._service.get(mission_id),
            decision,
            selected_action_type=candidate.action_type,
            coverage_key=candidate.coverage_key,
            policy_verdict=policy_verdict,
            execution_status=exec_status,
            evidence_added=evidence_added,
        )

    def _unavailable(
        self,
        mission_id: str,
        world: InMemoryWorldModel,
        decision: Decision,
        candidate: object,
        exc: AdapterUnavailable,
    ) -> CycleReport:
        exec_status = "unavailable"
        self._failures[mission_id] = self._failures.get(mission_id, 0) + 1
        world.record_coverage(candidate.coverage_key, "unavailable")
        locator = getattr(getattr(candidate, "target", None), "canonical_locator", "") or ""
        self._remember_diag(
            mission_id,
            action_type=str(getattr(candidate, "action_type", "")),
            status=exec_status,
            reason="adapter_unavailable",
            previous="",
            target=str(locator),
            retryable=False,
        )
        self._append_event(
            mission_id,
            TimelineKind.ERROR,
            unavailable_event(exc.adapter_name),
        )
        if self._failures[mission_id] >= MAX_CONSECUTIVE_FAILURES:
            self._service.complete(mission_id, StopReason.TOO_MANY_FAILURES)
            self._persist_cycle(mission_id, world)
            return self._report(
                self._service.get(mission_id),
                decision,
                completed=True,
                stop_reason="too_many_failures",
                execution_status=exec_status,
            )
        self._service.bump_iteration(mission_id)
        self._persist_cycle(mission_id, world)
        return self._report(
            self._service.get(mission_id),
            decision,
            execution_status=exec_status,
        )

    def run_forever(self, mission_id: str) -> list[CycleReport]:
        reports: list[CycleReport] = []
        while True:
            report = self.run_one_cycle(mission_id)
            reports.append(report)
            if report.completed or report.paused:
                return reports
            status = self._service.get(mission_id).status
            if status in TERMINAL:
                return reports

    def traces(self, mission_id: str) -> list[DecisionTrace]:
        return list(self._traces.get(mission_id, []))

    def action_diagnostic(self, mission_id: str) -> dict[str, str]:
        if mission_id not in self._diag:
            self._hydrate_diag(mission_id)
        return dict(self._diag.get(mission_id) or {})

    def network_context(self, mission_id: str) -> NetworkContext | None:
        bundle = self._service.get_bundle(mission_id)
        return self._net.observe(mission_id, bundle.target, bundle.scope)

    def _observe_network(
        self, mission_id: str, target: object, scope: object, *, emit: bool = True
    ) -> NetworkContext:
        return self._net.observe(mission_id, target, scope, emit=emit)

    def sync_locator_hosts(self, mission_id: str) -> None:
        """Label historical locator hosts and seed the current locator host."""
        from cyberx.mission.seed import host_for_locator
        from cyberx.world.delta import upsert_asset_delta

        bundle = self._service.get_bundle(mission_id)
        target = bundle.target
        world = self.world(mission_id)
        now = utcnow()
        identity = target.identity_key()
        current = target.current_locator
        if current:
            host = host_for_locator(
                mission_id,
                current,
                now,
                labels=[identity, "current_locator"],
            )
            if host is not None:
                world.seed_assets([host])
        for locator in target.historical_locators():
            existing = None
            for item in world.snapshot().hosts:
                addr = item.ipv4 or item.ipv6 or item.hostname
                if addr == locator:
                    existing = item
                    break
            if existing is None:
                existing = host_for_locator(
                    mission_id,
                    locator,
                    now,
                    labels=[identity, "historical"],
                )
                if existing is None:
                    continue
            labeled = existing.model_copy(
                update={"labels": list(dict.fromkeys([*existing.labels, identity, "historical"]))}
            )
            world.apply([upsert_asset_delta(labeled)])

    def _flush_ai_timeline(self, mission_id: str) -> None:
        unseen = list(self._events.iter_recent(after=self._ai_event_cursor, limit=1000))
        self._ai_event_cursor = self._events.emitted_count()
        for event in unseen:
            et = event.event_type
            value = et.value if et is not None else ""
            if not str(value).startswith("ai."):
                continue
            if event.mission_id not in {None, mission_id}:
                continue
            payload = event.payload or {}
            bits = [
                str(value),
                str(payload.get("provider") or ""),
                str(payload.get("task_type") or ""),
                str(payload.get("reason") or ""),
            ]
            self._append_event(mission_id, TimelineKind.AI, " ".join(b for b in bits if b)[:200])

    def _remember_diag(
        self,
        mission_id: str,
        *,
        action_type: str,
        status: str,
        reason: str,
        previous: str,
        target: str,
        retryable: bool,
    ) -> None:
        number, label, _more = attempt_display(previous, max_attempts=MAX_ACTION_ATTEMPTS)
        del number
        self._diag[mission_id] = {
            "action_type": action_type,
            "status": status,
            "reason": reason,
            "attempt": label,
            "retryable": "YES" if retryable else "NO",
            "target": target,
        }

    def _action_event(self, action_type: str, exec_status: str | None, mission_id: str) -> str:
        diag = self._diag.get(mission_id) or {}
        return format_action_event(
            action_type,
            exec_status or "unknown",
            reason=diag.get("reason", ""),
            attempt=diag.get("attempt", ""),
            retryable=diag.get("retryable", ""),
            target=diag.get("target", ""),
        )

    def _hydrate_diag(self, mission_id: str) -> None:
        if mission_id in self._diag:
            return
        bundle = self._service.get_bundle(mission_id)
        for event in reversed(bundle.timeline):
            if event.kind is not TimelineKind.ACTION:
                continue
            parsed = parse_action_event(event.message)
            if parsed is None:
                return
            self._diag[mission_id] = parsed
            return

    def _append_event(self, mission_id: str, kind: TimelineKind, message: str) -> None:
        bundle = self._service.get_bundle(mission_id)
        event = TimelineEvent(
            event_id=new_id(PREFIX_TIMELINE),
            mission_id=mission_id,
            kind=kind,
            message=message[:1000],
            at=utcnow(),
        )
        bundle.timeline.append(event)
        self._service._store.save(bundle)
        self._persist.append_timeline(event)

    def _note_progress(
        self, mission_id: str, world: InMemoryWorldModel, evidence_added: int
    ) -> None:
        rev = world.revision
        ev_count = len(world.get_recent_evidence(limit=1000)) + len(world.get_unmapped())
        prev = self._last_progress.get(mission_id)
        if prev is not None and prev[0] == rev and evidence_added == 0:
            self._stalls[mission_id] = self._stalls.get(mission_id, 0) + 1
        else:
            self._stalls[mission_id] = 0
        self._last_progress[mission_id] = (rev, ev_count)

    def _remember_trace(self, mission_id: str, trace: DecisionTrace) -> None:
        self._traces.setdefault(mission_id, []).append(trace)
        self._persist.save_trace(mission_id, trace.iteration, json.dumps(trace.compact()))

    def _persist_cycle(
        self,
        mission_id: str,
        world: InMemoryWorldModel,
        *,
        trace: DecisionTrace | None = None,
    ) -> None:
        del trace
        self._persist.persist_cycle(
            mission_id,
            world,
            self._failures.get(mission_id, 0),
            self._stalls.get(mission_id, 0),
        )

    def _report(
        self,
        mission: Mission,
        decision: Decision,
        *,
        paused: bool = False,
        completed: bool = False,
        stop_reason: str | None = None,
        selected_action_type: str | None = None,
        coverage_key: str | None = None,
        policy_verdict: str | None = None,
        execution_status: str | None = None,
        evidence_added: int = 0,
    ) -> CycleReport:
        world = self._worlds.get(mission.mission_id)
        revision = world.revision if world is not None else 0
        selected = selected_action_type
        if selected is None and decision.action is not None:
            selected = decision.action.action_type
        key = coverage_key
        if key is None and decision.action is not None:
            key = decision.action.coverage_key
        return CycleReport(
            mission_id=mission.mission_id,
            iteration=mission.iteration,
            decision=decision,
            world_revision=revision,
            evidence_added=evidence_added,
            paused=paused,
            completed=completed,
            stop_reason=stop_reason,
            selected_action_type=selected,
            coverage_key=key,
            policy_verdict=policy_verdict,
            execution_status=execution_status,
        )
