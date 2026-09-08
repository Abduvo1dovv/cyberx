"""MissionEngine adaptive loop. The only sequencer. Brain never executes."""

from __future__ import annotations

import json
from typing import Any

from cyberx.brain.context import BrainContextBuilder, context_hash
from cyberx.brain.facade import Brain
from cyberx.brain.types import CycleReport, Decision, DecisionTrace, HypothesisDelta
from cyberx.domain.enums import (
    ActionResultStatus,
    ActionStatus,
    HypothesisSource,
    HypothesisStatus,
    MissionStatus,
    ReachabilityStatus,
    StopReason,
    TimelineKind,
)
from cyberx.domain.errors import (
    ActionRejected,
    AdapterUnavailable,
    ParseError,
    PolicyDeniedError,
)
from cyberx.domain.ids import (
    PREFIX_HYPOTHESIS,
    PREFIX_TIMELINE,
    new_id,
)
from cyberx.domain.models.actions import ActionRequest
from cyberx.domain.models.findings import Hypothesis, TimelineEvent
from cyberx.domain.models.mission import Mission
from cyberx.domain.models.network import NetworkContext
from cyberx.domain.time import utcnow
from cyberx.engine.boundary import ExecutionBoundary
from cyberx.evidence.pipeline import EvidencePipeline
from cyberx.mission.service import MissionService
from cyberx.network.resolver import NetworkResolver
from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe
from cyberx.ports.execution import ExecutionContext
from cyberx.scope.gate import MissionScopeGate
from cyberx.validation.engine import ValidationEngine
from cyberx.world.correlation import ScopeGate
from cyberx.world.model import InMemoryWorldModel

TERMINAL = frozenset({MissionStatus.COMPLETED, MissionStatus.STOPPED, MissionStatus.FAILED})
RETRYABLE = frozenset({"timeout", "adapter_crash", "empty_output"})
MAX_CONSECUTIVE_FAILURES = 5
PROGRESS_STALL_CYCLES = 3


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
        store: Any | None = None,
        builder: BrainContextBuilder | None = None,
        events: EventSink | None = None,
        network: NetworkResolver | None = None,
    ) -> None:
        self._service = service
        self._brain = brain or Brain()
        self._boundary = boundary or ExecutionBoundary()
        self._pipeline = pipeline or EvidencePipeline()
        self._store = store
        self._builder = builder or BrainContextBuilder()
        self._events = events or NullEventSink()
        self._network = network or NetworkResolver()
        self._worlds: dict[str, InMemoryWorldModel] = {}
        self._failures: dict[str, int] = {}
        self._stalls: dict[str, int] = {}
        self._last_progress: dict[str, tuple[int, int]] = {}
        self._results: dict[str, list] = {}
        self._traces: dict[str, list[DecisionTrace]] = {}
        self._last_network: dict[str, NetworkContext] = {}
        self._ai_event_cursor = 0

    def world(self, mission_id: str) -> InMemoryWorldModel:
        if mission_id not in self._worlds:
            self._worlds[mission_id] = self._load_world(mission_id)
        return self._worlds[mission_id]

    def _load_world(self, mission_id: str) -> InMemoryWorldModel:
        bundle = self._service.get_bundle(mission_id)
        gate: ScopeGate = MissionScopeGate(bundle.scope)
        store = self._store
        if store is not None and hasattr(store, "resume_world"):
            try:
                world = store.resume_world(mission_id)
                fails, stalls, last_rev, last_ev = (0, 0, 0, 0)
                if hasattr(store, "get_runtime"):
                    fails, stalls, last_rev, last_ev = store.get_runtime(mission_id)
                self._failures[mission_id] = fails
                self._stalls[mission_id] = stalls
                self._last_progress[mission_id] = (last_rev, last_ev)
                if hasattr(world, "_scope_gate"):
                    world._scope_gate = gate
                return world
            except Exception:
                pass
        world = InMemoryWorldModel(mission_id, scope_gate=gate)
        if bundle.seed_assets:
            world.seed_assets(bundle.seed_assets)
        return world

    def run_one_cycle(self, mission_id: str) -> CycleReport:
        bundle = self._service.get_bundle(mission_id)
        mission = bundle.mission
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

        world = self.world(mission_id)
        if world.revision == 0 and bundle.seed_assets:
            world.seed_assets(bundle.seed_assets)

        snapshot = world.snapshot()
        prev_net = self._last_network.get(mission_id)
        prev_digest = prev_net.digest() if prev_net is not None else None
        net = self._observe_network(mission_id, bundle.target, bundle.scope)
        validation = ValidationEngine()
        candidates = validation.evaluate(world)
        validation.sync_findings(world, candidates)
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
        hyp_deltas = self._brain.revise_hypotheses(ctx)
        self._apply_hypotheses(world, mission_id, hyp_deltas)
        self._flush_ai_timeline(mission_id)
        candidates = validation.evaluate(world)
        validation.sync_findings(world, candidates)
        ctx = self._builder.build(
            world.snapshot(),
            mission,
            scope=bundle.scope,
            recent_results=self._results.get(mission_id, [])[-5:],
            recent_events=bundle.timeline[-10:],
            validation_candidates=candidates,
            network_context=net,
            target=bundle.target,
            previous_network_digest=prev_digest,
        )
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
            reason = StopReason(decision.stop_reason or "no_actions")
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

        candidate = decision.action
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
        exec_ctx = self._execution_context(candidate, net)
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
            exec_status = "unavailable"
            self._failures[mission_id] = self._failures.get(mission_id, 0) + 1
            world.record_coverage(candidate.coverage_key, "unavailable")
            self._append_event(
                mission_id,
                TimelineKind.ERROR,
                _unavailable_event(exc.adapter_name),
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

        policy_verdict = "allow"
        exec_status = outcome.result.status.value
        self._results.setdefault(mission_id, []).append(outcome.result)
        if store_has(self._store, "save_action"):
            self._store.save_action(outcome.action)
            self._store.save_tool_run(outcome.tool_run)
            self._store.save_result(outcome.result)

        if outcome.result.status is ActionResultStatus.COMPLETED:
            self._failures[mission_id] = 0
            parsed_ok = True
            obs: list = []
            evidence: list = []
            try:
                obs, evidence = self._pipeline.normalize(outcome.artifact)
            except ParseError as exc:
                parsed_ok = False
                emit_safe(
                    self._events,
                    DomainEvent(
                        event_type=EventType.PARSE_FAILED,
                        mission_id=mission_id,
                        payload={
                            "action_type": candidate.action_type,
                            "code": exc.code,
                        },
                    ),
                )
                self._append_event(mission_id, TimelineKind.ERROR, f"parse failed: {exc.code}")
                exec_status = "failed"
                world.record_coverage(candidate.coverage_key, "failed")
                self._failures[mission_id] = self._failures.get(mission_id, 0) + 1
            if parsed_ok:
                emit_safe(
                    self._events,
                    DomainEvent(
                        event_type=EventType.PARSE_COMPLETED,
                        mission_id=mission_id,
                        payload={
                            "action_type": candidate.action_type,
                            "observation_count": len(obs),
                            "evidence_count": len(evidence),
                        },
                    ),
                )
                if store_has(self._store, "put"):
                    self._store.put(outcome.artifact)
                for item in obs:
                    if store_has(self._store, "insert_observation"):
                        self._store.insert_observation(item)
                for item in evidence:
                    if store_has(self._store, "insert_evidence"):
                        self._store.insert_evidence(item)
                    world.apply_evidence(item)
                    evidence_added += 1
                self._ingest_locator_evidence(mission_id, evidence)
                world.record_coverage(candidate.coverage_key, "completed")
        else:
            self._failures[mission_id] = self._failures.get(mission_id, 0) + 1
            retryable = (outcome.result.error_code or "") in RETRYABLE
            if retryable and outcome.action.attempt < 2:
                # one immediate retry of the same authorized path is engine-owned
                try:
                    retry = self._boundary.run(request, mission, bundle.scope, ctx=exec_ctx)
                    if retry.result.status is ActionResultStatus.COMPLETED:
                        self._failures[mission_id] = 0
                        _obs, evidence = self._pipeline.normalize(retry.artifact)
                        for item in evidence:
                            world.apply_evidence(item)
                            evidence_added += 1
                        self._ingest_locator_evidence(mission_id, evidence)
                        world.record_coverage(candidate.coverage_key, "completed")
                        exec_status = "completed"
                    else:
                        world.record_coverage(candidate.coverage_key, "failed")
                except Exception:
                    world.record_coverage(candidate.coverage_key, "failed")
            else:
                world.record_coverage(candidate.coverage_key, "failed")
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
            f"{candidate.action_type} {exec_status}",
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

    def network_context(self, mission_id: str) -> NetworkContext | None:
        bundle = self._service.get_bundle(mission_id)
        return self._observe_network(mission_id, bundle.target, bundle.scope)

    def _observe_network(
        self, mission_id: str, target: Any, scope: Any, *, emit: bool = True
    ) -> NetworkContext:
        token = _target_token(target)
        resolved = list(getattr(target, "resolved_ipv4", None) or [])
        resolved.extend(getattr(target, "resolved_ipv6", None) or [])
        try:
            net = self._network.resolve(token, scope=scope, resolved_ips=resolved)
        except Exception:
            net = NetworkContext.unavailable(token, diagnostic="network observe failed")
        prev = self._last_network.get(mission_id)
        self._last_network[mission_id] = net
        changed = prev is None or prev.digest() != net.digest()
        blocking = net.reachability.value in {"ROUTE_MISSING", "UNREACHABLE", "BLOCKED"}
        if emit and net.reachability is ReachabilityStatus.UNREACHABLE and (net.target_ip or token):
            try:
                self._service.mark_locator_unreachable(mission_id, net.target_ip or token)
            except Exception:
                pass
        if emit and changed:
            msg = (
                f"network {net.reachability.value}"
                + (f" via {net.selected_interface}" if net.selected_interface else "")
                + (f" src={net.source_address}" if net.source_address else "")
                + (f" route={net.selected_route}" if net.selected_route else "")
                + f" digest={net.digest()}"
            )
            if blocking and net.diagnostic:
                msg = f"{msg}; {net.diagnostic}"
            self._append_event(mission_id, TimelineKind.NETWORK, msg[:1000])
            emit_safe(
                self._events,
                DomainEvent(
                    event_type=EventType.NETWORK_OBSERVED,
                    mission_id=mission_id,
                    payload={
                        "reachability": net.reachability.value,
                        "interface": net.selected_interface or "",
                        "route": net.selected_route or "",
                        "source": net.source_address or "",
                        "digest": net.digest(),
                    },
                ),
            )
        return net

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

    def _ingest_locator_evidence(self, mission_id: str, evidence: list) -> None:
        for item in evidence:
            preview = getattr(item, "claim_preview", None) or {}
            pred = str(preview.get("predicate") or "")
            obj = preview.get("object")
            locators: list[str] = []
            if pred == "dns.record" and isinstance(obj, dict):
                rtype = str(obj.get("type") or "").upper()
                if rtype in {"A", "AAAA"}:
                    value = str(obj.get("value") or "")
                    if value:
                        locators.append(value)
            elif pred == "host.address":
                if isinstance(obj, str):
                    locators.append(obj)
                elif isinstance(obj, dict):
                    value = str(obj.get("value") or obj.get("ip") or "")
                    if value:
                        locators.append(value)
            for locator in locators:
                try:
                    self._service.observe_locator(
                        mission_id,
                        locator,
                        source="dns" if pred == "dns.record" else "recon",
                        evidence_ids=[item.evidence_id],
                    )
                except Exception:
                    continue

    def _execution_context(self, candidate: Any, net: NetworkContext) -> ExecutionContext:
        return ExecutionContext(
            mission_id=candidate.target.asset_id or "pending",
            action_id="pending",
            timeout_s=int(getattr(candidate, "timeout_s", 30) or 30),
            stub=False,
            source_interface=net.selected_interface,
            source_address=net.source_address,
            route_cidr=net.selected_route,
            reachability=net.reachability.value,
            likely_tunnel=net.likely_tunnel,
            network_diagnostic=net.diagnostic[:200],
        )

    def _apply_hypotheses(
        self, world: InMemoryWorldModel, mission_id: str, deltas: list[HypothesisDelta]
    ) -> None:
        existing = {h.statement: h for h in world.get_hypotheses()}
        for delta in deltas:
            if delta.op == "create" and delta.statement not in existing:
                source = HypothesisSource.AI if delta.source == "ai" else HypothesisSource.HEURISTIC
                confidence = delta.confidence
                if source is HypothesisSource.AI:
                    confidence = min(0.4, confidence)
                try:
                    hyp = Hypothesis(
                        hypothesis_id=new_id(PREFIX_HYPOTHESIS),
                        mission_id=mission_id,
                        statement=delta.statement,
                        status=HypothesisStatus.OPEN,
                        confidence=confidence,
                        created_at=utcnow(),
                        rationale=delta.rationale,
                        related_asset_ids=[delta.subject_id] if delta.subject_id else [],
                        related_gap_ids=[delta.gap_id] if delta.gap_id else [],
                        source=source,
                    )
                except Exception:
                    continue
                world.record_hypothesis(hyp)
            elif delta.op == "support":
                for hyp in world.get_hypotheses():
                    if hyp.statement == delta.statement or (
                        delta.hypothesis_id and hyp.hypothesis_id == delta.hypothesis_id
                    ):
                        world.record_hypothesis(
                            hyp.model_copy(
                                update={
                                    "status": HypothesisStatus.SUPPORTED,
                                    "confidence": min(1.0, hyp.confidence + 0.15),
                                    "rationale": delta.rationale or hyp.rationale,
                                }
                            )
                        )
            elif delta.op == "retire":
                for hyp in world.get_hypotheses():
                    if hyp.statement == delta.statement or (
                        delta.hypothesis_id and hyp.hypothesis_id == delta.hypothesis_id
                    ):
                        world.record_hypothesis(
                            hyp.model_copy(update={"status": HypothesisStatus.RETIRED})
                        )

    def _flush_ai_timeline(self, mission_id: str) -> None:
        events = getattr(self._events, "events", None)
        if not isinstance(events, list):
            return
        unseen = events[self._ai_event_cursor :]
        self._ai_event_cursor = len(events)
        for event in unseen:
            et = getattr(event, "event_type", None)
            value = et.value if et is not None else ""
            if not str(value).startswith("ai."):
                continue
            if getattr(event, "mission_id", None) not in {None, mission_id}:
                continue
            payload = getattr(event, "payload", None) or {}
            bits = [
                str(value),
                str(payload.get("provider") or ""),
                str(payload.get("task_type") or ""),
                str(payload.get("reason") or ""),
            ]
            self._append_event(mission_id, TimelineKind.AI, " ".join(b for b in bits if b)[:200])

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
        if store_has(self._store, "append_timeline"):
            self._store.append_timeline(event)

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
        if store_has(self._store, "save_decision_trace"):
            self._store.save_decision_trace(
                mission_id, trace.iteration, json.dumps(trace.compact())
            )

    def _persist_cycle(
        self,
        mission_id: str,
        world: InMemoryWorldModel,
        *,
        trace: DecisionTrace | None = None,
    ) -> None:
        del trace
        store = self._store
        if store is None:
            return
        if store_has(store, "transaction"):
            with store.transaction():
                if store_has(store, "persist_world"):
                    store.persist_world(world)
                if store_has(store, "save_runtime"):
                    store.save_runtime(
                        mission_id,
                        self._failures.get(mission_id, 0),
                        self._stalls.get(mission_id, 0),
                        world.revision,
                        len(list(world.get_recent_evidence(limit=10000))),
                    )
        elif store_has(store, "persist_world"):
            store.persist_world(world)

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


def store_has(store: Any, name: str) -> bool:
    return store is not None and hasattr(store, name)


def _unavailable_event(adapter_name: str) -> str:
    token = (adapter_name or "").lower()
    if "nmap" in token:
        return "nmap unavailable"
    if "directory" in token:
        return "directory enumeration transport unavailable"
    if "http" in token or "tech" in token or "endpoint" in token:
        return "HTTP transport unavailable"
    if "dns" in token or "subdomain" in token:
        return "DNS resolver unavailable"
    return f"adapter unavailable: {adapter_name}"


def _target_token(target: Any) -> str:
    current = getattr(target, "current_locator", None)
    if current:
        return str(current)
    kind = getattr(getattr(target, "kind", None), "value", "")
    if kind == "url":
        host = getattr(target, "normalized", "") or ""
        if "://" in host:
            from urllib.parse import urlsplit

            return urlsplit(host).hostname or host
        return host
    return str(getattr(target, "normalized", "") or getattr(target, "raw_input", "") or "")
