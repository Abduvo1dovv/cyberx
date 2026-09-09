"""Thin operator facade. Orchestrates existing services; holds no business rules."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from cyberx.app.views import (
    AiStatusView,
    CurrentActionView,
    CycleView,
    DashboardView,
    EventView,
    FindingView,
    GraphView,
    HypothesisView,
    InvestigationView,
    MissionListItem,
    MissionStatusView,
    NetworkView,
    ProviderOption,
    ScopeReviewView,
    WorldSummaryView,
)
from cyberx.brain.types import CycleReport
from cyberx.config import AppConfig
from cyberx.domain.enums import (
    REGISTERED_AI_PROVIDERS,
    FindingStatus,
    MissionMode,
    MissionStatus,
    StopReason,
)
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.models.mission import Mission, Scope, Target
from cyberx.domain.time import utcnow
from cyberx.engine.loop import MissionEngine
from cyberx.mission.commands import ConfirmLocatorCmd, CreateMissionCmd
from cyberx.mission.service import MissionService
from cyberx.observability.sink import InMemoryEventSink
from cyberx.ports.events import EventSink
from cyberx.world.priority import rank_investigations

_RESUMABLE = {
    MissionStatus.CREATED,
    MissionStatus.CONFIRMED,
    MissionStatus.RUNNING,
    MissionStatus.PAUSED,
}

_MODE_ALIASES = {
    "1": MissionMode.CTF,
    "ctf": MissionMode.CTF,
    "2": MissionMode.LAB,
    "lab": MissionMode.LAB,
    "3": MissionMode.AUTHORIZED_ASSESSMENT,
    "authorized_assessment": MissionMode.AUTHORIZED_ASSESSMENT,
    "professional": MissionMode.AUTHORIZED_ASSESSMENT,
    "recon_only": MissionMode.CTF,
}

HELP_LINE = (
    "[s]tart [p]ause [r]esume [x]top [c]ycle  "
    "[f]indings [i]nvestigate [g]raph [n]etwork [t]arget  "
    "[w]orld [h]ypotheses [l]ogs [o]report [q]uit"
)


def parse_mode(raw: str) -> MissionMode:
    key = raw.strip().lower().replace(" ", "_")
    if key not in _MODE_ALIASES:
        raise DomainValidationError(
            "mode must be ctf, lab, or authorized_assessment (professional)"
        )
    return _MODE_ALIASES[key]


_PROVIDER_ORDER = (
    "none",
    "grok",
    "gemini",
    "claude",
    "openai",
    "deepseek",
    "local",
    "custom",
)


def parse_provider(raw: str, registered: Sequence[str] | None = None) -> str:
    name = raw.strip().lower()
    allowed = (
        tuple(registered)
        if registered
        else tuple(item for item in _PROVIDER_ORDER if item in REGISTERED_AI_PROVIDERS)
    )
    numbered = {str(i + 1): item for i, item in enumerate(allowed)}
    if name in numbered:
        name = numbered[name]
    if name not in REGISTERED_AI_PROVIDERS:
        raise DomainValidationError(f"unknown ai_provider: {raw}")
    return name


class OperatorFacade:
    def __init__(
        self,
        config: AppConfig,
        service: MissionService,
        engine: MissionEngine,
        events: EventSink | None = None,
        *,
        stub_mode: bool = True,
    ) -> None:
        self._config = config
        self._service = service
        self._engine = engine
        self._events = events or InMemoryEventSink()
        self._stub_mode = stub_mode
        self._last_cycle: dict[str, CycleView] = {}

    @property
    def config(self) -> AppConfig:
        return self._config

    @property
    def stub_mode(self) -> bool:
        return self._stub_mode

    def provider_options(self) -> tuple[ProviderOption, ...]:
        names = [n for n in _PROVIDER_ORDER if n in REGISTERED_AI_PROVIDERS]
        return tuple(
            ProviderOption(
                name=name,
                implemented=name in {"none", "grok"},
                label="implemented" if name in {"none", "grok"} else "reserved",
            )
            for name in names
        )

    def create_mission(
        self,
        *,
        target: str,
        name: str,
        intent: str,
        mode: str,
        ai_provider: str = "none",
        authorized_by: str | None = None,
        authorization_note: str | None = None,
    ) -> Mission:
        defaults = self._config.mission
        provider = parse_provider(ai_provider)
        cmd = CreateMissionCmd(
            name=name.strip(),
            intent=intent.strip(),
            raw_target=target.strip(),
            mode=parse_mode(mode),
            ai_provider=provider,
            authorized_by=authorized_by,
            authorization_note=authorization_note,
            max_iterations=defaults.max_iterations,
            max_runtime_s=defaults.max_runtime_s,
            min_action_score=defaults.min_action_score,
            policy_profile=defaults.policy_profile,
        )
        return self._service.create(cmd)

    def confirm_mission(self, mission_id: str) -> Mission:
        return self._service.confirm(mission_id)

    def start_mission(self, mission_id: str) -> Mission:
        return self._service.start(mission_id)

    def pause_mission(self, mission_id: str) -> Mission:
        return self._service.pause(mission_id)

    def resume_mission(self, mission_id: str) -> Mission:
        return self._service.resume(mission_id)

    def stop_mission(self, mission_id: str, reason: StopReason = StopReason.OPERATOR) -> Mission:
        return self._service.stop(mission_id, reason)

    def confirm_locator(self, mission_id: str, locator: str, *, actor: str = "operator") -> Target:
        target = self._service.confirm_locator(
            mission_id, ConfirmLocatorCmd(locator=locator, actor=actor)
        )
        try:
            self._engine.sync_locator_hosts(mission_id)
        except Exception:
            pass
        return target

    def update_scope(self, mission_id: str, **changes: object) -> ScopeReviewView:
        scope = self._service.update_scope(mission_id, **changes)
        mission = self._service.get(mission_id)
        return self._scope_view(scope, mission.policy_profile)

    def list_resumable(self) -> tuple[MissionListItem, ...]:
        items: list[MissionListItem] = []
        for bundle in self._service.list_missions():
            if bundle.mission.status in _RESUMABLE:
                items.append(self._list_item(bundle.mission, bundle.target.raw_input))
        return tuple(items)

    def get_mission_status(self, mission_id: str) -> MissionStatusView:
        bundle = self._service.get_bundle(mission_id)
        mission = bundle.mission
        elapsed = 0.0
        if mission.started_at is not None:
            end = mission.ended_at or utcnow()
            elapsed = max(0.0, (end - mission.started_at).total_seconds())
        return MissionStatusView(
            mission_id=mission.mission_id,
            name=mission.name,
            intent=mission.intent,
            status=mission.status.value,
            target=bundle.target.current_locator or bundle.target.raw_input,
            target_kind=bundle.target.kind.value,
            mode=mission.mode.value,
            provider=mission.ai_provider,
            iteration=mission.iteration,
            max_iterations=mission.max_iterations,
            elapsed_s=elapsed,
            max_runtime_s=mission.max_runtime_s,
            stop_reason=mission.stop_reason.value if mission.stop_reason else None,
            policy_profile=mission.policy_profile,
            scope=self._scope_view(bundle.scope, mission.policy_profile),
        )

    def get_world_summary(self, mission_id: str) -> WorldSummaryView:
        world = self._engine.world(mission_id)
        snap = world.snapshot()
        hosts = snap.get_hosts()
        ports = snap.get_open_ports()
        services = snap.get_services()
        techs = snap.get_technologies()
        urls = snap.get_web_surfaces()
        gaps = [g for g in snap.get_gaps() if not g.closed]
        closed = [g for g in snap.get_gaps() if g.closed]
        live_claims = [c for c in snap.claims if c.epistemic_status.value != "INVALIDATED"]
        return WorldSummaryView(
            revision=snap.revision,
            hosts=len(hosts),
            open_ports=len(ports),
            services=len(services),
            technologies=len(techs),
            urls=len(urls),
            endpoints=len(snap.endpoints),
            findings=len([f for f in snap.findings if f.status is FindingStatus.OPEN]),
            hypotheses=len(snap.hypotheses),
            open_gaps=len(gaps),
            closed_gaps=len(closed),
            host_lines=tuple(h.display_name for h in hosts[:8]),
            port_lines=tuple(f"{p.number}/{p.protocol.value} {p.state.value}" for p in ports[:8]),
            service_lines=tuple(s.display_name or s.name for s in services[:8]),
            tech_lines=tuple(t.display_name or t.product for t in techs[:8]),
            url_lines=tuple(u.display_name for u in urls[:8]),
            gap_lines=tuple(f"{g.kind} {g.detail}".strip() for g in gaps[:8]),
            claim_lines=tuple(
                f"{c.predicate}={c.object!s} [{c.epistemic_status.value}]" for c in live_claims[:8]
            ),
        )

    def get_findings(self, mission_id: str) -> tuple[FindingView, ...]:
        world = self._engine.world(mission_id)
        ranked = {item.finding_id: item for item in self._investigations(mission_id)}
        out: list[FindingView] = []
        for item in world.get_findings():
            rank = ranked.get(item.finding_id)
            out.append(
                FindingView(
                    title=item.title,
                    kind=item.kind.value,
                    severity=item.severity.value,
                    status=item.status.value,
                    epistemic=item.epistemic_status.value,
                    summary=item.summary,
                    signal=item.signal or item.kind.value,
                    confidence=f"{item.confidence:.2f}",
                    priority=f"{rank.priority:.2f}" if rank else "",
                    asset=rank.asset if rank else "",
                    observation_count=item.observation_count,
                    validation_state=item.validation_state,
                )
            )
        return tuple(out)

    def get_investigations(self, mission_id: str) -> tuple[InvestigationView, ...]:
        return tuple(
            InvestigationView(
                title=item.title,
                reason=item.reason,
                priority=f"{item.priority:.2f}",
                asset=item.asset,
                kind=item.kind,
            )
            for item in self._investigations(mission_id)
        )

    def get_graph(self, mission_id: str) -> GraphView:
        from cyberx.graph.paths import PathPlanner
        from cyberx.graph.projector import GraphProjector
        from cyberx.graph.tree import render_attack_tree, render_path_line
        from cyberx.validation.engine import ValidationEngine

        world = self._engine.world(mission_id)
        snap = world.snapshot()
        candidates = ValidationEngine().evaluate(world)
        graph = GraphProjector().project(snap, validation_candidates=candidates)
        paths = PathPlanner().plan(graph, snap, validation_candidates=candidates)
        return GraphView(
            revision=graph.revision,
            digest=graph.digest[:16],
            node_count=len(graph.nodes),
            edge_count=len(graph.edges),
            tree=render_attack_tree(graph),
            paths=tuple(render_path_line(item) for item in paths[:8]),
            conflict_count=graph.conflict_count,
        )

    def get_network(self, mission_id: str) -> NetworkView:
        net = self._engine.network_context(mission_id)
        if net is None:
            return NetworkView(
                target="",
                route="",
                interface="",
                source="",
                reachability="UNKNOWN",
                tunnel="none",
                diagnostic="network not observed",
                platform="unknown",
                available=False,
            )
        compact = net.compact()
        tunnel = compact.get("tunnel") or "none"
        if tunnel == "detected_unverified":
            label = "DETECTED (unverified)"
        elif tunnel == "present_unused":
            label = "PRESENT (unused, unverified)"
        else:
            label = "none"
        iface_lines = tuple(
            f"{item.name} {' '.join(a.ip for a in item.addresses) or '-'} "
            f"{item.operstate}" + (" tunnel" if item.likely_tunnel else "")
            for item in net.interfaces[:12]
        )
        route_lines = tuple(
            f"{item.destination} dev {item.interface} metric {item.metric}"
            for item in net.routes[:12]
        )
        oos = ""
        if net.oos_routes:
            oos = "out-of-scope routes (diagnostic only): " + ", ".join(net.oos_routes[:4])
        bundle = self._service.get_bundle(mission_id)
        target = bundle.target
        return NetworkView(
            target=net.target,
            route=net.selected_route or "-",
            interface=net.selected_interface or "-",
            source=net.source_address or "-",
            reachability=net.reachability.value,
            tunnel=label,
            diagnostic=net.diagnostic,
            platform=net.platform,
            available=net.available,
            interface_lines=iface_lines,
            route_lines=route_lines,
            oos_note=oos,
            identity=target.identity_key(),
            current_locator=target.current_locator or target.normalized,
            previous_locator=target.previous_locator() or "",
            digest=net.digest(),
        )

    def get_ai_status(self) -> AiStatusView:
        raw = self._engine._brain.ai_status()
        return AiStatusView(
            provider=str(raw.get("provider") or "none"),
            status=str(raw.get("status") or "DISABLED"),
            reason=str(raw.get("reason") or ""),
            calls=int(raw.get("calls") or 0),
            budget=int(raw.get("budget") or 0),
            model=str(raw.get("model") or ""),
        )

    def _investigations(self, mission_id: str):
        return rank_investigations(self._engine.world(mission_id), limit=12)

    def get_hypotheses(self, mission_id: str) -> tuple[HypothesisView, ...]:
        world = self._engine.world(mission_id)
        return tuple(
            HypothesisView(
                statement=item.statement,
                status=item.status.value,
                confidence=item.confidence,
                source=item.source.value,
                rationale=item.rationale or "",
            )
            for item in world.get_hypotheses()
        )

    def get_recent_events(self, mission_id: str, limit: int = 8) -> tuple[EventView, ...]:
        bundle = self._service.get_bundle(mission_id)
        events = bundle.timeline[-limit:]
        return tuple(
            EventView(
                at=item.at.strftime("%H:%M:%S"),
                kind=item.kind.value,
                message=item.message,
            )
            for item in events
        )

    def get_current_action(self, mission_id: str) -> CurrentActionView:
        traces = self._engine.traces(mission_id)
        last = self._last_cycle.get(mission_id)
        diag = self._engine.action_diagnostic(mission_id)
        if not traces:
            return CurrentActionView(
                action_type=last.selected_action_type if last else None,
                target=diag.get("target") or None,
                rationale=last.rationale if last else "",
                score=None,
                coverage_key=None,
                policy_verdict=last.execution_status if last else None,
                execution_status=last.execution_status if last else None,
                last_result=last.execution_status if last else None,
                error_code=diag.get("reason") or None,
                attempt=diag.get("attempt") or None,
                retryable=diag.get("retryable") or None,
            )
        trace = traces[-1]
        score = None
        if trace.candidates:
            score = trace.candidates[0].get("score")
        decision = last
        status = decision.execution_status if decision is not None else trace.execution_status
        return CurrentActionView(
            action_type=trace.selected_type or diag.get("action_type") or None,
            target=diag.get("target") or None,
            rationale=trace.rationale,
            score=score,
            coverage_key=trace.selected_coverage_key,
            policy_verdict=trace.policy_verdict,
            execution_status=status,
            last_result=status,
            error_code=diag.get("reason") or None,
            attempt=diag.get("attempt") or None,
            retryable=diag.get("retryable") or None,
        )

    def get_dashboard(self, mission_id: str) -> DashboardView:
        mission = self.get_mission_status(mission_id)
        graph = self.get_graph(mission_id)
        return DashboardView(
            mission=mission,
            world=self.get_world_summary(mission_id),
            action=self.get_current_action(mission_id),
            findings=self.get_findings(mission_id)[:5],
            hypotheses=self.get_hypotheses(mission_id)[:8],
            events=self.get_recent_events(mission_id, limit=8),
            investigations=self.get_investigations(mission_id)[:5],
            last_cycle=self._last_cycle.get(mission_id),
            stub_mode=self._stub_mode,
            help_line=HELP_LINE,
            path_lines=graph.paths[:3],
            network=self.get_network(mission_id),
            ai=self.get_ai_status(),
        )

    def run_one_cycle(self, mission_id: str) -> CycleView:
        report = self._engine.run_one_cycle(mission_id)
        view = self._cycle_view(report)
        self._last_cycle[mission_id] = view
        return view

    def run_mission(self, mission_id: str) -> tuple[CycleView, ...]:
        status = self._service.get(mission_id).status
        if status is MissionStatus.CONFIRMED:
            self._service.start(mission_id)
        elif status is MissionStatus.PAUSED:
            self._service.resume(mission_id)
        reports = self._engine.run_forever(mission_id)
        views = tuple(self._cycle_view(item) for item in reports)
        if views:
            self._last_cycle[mission_id] = views[-1]
        return views

    def export_report(self, mission_id: str) -> tuple[str, str]:
        from cyberx.app.report import build_report, write_report

        bundle = self._service.get_bundle(mission_id)
        world = self._engine.world(mission_id)
        network = self._engine.network_context(mission_id)
        payload = build_report(
            bundle=bundle,
            world=world,
            traces=self._engine.traces(mission_id),
            network=network,
        )
        folder = Path(self._config.runtime.data_dir) / "missions" / mission_id
        json_path, md_path = write_report(payload, folder)
        return str(json_path), str(md_path)

    def _cycle_view(self, report: CycleReport) -> CycleView:
        return CycleView(
            iteration=report.iteration,
            selected_action_type=report.selected_action_type,
            execution_status=report.execution_status,
            evidence_added=report.evidence_added,
            world_revision=report.world_revision,
            completed=report.completed,
            paused=report.paused,
            stop_reason=report.stop_reason,
            rationale=report.decision.rationale,
        )

    def _scope_view(self, scope: Scope, policy_profile: str) -> ScopeReviewView:
        return ScopeReviewView(
            allowed_targets=tuple(scope.allowed_targets),
            allowed_networks=tuple(scope.allowed_networks),
            allowed_ports=tuple(scope.allowed_ports),
            allowed_protocols=tuple(scope.allowed_protocols),
            excluded_targets=tuple(scope.excluded_targets),
            excluded_networks=tuple(scope.excluded_networks),
            excluded_ports=tuple(scope.excluded_ports),
            allow_subdomains=scope.allow_subdomains,
            frozen=scope.frozen,
            policy_profile=policy_profile,
        )

    def _list_item(self, mission: Mission, target: str) -> MissionListItem:
        return MissionListItem(
            mission_id=mission.mission_id,
            name=mission.name,
            status=mission.status.value,
            target=target,
            mode=mission.mode.value,
            iteration=mission.iteration,
        )
