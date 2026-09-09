"""Typed view models for the operator console. No domain objects leak to the TUI."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MissionListItem:
    mission_id: str
    name: str
    status: str
    target: str
    mode: str
    iteration: int


@dataclass(frozen=True)
class ScopeReviewView:
    allowed_targets: tuple[str, ...]
    allowed_networks: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    allowed_protocols: tuple[str, ...]
    excluded_targets: tuple[str, ...]
    excluded_networks: tuple[str, ...]
    excluded_ports: tuple[int, ...]
    allow_subdomains: bool
    frozen: bool
    policy_profile: str


@dataclass(frozen=True)
class MissionStatusView:
    mission_id: str
    name: str
    intent: str
    status: str
    target: str
    target_kind: str
    mode: str
    provider: str
    iteration: int
    max_iterations: int
    elapsed_s: float
    max_runtime_s: int
    stop_reason: str | None
    policy_profile: str
    scope: ScopeReviewView


@dataclass(frozen=True)
class CurrentActionView:
    action_type: str | None
    target: str | None
    rationale: str
    score: str | None
    coverage_key: str | None
    policy_verdict: str | None
    execution_status: str | None
    last_result: str | None
    error_code: str | None = None
    attempt: str | None = None
    retryable: str | None = None
    family: str | None = None
    interface: str | None = None
    source: str | None = None
    route: str | None = None


@dataclass(frozen=True)
class WorldSummaryView:
    revision: int
    hosts: int
    open_ports: int
    services: int
    technologies: int
    urls: int
    endpoints: int
    findings: int
    hypotheses: int
    open_gaps: int
    closed_gaps: int
    host_lines: tuple[str, ...]
    port_lines: tuple[str, ...]
    service_lines: tuple[str, ...]
    tech_lines: tuple[str, ...]
    url_lines: tuple[str, ...]
    gap_lines: tuple[str, ...]
    claim_lines: tuple[str, ...]


@dataclass(frozen=True)
class FindingView:
    title: str
    kind: str
    severity: str
    status: str
    epistemic: str
    summary: str
    signal: str = ""
    confidence: str = ""
    priority: str = ""
    asset: str = ""
    observation_count: int = 1
    validation_state: str = ""


@dataclass(frozen=True)
class InvestigationView:
    title: str
    reason: str
    priority: str
    asset: str
    kind: str


@dataclass(frozen=True)
class HypothesisView:
    statement: str
    status: str
    confidence: float
    source: str
    rationale: str


@dataclass(frozen=True)
class EventView:
    at: str
    kind: str
    message: str


@dataclass(frozen=True)
class CycleView:
    iteration: int
    selected_action_type: str | None
    execution_status: str | None
    evidence_added: int
    world_revision: int
    completed: bool
    paused: bool
    stop_reason: str | None
    rationale: str


@dataclass(frozen=True)
class NetworkView:
    target: str
    route: str
    interface: str
    source: str
    reachability: str
    tunnel: str
    diagnostic: str
    platform: str
    available: bool
    interface_lines: tuple[str, ...] = ()
    route_lines: tuple[str, ...] = ()
    oos_note: str = ""
    identity: str = ""
    current_locator: str = ""
    previous_locator: str = ""
    digest: str = ""
    family: str = ""


@dataclass(frozen=True)
class AiStatusView:
    provider: str
    status: str
    reason: str
    calls: int
    budget: int
    model: str = ""


@dataclass(frozen=True)
class DashboardView:
    mission: MissionStatusView
    world: WorldSummaryView
    action: CurrentActionView
    findings: tuple[FindingView, ...]
    hypotheses: tuple[HypothesisView, ...]
    events: tuple[EventView, ...]
    investigations: tuple[InvestigationView, ...] = ()
    last_cycle: CycleView | None = None
    stub_mode: bool = True
    help_line: str = ""
    path_lines: tuple[str, ...] = ()
    network: NetworkView | None = None
    ai: AiStatusView | None = None


@dataclass(frozen=True)
class GraphView:
    revision: int
    digest: str
    node_count: int
    edge_count: int
    tree: str
    paths: tuple[str, ...] = ()
    conflict_count: int = 0


@dataclass(frozen=True)
class ProviderOption:
    name: str
    implemented: bool
    label: str


@dataclass
class CreateDraft:
    """Wizard scratch state. Never persisted until create_mission."""

    target: str = ""
    name: str = ""
    intent: str = ""
    mode: str = "ctf"
    provider: str = "none"
    authorized_by: str | None = None
    authorization_note: str | None = None
    extras: dict[str, str] = field(default_factory=dict)
