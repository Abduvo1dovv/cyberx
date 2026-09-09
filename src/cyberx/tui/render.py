"""Pure rendering. No IO, no services."""

from __future__ import annotations

from cyberx import __version__
from cyberx.app.views import (
    AiStatusView,
    DashboardView,
    FindingView,
    GraphView,
    HypothesisView,
    InvestigationView,
    MissionStatusView,
    NetworkView,
    ScopeReviewView,
    WorldSummaryView,
)
from cyberx.tui.keys import HELP_TEXT

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RED = "\033[31m"
DIM = "\033[2m"


def _c(color: bool, code: str, text: str) -> str:
    if not color:
        return text
    return f"{code}{text}{RESET}"


def _status_color(status: str) -> str:
    if status == "RUNNING":
        return GREEN
    if status in {"PAUSED", "CONFIRMED", "CREATED"}:
        return YELLOW
    if status in {"STOPPED", "FAILED"}:
        return RED
    return GREEN


def render_banner(color: bool = False) -> str:
    title = _c(color, BOLD, "CyberX") + f"  v{__version__}  operator console"
    sub = _c(color, DIM, "CTF edition  ·  recon/intelligence  ·  AI never executes")
    return f"{title}\n{sub}\n"


def render_scope(scope: ScopeReviewView, color: bool = False) -> str:
    ports = ",".join(str(p) for p in scope.allowed_ports) or "(all)"
    frozen = "yes (immutable)" if scope.frozen else "no"
    lines = [
        _c(color, BOLD, "Scope review"),
        f"  policy:        {scope.policy_profile} (recon-only)",
        f"  frozen:        {frozen}",
        f"  targets:       {', '.join(scope.allowed_targets) or '-'}",
        f"  networks:      {', '.join(scope.allowed_networks) or '-'}",
        f"  ports:         {ports}",
        f"  protocols:     {', '.join(scope.allowed_protocols)}",
        f"  excluded:      {', '.join(scope.excluded_targets) or '-'}",
        f"  excl networks: {', '.join(scope.excluded_networks) or '-'}",
        f"  subdomains:    {'yes' if scope.allow_subdomains else 'no'}",
    ]
    return "\n".join(lines)


def render_mission_header(mission: MissionStatusView, color: bool = False) -> str:
    status = _c(color, _status_color(mission.status), mission.status)
    elapsed = int(mission.elapsed_s)
    lines = [
        f"Mission  {mission.name}  [{mission.mission_id}]",
        f"Target   {mission.target}  ({mission.target_kind})",
        f"Mode     {mission.mode}   provider={mission.provider}   policy={mission.policy_profile}",
        (
            f"State    {status}   iteration {mission.iteration}/{mission.max_iterations}"
            f"   runtime {elapsed}s/{mission.max_runtime_s}s"
        ),
    ]
    if mission.stop_reason:
        lines.append(f"Stop     {mission.stop_reason}")
    return "\n".join(lines)


def _bar(closed: int, total: int, width: int = 20) -> str:
    if total <= 0:
        return "[" + "#" * width + "]"
    filled = int(width * closed / total)
    filled = min(width, max(0, filled))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _network_compact(view: NetworkView | None) -> list[str]:
    if view is None:
        return ["  (not observed)"]
    identity = view.identity or "-"
    current = view.current_locator or view.target or "-"
    previous = view.previous_locator or "-"
    return [
        f"  Identity: {identity}",
        f"  Current: {current}",
        f"  Previous: {previous}",
        f"  Status: {view.reachability}",
        f"  Interface: {view.interface or '-'}",
        f"  Source: {view.source or '-'}",
        f"  Route: {view.route or '-'}",
        f"  Tunnel: {view.tunnel}",
    ]


def _ai_compact(view: AiStatusView | None) -> list[str]:
    if view is None:
        return ["  AI: DISABLED", "  Reason: provider not configured"]
    name = view.provider.upper() if view.provider and view.provider != "none" else "DISABLED"
    if view.status != "AVAILABLE":
        return [
            f"  AI: {name}",
            f"  Status: {view.status}",
            f"  Reason: {view.reason or 'provider not configured'}",
        ]
    calls = f"  Calls: {view.calls} / {view.budget}"
    model = f"  Model: {view.model}" if view.model else ""
    rows = [f"  AI: {name}", f"  Status: {view.status}", calls]
    if model:
        rows.append(model)
    return rows


def render_dashboard(view: DashboardView, *, color: bool = False) -> str:
    m = view.mission
    w = view.world
    a = view.action
    total_gaps = w.open_gaps + w.closed_gaps
    bar = _bar(w.closed_gaps, total_gaps)
    action_type = a.action_type or "(none)"
    last = a.last_result or "-"
    failed = (a.execution_status or "").lower() in {
        "failed",
        "timeout",
        "unavailable",
        "denied",
        "rejected",
    }
    if failed:
        action_block = [
            f"  {action_type}",
            f"  {(a.execution_status or 'failed').upper()}",
            f"  reason: {a.error_code or '-'}",
            f"  attempt: {a.attempt or '-'}",
            f"  retryable: {a.retryable or '-'}",
            f"  target: {a.target or '-'}",
        ]
    else:
        action_block = [
            f"  type={action_type}  result={last}  verdict={a.policy_verdict or '-'}",
            f"  {a.rationale or '-'}",
        ]
    finding_rows = [f"  · [{item.epistemic}] {item.title}" for item in view.findings[:5]] or [
        "  (none)"
    ]
    inv_rows = [
        f"  {idx}. {item.title}  reason={item.reason}  priority={item.priority}"
        for idx, item in enumerate(view.investigations[:5], start=1)
    ] or ["  (none)"]
    path_rows = [f"  {idx}. {line}" for idx, line in enumerate(view.path_lines[:3], start=1)] or [
        "  (none)"
    ]
    hyp_rows = [
        f"  · HYPOTHESIS [{item.status}] {item.statement}" for item in view.hypotheses[:5]
    ] or ["  (none)"]
    event_rows = [f"  {e.at} [{e.kind}] {e.message}" for e in view.events[-8:]] or ["  (none)"]
    host_rows = [f"  · {row}" for row in w.host_lines[:4]] or ["  · (none)"]
    gap_rows = [f"  · {row}" for row in w.gap_lines[:4]] or ["  · (none open)"]
    lines = [
        render_mission_header(m, color),
        "",
        _c(color, BOLD, "Current action"),
        *action_block,
        "",
        _c(color, BOLD, "Known assets"),
        (
            f"  hosts={w.hosts}  open_ports={w.open_ports}  services={w.services}"
            f"  tech={w.technologies}  urls={w.urls}"
        ),
        *host_rows,
        "",
        _c(color, GREEN if color else "", "Findings (facts)"),
        *finding_rows,
        "",
        _c(color, CYAN if color else "", "Top investigations (recon only)"),
        *inv_rows,
        "",
        _c(color, CYAN if color else "", "Investigation paths"),
        *path_rows,
        "",
        _c(color, BOLD, "TARGET"),
        *_network_compact(view.network)[:4],
        "",
        _c(color, BOLD, "NETWORK"),
        *(_network_compact(view.network)[4:] if view.network is not None else ["  (not observed)"]),
        "",
        _c(color, BOLD, "AI"),
        *_ai_compact(view.ai),
        "",
        _c(color, YELLOW if color else "", "Hypotheses (NOT facts)"),
        *hyp_rows,
        "",
        _c(color, CYAN if color else "", "Knowledge gaps"),
        f"  {bar}  closed {w.closed_gaps}/{total_gaps}",
        *gap_rows,
        "",
        _c(color, DIM if color else "", "Recent events"),
        *event_rows,
        "",
        HELP_TEXT,
    ]
    if view.stub_mode:
        lines.insert(1, _c(color, DIM, "executor=stub  (no network recon)"))
    return "\n".join(lines) + "\n"


def render_findings(items: tuple[FindingView, ...], color: bool = False) -> str:
    header = _c(color, GREEN, "Findings — facts only, never hypotheses")
    if not items:
        return header + "\n  (none)\n"
    rows = [
        f"  [{item.epistemic}/{item.severity}] {item.title}\n"
        f"    {item.summary}"
        + (f"  signal={item.signal}  c={item.confidence}" if item.signal else "")
        + (f"  validation={item.validation_state}" if item.validation_state else "")
        for item in items
    ]
    return header + "\n" + "\n".join(rows) + "\n"


def render_investigations(items: tuple[InvestigationView, ...], color: bool = False) -> str:
    header = _c(color, CYAN, "Top investigations — reconnaissance priority, not an exploit queue")
    if not items:
        return header + "\n  (none)\n"
    rows = [
        f"  {idx}. {item.title}\n"
        f"     reason={item.reason}  priority={item.priority}  asset={item.asset or '-'}"
        for idx, item in enumerate(items, start=1)
    ]
    return header + "\n" + "\n".join(rows) + "\n"


def render_hypotheses(items: tuple[HypothesisView, ...], color: bool = False) -> str:
    header = _c(color, YELLOW, "Hypotheses — HYPOTHESIS / NOT CONFIRMED")
    if not items:
        return header + "\n  (none)\n"
    rows = [
        f"  HYPOTHESIS [{item.status}] c={item.confidence:.2f} ({item.source})\n"
        f"    {item.statement}"
        for item in items
    ]
    return header + "\n" + "\n".join(rows) + "\n"


def render_world(world: WorldSummaryView, color: bool = False) -> str:
    header = _c(color, BOLD, f"World Model  revision={world.revision}")
    sections = [
        header,
        "Hosts: " + ", ".join(world.host_lines) if world.host_lines else "Hosts: (none)",
        "Open ports: " + ", ".join(world.port_lines) if world.port_lines else "Open ports: (none)",
        "Services: " + ", ".join(world.service_lines)
        if world.service_lines
        else "Services: (none)",
        "Technologies: " + ", ".join(world.tech_lines)
        if world.tech_lines
        else "Technologies: (none)",
        "Web: " + ", ".join(world.url_lines) if world.url_lines else "Web: (none)",
        "Claims:",
        *("  · " + row for row in world.claim_lines or ("(none)",)),
        "Open gaps:",
        *("  · " + row for row in world.gap_lines or ("(none)",)),
    ]
    return "\n".join(sections) + "\n"


def render_graph(view: GraphView, color: bool = False) -> str:
    header = _c(
        color,
        BOLD,
        f"Attack surface graph  rev={view.revision}  "
        f"nodes={view.node_count}  edges={view.edge_count}",
    )
    tree = view.tree or "(empty graph)"
    paths = "\n".join(f"  {idx}. {line}" for idx, line in enumerate(view.paths[:8], start=1))
    if not paths:
        paths = "  (none)"
    return (
        header
        + "\n"
        + tree
        + "\n\n"
        + _c(color, CYAN, "Top investigation paths")
        + "\n"
        + paths
        + "\n"
    )


def render_network(view: NetworkView, color: bool = False) -> str:
    header = _c(color, BOLD, "TARGET")
    lines = [
        header,
        "--------------------------------",
        f"Identity: {view.identity or '-'}",
        f"Current: {view.current_locator or view.target or '-'}",
        f"Previous: {view.previous_locator or '-'}",
        f"Status: {view.reachability}",
        _c(color, BOLD, "NETWORK"),
        "--------------------------------",
        f"Interface: {view.interface or '-'}",
        f"Source: {view.source or '-'}",
        f"Route: {view.route or '-'}",
        f"Tunnel: {view.tunnel}",
        "--------------------------------",
    ]
    if view.diagnostic:
        lines.append(f"Diagnostic: {view.diagnostic}")
    if view.oos_note:
        lines.append(view.oos_note)
    if view.interface_lines:
        lines.append("Interfaces:")
        lines.extend(f"  · {row}" for row in view.interface_lines)
    if view.route_lines:
        lines.append("Routes:")
        lines.extend(f"  · {row}" for row in view.route_lines)
    lines.append("Tunnel labels are heuristic and unverified. No VPN provider is assumed.")
    return "\n".join(lines) + "\n"


def render_logs(events: tuple, color: bool = False) -> str:
    header = _c(color, BOLD, "Timeline")
    if not events:
        return header + "\n  (none)\n"
    rows = [f"  {e.at} [{e.kind}] {e.message}" for e in events]
    return header + "\n" + "\n".join(rows) + "\n"
