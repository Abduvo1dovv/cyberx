"""Operator TUI: screens, wizard, controls. No recon/AI providers."""

from __future__ import annotations

import ast
from pathlib import Path

from cyberx.app.bootstrap import bootstrap
from cyberx.app.views import (
    CurrentActionView,
    DashboardView,
    MissionStatusView,
    ScopeReviewView,
    WorldSummaryView,
)
from cyberx.config import AppConfig
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.tui.app import ConsoleApp
from cyberx.tui.io import ScriptedIO
from cyberx.tui.render import render_banner, render_dashboard, render_scope

TUI_ROOT = Path(__file__).resolve().parents[2] / "src" / "cyberx" / "tui"

_FORBIDDEN_TUI = (
    "subprocess",
    "httpx",
    "nmap",
    "sqlite3",
    "cyberx.recon",
    "cyberx.storage",
    "cyberx.evidence.parsers",
    "cyberx.ai.providers",
    "cyberx.engine.stub_executor",
)


def _empty_dashboard() -> DashboardView:
    scope = ScopeReviewView(
        allowed_targets=("10.10.11.23",),
        allowed_networks=(),
        allowed_ports=(),
        allowed_protocols=("tcp", "http", "https"),
        excluded_targets=(),
        excluded_networks=(),
        excluded_ports=(),
        allow_subdomains=True,
        frozen=True,
        policy_profile="recon_default",
    )
    mission = MissionStatusView(
        mission_id="mis_01AAAAAAAAAAAAAAAAAAAAAAAA",
        name="demo",
        intent="enumerate",
        status="CONFIRMED",
        target="10.10.11.23",
        target_kind="ipv4",
        mode="ctf",
        provider="none",
        iteration=0,
        max_iterations=50,
        elapsed_s=0,
        max_runtime_s=3600,
        stop_reason=None,
        policy_profile="recon_default",
        scope=scope,
    )
    world = WorldSummaryView(
        revision=0,
        hosts=1,
        open_ports=0,
        services=0,
        technologies=0,
        urls=0,
        endpoints=0,
        findings=0,
        hypotheses=0,
        open_gaps=1,
        closed_gaps=0,
        host_lines=("10.10.11.23",),
        port_lines=(),
        service_lines=(),
        tech_lines=(),
        url_lines=(),
        gap_lines=("host.ports_unknown",),
        claim_lines=(),
    )
    action = CurrentActionView(
        action_type=None,
        target=None,
        rationale="",
        score=None,
        coverage_key=None,
        policy_verdict=None,
        execution_status=None,
        last_result=None,
    )
    return DashboardView(
        mission=mission,
        world=world,
        action=action,
        findings=(),
        hypotheses=(),
        events=(),
        help_line="s start",
    )


def test_initial_screen_and_status_render() -> None:
    banner = render_banner(color=False)
    assert "CyberX" in banner
    dash = render_dashboard(_empty_dashboard(), color=False)
    assert "CONFIRMED" in dash
    assert "10.10.11.23" in dash
    assert "host.ports_unknown" in dash
    assert "[s]tart" in dash or "s start" in dash
    assert "AI:" in dash
    scope = render_scope(_empty_dashboard().mission.scope, color=False)
    assert "recon_default" in scope


def test_confirmation_flow() -> None:
    app = bootstrap(AppConfig(), store=InMemoryMissionStore())
    io = ScriptedIO(
        [
            "http://10.10.10.10",
            "box",
            "enumerate the in-scope attack surface",
            "1",
            "1",
            "y",
        ]
    )
    try:
        code = ConsoleApp(app.facade, io=io).run()
        assert code == 0
        text = io.text()
        assert "Scope review" in text
        assert "CONFIRMED" in text or "frozen" in text.lower()
        items = app.facade.list_resumable()
        assert len(items) == 1
        assert items[0].status == "CONFIRMED"
    finally:
        app.close()


def test_invalid_target_is_operator_facing() -> None:
    app = bootstrap(AppConfig(), store=InMemoryMissionStore())
    io = ScriptedIO(
        [
            "???",
            "bad",
            "enumerate the in-scope attack surface",
            "1",
            "1",
            "n",
        ]
    )
    try:
        code = ConsoleApp(app.facade, io=io).run()
        assert code == 0
        text = io.text()
        assert "Invalid target" in text or "Invalid input" in text
        assert "Traceback" not in text
    finally:
        app.close()


def test_pause_and_stop_controls() -> None:
    app = bootstrap(AppConfig(), store=InMemoryMissionStore())
    io = ScriptedIO(
        [
            "10.10.11.23",
            "keys",
            "enumerate the in-scope attack surface",
            "1",
            "1",
            "y",
            "c",
            "",
            "x",
            "y",
            "",
            "q",
        ]
    )
    try:
        code = ConsoleApp(app.facade, io=io).run()
        assert code == 0
        items = app.facade.list_resumable()
        # stopped missions are not resumable
        assert items == () or items[0].status in {"STOPPED", "PAUSED", "COMPLETED"}
        status = app.service.list_missions()[0].mission.status.value
        assert status in {"STOPPED", "PAUSED", "COMPLETED", "RUNNING"}
    finally:
        app.close()


def test_tui_does_not_import_forbidden_modules() -> None:
    for path in TUI_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module)
        text = path.read_text(encoding="utf-8")
        for token in _FORBIDDEN_TUI:
            assert token not in names, f"{path} imports {token}"
            assert not any(n.startswith(token + ".") for n in names)
        assert "shell=True" not in text
        assert "cyberx.storage.sqlite" not in names


def test_wizard_records_grok_as_advisory() -> None:
    app = bootstrap(AppConfig(), store=InMemoryMissionStore())
    io = ScriptedIO(
        [
            "10.10.11.23",
            "grok-box",
            "enumerate the in-scope attack surface",
            "1",
            "2",
            "y",
            "q",
        ]
    )
    try:
        code = ConsoleApp(app.facade, io=io).run()
        assert code == 0
        text = io.text()
        assert "Grok" in text or "grok" in text
        assert "Deterministic Brain" in text
        items = app.facade.list_resumable()
        assert items
        assert app.service.get(items[0].mission_id).ai_provider == "grok"
    finally:
        app.close()
