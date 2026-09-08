"""Operator facade: mission lifecycle without a TUI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberx.app.bootstrap import bootstrap
from cyberx.app.facade import parse_mode
from cyberx.config import AppConfig, RuntimeSettings
from cyberx.domain.enums import MissionMode, MissionStatus
from cyberx.domain.errors import DomainValidationError, TargetValidationError
from cyberx.mission.memory import InMemoryMissionStore


def _app():
    return bootstrap(AppConfig(), store=InMemoryMissionStore())


def test_create_confirm_start_pause_resume_stop() -> None:
    app = _app()
    try:
        facade = app.facade
        mission = facade.create_mission(
            target="10.10.11.23",
            name="lifecycle",
            intent="enumerate the in-scope attack surface",
            mode="ctf",
        )
        mid = mission.mission_id
        assert facade.get_mission_status(mid).status == "CREATED"
        scope = facade.get_mission_status(mid).scope
        assert scope.frozen is False
        assert "10.10.11.23" in scope.allowed_targets
        confirmed = facade.confirm_mission(mid)
        assert confirmed.status is MissionStatus.CONFIRMED
        assert facade.get_mission_status(mid).scope.frozen is True
        facade.start_mission(mid)
        assert facade.get_mission_status(mid).status == "RUNNING"
        facade.pause_mission(mid)
        assert facade.get_mission_status(mid).status == "PAUSED"
        facade.resume_mission(mid)
        assert facade.get_mission_status(mid).status == "RUNNING"
        facade.stop_mission(mid)
        assert facade.get_mission_status(mid).status == "STOPPED"
    finally:
        app.close()


def test_one_cycle_grows_world() -> None:
    app = _app()
    try:
        facade = app.facade
        mission = facade.create_mission(
            target="10.10.11.23",
            name="cycle",
            intent="enumerate the in-scope attack surface",
            mode="lab",
        )
        mid = mission.mission_id
        facade.confirm_mission(mid)
        facade.start_mission(mid)
        cycle = facade.run_one_cycle(mid)
        assert cycle.selected_action_type == "port_scan"
        assert cycle.evidence_added > 0
        world = facade.get_world_summary(mid)
        assert world.open_ports > 0
        assert world.revision > 0
        dash = facade.get_dashboard(mid)
        assert dash.mission.iteration >= 1
        assert dash.action.action_type == "port_scan"
        assert dash.ai is not None
        assert dash.ai.provider == "none"
    finally:
        app.close()


def test_full_stub_mission_via_facade() -> None:
    app = _app()
    try:
        facade = app.facade
        mission = facade.create_mission(
            target="10.10.11.23",
            name="full",
            intent="enumerate the in-scope attack surface",
            mode="ctf",
        )
        mid = mission.mission_id
        facade.confirm_mission(mid)
        reports = facade.run_mission(mid)
        assert len(reports) >= 3
        types = [r.selected_action_type for r in reports if r.selected_action_type]
        assert "port_scan" in types
        assert len(set(types)) >= 2
        status = facade.get_mission_status(mid)
        assert status.status in {"COMPLETED", "STOPPED", "FAILED", "PAUSED"}
        world = facade.get_world_summary(mid)
        assert world.hosts >= 1
        assert world.open_ports >= 1
    finally:
        app.close()


def test_invalid_target_and_mode() -> None:
    app = _app()
    try:
        with pytest.raises(TargetValidationError):
            app.facade.create_mission(
                target="???",
                name="bad",
                intent="enumerate the in-scope attack surface",
                mode="ctf",
            )
        with pytest.raises(DomainValidationError):
            parse_mode("exploit")
        with pytest.raises(DomainValidationError):
            app.facade.create_mission(
                target="10.10.11.23",
                name="bad",
                intent="enumerate the in-scope attack surface",
                mode="ctf",
                ai_provider="chatgpt",
            )
    finally:
        app.close()


def test_cannot_mutate_scope_after_confirm() -> None:
    app = _app()
    try:
        mission = app.facade.create_mission(
            target="10.10.11.23",
            name="frozen",
            intent="enumerate the in-scope attack surface",
            mode="ctf",
        )
        mid = mission.mission_id
        app.facade.confirm_mission(mid)
        with pytest.raises(Exception):
            app.facade.update_scope(mid, excluded_targets=["8.8.8.8"])
    finally:
        app.close()


def test_export_report_writes_json_and_markdown(tmp_path) -> None:
    cfg = AppConfig(runtime=RuntimeSettings(data_dir=str(tmp_path), stub_mode=True))
    app = bootstrap(cfg, store=InMemoryMissionStore())
    try:
        mission = app.facade.create_mission(
            target="10.10.11.23",
            name="report",
            intent="enumerate the in-scope attack surface",
            mode="ctf",
        )
        app.facade.confirm_mission(mission.mission_id)
        json_path, md_path = app.facade.export_report(mission.mission_id)
        assert json_path.endswith("report.json")
        assert md_path.endswith("report.md")
        json_text = Path(json_path).read_text(encoding="utf-8")
        md_text = Path(md_path).read_text(encoding="utf-8")
        assert "10.10.11.23" in json_text
        assert "HYPOTHESIS / NOT CONFIRMED" in md_text or "Hypotheses" in md_text
        assert "meterpreter" not in md_text.lower()
        assert "how to exploit" not in md_text.lower()
        assert "spawn a shell" not in md_text.lower()
        payload = json.loads(json_text)
        for key in (
            "mission",
            "target",
            "scope",
            "network",
            "assets",
            "hosts",
            "findings",
            "hypotheses",
            "unresolved_knowledge_gaps",
        ):
            assert key in payload
        assert payload["target"]["current_locator"] == "10.10.11.23"
    finally:
        app.close()


def test_mode_aliases() -> None:
    assert parse_mode("professional") is MissionMode.AUTHORIZED_ASSESSMENT
    assert parse_mode("1") is MissionMode.CTF
    assert parse_mode("lab") is MissionMode.LAB
