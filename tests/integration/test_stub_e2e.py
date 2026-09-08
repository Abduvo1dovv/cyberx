"""End-to-end stub mission through the application facade."""

from __future__ import annotations

from cyberx.app.bootstrap import bootstrap
from cyberx.config import AppConfig, RuntimeSettings
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.tui.app import ConsoleApp
from cyberx.tui.io import ScriptedIO


def test_new_mission_runs_several_brain_cycles() -> None:
    app = bootstrap(AppConfig(), store=InMemoryMissionStore())
    try:
        facade = app.facade
        mission = facade.create_mission(
            target="10.10.11.23",
            name="e2e",
            intent="enumerate the in-scope attack surface",
            mode="ctf",
        )
        mid = mission.mission_id
        facade.confirm_mission(mid)
        facade.start_mission(mid)
        types: list[str] = []
        for _ in range(8):
            report = facade.run_one_cycle(mid)
            if report.selected_action_type:
                types.append(report.selected_action_type)
            if report.completed or report.paused:
                break
        assert len(types) >= 3
        assert types[0] == "port_scan"
        assert len(set(types)) >= 2
        world = facade.get_world_summary(mid)
        assert world.hosts >= 1
        assert world.open_ports >= 1
        assert world.revision > 1
        status = facade.get_mission_status(mid).status
        assert status in {"RUNNING", "COMPLETED", "STOPPED", "PAUSED", "FAILED"}
    finally:
        app.close()


def test_tui_start_runs_stub_loop() -> None:
    app = bootstrap(AppConfig(), store=InMemoryMissionStore())
    io = ScriptedIO(
        [
            "10.10.11.23",
            "tui-e2e",
            "enumerate the in-scope attack surface",
            "1",
            "1",
            "y",
            "s",
        ]
    )
    try:
        code = ConsoleApp(app.facade, io=io).run()
        assert code == 0
        bundles = app.service.list_missions()
        assert bundles
        mid = bundles[0].mission.mission_id
        world = app.facade.get_world_summary(mid)
        assert world.open_ports >= 1
        assert world.revision >= 1
        text = io.text()
        assert "port_scan" in text or "open_ports" in text or "RUNNING" in text
        assert "Traceback" not in text
    finally:
        app.close()


def test_resume_after_persist(tmp_path) -> None:
    cfg = AppConfig(runtime=RuntimeSettings(data_dir=str(tmp_path), stub_mode=True))
    app = bootstrap(cfg)
    try:
        mission = app.facade.create_mission(
            target="10.10.11.23",
            name="resume-me",
            intent="enumerate the in-scope attack surface",
            mode="ctf",
        )
        mid = mission.mission_id
        app.facade.confirm_mission(mid)
        app.facade.start_mission(mid)
        app.facade.run_one_cycle(mid)
        app.facade.pause_mission(mid)
    finally:
        app.close()
    resumed = bootstrap(cfg)
    try:
        items = resumed.facade.list_resumable()
        assert any(item.mission_id == mid and item.status == "PAUSED" for item in items)
        resumed.facade.resume_mission(mid)
        cycle = resumed.facade.run_one_cycle(mid)
        assert cycle.paused is False
        world = resumed.facade.get_world_summary(mid)
        assert world.open_ports >= 1
    finally:
        resumed.close()
