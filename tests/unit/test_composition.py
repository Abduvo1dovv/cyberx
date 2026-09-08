"""Composition root wiring."""

from __future__ import annotations

from cyberx.app.bootstrap import Application, bootstrap
from cyberx.app.facade import OperatorFacade
from cyberx.brain.facade import Brain
from cyberx.config import AppConfig, ProviderConfig, RuntimeSettings
from cyberx.engine.loop import MissionEngine
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.engine.stub_executor import StubExecutor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.policy.engine import PolicyEngine


def test_bootstrap_wires_all_dependencies() -> None:
    app = bootstrap(AppConfig(), store=InMemoryMissionStore())
    try:
        assert isinstance(app, Application)
        assert isinstance(app.service, MissionService)
        assert isinstance(app.engine, MissionEngine)
        assert isinstance(app.facade, OperatorFacade)
        assert isinstance(app.policy, PolicyEngine)
        assert isinstance(app.executor, StubExecutor)
        assert isinstance(app.engine._brain, Brain)
        assert app.facade.config.runtime.stub_mode is True
        assert app.catalog.get("port_scan") is not None
        assert app.engine._service is app.service
        assert app.facade._engine is app.engine
        status = app.engine._brain.ai_status()
        assert status["provider"] == "none"
        assert status["status"] == "DISABLED"
    finally:
        app.close()


def test_bootstrap_wires_nmap_when_not_stub() -> None:
    cfg = AppConfig(runtime=RuntimeSettings(stub_mode=False))
    app = bootstrap(cfg, store=InMemoryMissionStore())
    try:
        assert isinstance(app.executor, ReconExecutor)
        assert app.executor._nmap_enabled is True
        assert app.facade.stub_mode is False
    finally:
        app.close()


def test_stub_mission_can_be_constructed() -> None:
    app = bootstrap(AppConfig(), store=InMemoryMissionStore())
    try:
        mission = app.facade.create_mission(
            target="10.10.11.23",
            name="wired",
            intent="enumerate in-scope surface",
            mode="ctf",
        )
        assert mission.mission_id.startswith("mis_")
        assert mission.ai_provider == "none"
        assert app.service.get(mission.mission_id).name == "wired"
    finally:
        app.close()


def test_sqlite_bootstrap_round_trip(tmp_path) -> None:
    cfg = AppConfig(runtime=RuntimeSettings(data_dir=str(tmp_path), stub_mode=True))
    app = bootstrap(cfg)
    try:
        mission = app.facade.create_mission(
            target="10.10.11.23",
            name="persist",
            intent="enumerate in-scope surface",
            mode="ctf",
        )
        mid = mission.mission_id
    finally:
        app.close()
    again = bootstrap(cfg)
    try:
        items = again.facade.list_resumable()
        assert any(item.mission_id == mid for item in items)
    finally:
        again.close()


def test_bootstrap_wires_grok_when_configured() -> None:
    cfg = AppConfig(
        provider=ProviderConfig(name="grok", api_key="test-key", model="test-model", enabled=True)
    )
    app = bootstrap(cfg, store=InMemoryMissionStore())
    try:
        status = app.engine._brain.ai_status()
        assert status["provider"] == "grok"
        assert status["status"] == "AVAILABLE"
        assert status["model"] == "test-model"
        dash = app.facade.get_ai_status()
        assert dash.provider == "grok"
        assert dash.status == "AVAILABLE"
    finally:
        app.close()
