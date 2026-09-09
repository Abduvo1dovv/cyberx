"""v1 CTF release smoke: version, doctor, reports, corrupt DB, no secrets."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberx import __release__, __version__
from cyberx.app.bootstrap import bootstrap
from cyberx.config import AppConfig, RuntimeSettings
from cyberx.domain.errors import StorageError
from cyberx.main import main, run_doctor
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.storage.sqlite import SqliteStore


def test_version_string() -> None:
    assert __version__ == "1.0.0-ctf"
    assert "Recon/Intelligence" in __release__
    assert "production" not in __release__.lower()


def test_version_flag(capsys) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == "1.0.0-ctf"


def test_doctor_does_not_print_api_key(capsys) -> None:
    cfg = AppConfig.from_env(
        {
            "CYBERX_STUB": "1",
            "CYBERX_AI_PROVIDER": "grok",
            "CYBERX_AI_API_KEY": "super-secret-key-xyz",
            "CYBERX_DATA_DIR": "data",
        }
    )
    assert run_doctor(cfg) == 0
    out = capsys.readouterr().out
    assert "1.0.0-ctf" in out
    assert "super-secret-key-xyz" not in out
    assert "nmap" in out
    assert "VPN" in out


def test_diagnose_does_not_print_secrets_or_scan(monkeypatch, capsys) -> None:
    from cyberx.domain.models.network import NetworkContext

    class _Fake:
        def resolve(self, target: str) -> NetworkContext:
            return NetworkContext.unavailable(target, diagnostic="fixture")

    monkeypatch.setattr("cyberx.network.resolver.NetworkResolver", lambda: _Fake())
    assert (
        main(
            [
                "--diagnose",
                "10.10.11.23",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "DIAGNOSE" in out
    assert "10.10.11.23" in out
    assert "normalized" in out
    assert "nmap_timeout_s" in out
    assert "No routes" in out
    assert "super-secret" not in out


def test_network_flag_does_not_scan(monkeypatch, capsys) -> None:
    from cyberx.domain.models.network import NetworkContext

    class _Fake:
        def resolve(self, target: str) -> NetworkContext:
            return NetworkContext.unavailable(target, diagnostic="fixture")

    monkeypatch.setattr("cyberx.network.resolver.NetworkResolver", lambda: _Fake())
    assert main(["--network", "10.10.11.23"]) == 0
    out = capsys.readouterr().out
    assert "10.10.11.23" in out
    assert "No routes" in out
    assert "informational" in out.lower()


def test_corrupt_database_fails_clearly(tmp_path) -> None:
    path = tmp_path / "cyberx.db"
    path.write_bytes(b"this is not a sqlite database" * 8)
    with pytest.raises(StorageError) as err:
        SqliteStore(path, data_dir=tmp_path)
    assert err.value.code == "database_corrupt"
    assert "database" in err.value.message.lower() or "malformed" in str(err.value).lower()


def test_stub_mission_exports_report(tmp_path) -> None:
    cfg = AppConfig(runtime=RuntimeSettings(data_dir=str(tmp_path), stub_mode=True))
    app = bootstrap(cfg, store=InMemoryMissionStore())
    try:
        mission = app.facade.create_mission(
            target="10.10.11.23",
            name="release-smoke",
            intent="enumerate the in-scope attack surface",
            mode="ctf",
        )
        mid = mission.mission_id
        app.facade.confirm_mission(mid)
        app.facade.start_mission(mid)
        for _ in range(3):
            report = app.facade.run_one_cycle(mid)
            if report.completed:
                break
        json_path, md_path = app.facade.export_report(mid)
        payload = json.loads(Path(json_path).read_text(encoding="utf-8"))
        markdown = Path(md_path).read_text(encoding="utf-8")
        assert payload["version"] == "1.0.0-ctf"
        assert payload["target"]["identity"]
        assert payload["target"]["current_locator"] == "10.10.11.23"
        assert payload["assets"]["hosts"] >= 1
        assert "FACT" in markdown or "Findings" in markdown
        assert "HYPOTHESIS" in markdown
        assert "UNKNOWN" in markdown or "Unresolved" in markdown
        lowered = markdown.lower()
        assert "meterpreter" not in lowered
        assert "how to exploit" not in lowered
        assert "spawn a shell" not in lowered
    finally:
        app.close()
