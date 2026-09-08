from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "cyberx"

FORBIDDEN_IN_DOMAIN = (
    "subprocess",
    "httpx",
    "nmap",
    "sqlalchemy",
    "cyberx.recon",
    "cyberx.tui",
    "cyberx.ai",
    "cyberx.storage",
    "shell=True",
)

FORBIDDEN_EVERYWHERE = ("shell=True", "eval(", "os.system(")


def _iter_py(package: str) -> list[Path]:
    return list((ROOT / package).rglob("*.py"))


def test_domain_has_no_infrastructure_imports() -> None:
    for path in _iter_py("domain"):
        text = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_IN_DOMAIN:
            assert token not in text, f"{path} contains {token}"


def test_no_shell_true_anywhere() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_EVERYWHERE:
            assert token not in text, f"{path} contains {token}"


def test_policy_and_catalog_do_not_execute_tools() -> None:
    for package in ("policy", "actions"):
        for path in _iter_py(package):
            text = path.read_text(encoding="utf-8")
            assert "subprocess" not in text
            assert "httpx" not in text
            assert "cyberx.recon" not in text


def test_evidence_does_not_execute_tools_or_apply_world() -> None:
    for path in _iter_py("evidence"):
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "httpx" not in text
        assert "cyberx.recon" not in text
        assert "shell=True" not in text


def test_brain_is_pure() -> None:
    for path in _iter_py("brain"):
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "httpx" not in text
        assert "shell=True" not in text
        assert "sqlite3" not in text
        assert "cyberx.recon" not in text
        assert "cyberx.engine" not in text
        assert "cyberx.storage" not in text


def test_storage_is_isolated() -> None:
    for path in _iter_py("storage"):
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "httpx" not in text
        assert "shell=True" not in text
        assert "cyberx.recon" not in text
        assert "cyberx.brain" not in text
        assert "cyberx.engine" not in text
        assert "cyberx.tui" not in text


def test_world_does_not_import_infra_or_execute() -> None:
    for path in _iter_py("world"):
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "httpx" not in text
        assert "cyberx.recon" not in text
        assert "cyberx.engine" not in text
        assert "cyberx.ai" not in text
        assert "cyberx.tui" not in text
        assert "shell=True" not in text


def test_tui_does_not_import_infra_or_execute() -> None:
    for path in _iter_py("tui"):
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "httpx" not in text
        assert "sqlite3" not in text
        assert "cyberx.recon" not in text
        assert "cyberx.storage" not in text
        assert "shell=True" not in text
        assert "nmap" not in text


def test_validation_is_pure() -> None:
    for path in _iter_py("validation"):
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "httpx" not in text
        assert "shell=True" not in text
        assert "os.system(" not in text
        assert "cyberx.recon" not in text
        assert "cyberx.engine" not in text
        assert "cyberx.storage" not in text
        assert "sqlite3" not in text


def test_graph_is_pure() -> None:
    for path in _iter_py("graph"):
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "httpx" not in text
        assert "shell=True" not in text
        assert "os.system(" not in text
        assert "cyberx.recon" not in text
        assert "cyberx.engine" not in text
        assert "cyberx.storage" not in text
        assert "cyberx.brain" not in text
        assert "cyberx.tui" not in text
        assert "sqlite3" not in text


def test_world_does_not_import_graph_package() -> None:
    for path in _iter_py("world"):
        text = path.read_text(encoding="utf-8")
        assert "cyberx.graph" not in text


def test_network_is_isolated_and_read_only() -> None:
    for path in _iter_py("network"):
        text = path.read_text(encoding="utf-8")
        assert "subprocess" not in text
        assert "httpx" not in text
        assert "shell=True" not in text
        assert "os.system(" not in text
        assert "cyberx.recon" not in text
        assert "cyberx.engine" not in text
        assert "cyberx.brain" not in text
        assert "cyberx.tui" not in text
        assert "cyberx.storage" not in text
        assert "cyberx.world" not in text
        assert "openvpn" not in text
        assert "iptables" not in text


def test_world_brain_recon_do_not_import_network_package() -> None:
    for package in ("world", "brain", "recon"):
        for path in _iter_py(package):
            text = path.read_text(encoding="utf-8")
            assert "cyberx.network" not in text


def test_ai_is_isolated_and_cannot_execute() -> None:
    for path in _iter_py("ai"):
        text = path.read_text(encoding="utf-8")
        assert "shell=True" not in text
        assert "os.system(" not in text
        assert "cyberx.engine" not in text
        assert "cyberx.recon" not in text
        assert "cyberx.policy" not in text
    for path in _iter_py("brain"):
        text = path.read_text(encoding="utf-8")
        assert "cyberx.ai.providers" not in text

