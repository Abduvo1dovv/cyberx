"""Architecture regression tests (import direction, no policy bypass)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from cyberx.actions.catalog import ActionCatalog

ROOT = Path(__file__).resolve().parents[2] / "src" / "cyberx"

DOMAIN_FORBIDDEN = {
    "subprocess",
    "socket",
    "httpx",
    "sqlalchemy",
    "sqlite3",
    "cyberx.recon",
    "cyberx.engine",
    "cyberx.tui",
    "cyberx.ai",
    "cyberx.storage",
    "cyberx.observability",
}

INFRA_TOKENS = {"subprocess", "shell=True", "os.system"}


def _full_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
            names.add(node.module)
    return names


def _iter(package: str) -> list[Path]:
    folder = ROOT / package
    if not folder.exists():
        return []
    return [p for p in folder.rglob("*.py") if p.name != "__pycache__"]


def test_domain_imports_are_pure() -> None:
    for path in _iter("domain"):
        imported = _imports(path)
        text = path.read_text(encoding="utf-8")
        for token in DOMAIN_FORBIDDEN:
            assert token not in imported, f"{path} imports {token}"
            assert token not in text, f"{path} mentions {token}"
        assert "subprocess" not in imported


def test_policy_and_catalog_cannot_subprocess() -> None:
    for package in ("policy", "actions"):
        for path in _iter(package):
            imported = _imports(path)
            assert "subprocess" not in imported
            assert "cyberx.recon" not in imported
            assert "cyberx.ai" not in imported


def test_catalog_cannot_register_unknown_actions() -> None:
    catalog = ActionCatalog()
    assert not hasattr(catalog, "register")
    with pytest.raises(TypeError):
        catalog._specs["exploit_http"] = object()  # type: ignore[index]


def test_ai_protocol_cannot_execute_actions() -> None:
    path = ROOT / "ai" / "protocol.py"
    text = path.read_text(encoding="utf-8")
    assert "def execute" not in text
    assert "subprocess" not in text
    assert "ActionExecutor" not in text
    imported = _imports(path)
    assert "cyberx.engine" not in imported
    assert "cyberx.recon" not in imported


def test_no_shell_true_in_repo() -> None:
    allowed_subprocess = {ROOT / "recon" / "nmap" / "process.py"}
    for path in ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "shell=True" not in text, f"{path} contains shell=True"
        assert "os.system(" not in text, f"{path} contains os.system"
        imported = _imports(path)
        if path.resolve() in {p.resolve() for p in allowed_subprocess}:
            continue
        assert "subprocess" not in imported, f"{path} imports subprocess"


def test_stub_and_engine_do_not_call_subprocess() -> None:
    for package in ("recon", "engine"):
        for path in _iter(package):
            if path.name == "process.py" and path.parent.name == "nmap":
                continue
            imported = _imports(path)
            assert "subprocess" not in imported, f"{path} imports subprocess"
            assert "httpx" not in imported


def test_domain_imports_only_cyberx_domain() -> None:
    for path in _iter("domain"):
        for name in _full_imports(path):
            if name == "cyberx" or (
                name.startswith("cyberx.") and not name.startswith("cyberx.domain")
            ):
                pytest.fail(f"{path} imports {name}")


def test_actions_and_policy_do_not_import_engine_or_recon() -> None:
    forbidden = (
        "cyberx.recon",
        "cyberx.engine",
        "cyberx.ai",
        "cyberx.tui",
        "cyberx.storage",
    )
    for package in ("actions", "policy", "scope"):
        for path in _iter(package):
            imported = _full_imports(path)
            for token in forbidden:
                assert token not in imported, f"{path} imports {token}"
                assert not any(name.startswith(token + ".") for name in imported)


def test_ports_do_not_import_infrastructure() -> None:
    for path in _iter("ports"):
        imported = _full_imports(path)
        for token in ("cyberx.recon", "cyberx.engine", "subprocess", "httpx"):
            assert token not in imported, f"{path} imports {token}"


def test_ai_cannot_import_execution_path() -> None:
    for path in _iter("ai"):
        imported = _full_imports(path)
        for token in ("cyberx.engine", "cyberx.recon", "cyberx.policy", "subprocess"):
            assert token not in imported, f"{path} imports {token}"


def test_evidence_parsers_are_pure_and_cannot_execute() -> None:
    forbidden = (
        "cyberx.recon",
        "cyberx.engine",
        "cyberx.ai",
        "cyberx.tui",
        "cyberx.brain",
        "cyberx.storage",
        "subprocess",
        "httpx",
        "socket",
    )
    for path in _iter("evidence"):
        imported = _full_imports(path)
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in imported, f"{path} imports {token}"
            assert not any(name.startswith(token + ".") for name in imported)
        assert "shell=True" not in text
        assert "WorldModel" not in text
        assert ".apply(" not in text or path.name != "pipeline.py" or "No World Model apply" in text


def test_parsers_do_not_import_world_apply() -> None:
    for path in _iter("evidence/parsers"):
        imported = _full_imports(path)
        assert "cyberx.world" not in imported
        assert "cyberx.brain" not in imported


def test_brain_does_not_execute_or_touch_storage() -> None:
    forbidden = (
        "cyberx.recon",
        "cyberx.engine",
        "cyberx.tui",
        "cyberx.storage",
        "subprocess",
        "httpx",
        "socket",
        "sqlite3",
    )
    for path in _iter("brain"):
        imported = _full_imports(path)
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in imported, f"{path} imports {token}"
            assert not any(name.startswith(token + ".") for name in imported)
        assert "shell=True" not in text
        assert "def execute" not in text


def test_storage_does_not_import_brain_or_recon() -> None:
    forbidden = (
        "cyberx.brain",
        "cyberx.tui",
        "cyberx.recon",
        "cyberx.engine",
        "subprocess",
        "httpx",
        "socket",
    )
    for path in _iter("storage"):
        imported = _full_imports(path)
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in imported, f"{path} imports {token}"
            assert not any(name.startswith(token + ".") for name in imported)
        assert "shell=True" not in text


def test_engine_loop_does_not_import_sqlite_or_ai_providers() -> None:
    for path in _iter("engine"):
        imported = _full_imports(path)
        assert "sqlite3" not in imported
        assert "cyberx.storage.sqlite" not in imported
        assert "cyberx.ai.providers" not in imported
        assert "subprocess" not in imported
        assert "httpx" not in imported


def test_engine_does_not_duck_type_storage_or_event_internals() -> None:
    for path in _iter("engine"):
        text = path.read_text(encoding="utf-8")
        assert "store_has" not in text, f"{path} uses store_has"
        assert 'getattr(self._events, "events"' not in text
        assert "hasattr(store" not in text
        assert "hasattr(self._store" not in text


def test_policy_and_world_remain_fail_closed() -> None:
    policy = (ROOT / "policy" / "engine.py").read_text(encoding="utf-8")
    assert "fail" in policy.lower() or "deny" in policy.lower()
    assert "subprocess" not in policy
    loop = (ROOT / "engine" / "loop.py").read_text(encoding="utf-8")
    assert "BrainContext" in loop
    assert loop.count("self._builder.build(") == 1
    for name in ("persist.py", "observe.py", "hypotheses.py", "apply.py"):
        assert (ROOT / "engine" / name).is_file()


def test_world_imports_only_domain() -> None:
    forbidden = (
        "cyberx.recon",
        "cyberx.engine",
        "cyberx.tui",
        "cyberx.ai",
        "cyberx.storage",
        "cyberx.evidence",
        "cyberx.scope",
        "cyberx.brain",
        "subprocess",
        "httpx",
        "socket",
        "sqlite3",
    )
    for path in _iter("world"):
        imported = _full_imports(path)
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in imported, f"{path} imports {token}"
            assert not any(name.startswith(token + ".") for name in imported)
        assert "shell=True" not in text
        assert "os.system(" not in text


def test_tui_imports_only_application_surface() -> None:
    forbidden = (
        "cyberx.recon",
        "cyberx.storage",
        "cyberx.evidence.parsers",
        "cyberx.ai.providers",
        "subprocess",
        "httpx",
        "socket",
        "sqlite3",
        "nmap",
    )
    for path in _iter("tui"):
        imported = _full_imports(path)
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in imported, f"{path} imports {token}"
            assert not any(name.startswith(token + ".") for name in imported)
        assert "shell=True" not in text
        assert "cyberx.storage.sqlite" not in imported


def test_facade_does_not_select_infrastructure() -> None:
    forbidden = (
        "cyberx.storage.sqlite",
        "cyberx.recon",
        "sqlite3",
        "subprocess",
        "httpx",
    )
    path = ROOT / "app" / "facade.py"
    imported = _full_imports(path)
    for token in forbidden:
        assert token not in imported, f"facade imports {token}"


def test_nmap_adapter_cannot_bypass_policy_or_touch_world() -> None:
    from cyberx.domain.errors import ExecutionBypassError
    from cyberx.engine.recon_executor import ReconExecutor
    from cyberx.recon.nmap.adapter import NmapAdapter

    executor = ReconExecutor(nmap=NmapAdapter(available=False), nmap_enabled=True)
    with pytest.raises(ExecutionBypassError):
        executor.execute(object())  # type: ignore[arg-type]
    text = (ROOT / "recon" / "nmap" / "adapter.py").read_text(encoding="utf-8")
    assert "WorldModel" not in text
    imported = _full_imports(ROOT / "recon" / "nmap" / "adapter.py")
    assert "cyberx.brain" not in imported
    assert "cyberx.world" not in imported
    assert "cyberx.ai" not in imported
    parser = ROOT / "evidence" / "parsers" / "nmap_xml.py"
    imported_parser = _full_imports(parser)
    for token in ("subprocess", "httpx", "socket", "cyberx.recon", "cyberx.engine"):
        assert token not in imported_parser


def test_http_adapter_cannot_bypass_policy_or_touch_world() -> None:
    from cyberx.domain.errors import ExecutionBypassError
    from cyberx.engine.recon_executor import ReconExecutor
    from cyberx.recon.http.adapter import HttpAdapter

    executor = ReconExecutor(http=HttpAdapter(), http_enabled=True)
    with pytest.raises(ExecutionBypassError):
        executor.execute(object())  # type: ignore[arg-type]
    for rel in (
        "adapter.py",
        "tech.py",
        "transport.py",
        "request.py",
        "directory.py",
        "wordlist.py",
    ):
        path = ROOT / "recon" / "http" / rel
        text = path.read_text(encoding="utf-8")
        assert "WorldModel" not in text
        imported = _full_imports(path)
        assert "cyberx.brain" not in imported
        assert "cyberx.world" not in imported
        assert "cyberx.ai" not in imported
        assert "httpx" not in imported
    parser = ROOT / "evidence" / "parsers" / "http_probe.py"
    imported_parser = _full_imports(parser)
    for token in ("subprocess", "httpx", "socket", "cyberx.recon", "cyberx.engine"):
        assert token not in imported_parser
    endpoint = ROOT / "recon" / "http" / "endpoint.py"
    text = endpoint.read_text(encoding="utf-8")
    assert "http.client" not in text
    assert "WorldModel" not in text
    imported_ep = _full_imports(endpoint)
    assert "httpx" not in imported_ep
    assert "cyberx.brain" not in imported_ep
    assert "cyberx.world" not in imported_ep
    directory = ROOT / "recon" / "http" / "directory.py"
    text_dir = directory.read_text(encoding="utf-8")
    assert "WorldModel" not in text_dir
    assert "shell=True" not in text_dir
    imported_dir = _full_imports(directory)
    assert "subprocess" not in imported_dir
    assert "cyberx.brain" not in imported_dir
    assert "cyberx.world" not in imported_dir
    parser_dir = ROOT / "evidence" / "parsers" / "directory.py"
    imported_pd = _full_imports(parser_dir)
    for token in ("subprocess", "httpx", "socket", "cyberx.recon", "cyberx.engine"):
        assert token not in imported_pd


def test_dns_adapter_cannot_bypass_policy_or_touch_world() -> None:
    from cyberx.domain.errors import ExecutionBypassError
    from cyberx.engine.recon_executor import ReconExecutor
    from cyberx.recon.dns.adapter import DnsAdapter

    executor = ReconExecutor(dns=DnsAdapter(), dns_enabled=True)
    with pytest.raises(ExecutionBypassError):
        executor.execute(object())  # type: ignore[arg-type]
    for rel in ("adapter.py", "resolver.py", "wordlist.py"):
        path = ROOT / "recon" / "dns" / rel
        text = path.read_text(encoding="utf-8")
        assert "WorldModel" not in text
        assert "shell=True" not in text
        assert "os.system(" not in text
        imported = _full_imports(path)
        assert "cyberx.brain" not in imported
        assert "cyberx.world" not in imported
        assert "cyberx.ai" not in imported
        assert "subprocess" not in imported
    parser = ROOT / "evidence" / "parsers" / "dns.py"
    imported_parser = _full_imports(parser)
    for token in ("subprocess", "httpx", "socket", "cyberx.recon", "cyberx.engine"):
        assert token not in imported_parser


def test_validation_package_cannot_execute_or_exploit() -> None:
    forbidden = (
        "cyberx.recon",
        "cyberx.engine",
        "cyberx.tui",
        "cyberx.storage",
        "cyberx.ai",
        "subprocess",
        "httpx",
        "socket",
        "sqlite3",
    )
    for path in _iter("validation"):
        imported = _full_imports(path)
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in imported, f"{path} imports {token}"
            assert not any(name.startswith(token + ".") for name in imported)
        assert "shell=True" not in text
        assert "os.system(" not in text
        assert "def execute" not in text
        for banned in ("exploit_http", "sqlmap", "password="):
            assert banned not in text


def test_graph_package_cannot_execute_or_exploit() -> None:
    forbidden = (
        "cyberx.recon",
        "cyberx.engine",
        "cyberx.tui",
        "cyberx.storage",
        "cyberx.ai",
        "cyberx.brain",
        "subprocess",
        "httpx",
        "socket",
        "sqlite3",
    )
    for path in _iter("graph"):
        imported = _full_imports(path)
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in imported, f"{path} imports {token}"
            assert not any(name.startswith(token + ".") for name in imported)
        assert "shell=True" not in text
        assert "os.system(" not in text
        assert "def execute" not in text
        for banned in ("exploit_http", "sqlmap", "password="):
            assert banned not in text


def test_world_does_not_import_graph() -> None:
    for path in _iter("world"):
        imported = _full_imports(path)
        assert "cyberx.graph" not in imported
        assert not any(name.startswith("cyberx.graph.") for name in imported)


def test_network_package_is_read_only_observation() -> None:
    forbidden = (
        "cyberx.brain",
        "cyberx.engine",
        "cyberx.tui",
        "cyberx.recon",
        "cyberx.storage",
        "cyberx.ai",
        "cyberx.world",
        "subprocess",
        "httpx",
        "sqlite3",
    )
    for path in _iter("network"):
        imported = _full_imports(path)
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in imported, f"{path} imports {token}"
            assert not any(name.startswith(token + ".") for name in imported)
        assert "shell=True" not in text
        assert "os.system(" not in text
        assert "def execute" not in text
        for banned in ("openvpn", "wg-quick", "iptables", "HTB VPN", "password="):
            assert banned not in text


def test_world_and_brain_do_not_import_network_package() -> None:
    for package in ("world", "brain", "recon"):
        for path in _iter(package):
            imported = _full_imports(path)
            assert "cyberx.network" not in imported, f"{path} imports cyberx.network"
            assert not any(name.startswith("cyberx.network.") for name in imported)


def test_brain_does_not_import_ai_providers() -> None:
    for path in _iter("brain"):
        imported = _full_imports(path)
        assert "cyberx.ai.providers" not in imported
        assert not any(name.startswith("cyberx.ai.providers.") for name in imported)


def test_grok_provider_has_no_execute_path_or_hardcoded_secrets() -> None:
    grok = ROOT / "ai" / "providers" / "grok.py"
    text = grok.read_text(encoding="utf-8")
    assert "def execute" not in text
    assert "shell=True" not in text
    assert "grok-4.5" not in text
    imported = _full_imports(grok)
    assert "subprocess" not in imported
    assert "cyberx.engine" not in imported
    assert "cyberx.recon" not in imported
    for path in ROOT.rglob("*.py"):
        body = path.read_text(encoding="utf-8")
        assert "sk-proj-" not in body
        assert "xai-" not in body.lower()
