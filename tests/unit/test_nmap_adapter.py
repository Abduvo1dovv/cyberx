"""Nmap adapter: availability, timeout, exit codes, no shell, policy gate."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import FIXTURES

from cyberx.domain.enums import ActionResultStatus, ActionStatus, PolicyVerdict, Risk
from cyberx.domain.errors import AdapterUnavailable, ExecutionBypassError
from cyberx.domain.ids import PREFIX_ACTION, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import Action, ActionTarget, PolicyDecision
from cyberx.domain.time import utcnow
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.observability.sink import InMemoryEventSink
from cyberx.ports.events import EventType
from cyberx.ports.execution import AuthorizedAction, ExecutionContext
from cyberx.recon.nmap.adapter import NmapAdapter
from cyberx.recon.nmap.process import FixtureProcessRunner, ProcessRunner


def _action() -> Action:
    return Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type="port_scan",
        target=ActionTarget(canonical_locator="10.10.11.23"),
        parameters={"address": "10.10.11.23", "ports": "top1000"},
        reason="ports",
        expected_information_gain=0.8,
        risk=Risk.LOW,
        timeout_s=30,
        status=ActionStatus.AUTHORIZED,
        coverage_key="port_scan:10.10.11.23",
        created_at=utcnow(),
    )


def _authorized(action: Action | None = None) -> AuthorizedAction:
    item = action or _action()
    return AuthorizedAction(
        action=item,
        decision=PolicyDecision(verdict=PolicyVerdict.ALLOW, reason_code="allow"),
    )


def _xml(name: str) -> bytes:
    return (FIXTURES / "nmap" / name).read_bytes()


def test_unavailable_when_binary_missing() -> None:
    adapter = NmapAdapter(binary="nmap-not-installed-xyz", available=False)
    assert adapter.is_available() is False
    with pytest.raises(AdapterUnavailable):
        adapter.run(
            _action(),
            ExecutionContext(
                mission_id=new_id(PREFIX_MISSION),
                action_id=new_id(PREFIX_ACTION),
                timeout_s=5,
            ),
        )


def test_fixture_runner_captures_xml(tmp_path) -> None:
    sink = InMemoryEventSink()
    runner = FixtureProcessRunner(_xml("host_22_80.xml"))
    adapter = NmapAdapter(runner=runner, events=sink, available=True)
    action = _action()
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=15,
        workdir=str(tmp_path),
        stub=False,
    )
    artifact = adapter.run(action, ctx)
    assert artifact.media_type == "application/xml"
    assert artifact.byte_size > 0
    assert b"<nmaprun" in (artifact.body or b"")
    assert artifact.path and Path(artifact.path).is_file()
    types = {e.event_type for e in sink.events}
    assert EventType.NMAP_STARTED in types
    assert EventType.NMAP_COMPLETED in types
    assert all("<?xml" not in str(e.payload) for e in sink.events)
    assert "-sC" not in adapter._last_argv
    assert adapter._last_argv[-1] == "10.10.11.23"


def test_timeout_returns_timeout_result(tmp_path) -> None:
    runner = FixtureProcessRunner(_xml("host_22.xml"), timed_out=True)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), None)
    assert outcome.result.status is ActionResultStatus.TIMEOUT
    assert outcome.result.error_code == "timeout"
    assert outcome.tool_run.timed_out is True


def test_empty_output_is_failed(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=0)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), None)
    assert outcome.result.status is ActionResultStatus.FAILED
    assert outcome.result.error_code == "empty_artifact"


def test_nonzero_exit_with_xml_is_completed(tmp_path) -> None:
    runner = FixtureProcessRunner(_xml("host_22.xml"), exit_code=1)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), None)
    assert outcome.result.status is ActionResultStatus.COMPLETED


def test_executor_rejects_raw_action(tmp_path) -> None:
    executor = ReconExecutor(
        nmap=NmapAdapter(available=True), nmap_enabled=True, data_dir=str(tmp_path)
    )
    with pytest.raises(ExecutionBypassError):
        executor.execute(_action())  # type: ignore[arg-type]


def test_denied_authorized_action_cannot_run(tmp_path) -> None:
    action = _action()
    denied = AuthorizedAction(
        action=action,
        decision=PolicyDecision(verdict=PolicyVerdict.DENY, reason_code="denied"),
    )
    executor = ReconExecutor(
        nmap=NmapAdapter(available=True, runner=FixtureProcessRunner(_xml("host_22.xml"))),
        nmap_enabled=True,
        data_dir=str(tmp_path),
    )
    with pytest.raises(ExecutionBypassError):
        executor.execute(denied)


def test_unavailable_runner_raises(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=127, missing_binary=True)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    with pytest.raises(AdapterUnavailable):
        executor.execute(_authorized())


def test_process_error_is_classified(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=1, stderr=b"Could not bind to source address")
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), None)
    assert outcome.result.status is ActionResultStatus.FAILED
    assert outcome.result.error_code == "process_error"
    assert outcome.result.error_message
    assert "bind" in (outcome.result.error_message or "").lower()


def test_bind_failure_retries_without_source_address(tmp_path) -> None:
    xml = _xml("host_22.xml")

    class BindThenOk:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def run(self, argv, *, timeout_s, cwd=None):
            del timeout_s, cwd
            self.calls.append(list(argv))
            from cyberx.recon.nmap.process import CommandResult, _output_path

            if "-S" in argv:
                return CommandResult(
                    argv=list(argv),
                    exit_code=1,
                    stderr=b"Could not bind to requested source address",
                )
            path = _output_path(argv)
            if path:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(xml)
            return CommandResult(argv=list(argv), exit_code=0)

    runner = BindThenOk()
    adapter = NmapAdapter(runner=runner, available=True)
    ctx = ExecutionContext(
        mission_id=_action().mission_id,
        action_id=_action().action_id,
        timeout_s=30,
        workdir=str(tmp_path),
        reachability="REACHABLE",
        source_interface="tun0",
        source_address="10.10.15.7",
        address_family="ipv4",
    )
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), ctx)
    assert outcome.result.status is ActionResultStatus.COMPLETED
    assert runner.calls
    first = runner.calls[0]
    assert "-4" in first
    assert "-e" in first
    assert first[first.index("-e") + 1] == "tun0"
    assert "-S" not in first
    assert not any(t.lower().startswith("fe80:") for t in first)
    assert all("-S" not in call for call in runner.calls)


def test_nsock_fe80_retries_without_interface(tmp_path) -> None:
    xml = _xml("host_22.xml")
    nsock = (
        b"NSOCK ERROR mksock_bind_addr() Bind to fe80::aaaa failed: Invalid argument\n"
    )

    class NsockThenOk:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def run(self, argv, *, timeout_s, cwd=None):
            del timeout_s, cwd
            self.calls.append(list(argv))
            from cyberx.recon.nmap.process import CommandResult, _output_path

            if "-e" in argv:
                return CommandResult(argv=list(argv), exit_code=1, stderr=nsock)
            path = _output_path(argv)
            if path:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(xml)
            return CommandResult(argv=list(argv), exit_code=0)

    runner = NsockThenOk()
    adapter = NmapAdapter(runner=runner, available=True)
    ctx = ExecutionContext(
        mission_id=_action().mission_id,
        action_id=_action().action_id,
        timeout_s=30,
        workdir=str(tmp_path),
        reachability="REACHABLE",
        source_interface="tun0",
        source_address="10.10.15.212",
        address_family="ipv4",
    )
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), ctx)
    assert outcome.result.status is ActionResultStatus.COMPLETED
    assert outcome.result.error_code != "empty_output"
    assert len(runner.calls) == 2
    first, second = runner.calls
    assert "-4" in first and "-e" in first
    assert first[first.index("-e") + 1] == "tun0"
    assert "-S" not in first
    assert not any(t.lower().startswith("fe80:") for t in first)
    assert "-4" in second
    assert "-e" not in second
    assert "-S" not in second
    assert "eth0" not in second
    assert second[-1] == "10.10.11.23"


def test_stdout_empty_with_valid_ox_xml_is_success(tmp_path) -> None:
    """nmap -oX writes the file; empty stdout must not be classified as failure."""
    runner = FixtureProcessRunner(_xml("host_22_80.xml"), exit_code=0, stderr=b"")
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), None)
    assert outcome.result.status is ActionResultStatus.COMPLETED
    assert outcome.result.error_code is None
    assert outcome.artifact.byte_size > 0
    assert b"<nmaprun" in (outcome.artifact.body or b"")
    ox = adapter._last_argv[adapter._last_argv.index("-oX") + 1]
    assert Path(ox).is_absolute()
    assert Path(ox).is_file()
    assert adapter._last_result is not None
    assert adapter._last_result.stdout == b""
    assert adapter._last_result.exit_code == 0


def test_relative_workdir_ox_path_is_absolute_and_readable(tmp_path, monkeypatch) -> None:
    """Regression: relative -oX + cwd=workdir made nmap write XML where CyberX did not read it."""
    monkeypatch.chdir(tmp_path)
    xml = _xml("host_22_80.xml")

    class CwdHonoringRunner:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def run(self, argv, *, timeout_s, cwd=None):
            del timeout_s
            self.calls.append(list(argv))
            from cyberx.recon.nmap.process import CommandResult, _output_path

            dest = _output_path(argv)
            assert dest is not None
            path = Path(dest)
            if not path.is_absolute():
                path = Path(cwd or ".") / path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(xml)
            return CommandResult(
                argv=list(argv),
                exit_code=0,
                stdout=b"",
                stderr=b"",
                xml_path=str(path),
            )

    runner = CwdHonoringRunner()
    adapter = NmapAdapter(runner=runner, available=True)
    ctx = ExecutionContext(
        mission_id=_action().mission_id,
        action_id=_action().action_id,
        timeout_s=30,
        workdir="missions/rel-ox",
        stub=False,
        reachability="REACHABLE",
        source_interface="tun0",
        source_address="10.10.15.212",
        address_family="ipv4",
    )
    artifact = adapter.run(_action(), ctx)
    assert artifact.byte_size > 0
    assert b"<nmaprun" in (artifact.body or b"")
    ox = adapter._last_argv[adapter._last_argv.index("-oX") + 1]
    assert Path(ox).is_absolute()
    assert Path(ox).is_file()
    assert Path(ox).read_bytes() == xml
    nested = tmp_path / "missions/rel-ox" / "missions/rel-ox"
    assert not nested.exists()
    debug = adapter._last_debug
    assert debug["cwd"].startswith(str(tmp_path))
    assert Path(debug["xml_path"]).is_absolute()
    assert "-4" in adapter._last_argv
    assert "-e" in adapter._last_argv
    assert "-S" not in adapter._last_argv


def test_nonzero_exit_without_xml_is_process_error(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=1, write_xml=False, stderr=b"QUITTING!\n")
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), None)
    assert outcome.result.status is ActionResultStatus.FAILED
    assert outcome.result.error_code == "process_error"


def test_missing_xml_is_empty_artifact(tmp_path) -> None:
    runner = FixtureProcessRunner(b"", exit_code=0, write_xml=False)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), None)
    assert outcome.result.status is ActionResultStatus.FAILED
    assert outcome.result.error_code == "empty_artifact"
    assert outcome.result.error_code != "empty_output"


def test_malformed_xml_is_invalid_output(tmp_path) -> None:
    runner = FixtureProcessRunner(_xml("malformed.xml"), exit_code=0)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), None)
    assert outcome.result.status is ActionResultStatus.FAILED
    assert outcome.result.error_code == "invalid_output"


def test_stderr_warning_with_valid_xml_is_success(tmp_path) -> None:
    runner = FixtureProcessRunner(
        _xml("host_22.xml"),
        exit_code=0,
        stderr=b"Warning: Hostname did not resolve\n",
    )
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    outcome = executor.execute(_authorized(), None)
    assert outcome.result.status is ActionResultStatus.COMPLETED
    assert outcome.result.error_code is None


def test_nsock_without_xml_is_process_error_not_empty_output(tmp_path) -> None:
    nsock = b"NSOCK ERROR mksock_bind_addr() Bind to fe80::1 failed: Invalid argument"
    runner = FixtureProcessRunner(b"", exit_code=1, stderr=nsock)
    adapter = NmapAdapter(runner=runner, available=True)
    executor = ReconExecutor(nmap=adapter, nmap_enabled=True, data_dir=str(tmp_path))
    ctx = ExecutionContext(
        mission_id=_action().mission_id,
        action_id=_action().action_id,
        timeout_s=30,
        workdir=str(tmp_path),
        reachability="REACHABLE",
        source_interface="tun0",
        source_address="10.10.15.212",
        address_family="ipv4",
    )
    outcome = executor.execute(_authorized(), ctx)
    assert outcome.result.status is ActionResultStatus.FAILED
    assert outcome.result.error_code == "process_error"
    assert "nsock" in (outcome.result.error_message or "").lower()



def test_process_runner_is_the_only_subprocess_wrapper() -> None:
    assert hasattr(ProcessRunner, "run")
    src = Path(__file__).resolve().parents[2] / "src" / "cyberx" / "recon" / "nmap"
    for path in src.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "shell=True" not in text
        if path.name != "process.py":
            assert "import subprocess" not in text
