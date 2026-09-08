"""Directory adapter: GET-only, wildcard abort, scope, no World Model."""

from __future__ import annotations

import json

import pytest

from cyberx.domain.enums import ActionStatus, Risk
from cyberx.domain.errors import ExecutionBypassError
from cyberx.domain.ids import PREFIX_ACTION, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import Action, ActionTarget
from cyberx.domain.time import utcnow
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.ports.execution import ExecutionContext
from cyberx.recon.http.directory import DirectoryAdapter, classify_status
from cyberx.recon.http.transport import FixtureTransport, HttpRawResponse


def _action(url: str = "http://10.10.11.23/") -> Action:
    return Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type="directory_enumeration",
        target=ActionTarget(canonical_locator=url),
        parameters={"url": url, "wordlist": "small"},
        reason="directories",
        expected_information_gain=0.8,
        risk=Risk.MEDIUM,
        timeout_s=30,
        status=ActionStatus.AUTHORIZED,
        coverage_key="dir",
        created_at=utcnow(),
    )


def _ctx(action: Action, tmp_path, **extra) -> ExecutionContext:
    data = {
        "mission_id": action.mission_id,
        "action_id": action.action_id,
        "timeout_s": 30,
        "workdir": str(tmp_path),
        "allowed_targets": ["10.10.11.23"],
        "allowed_protocols": ["http", "https"],
    }
    data.update(extra)
    return ExecutionContext(**data)


def test_classify_status() -> None:
    assert classify_status(200) == "found"
    assert classify_status(301) == "redirect"
    assert classify_status(401) == "unauthorized"
    assert classify_status(403) == "forbidden"
    assert classify_status(404) == "not_found"
    assert classify_status(500) == "server_error"
    assert classify_status(0, timed_out=True) == "timeout"
    assert classify_status(0, error="connect_failure") == "unavailable"


def test_argv_is_closed_get() -> None:
    adapter = DirectoryAdapter(transport=FixtureTransport(HttpRawResponse(url="*", status=404)))
    argv = adapter.build_argv(_action())
    assert argv[0] == "GET"
    assert not any(flag.startswith("-") for flag in argv)
    assert "wordlist=small" in argv


def test_enumerates_mixed_statuses(tmp_path) -> None:
    transport = FixtureTransport(
        {
            "*": HttpRawResponse(url="*", status=404, body=b"nope"),
            "http://10.10.11.23/admin": HttpRawResponse(
                url="http://10.10.11.23/admin", status=200, body=b"<title>Admin</title>"
            ),
            "http://10.10.11.23/api": HttpRawResponse(
                url="http://10.10.11.23/api",
                status=200,
                headers={"content-type": "application/json"},
                body=b"{}",
            ),
            "http://10.10.11.23/backup": HttpRawResponse(
                url="http://10.10.11.23/backup", status=403, body=b"deny"
            ),
            "http://10.10.11.23/uploads": HttpRawResponse(
                url="http://10.10.11.23/uploads",
                status=301,
                headers={"location": "/login"},
                body=b"",
            ),
        }
    )
    adapter = DirectoryAdapter(transport=transport, max_candidates=12)
    action = _action()
    artifact = adapter.run(action, _ctx(action, tmp_path))
    body = json.loads(artifact.body or b"{}")
    assert body["wildcard_detected"] is False
    by_path = {row["path"]: row for row in body["paths"]}
    assert by_path["/admin"]["status"] == 200
    assert by_path["/admin"]["classification"] == "found"
    assert by_path["/admin"]["title"] == "Admin"
    assert by_path["/backup"]["classification"] == "forbidden"
    assert by_path["/uploads"]["classification"] == "redirect"
    assert by_path["/uploads"]["redirect"].endswith("/login")
    assert by_path["/uploads"]["out_of_scope"] is False
    assert by_path["/uploads"]["followed"] is False
    assert all(call.method == "GET" for call in transport.calls)


def test_wildcard_aborts_before_wordlist(tmp_path) -> None:
    same = HttpRawResponse(url="*", status=200, body=b"<html>same</html>")
    transport = FixtureTransport(same)
    adapter = DirectoryAdapter(transport=transport, max_candidates=12)
    action = _action()
    artifact = adapter.run(action, _ctx(action, tmp_path))
    body = json.loads(artifact.body or b"{}")
    assert body["wildcard_detected"] is True
    assert body["paths"] == []
    requested = [call.path for call in transport.calls]
    assert all("__cx_no_such_" in path for path in requested)
    assert "/admin" not in requested


def test_out_of_scope_redirect_not_followed(tmp_path) -> None:
    transport = FixtureTransport(
        {
            "*": HttpRawResponse(url="*", status=404, body=b"x"),
            "http://10.10.11.23/admin": HttpRawResponse(
                url="http://10.10.11.23/admin",
                status=302,
                headers={"location": "https://evil.example/x"},
                body=b"",
            ),
        }
    )
    adapter = DirectoryAdapter(transport=transport, max_candidates=12)
    action = _action()
    artifact = adapter.run(action, _ctx(action, tmp_path))
    body = json.loads(artifact.body or b"{}")
    admin = next(row for row in body["paths"] if row["path"] == "/admin")
    assert admin["out_of_scope"] is True
    assert admin["followed"] is False
    assert not any("evil.example" in (call.url or "") for call in transport.calls)


def test_timeout_and_unavailable(tmp_path) -> None:
    timed = FixtureTransport(HttpRawResponse(url="*", timed_out=True, error="timeout"))
    adapter = DirectoryAdapter(transport=timed)
    action = _action()
    artifact = adapter.run(action, _ctx(action, tmp_path))
    assert json.loads(artifact.body or b"{}")["status"] == "timeout"
    assert adapter._last_result is not None
    assert adapter._last_result.timed_out is True

    down = FixtureTransport(HttpRawResponse(url="*", error="connect_failure"))
    adapter = DirectoryAdapter(transport=down)
    action = _action()
    artifact = adapter.run(action, _ctx(action, tmp_path))
    assert json.loads(artifact.body or b"{}")["status"] == "connect_failure"


def test_executor_requires_authorized() -> None:
    transport = FixtureTransport(HttpRawResponse(url="*", status=404))
    executor = ReconExecutor(
        directory=DirectoryAdapter(transport=transport),
        http_enabled=True,
    )
    with pytest.raises(ExecutionBypassError):
        executor.execute(_action())  # type: ignore[arg-type]
