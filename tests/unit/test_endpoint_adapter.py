"""endpoint_discovery adapter is parse-only."""

from __future__ import annotations

import pytest
from tests.conftest import FIXTURES

from cyberx.domain.enums import ActionStatus, Risk
from cyberx.domain.errors import ExecutionBypassError
from cyberx.domain.ids import PREFIX_ACTION, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import Action, ActionTarget
from cyberx.domain.time import utcnow
from cyberx.engine.recon_executor import ReconExecutor
from cyberx.ports.execution import ExecutionContext
from cyberx.recon.http.endpoint import EndpointAdapter, FixtureHtmlSource


def _action(url: str = "http://10.10.11.23/") -> Action:
    return Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type="endpoint_discovery",
        target=ActionTarget(canonical_locator=url),
        parameters={"url": url},
        reason="parse page",
        expected_information_gain=0.8,
        risk=Risk.INFO,
        timeout_s=30,
        status=ActionStatus.AUTHORIZED,
        coverage_key="epdisc",
        created_at=utcnow(),
    )


def test_argv_is_parse_artifact_not_http(tmp_path) -> None:
    html = (FIXTURES / "endpoint" / "forms.html").read_text(encoding="utf-8")
    adapter = EndpointAdapter(source=FixtureHtmlSource({"http://10.10.11.23/": html}))
    action = _action()
    argv = adapter.build_argv(action)
    assert argv == ["parse-artifact", "http://10.10.11.23/"]
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=30,
        workdir=str(tmp_path),
    )
    artifact = adapter.run(action, ctx)
    assert artifact.adapter_name == "endpoint_adapter"
    assert b"html" in (artifact.body or b"") or b"login" in (artifact.body or b"")


def test_missing_artifact_completes_empty(tmp_path) -> None:
    adapter = EndpointAdapter()
    action = _action()
    ctx = ExecutionContext(
        mission_id=action.mission_id,
        action_id=action.action_id,
        timeout_s=30,
        workdir=str(tmp_path),
    )
    artifact = adapter.run(action, ctx)
    assert b"endpoints" in (artifact.body or b"")


def test_executor_requires_authorized_action(tmp_path) -> None:
    executor = ReconExecutor(endpoint=EndpointAdapter(), http_enabled=True, data_dir=str(tmp_path))
    with pytest.raises(ExecutionBypassError):
        executor.execute(_action())  # type: ignore[arg-type]
