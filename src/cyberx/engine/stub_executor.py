"""Stub executor. Accepts only AuthorizedAction. No subprocess, no network."""

from __future__ import annotations

import json

from cyberx.domain.enums import ActionResultStatus, ActionStatus
from cyberx.domain.errors import ExecutionBypassError
from cyberx.domain.ids import PREFIX_RESULT, new_id
from cyberx.domain.models.actions import ActionResult, ToolRun
from cyberx.domain.time import utcnow
from cyberx.engine.results import ExecutionOutcome
from cyberx.ports.execution import AuthorizedAction, ExecutionContext
from cyberx.recon.stub import StubAdapter, synthetic_payload


class StubExecutor:
    def __init__(self, adapter: StubAdapter | None = None) -> None:
        self._adapter = adapter or StubAdapter()

    def execute(
        self, authorized: AuthorizedAction, ctx: ExecutionContext | None = None
    ) -> ExecutionOutcome:
        if not isinstance(authorized, AuthorizedAction):
            raise ExecutionBypassError()
        if not authorized.decision.allowed:
            raise ExecutionBypassError("policy did not allow this action")
        action = authorized.action
        context = ctx or ExecutionContext(
            mission_id=action.mission_id,
            action_id=action.action_id,
            timeout_s=action.timeout_s,
            stub=True,
        )
        started = utcnow()
        argv = self._adapter.build_argv(action)
        artifact = self._adapter.run(action, context)
        ended = utcnow()
        tool_run = ToolRun(
            tool_run_id=artifact.tool_run_id,
            action_id=action.action_id,
            adapter_name=self._adapter.name,
            argv=argv,
            started_at=started,
            ended_at=ended,
            status="completed",
            exit_code=0,
            artifact_id=artifact.artifact_id,
            timed_out=False,
            unavailable=False,
        )
        result = ActionResult(
            result_id=new_id(PREFIX_RESULT),
            action_id=action.action_id,
            tool_run_id=artifact.tool_run_id,
            status=ActionResultStatus.COMPLETED,
            started_at=started,
            ended_at=ended,
            observation_count=_count_obs(artifact.body),
        )
        completed = action.model_copy(update={"status": ActionStatus.COMPLETED})
        return ExecutionOutcome(
            action=completed,
            result=result,
            tool_run=tool_run,
            artifact=artifact,
            observations=synthetic_payload(action),
        )


def _count_obs(body: bytes | None) -> int:
    if not body:
        return 0
    data = json.loads(body.decode("utf-8"))
    keys = (
        "ports",
        "hosts",
        "services",
        "paths",
        "endpoints",
        "subdomains",
        "records",
        "technologies",
    )
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return len(value)
    return 1
