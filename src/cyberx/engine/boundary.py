"""Policy-gated execution. The only supported way to run an action."""

from __future__ import annotations

from typing import Any

from cyberx.actions.validator import ActionValidator
from cyberx.domain.enums import ActionStatus
from cyberx.domain.errors import ActionRejected, PolicyDeniedError
from cyberx.domain.models.actions import ActionRequest
from cyberx.domain.models.mission import Mission, Scope
from cyberx.engine.results import ExecutionOutcome
from cyberx.engine.stub_executor import StubExecutor
from cyberx.policy.engine import PolicyEngine
from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe
from cyberx.ports.execution import AuthorizedAction, ExecutionContext


class ExecutionBoundary:
    """
    ActionRequest → ActionValidator → PolicyEngine → ActionExecutor.

    Adapters never see an unauthorized action. AI cannot call this without
    going through the same gate.
    """

    def __init__(
        self,
        *,
        validator: ActionValidator | None = None,
        policy: PolicyEngine | None = None,
        executor: Any | None = None,
        events: EventSink | None = None,
    ) -> None:
        self._validator = validator or ActionValidator()
        self._policy = policy or PolicyEngine()
        self._executor = executor or StubExecutor()
        self._events = events or NullEventSink()

    def authorize(
        self,
        request: ActionRequest,
        mission: Mission,
        scope: Scope,
    ) -> AuthorizedAction:
        try:
            action = self._validator.validate(request)
        except ActionRejected as exc:
            emit_safe(
                self._events,
                DomainEvent(
                    event_type=EventType.ACTION_REJECTED,
                    mission_id=request.mission_id,
                    payload={"reason_code": exc.reason_code, "message": exc.message},
                ),
            )
            raise
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.ACTION_VALIDATED,
                mission_id=action.mission_id,
                payload={
                    "action_id": action.action_id,
                    "action_type": action.action_type,
                    "coverage_key": action.coverage_key,
                },
            ),
        )
        decision = self._policy.authorize(action, mission, scope)
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.POLICY_DECISION,
                mission_id=mission.mission_id,
                payload={
                    "verdict": decision.verdict.value,
                    "reason_code": decision.reason_code,
                    "action_type": action.action_type,
                },
            ),
        )
        if not decision.allowed:
            emit_safe(
                self._events,
                DomainEvent(
                    event_type=EventType.EXECUTION_DENIED,
                    mission_id=mission.mission_id,
                    payload={"reason_code": decision.reason_code},
                ),
            )
            raise PolicyDeniedError(decision.reason_code, decision.message)
        authorized_action = action.model_copy(update={"status": ActionStatus.AUTHORIZED})
        return AuthorizedAction(action=authorized_action, decision=decision)

    def run(
        self,
        request: ActionRequest,
        mission: Mission,
        scope: Scope,
        ctx: ExecutionContext | None = None,
    ) -> ExecutionOutcome:
        authorized = self.authorize(request, mission, scope)
        action = authorized.action
        context = ExecutionContext(
            mission_id=action.mission_id,
            action_id=action.action_id,
            timeout_s=action.timeout_s,
            stub=False if ctx is None else ctx.stub,
            workdir=None if ctx is None else ctx.workdir,
            source_interface=None if ctx is None else ctx.source_interface,
            source_address=None if ctx is None else ctx.source_address,
            route_cidr=None if ctx is None else ctx.route_cidr,
            reachability="UNKNOWN" if ctx is None else ctx.reachability,
            likely_tunnel=False if ctx is None else ctx.likely_tunnel,
            network_diagnostic="" if ctx is None else ctx.network_diagnostic,
            address_family="" if ctx is None else ctx.address_family,
        )
        context = context.model_copy(
            update={
                "allowed_targets": list(scope.allowed_targets),
                "allowed_networks": list(scope.allowed_networks),
                "excluded_targets": list(scope.excluded_targets),
                "excluded_networks": list(scope.excluded_networks),
                "allowed_protocols": list(scope.allowed_protocols),
                "allow_subdomains": bool(scope.allow_subdomains),
            }
        )
        return self.execute_authorized(authorized, context)

    def execute_authorized(
        self,
        authorized: AuthorizedAction,
        ctx: ExecutionContext | None = None,
    ) -> ExecutionOutcome:
        if not isinstance(authorized, AuthorizedAction) or not authorized.allowed:
            raise PolicyDeniedError("policy_bypass", "executor cannot bypass policy")
        action = authorized.action
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.ACTION_STARTED,
                mission_id=action.mission_id,
                payload={"action_id": action.action_id, "action_type": action.action_type},
            ),
        )
        outcome = self._executor.execute(authorized, ctx)
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.ACTION_COMPLETED,
                mission_id=action.mission_id,
                payload={
                    "action_id": action.action_id,
                    "status": outcome.result.status.value,
                    "observation_count": outcome.result.observation_count,
                },
            ),
        )
        return outcome
