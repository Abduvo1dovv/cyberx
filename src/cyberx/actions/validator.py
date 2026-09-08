"""Fail-closed action validation against the catalog. Does not execute."""

from __future__ import annotations

from pydantic import ValidationError

from cyberx.actions.catalog import DEFAULT_CATALOG, ActionCatalog
from cyberx.actions.coverage import coverage_key
from cyberx.domain.enums import FORBIDDEN_ACTION_MARKERS, ActionStatus, Risk
from cyberx.domain.errors import (
    ActionRejected,
    ActionValidationIssue,
    DomainValidationError,
)
from cyberx.domain.ids import PREFIX_ACTION, new_id
from cyberx.domain.models.actions import Action, ActionRequest
from cyberx.domain.time import utcnow


def _risk_rank(risk: Risk) -> int:
    return {Risk.INFO: 0, Risk.LOW: 1, Risk.MEDIUM: 2}[risk]


def _issues_from_pydantic(exc: ValidationError) -> list[ActionValidationIssue]:
    issues: list[ActionValidationIssue] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ())) or "parameters"
        issues.append(
            ActionValidationIssue(
                field=loc,
                code=str(err.get("type", "value_error")),
                message=str(err.get("msg", "")),
            )
        )
    return issues


class ActionValidator:
    """Validates action shape. Mission/scope authorization stays in PolicyEngine."""

    def __init__(self, catalog: ActionCatalog | None = None) -> None:
        self._catalog = catalog or DEFAULT_CATALOG

    def validate(self, request: ActionRequest) -> Action:
        action_type = (request.action_type or "").strip()
        if not action_type:
            raise ActionRejected(
                "malformed_action",
                "action_type is required",
                issues=[ActionValidationIssue("action_type", "missing", "required")],
            )
        lowered = action_type.lower()
        if any(marker in lowered for marker in FORBIDDEN_ACTION_MARKERS):
            raise ActionRejected(
                "forbidden_action_kind",
                f"v1 denies {action_type}",
                issues=[ActionValidationIssue("action_type", "forbidden", action_type)],
            )
        spec = self._catalog.get(action_type)
        if spec is None or not spec.enabled:
            raise ActionRejected(
                "unknown_action",
                f"unknown action type: {action_type}",
                issues=[ActionValidationIssue("action_type", "unknown", action_type)],
            )
        if not isinstance(request.parameters, dict):
            raise ActionRejected(
                "malformed_action",
                "parameters must be an object",
                issues=[ActionValidationIssue("parameters", "type", "expected object")],
            )
        try:
            parsed = spec.parameter_schema.model_validate(request.parameters)
        except ValidationError as exc:
            raise ActionRejected(
                "malformed_action",
                "invalid parameters",
                issues=_issues_from_pydantic(exc),
            ) from exc
        except DomainValidationError as exc:
            raise ActionRejected(
                "malformed_action",
                str(exc),
                issues=[ActionValidationIssue("parameters", "value_error", str(exc))],
            ) from exc
        params = parsed.model_dump()
        timeout = request.timeout_s if request.timeout_s is not None else spec.default_timeout_s
        if timeout < 1 or timeout > spec.max_timeout_s:
            raise ActionRejected(
                "timeout_exceeded",
                "timeout exceeds spec max",
                issues=[
                    ActionValidationIssue(
                        "timeout_s",
                        "timeout_exceeded",
                        f"{timeout} > {spec.max_timeout_s}",
                    )
                ],
            )
        risk = request.risk if request.risk is not None else spec.risk
        if _risk_rank(risk) > _risk_rank(spec.risk):
            raise ActionRejected(
                "risk_exceeded",
                "requested risk exceeds catalog risk",
                issues=[ActionValidationIssue("risk", "risk_exceeded", risk.value)],
            )
        if spec.prerequisites_gap_kinds and not request.prerequisites:
            raise ActionRejected(
                "missing_prerequisites",
                "prerequisites required",
                issues=[
                    ActionValidationIssue(
                        "prerequisites",
                        "missing",
                        ",".join(spec.prerequisites_gap_kinds),
                    )
                ],
            )
        if not request.target.asset_id and not request.target.canonical_locator:
            raise ActionRejected(
                "malformed_action",
                "target requires asset_id or canonical_locator",
                issues=[ActionValidationIssue("target", "missing", "locator required")],
            )
        gain = (
            request.expected_information_gain
            if request.expected_information_gain is not None
            else 0.5
        )
        key = coverage_key(action_type, request.target, params)
        return Action(
            action_id=new_id(PREFIX_ACTION),
            mission_id=request.mission_id,
            action_type=action_type,
            target=request.target,
            parameters=params,
            reason=request.reason,
            expected_information_gain=gain,
            risk=risk,
            timeout_s=timeout,
            prerequisites=list(request.prerequisites),
            evidence_expected=list(spec.produces_predicates),
            status=ActionStatus.VALIDATED,
            coverage_key=key,
            created_at=utcnow(),
        )
