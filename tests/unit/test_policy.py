from __future__ import annotations

import pytest
from tests.conftest import create_cmd

from cyberx.actions.validator import ActionValidator
from cyberx.domain.enums import MissionMode
from cyberx.domain.errors import ActionRejected
from cyberx.domain.ids import PREFIX_MISSION, new_id
from cyberx.domain.models.actions import ActionRequest, ActionTarget
from cyberx.policy.engine import PolicyEngine


def _running_bundle(service, **kwargs):
    mission = service.create(create_cmd(**kwargs))
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    return service.get_bundle(mission.mission_id)


def _req(mission_id, action_type, locator, params, **kwargs) -> ActionRequest:
    return ActionRequest(
        mission_id=mission_id,
        action_type=action_type,
        target=ActionTarget(canonical_locator=locator),
        parameters=params,
        reason=kwargs.get("reason", "test"),
        prerequisites=kwargs.get("prerequisites", ["gap_placeholder"]),
        timeout_s=kwargs.get("timeout_s"),
        risk=kwargs.get("risk"),
    )


def test_unknown_action_denied(service) -> None:
    bundle = _running_bundle(service)
    decision = PolicyEngine().authorize(
        _req(bundle.mission.mission_id, "nuclei_scan", "10.10.11.23", {}),
        bundle.mission,
        bundle.scope,
    )
    assert not decision.allowed
    assert decision.reason_code == "unknown_action"


def test_malformed_action_denied(service) -> None:
    bundle = _running_bundle(service)
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req(bundle.mission.mission_id, "port_scan", "10.10.11.23", {"ports": "top1000"})
        )
    assert err.value.reason_code == "malformed_action"
    decision = PolicyEngine().authorize(
        _req(bundle.mission.mission_id, "port_scan", "10.10.11.23", {"ports": "top1000"}),
        bundle.mission,
        bundle.scope,
    )
    assert not decision.allowed
    assert decision.reason_code == "malformed_action"


def test_exploit_like_denied(service) -> None:
    bundle = _running_bundle(service)
    for atype in ("exploit_http", "validate_rce", "privesc_sudo", "persist_cron", "shell_command"):
        decision = PolicyEngine().authorize(
            _req(bundle.mission.mission_id, atype, "10.10.11.23", {}),
            bundle.mission,
            bundle.scope,
        )
        assert not decision.allowed
        assert decision.reason_code == "forbidden_action_kind"


def test_invalid_mission_state_denied(service) -> None:
    mission = service.create(create_cmd())
    bundle = service.get_bundle(mission.mission_id)
    req = _req(
        mission.mission_id,
        "port_scan",
        "10.10.11.23",
        {"address": "10.10.11.23", "ports": "top1000"},
    )
    decision = PolicyEngine().authorize(req, bundle.mission, bundle.scope)
    assert not decision.allowed
    assert decision.reason_code in {"mission_not_running", "scope_not_frozen"}


def test_out_of_scope_denied(service) -> None:
    bundle = _running_bundle(service)
    decision = PolicyEngine().authorize(
        _req(
            bundle.mission.mission_id,
            "port_scan",
            "1.2.3.4",
            {"address": "1.2.3.4", "ports": "top1000"},
        ),
        bundle.mission,
        bundle.scope,
    )
    assert not decision.allowed
    assert decision.reason_code == "not_in_allowlist"


def test_timeout_exceeded_denied(service) -> None:
    bundle = _running_bundle(service)
    decision = PolicyEngine().authorize(
        _req(
            bundle.mission.mission_id,
            "http_probe",
            "http://10.10.11.23/",
            {"url": "http://10.10.11.23/"},
            timeout_s=9999,
        ),
        bundle.mission,
        bundle.scope,
    )
    assert not decision.allowed
    assert decision.reason_code == "timeout_exceeded"


def test_missing_prerequisites_denied(service) -> None:
    bundle = _running_bundle(service)
    decision = PolicyEngine().authorize(
        _req(
            bundle.mission.mission_id,
            "port_scan",
            "10.10.11.23",
            {"address": "10.10.11.23", "ports": "top1000"},
            prerequisites=[],
        ),
        bundle.mission,
        bundle.scope,
    )
    assert not decision.allowed
    assert decision.reason_code == "missing_prerequisites"


def test_in_scope_port_scan_allowed(service) -> None:
    bundle = _running_bundle(service)
    decision = PolicyEngine().authorize(
        _req(
            bundle.mission.mission_id,
            "port_scan",
            "10.10.11.23",
            {"address": "10.10.11.23", "ports": "top1000"},
        ),
        bundle.mission,
        bundle.scope,
    )
    assert decision.allowed, decision.message


def test_assessment_top1000_denied_when_ports_restricted(service) -> None:
    bundle = _running_bundle(service, mode=MissionMode.AUTHORIZED_ASSESSMENT, authorized_by="bob")
    decision = PolicyEngine().authorize(
        _req(
            bundle.mission.mission_id,
            "port_scan",
            "10.10.11.23",
            {"address": "10.10.11.23", "ports": "top1000"},
        ),
        bundle.mission,
        bundle.scope,
    )
    assert not decision.allowed
    assert decision.reason_code == "port_not_allowed"
    decision2 = PolicyEngine().authorize(
        _req(
            bundle.mission.mission_id,
            "port_scan",
            "10.10.11.23",
            {"address": "10.10.11.23", "ports": "specified", "port_list": [80, 443]},
        ),
        bundle.mission,
        bundle.scope,
    )
    assert decision2.allowed, decision2.message


def test_validator_rejects_unknown_without_policy() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            ActionRequest(
                mission_id=new_id(PREFIX_MISSION),
                action_type="msf_exploit",
                target=ActionTarget(canonical_locator="10.10.11.23"),
                parameters={},
                reason="no",
            )
        )
    assert err.value.reason_code == "forbidden_action_kind"


def test_catalog_cannot_register_new_types() -> None:
    assert not hasattr(
        DEFAULT_CATALOG := __import__(
            "cyberx.actions.catalog", fromlist=["DEFAULT_CATALOG"]
        ).DEFAULT_CATALOG,
        "register",
    )
    assert DEFAULT_CATALOG.get("exploit") is None
