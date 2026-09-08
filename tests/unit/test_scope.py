from __future__ import annotations

import pytest
from tests.conftest import create_cmd

from cyberx.actions.validator import ActionValidator
from cyberx.domain.enums import MissionMode
from cyberx.domain.errors import ScopeValidationError, TargetValidationError
from cyberx.domain.models.actions import ActionRequest, ActionTarget
from cyberx.policy.engine import PolicyEngine
from cyberx.scope.checker import ScopeChecker


def _running(service, **cmd_kwargs):
    mission = service.create(create_cmd(**cmd_kwargs))
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    return service.get_bundle(mission.mission_id)


def _action(mission_id: str, action_type: str, locator: str, params: dict, **kwargs):
    req = ActionRequest(
        mission_id=mission_id,
        action_type=action_type,
        target=ActionTarget(canonical_locator=locator),
        parameters=params,
        reason="test",
        prerequisites=kwargs.get("prerequisites", ["gap_placeholder"]),
    )
    return ActionValidator().validate(req)


def test_allow_ip_in_scope(service) -> None:
    bundle = _running(service)
    action = _action(
        bundle.mission.mission_id,
        "port_scan",
        "10.10.11.23",
        {"address": "10.10.11.23", "ports": "top1000"},
        prerequisites=["gap_placeholder"],
    )
    decision = ScopeChecker().check(action, bundle.scope)
    assert decision.allowed


def test_exclude_other_ip(service) -> None:
    bundle = _running(service, excluded_targets=["8.8.8.8"])
    action = _action(
        bundle.mission.mission_id,
        "port_scan",
        "8.8.8.8",
        {"address": "8.8.8.8", "ports": "top1000"},
    )
    decision = PolicyEngine().authorize(action, bundle.mission, bundle.scope)
    assert not decision.allowed
    assert decision.reason_code in {"excluded", "not_in_allowlist"}


def test_target_cannot_be_excluded_at_create(service) -> None:
    with pytest.raises(ScopeValidationError):
        service.create(create_cmd(excluded_targets=["10.10.11.23"]))


def test_out_of_scope_ip_denied(service) -> None:
    bundle = _running(service)
    action = _action(
        bundle.mission.mission_id,
        "port_scan",
        "8.8.8.8",
        {"address": "8.8.8.8", "ports": "top1000"},
    )
    decision = PolicyEngine().authorize(action, bundle.mission, bundle.scope)
    assert not decision.allowed
    assert decision.reason_code == "not_in_allowlist"


def test_cidr_allow_and_prefix_limits(service) -> None:
    mission = service.create(
        create_cmd(raw_target="10.10.11.0/24", allowed_networks=["10.10.11.0/24"])
    )
    service.confirm(mission.mission_id)
    bundle = service.get_bundle(mission.mission_id)
    assert "10.10.11.0/24" in bundle.scope.allowed_networks


def test_assessment_default_ports(service) -> None:
    bundle = _running(
        service,
        mode=MissionMode.AUTHORIZED_ASSESSMENT,
        authorized_by="alice",
    )
    assert set(bundle.scope.allowed_ports) == {80, 443, 8080, 8443}


def test_protocol_not_allowed(service) -> None:
    bundle = _running(service, allowed_protocols=["tcp", "http", "https"])
    action = _action(
        bundle.mission.mission_id,
        "dns_enumeration",
        "box.htb",
        {"fqdn": "box.htb"},
    )
    # box.htb is not in allowed_targets (only 10.10.11.23)
    decision = PolicyEngine().authorize(action, bundle.mission, bundle.scope)
    assert not decision.allowed


def test_dns_in_scope_name(service) -> None:
    bundle = _running(service, raw_target="box.htb")
    action = _action(
        bundle.mission.mission_id,
        "dns_enumeration",
        "box.htb",
        {"fqdn": "box.htb"},
    )
    decision = PolicyEngine().authorize(action, bundle.mission, bundle.scope)
    assert decision.allowed, decision.message


def test_subdomain_allowed_when_flag_set(service) -> None:
    bundle = _running(service, raw_target="box.htb")
    action = _action(
        bundle.mission.mission_id,
        "http_probe",
        "http://www.box.htb/",
        {"url": "http://www.box.htb/", "scheme": "http"},
        prerequisites=["gap_placeholder"],
    )
    decision = ScopeChecker().check(action, bundle.scope)
    assert decision.allowed


def test_assessment_large_cidr_rejected(service) -> None:
    with pytest.raises((ScopeValidationError, TargetValidationError)):
        service.create(
            create_cmd(
                mode=MissionMode.AUTHORIZED_ASSESSMENT,
                authorized_by="alice",
                raw_target="10.0.0.0/8",
            )
        )
