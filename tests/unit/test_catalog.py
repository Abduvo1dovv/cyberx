from __future__ import annotations

from cyberx.actions.catalog import DEFAULT_CATALOG
from cyberx.actions.coverage import coverage_key
from cyberx.actions.validator import ActionValidator
from cyberx.actions.wordlists import DIRECTORY_WORDLIST, SUBDOMAIN_WORDLIST
from cyberx.domain.enums import V1_ACTION_TYPES
from cyberx.domain.ids import PREFIX_MISSION, new_id
from cyberx.domain.models.actions import ActionRequest, ActionTarget


def test_nine_types_registered() -> None:
    types = DEFAULT_CATALOG.types()
    assert types == V1_ACTION_TYPES
    assert len(DEFAULT_CATALOG.all()) == 9
    for name in V1_ACTION_TYPES:
        spec = DEFAULT_CATALOG.get(name)
        assert spec is not None
        assert spec.action_type == name
        assert spec.summary
        assert spec.parameter_schema is not None
        assert spec.produces_predicates
        assert spec.risk
        assert 0.0 <= spec.cost <= 1.0
        assert spec.default_timeout_s <= spec.max_timeout_s
        assert spec.max_attempts >= 1
        assert spec.allowed_modes
        assert spec.adapter_name
        assert spec.enabled is True


def test_no_exploit_types_in_catalog() -> None:
    joined = " ".join(DEFAULT_CATALOG.types())
    for marker in ("exploit", "shell", "privesc", "persist"):
        assert marker not in joined


def test_wordlists_match_spec() -> None:
    assert "www" in SUBDOMAIN_WORDLIST
    assert len(SUBDOMAIN_WORDLIST) <= 100
    assert "admin" in DIRECTORY_WORDLIST
    assert len(DIRECTORY_WORDLIST) <= 50


def test_coverage_key_deterministic() -> None:
    target = ActionTarget(canonical_locator="10.10.11.23")
    params = {"address": "10.10.11.23", "ports": "top1000", "protocol": "tcp"}
    a = coverage_key("port_scan", target, params)
    b = coverage_key("port_scan", target, params)
    assert a == b
    assert len(a) == 64
    c = coverage_key("port_scan", target, {**params, "ports": "top100"})
    assert a != c


def test_validated_action_has_coverage_key() -> None:
    req = ActionRequest(
        mission_id=new_id(PREFIX_MISSION),
        action_type="dns_enumeration",
        target=ActionTarget(canonical_locator="box.htb"),
        parameters={"fqdn": "box.htb"},
        reason="resolve names",
        prerequisites=["gap_placeholder"],
    )
    action = ActionValidator().validate(req)
    assert action.coverage_key == coverage_key("dns_enumeration", action.target, action.parameters)
    assert action.evidence_expected
    assert action.timeout_s == 30
