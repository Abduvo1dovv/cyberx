from __future__ import annotations

import ast
from pathlib import Path

import pytest

from cyberx.actions.validator import ActionValidator
from cyberx.domain.enums import Risk
from cyberx.domain.errors import ActionRejected
from cyberx.domain.ids import PREFIX_HOST, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import ActionRequest, ActionTarget


def _req(action_type: str, locator: str, params: dict, **kwargs) -> ActionRequest:
    return ActionRequest(
        mission_id=new_id(PREFIX_MISSION),
        action_type=action_type,
        target=ActionTarget(canonical_locator=locator),
        parameters=params,
        reason=kwargs.get("reason", "test"),
        prerequisites=kwargs.get("prerequisites", ["gap_placeholder"]),
        timeout_s=kwargs.get("timeout_s"),
        risk=kwargs.get("risk"),
    )


def test_unknown_type_denied() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(_req("nuclei_scan", "10.10.11.23", {}))
    assert err.value.reason_code == "unknown_action"
    assert err.value.issues


def test_empty_action_type_denied() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(_req("", "10.10.11.23", {}))
    assert err.value.reason_code == "malformed_action"


def test_blank_action_type_denied() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(_req("   ", "10.10.11.23", {}))
    assert err.value.reason_code == "malformed_action"


def test_exploit_markers_denied() -> None:
    for atype in ("exploit_http", "validate_login", "shell_exec", "privesc_sudo", "persist_cron"):
        with pytest.raises(ActionRejected) as err:
            ActionValidator().validate(_req(atype, "10.10.11.23", {}))
        assert err.value.reason_code == "forbidden_action_kind"


def test_missing_required_params() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(_req("port_scan", "10.10.11.23", {"ports": "top1000"}))
    assert err.value.reason_code == "malformed_action"


def test_wrong_parameter_type() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req("port_scan", "10.10.11.23", {"address": "10.10.11.23", "ports": 1000})
        )
    assert err.value.reason_code == "malformed_action"


def test_disallowed_extra_parameter() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req(
                "port_scan",
                "10.10.11.23",
                {"address": "10.10.11.23", "ports": "top1000", "evil": True},
            )
        )
    assert err.value.reason_code == "malformed_action"


def test_invalid_enum_value() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req("port_scan", "10.10.11.23", {"address": "10.10.11.23", "ports": "all"})
        )
    assert err.value.reason_code == "malformed_action"


def test_invalid_host_id_type() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req("port_scan", "10.10.11.23", {"host_id": "not-a-ulid", "ports": "top1000"})
        )
    assert err.value.reason_code == "malformed_action"


def test_valid_host_id_accepted() -> None:
    action = ActionValidator().validate(
        _req(
            "port_scan",
            "10.10.11.23",
            {"host_id": new_id(PREFIX_HOST), "ports": "top1000"},
        )
    )
    assert action.action_type == "port_scan"
    assert action.coverage_key


def test_timeout_over_max() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req(
                "http_probe",
                "http://10.10.11.23/",
                {"url": "http://10.10.11.23/"},
                timeout_s=9999,
            )
        )
    assert err.value.reason_code == "timeout_exceeded"


def test_timeout_below_one() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req(
                "http_probe",
                "http://10.10.11.23/",
                {"url": "http://10.10.11.23/"},
                timeout_s=0,
            )
        )
    assert err.value.reason_code == "timeout_exceeded"


def test_missing_prerequisites() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req(
                "port_scan",
                "10.10.11.23",
                {"address": "10.10.11.23", "ports": "top1000"},
                prerequisites=[],
            )
        )
    assert err.value.reason_code == "missing_prerequisites"


def test_risk_exceeded() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req(
                "http_probe",
                "http://10.10.11.23/",
                {"url": "http://10.10.11.23/"},
                risk=Risk.MEDIUM,
            )
        )
    assert err.value.reason_code == "risk_exceeded"


def test_ftp_url_rejected() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req("http_probe", "ftp://10.10.11.23/", {"url": "ftp://10.10.11.23/"})
        )
    assert err.value.reason_code == "malformed_action"


def test_credentials_in_probe_url_rejected() -> None:
    with pytest.raises(ActionRejected):
        ActionValidator().validate(
            _req(
                "http_probe",
                "http://u:p@10.10.11.23/",
                {"url": "http://u:p@10.10.11.23/"},
            )
        )


def test_invalid_cidr_rejected() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req("network_discovery", "10.10.11.0/24", {"network": "not-a-cidr"})
        )
    assert err.value.reason_code == "malformed_action"


def test_disallowed_wordlist_rejected() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req(
                "directory_enumeration",
                "http://10.10.11.23/",
                {"url": "http://10.10.11.23/", "wordlist": "huge"},
            )
        )
    assert err.value.reason_code == "malformed_action"


def test_specified_ports_require_list() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req(
                "port_scan",
                "10.10.11.23",
                {"address": "10.10.11.23", "ports": "specified"},
            )
        )
    assert err.value.reason_code == "malformed_action"


def test_port_out_of_range() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(
            _req(
                "port_scan",
                "10.10.11.23",
                {"address": "10.10.11.23", "ports": "specified", "port_list": [70000]},
            )
        )
    assert err.value.reason_code == "malformed_action"


def test_coverage_key_stable_for_same_request() -> None:
    params = {"address": "10.10.11.23", "ports": "top1000"}
    a = ActionValidator().validate(_req("port_scan", "10.10.11.23", params))
    b = ActionValidator().validate(_req("port_scan", "10.10.11.23", params))
    assert a.coverage_key == b.coverage_key
    assert a.action_id != b.action_id


def test_structured_issues_are_dicts() -> None:
    with pytest.raises(ActionRejected) as err:
        ActionValidator().validate(_req("port_scan", "10.10.11.23", {"ports": "top1000"}))
    assert err.value.issues
    assert err.value.details["issues"][0]["field"]
    assert err.value.category == "action_validation"


def test_validator_does_not_execute_or_import_tools() -> None:
    path = Path(__file__).resolve().parents[2] / "src" / "cyberx" / "actions" / "validator.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert "subprocess" not in imported
    assert not any(name.startswith("cyberx.recon") for name in imported)
    assert not any(name.startswith("cyberx.ai") for name in imported)
    assert not any(name.startswith("cyberx.engine") for name in imported)
    assert "shell=True" not in path.read_text(encoding="utf-8")
