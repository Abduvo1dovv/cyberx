"""Nmap argv is a closed list. No shell, no extra flags."""

from __future__ import annotations

import pytest

from cyberx.domain.enums import ActionStatus, Risk
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import PREFIX_ACTION, PREFIX_MISSION, new_id
from cyberx.domain.models.actions import Action, ActionTarget
from cyberx.domain.time import utcnow
from cyberx.recon.nmap.argv import build_nmap_argv, safe_target


def _action(action_type: str, locator: str, params: dict, timeout_s: int = 180) -> Action:
    return Action(
        action_id=new_id(PREFIX_ACTION),
        mission_id=new_id(PREFIX_MISSION),
        action_type=action_type,
        target=ActionTarget(canonical_locator=locator),
        parameters=params,
        reason="test",
        expected_information_gain=0.8,
        risk=Risk.LOW,
        timeout_s=timeout_s,
        status=ActionStatus.AUTHORIZED,
        coverage_key=f"{action_type}:{locator}",
        created_at=utcnow(),
    )


def test_port_scan_top1000_argv_is_deterministic() -> None:
    action = _action("port_scan", "10.10.11.23", {"address": "10.10.11.23", "ports": "top1000"})
    first = build_nmap_argv(action, xml_path="/tmp/scan.xml", timeout_s=180)
    second = build_nmap_argv(action, xml_path="/tmp/scan.xml", timeout_s=180)
    assert first == second
    assert first[0] == "nmap"
    assert first[-1] == "10.10.11.23"
    assert "-sT" in first
    assert "--top-ports" in first
    assert "1000" in first
    assert "-oX" in first
    assert "-n" in first
    assert "-Pn" in first
    assert "-sC" not in first
    assert "-A" not in first
    assert "-O" not in first
    assert "--script" not in first
    joined = " ".join(first)
    assert "shell=True" not in joined
    assert ";" not in joined
    assert "|" not in first


def test_specified_ports_are_sorted_and_validated() -> None:
    action = _action(
        "port_scan",
        "10.10.11.23",
        {"address": "10.10.11.23", "ports": "specified", "port_list": [80, 22, 443]},
    )
    argv = build_nmap_argv(action, xml_path="/tmp/scan.xml", timeout_s=30)
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == "22,80,443"


def test_udp_uses_su() -> None:
    action = _action(
        "port_scan",
        "10.10.11.23",
        {"address": "10.10.11.23", "ports": "top100", "protocol": "udp"},
    )
    argv = build_nmap_argv(action, xml_path="/tmp/scan.xml", timeout_s=60)
    assert "-sU" in argv
    assert "-sT" not in argv


def test_timeout_propagated() -> None:
    action = _action("port_scan", "10.10.11.23", {"address": "10.10.11.23", "ports": "top1000"})
    argv = build_nmap_argv(action, xml_path="/tmp/scan.xml", timeout_s=42)
    assert "--host-timeout" in argv
    assert argv[argv.index("--host-timeout") + 1] == "42s"


def test_arbitrary_flags_rejected() -> None:
    action = _action(
        "port_scan",
        "10.10.11.23",
        {"address": "10.10.11.23", "ports": "top1000", "flags": "-sC --script vuln"},
    )
    with pytest.raises(DomainValidationError):
        build_nmap_argv(action, xml_path="/tmp/scan.xml", timeout_s=30)


def test_invalid_ports_rejected() -> None:
    with pytest.raises(DomainValidationError):
        build_nmap_argv(
            _action(
                "port_scan",
                "10.10.11.23",
                {"address": "10.10.11.23", "ports": "specified", "port_list": [70000]},
            ),
            xml_path="/tmp/scan.xml",
            timeout_s=30,
        )


def test_invalid_targets_rejected() -> None:
    with pytest.raises(DomainValidationError):
        safe_target("-Pn")
    with pytest.raises(DomainValidationError):
        safe_target("10.10.11.23; rm -rf /")
    with pytest.raises(DomainValidationError):
        safe_target("10.10.11.23 | nmap")
    with pytest.raises(DomainValidationError):
        safe_target("")
    with pytest.raises(DomainValidationError):
        build_nmap_argv(
            _action("port_scan", "10.10.11.23", {"address": "-sC", "ports": "top1000"}),
            xml_path="/tmp/scan.xml",
            timeout_s=30,
        )


def test_service_enumeration_uses_sv() -> None:
    from cyberx.domain.ids import PREFIX_HOST

    host_id = new_id(PREFIX_HOST)
    action = _action(
        "service_enumeration",
        "10.10.11.23",
        {"host_id": host_id, "port": 22},
    )
    argv = build_nmap_argv(action, xml_path="/tmp/scan.xml", timeout_s=90)
    assert "-sV" in argv
    assert "-p" in argv
    assert "22" in argv


def test_optional_bind_flags_are_appended_only_when_valid() -> None:
    action = _action("port_scan", "10.10.11.23", {"address": "10.10.11.23", "ports": "top1000"})
    plain = build_nmap_argv(action, xml_path="/tmp/scan.xml", timeout_s=180)
    assert "-e" not in plain
    assert "-S" not in plain
    bound = build_nmap_argv(
        action,
        xml_path="/tmp/scan.xml",
        timeout_s=180,
        source_interface="tun0",
        source_address="10.10.14.5",
    )
    assert bound[0] == "nmap"
    assert "-e" in bound
    assert bound[bound.index("-e") + 1] == "tun0"
    assert "-S" in bound
    assert bound[bound.index("-S") + 1] == "10.10.14.5"
    assert bound[-1] == "10.10.11.23"
    with pytest.raises(DomainValidationError):
        build_nmap_argv(
            action,
            xml_path="/tmp/scan.xml",
            timeout_s=180,
            source_interface="tun0; reboot",
        )
