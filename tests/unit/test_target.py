from __future__ import annotations

import pytest

from cyberx.domain.enums import MissionMode, TargetKind
from cyberx.domain.errors import TargetValidationError
from cyberx.mission.target_parse import parse_target


def test_valid_ipv4() -> None:
    parsed = parse_target("10.10.11.23", mode=MissionMode.CTF)
    assert parsed.kind is TargetKind.IPV4
    assert parsed.normalized == "10.10.11.23"


def test_valid_cidr() -> None:
    parsed = parse_target("10.10.11.0/24", mode=MissionMode.LAB)
    assert parsed.kind is TargetKind.CIDR
    assert parsed.normalized == "10.10.11.0/24"


def test_hostname_and_domain() -> None:
    host = parse_target("box", mode=MissionMode.CTF)
    assert host.kind is TargetKind.HOSTNAME
    domain = parse_target("box.htb", mode=MissionMode.CTF)
    assert domain.kind is TargetKind.DOMAIN
    assert domain.normalized == "box.htb"


def test_https_url() -> None:
    parsed = parse_target("https://box.htb/login", mode=MissionMode.CTF)
    assert parsed.kind is TargetKind.URL
    assert parsed.url_scheme == "https"
    assert parsed.url_port == 443
    assert parsed.host == "box.htb"


def test_credentials_in_url_rejected() -> None:
    with pytest.raises(TargetValidationError, match="credentials"):
        parse_target("http://user:pass@10.10.11.23/", mode=MissionMode.CTF)


def test_ftp_url_rejected() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("ftp://box.htb/", mode=MissionMode.CTF)


def test_empty_rejected() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("   ", mode=MissionMode.CTF)


def test_loopback_denied_by_default() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("127.0.0.1", mode=MissionMode.CTF)


def test_loopback_allowed_when_operator_confirms_lab() -> None:
    parsed = parse_target("127.0.0.1", mode=MissionMode.LAB, allow_special=True)
    assert parsed.normalized == "127.0.0.1"


def test_assessment_cidr_larger_than_slash16_rejected() -> None:
    with pytest.raises(TargetValidationError, match="/16"):
        parse_target("10.0.0.0/8", mode=MissionMode.AUTHORIZED_ASSESSMENT)


def test_garbage_rejected() -> None:
    with pytest.raises(TargetValidationError):
        parse_target("not a host!!", mode=MissionMode.CTF)
