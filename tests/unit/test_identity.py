from __future__ import annotations

import pytest

from cyberx.domain.errors import IdentityError
from cyberx.domain.identity import (
    address_family,
    domain_key,
    host_key_ipv4,
    host_key_ipv6,
    host_key_name,
    is_ipv6_link_local,
    parse_http_url,
    port_key,
    tech_key,
    url_key,
    url_key_from_string,
)


def test_ipv4_canonical_has_no_leading_zeros() -> None:
    assert host_key_ipv4("10.10.11.23") == "host:ipv4:10.10.11.23"
    with pytest.raises(IdentityError):
        host_key_ipv4("010.010.011.023")


def test_ipv6_canonical_compresses() -> None:
    assert host_key_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001") == "host:ipv6:2001:db8::1"


def test_hostname_canonical_lowercases() -> None:
    assert host_key_name("Box.HTB") == "host:name:box.htb"


def test_address_family_and_link_local() -> None:
    assert address_family("10.129.92.49") == "ipv4"
    assert address_family("2001:db8::1") == "ipv6"
    assert address_family("box.htb") == "hostname"
    assert address_family("10.129.0.0/16") == "ipv4"
    assert is_ipv6_link_local("fe80::1") is True
    assert is_ipv6_link_local("10.10.15.212") is False


def test_domain_key_rejects_single_label() -> None:
    with pytest.raises(IdentityError):
        domain_key("box")


def test_port_key() -> None:
    host = host_key_ipv4("10.10.11.23")
    assert port_key(host, "tcp", 80) == "port:host:ipv4:10.10.11.23:tcp:80"


def test_url_key_includes_explicit_port() -> None:
    assert url_key("http", "box.htb", 80, "/") == "url:http://box.htb:80/"
    assert url_key_from_string("HTTP://Box.HTB/login") == "url:http://box.htb:80/login"


def test_url_rejects_credentials_and_dotdot() -> None:
    with pytest.raises(IdentityError, match="credentials"):
        parse_http_url("http://user:pass@box.htb/")
    with pytest.raises(IdentityError):
        parse_http_url("http://box.htb/../../etc/passwd")


def test_tech_slug() -> None:
    assert (
        tech_key("url:http://x:80/", "Nginx Plus", "1.2") == "tech:url:http://x:80/:nginx-plus:1.2"
    )


def test_callers_cannot_invent_host_keys() -> None:
    from datetime import datetime, timezone

    from pydantic import ValidationError

    from cyberx.domain.enums import AddressType, AssetKind, EpistemicStatus
    from cyberx.domain.ids import PREFIX_HOST, PREFIX_MISSION, new_id
    from cyberx.domain.models.assets import Host

    now = datetime.now(timezone.utc)
    with pytest.raises((IdentityError, ValidationError)):
        Host(
            asset_id=new_id(PREFIX_HOST),
            mission_id=new_id(PREFIX_MISSION),
            kind=AssetKind.HOST,
            canonical_key="invented",
            display_name="x",
            first_seen_at=now,
            last_seen_at=now,
            epistemic_status=EpistemicStatus.KNOWN,
            address_type=AddressType.IPV4,
            ipv4="10.10.11.23",
        )
