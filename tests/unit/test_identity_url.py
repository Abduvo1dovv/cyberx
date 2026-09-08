"""URL canonical identity: fragments, query, ports, credentials."""

from __future__ import annotations

import pytest

from cyberx.domain.errors import IdentityError
from cyberx.domain.identity import parse_http_url, url_key, url_key_from_string


def test_fragment_stripped() -> None:
    assert url_key_from_string("http://10.10.11.23/login#x") == url_key_from_string(
        "http://10.10.11.23/login"
    )


def test_query_does_not_change_identity() -> None:
    assert url_key_from_string("http://10.10.11.23/a?b=1") == url_key_from_string(
        "http://10.10.11.23/a"
    )


def test_default_ports_normalized() -> None:
    http = parse_http_url("http://10.10.11.23/login")
    https = parse_http_url("https://box.htb/login")
    assert http[2] == 80
    assert https[2] == 443
    assert url_key(*http) == "url:http://10.10.11.23:80/login"
    assert url_key(*https) == "url:https://box.htb:443/login"


def test_hostname_case_and_trailing_slash() -> None:
    a = url_key_from_string("http://Box.HTB/admin/")
    b = url_key_from_string("http://box.htb/admin")
    assert a == b


def test_credentials_rejected() -> None:
    with pytest.raises(IdentityError):
        parse_http_url("http://user:pass@10.10.11.23/")


def test_equivalent_urls_dedup() -> None:
    keys = {
        url_key_from_string("http://10.10.11.23:80/login"),
        url_key_from_string("http://10.10.11.23/login"),
        url_key_from_string("http://10.10.11.23/login?next=/"),
        url_key_from_string("http://10.10.11.23/login#top"),
    }
    assert keys == {"url:http://10.10.11.23:80/login"}
