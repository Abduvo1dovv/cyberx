"""Optional live DNS tests. Skipped unless CYBERX_LIVE_DNS=1."""

from __future__ import annotations

import os

import pytest

from cyberx.recon.dns.resolver import UdpDnsResolver

pytestmark = pytest.mark.requires_dns


@pytest.mark.skipif(os.environ.get("CYBERX_LIVE_DNS") != "1", reason="live DNS disabled")
def test_live_localhost_query_does_not_crash() -> None:
    resolver = UdpDnsResolver()
    answer = resolver.query("localhost", "A", 2.0)
    assert answer.rcode in {"NOERROR", "NXDOMAIN", "SERVFAIL", "TIMEOUT", "REFUSED"}
