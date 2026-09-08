"""Optional live Linux inspect. Skipped by default. No Internet or HTB required."""

from __future__ import annotations

import os
import sys

import pytest

from cyberx.network.observer import LinuxProcObserver
from cyberx.network.resolver import NetworkResolver

pytestmark = pytest.mark.requires_network


@pytest.mark.skipif(
    os.environ.get("CYBERX_LIVE_NETWORK") != "1", reason="live network inspect disabled"
)
def test_linux_observer_inspects_without_crash() -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("linux only")
    snap = LinuxProcObserver().inspect()
    assert snap.platform == "linux"
    ctx = NetworkResolver().resolve("127.0.0.1")
    assert ctx.reachability.value in {
        "UNKNOWN",
        "REACHABLE",
        "UNREACHABLE",
        "ROUTE_MISSING",
        "BLOCKED",
        "TIMEOUT",
    }
    assert "HTB VPN" not in ctx.diagnostic
