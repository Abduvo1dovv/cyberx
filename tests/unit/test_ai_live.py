"""Optional live Grok test. Skipped unless CYBERX_LIVE_GROK=1."""

from __future__ import annotations

import os

import pytest

from cyberx.ai.factory import build_provider
from cyberx.config import AppConfig, ProviderConfig
from cyberx.domain.ids import PREFIX_MISSION, new_id
from cyberx.domain.models.findings import BrainContext

pytestmark = pytest.mark.requires_grok


@pytest.mark.skipif(os.environ.get("CYBERX_LIVE_GROK") != "1", reason="live Grok disabled")
def test_live_grok_hypothesize_is_structured_or_empty() -> None:
    key = os.environ.get("CYBERX_AI_API_KEY") or os.environ.get("XAI_API_KEY")
    if not key:
        pytest.skip("no Grok credentials")
    cfg = AppConfig(
        provider=ProviderConfig(
            name="grok",
            api_key=key,
            model=os.environ.get("CYBERX_AI_MODEL", "").strip() or "grok-4.5",
            timeout_s=8,
            enabled=True,
        )
    )
    provider = build_provider(cfg)
    ctx = BrainContext(
        mission_id=new_id(PREFIX_MISSION),
        intent="enumerate surface",
        mode="ctf",
        iteration=1,
        scope_digest="test",
        gaps=[{"kind": "service.http_unprobed", "id": "g1"}],
        top_findings=[{"title": "open http", "kind": "open_port"}],
    )
    drafts = provider.hypothesize(ctx)
    assert isinstance(drafts, list)
    for item in drafts:
        assert item.confidence <= 0.4
        assert "exploit" not in item.statement.lower()
