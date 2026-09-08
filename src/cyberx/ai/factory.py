"""Compose an IntelligenceProvider from AppConfig. Lazy-imports Grok."""

from __future__ import annotations

from typing import Any

from cyberx.ai.budget import GuardedProvider
from cyberx.ai.none import NoneProvider
from cyberx.ai.protocol import IntelligenceProvider
from cyberx.config import AppConfig, ProviderConfig
from cyberx.ports.events import EventSink


def build_provider(
    config: AppConfig | ProviderConfig,
    events: EventSink | None = None,
    transport: Any = None,
) -> IntelligenceProvider:
    settings = config.provider if isinstance(config, AppConfig) else config
    name = (settings.name or "none").strip().lower()
    inner: IntelligenceProvider
    if name == "grok":
        from cyberx.ai.providers.grok import GrokProvider

        inner = GrokProvider(settings, events=events, transport=transport)
    else:
        inner = NoneProvider()
    return GuardedProvider(inner, settings, events)
