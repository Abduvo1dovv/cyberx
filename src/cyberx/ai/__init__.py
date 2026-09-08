"""AI extension point. Providers are advisory plugins behind IntelligenceProvider."""

from cyberx.ai.factory import build_provider
from cyberx.ai.none import NoneProvider
from cyberx.ai.protocol import HypothesisDraft, IntelligenceProvider, ScoreAdvice

__all__ = [
    "HypothesisDraft",
    "IntelligenceProvider",
    "NoneProvider",
    "ScoreAdvice",
    "build_provider",
]
