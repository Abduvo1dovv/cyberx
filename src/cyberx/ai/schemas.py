"""Structured Grok request/response schemas. Invalid JSON is discarded."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cyberx.ai.protocol import HypothesisDraft, ScoreAdvice


class HypothesesResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    hypotheses: list[HypothesisDraft] = Field(default_factory=list)


class AdviceResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    advice: list[ScoreAdvice] = Field(default_factory=list)


class ExplanationResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    explanation: str = ""
    why_it_matters: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)


class ReportSectionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    section: str = ""
    uncertain: bool = True
