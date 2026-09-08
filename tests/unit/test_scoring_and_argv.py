from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from cyberx.actions.scoring import ScoreFactors, compute_score
from cyberx.domain.enums import Risk
from cyberx.domain.errors import DomainValidationError
from cyberx.domain.ids import PREFIX_ACTION, PREFIX_TOOL_RUN, new_id
from cyberx.domain.models.actions import ToolRun


def test_score_zero_when_no_novelty() -> None:
    factors = ScoreFactors(
        mission_relevance=1,
        information_gain=1,
        evidence_strength=1,
        p_useful=1,
        novelty=0,
        dependency_readiness=1,
        cost=0.2,
        risk=0.1,
    )
    assert compute_score(factors) == 0.0


def test_score_formula() -> None:
    factors = ScoreFactors(
        mission_relevance=1,
        information_gain=1,
        evidence_strength=1,
        p_useful=1,
        novelty=1,
        dependency_readiness=1,
        cost=0,
        risk=0,
    )
    assert compute_score(factors) == pytest.approx(1.0)


def test_toolrun_rejects_shell_operators() -> None:
    now = datetime.now(timezone.utc)
    with pytest.raises((DomainValidationError, ValidationError)):
        ToolRun(
            tool_run_id=new_id(PREFIX_TOOL_RUN),
            action_id=new_id(PREFIX_ACTION),
            adapter_name="nmap_adapter",
            argv=["nmap", "-sV", "10.10.11.23", ";", "id"],
            started_at=now,
            status="running",
        )


def test_risk_enum_has_no_high() -> None:
    assert set(Risk) == {Risk.INFO, Risk.LOW, Risk.MEDIUM}
