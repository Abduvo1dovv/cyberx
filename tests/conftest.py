from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cyberx.domain.enums import MissionMode
from cyberx.domain.ids import PREFIX_ARTIFACT, PREFIX_MISSION, PREFIX_TOOL_RUN, new_id
from cyberx.mission.commands import CreateMissionCmd
from cyberx.mission.memory import InMemoryMissionStore
from cyberx.mission.service import MissionService
from cyberx.ports.execution import RawArtifact

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def service() -> MissionService:
    return MissionService(InMemoryMissionStore())


def create_cmd(**overrides) -> CreateMissionCmd:
    data = {
        "name": "box recon",
        "intent": "enumerate the in-scope attack surface",
        "raw_target": "10.10.11.23",
        "mode": MissionMode.CTF,
    }
    data.update(overrides)
    return CreateMissionCmd(**data)


def artifact_from_fixture(
    relative: str,
    *,
    adapter_name: str,
    media_type: str,
    source_locator: str | None = None,
    in_memory: bool = True,
    mission_id: str | None = None,
) -> RawArtifact:
    file_path = FIXTURES / relative
    raw = file_path.read_bytes()
    return RawArtifact(
        artifact_id=new_id(PREFIX_ARTIFACT),
        tool_run_id=new_id(PREFIX_TOOL_RUN),
        adapter_name=adapter_name,
        media_type=media_type,
        sha256=hashlib.sha256(raw).hexdigest(),
        byte_size=len(raw),
        body=raw if in_memory else None,
        path=None if in_memory else str(file_path),
        mission_id=mission_id or new_id(PREFIX_MISSION),
        source_locator=source_locator,
    )


def shapes(observations) -> list[dict]:
    return [
        {
            "predicate": item.predicate,
            "subject_hint": item.subject_hint,
            "object": item.object,
        }
        for item in observations
    ]


def load_golden(relative: str) -> list[dict]:
    return json.loads((FIXTURES / relative).read_text(encoding="utf-8"))
