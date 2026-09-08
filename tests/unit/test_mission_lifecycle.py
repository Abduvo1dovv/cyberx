from __future__ import annotations

import pytest
from tests.conftest import create_cmd

from cyberx.domain.enums import MissionMode, MissionStatus, StopReason
from cyberx.domain.errors import IllegalMissionTransition, ScopeFrozenError


def test_create_starts_in_created(service) -> None:
    mission = service.create(create_cmd())
    assert mission.status is MissionStatus.CREATED
    assert mission.created_at.tzinfo is not None
    bundle = service.get_bundle(mission.mission_id)
    assert bundle.scope.frozen is False


def test_confirm_freezes_scope(service) -> None:
    mission = service.create(create_cmd())
    confirmed = service.confirm(mission.mission_id)
    assert confirmed.status is MissionStatus.CONFIRMED
    bundle = service.get_bundle(mission.mission_id)
    assert bundle.scope.frozen is True
    assert bundle.seed_assets  # IP target seeds a host


def test_scope_mutation_rejected_after_confirm(service) -> None:
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    with pytest.raises(ScopeFrozenError):
        service.update_scope(mission.mission_id, allowed_targets=["10.10.11.24"])


def test_scope_mutation_allowed_while_created(service) -> None:
    mission = service.create(create_cmd())
    scope = service.update_scope(mission.mission_id, allowed_targets=["10.10.11.23", "box.htb"])
    assert "box.htb" in scope.allowed_targets
    assert scope.frozen is False


def test_start_pause_resume(service) -> None:
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    started = service.start(mission.mission_id)
    assert started.status is MissionStatus.RUNNING
    assert started.started_at is not None
    paused = service.pause(mission.mission_id)
    assert paused.status is MissionStatus.PAUSED
    resumed = service.resume(mission.mission_id)
    assert resumed.status is MissionStatus.RUNNING


def test_stop_from_created(service) -> None:
    mission = service.create(create_cmd())
    stopped = service.stop(mission.mission_id)
    assert stopped.status is MissionStatus.STOPPED
    assert stopped.stop_reason is StopReason.OPERATOR
    assert stopped.ended_at is not None


def test_complete_and_fail(service) -> None:
    mission = service.create(create_cmd())
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    done = service.complete(mission.mission_id, StopReason.OBJECTIVES_MET)
    assert done.status is MissionStatus.COMPLETED
    with pytest.raises(IllegalMissionTransition):
        service.start(mission.mission_id)


def test_invalid_transitions(service) -> None:
    mission = service.create(create_cmd())
    with pytest.raises(IllegalMissionTransition):
        service.start(mission.mission_id)
    with pytest.raises(IllegalMissionTransition):
        service.pause(mission.mission_id)
    service.confirm(mission.mission_id)
    with pytest.raises(IllegalMissionTransition):
        service.resume(mission.mission_id)


def test_terminal_state_protection(service) -> None:
    mission = service.create(create_cmd())
    service.stop(mission.mission_id)
    for op in (service.confirm, service.start, service.pause, service.resume):
        with pytest.raises(IllegalMissionTransition):
            op(mission.mission_id)


def test_assessment_requires_authorized_by(service) -> None:
    with pytest.raises(Exception):
        service.create(create_cmd(mode=MissionMode.AUTHORIZED_ASSESSMENT, authorized_by=None))


def test_happy_path_assessment_single_host(service) -> None:
    mission = service.create(
        create_cmd(
            mode=MissionMode.AUTHORIZED_ASSESSMENT,
            authorized_by="alice",
            raw_target="10.10.11.23",
        )
    )
    service.confirm(mission.mission_id)
    service.start(mission.mission_id)
    assert service.get(mission.mission_id).status is MissionStatus.RUNNING
