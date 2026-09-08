"""Mission status transitions (SPEC §4.1). Command-based so start ≠ resume."""

from __future__ import annotations

from cyberx.domain.enums import MissionStatus, StrEnum
from cyberx.domain.errors import IllegalMissionTransition


class MissionCommand(StrEnum):
    CONFIRM = "confirm"
    START = "start"
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"
    COMPLETE = "complete"
    FAIL = "fail"


_TRANSITIONS: dict[tuple[MissionStatus, MissionCommand], MissionStatus] = {
    (MissionStatus.CREATED, MissionCommand.CONFIRM): MissionStatus.CONFIRMED,
    (MissionStatus.CREATED, MissionCommand.STOP): MissionStatus.STOPPED,
    (MissionStatus.CONFIRMED, MissionCommand.START): MissionStatus.RUNNING,
    (MissionStatus.CONFIRMED, MissionCommand.STOP): MissionStatus.STOPPED,
    (MissionStatus.RUNNING, MissionCommand.PAUSE): MissionStatus.PAUSED,
    (MissionStatus.RUNNING, MissionCommand.STOP): MissionStatus.STOPPED,
    (MissionStatus.RUNNING, MissionCommand.COMPLETE): MissionStatus.COMPLETED,
    (MissionStatus.RUNNING, MissionCommand.FAIL): MissionStatus.FAILED,
    (MissionStatus.PAUSED, MissionCommand.RESUME): MissionStatus.RUNNING,
    (MissionStatus.PAUSED, MissionCommand.STOP): MissionStatus.STOPPED,
    (MissionStatus.PAUSED, MissionCommand.FAIL): MissionStatus.FAILED,
}

TERMINAL = frozenset({MissionStatus.COMPLETED, MissionStatus.STOPPED, MissionStatus.FAILED})


def destination(current: MissionStatus, command: MissionCommand) -> MissionStatus:
    try:
        return _TRANSITIONS[(current, command)]
    except KeyError as exc:
        raise IllegalMissionTransition(current.value, command.value) from exc


def can_command(current: MissionStatus, command: MissionCommand) -> bool:
    return (current, command) in _TRANSITIONS


def assert_transition(current: MissionStatus, dest: MissionStatus) -> None:
    """Status-to-status check; prefer assert_command in services."""
    allowed = {d for (c, _cmd), d in _TRANSITIONS.items() if c is current}
    if dest not in allowed:
        raise IllegalMissionTransition(current.value, dest.value)


def assert_command(current: MissionStatus, command: MissionCommand) -> MissionStatus:
    return destination(current, command)
