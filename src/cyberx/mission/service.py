"""MissionService — create, confirm, start, pause, resume, stop."""

from __future__ import annotations

from datetime import datetime

from cyberx.domain.enums import (
    MissionStatus,
    StopReason,
    TimelineKind,
)
from cyberx.domain.errors import (
    DomainValidationError,
    LocatorRejected,
    ScopeFrozenError,
    ScopeValidationError,
)
from cyberx.domain.ids import (
    PREFIX_MISSION,
    PREFIX_SCOPE,
    PREFIX_TARGET,
    PREFIX_TIMELINE,
    new_id,
)
from cyberx.domain.models.findings import TimelineEvent
from cyberx.domain.models.mission import Mission, Scope, Target
from cyberx.domain.time import utcnow
from cyberx.mission.commands import ConfirmLocatorCmd, CreateMissionCmd
from cyberx.mission.locator import (
    confirm_locator as apply_confirm_locator,
)
from cyberx.mission.locator import (
    mark_locator_unreachable as apply_unreachable,
)
from cyberx.mission.locator import (
    observe_locator as apply_observe_locator,
)
from cyberx.mission.locator import (
    seed_identity_fields,
)
from cyberx.mission.ports import MissionBundle, MissionStore
from cyberx.mission.scope_build import (
    build_scope_fields,
    ensure_scope_includes_target,
    target_is_excluded,
    validate_scope_values,
)
from cyberx.mission.seed import host_for_locator, seed_assets_for_target
from cyberx.mission.state_machine import MissionCommand, assert_command
from cyberx.mission.target_parse import parse_target
from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe


class MissionService:
    def __init__(
        self,
        store: MissionStore,
        *,
        clock=utcnow,
        events: EventSink | None = None,
    ) -> None:
        self._store = store
        self._clock = clock
        self._events = events or NullEventSink()

    def create(self, cmd: CreateMissionCmd) -> Mission:
        now = self._clock()
        parsed = parse_target(
            cmd.raw_target, mode=cmd.mode, allow_special=cmd.allow_special_targets
        )
        fields = build_scope_fields(parsed, cmd.mode, cmd.scope_overrides())
        mission_id = new_id(PREFIX_MISSION)
        identity = seed_identity_fields(parsed, now)
        target = Target(
            target_id=new_id(PREFIX_TARGET),
            mission_id=mission_id,
            raw_input=cmd.raw_target.strip(),
            kind=parsed.kind,
            normalized=parsed.normalized,
            created_at=now,
            url_scheme=parsed.url_scheme,
            url_port=parsed.url_port,
            url_path=parsed.url_path,
            **identity,
        )
        scope = Scope(
            scope_id=new_id(PREFIX_SCOPE),
            mission_id=mission_id,
            created_at=now,
            frozen=False,
            version=1,
            **fields,
        )
        mission = Mission(
            mission_id=mission_id,
            name=cmd.name,
            intent=cmd.intent,
            mode=cmd.mode,
            status=MissionStatus.CREATED,
            target_id=target.target_id,
            scope_id=scope.scope_id,
            policy_profile=cmd.policy_profile,
            ai_provider=cmd.ai_provider,
            max_iterations=cmd.max_iterations,
            max_runtime_s=cmd.max_runtime_s,
            min_action_score=cmd.min_action_score,
            created_at=now,
            updated_at=now,
            authorized_by=cmd.authorized_by,
            authorization_note=cmd.authorization_note,
        )
        bundle = MissionBundle(mission, target, scope)
        self._append(bundle, TimelineKind.MISSION_STATUS, "mission created", now)
        self._store.save(bundle)
        return mission

    def get(self, mission_id: str) -> Mission:
        return self._store.get(mission_id).mission

    def get_bundle(self, mission_id: str) -> MissionBundle:
        return self._store.get(mission_id)

    def list_missions(self) -> list[MissionBundle]:
        missions = self._store.list_missions()
        return [self._store.get(item.mission_id) for item in missions]

    def update_scope(self, mission_id: str, **changes) -> Scope:
        """Mutate scope. Only legal while status is CREATED. AI has no access here."""
        bundle = self._store.get(mission_id)
        if bundle.mission.status is not MissionStatus.CREATED:
            raise ScopeFrozenError("scope can only be modified while mission status is CREATED")
        if bundle.scope.frozen:
            raise ScopeFrozenError("scope is frozen")
        allowed = {
            "allowed_targets",
            "allowed_networks",
            "allowed_ports",
            "allowed_protocols",
            "excluded_targets",
            "excluded_networks",
            "excluded_ports",
            "allow_subdomains",
            "time_window_start",
            "time_window_end",
            "follow_redirects_in_scope_only",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise DomainValidationError(f"cannot set scope fields: {unknown}")
        updated = bundle.scope.model_copy(update=changes)
        parsed = parse_target(bundle.target.raw_input, mode=bundle.mission.mode, allow_special=True)
        validate_scope_values(
            mode=bundle.mission.mode,
            allowed_targets=updated.allowed_targets,
            allowed_networks=updated.allowed_networks,
            allowed_protocols=updated.allowed_protocols,
            excluded_targets=updated.excluded_targets,
            excluded_networks=updated.excluded_networks,
            parsed=parsed,
        )
        now = self._clock()
        bundle.scope = updated
        bundle.mission = bundle.mission.model_copy(update={"updated_at": now})
        self._append(bundle, TimelineKind.OPERATOR, "scope updated", now)
        self._store.save(bundle)
        return bundle.scope

    def confirm(self, mission_id: str) -> Mission:
        bundle = self._store.get(mission_id)
        assert_command(bundle.mission.status, MissionCommand.CONFIRM)

        parsed = parse_target(
            bundle.target.raw_input,
            mode=bundle.mission.mode,
            allow_special=True,
        )
        scope = ensure_scope_includes_target(bundle.scope, bundle.target, parsed)
        if target_is_excluded(
            parsed,
            excluded_targets=scope.excluded_targets,
            excluded_networks=scope.excluded_networks,
        ):
            raise ScopeValidationError("target itself is excluded from scope")
        validate_scope_values(
            mode=bundle.mission.mode,
            allowed_targets=scope.allowed_targets,
            allowed_networks=scope.allowed_networks,
            allowed_protocols=scope.allowed_protocols,
            excluded_targets=scope.excluded_targets,
            excluded_networks=scope.excluded_networks,
            parsed=parsed,
        )
        now = self._clock()
        frozen = scope.model_copy(update={"frozen": True, "version": 1})
        seeds = seed_assets_for_target(bundle.mission.mission_id, bundle.target, parsed, now)
        mission = bundle.mission.model_copy(
            update={"status": MissionStatus.CONFIRMED, "updated_at": now}
        )
        bundle.mission = mission
        bundle.scope = frozen
        bundle.seed_assets = seeds
        self._append(bundle, TimelineKind.MISSION_STATUS, "mission confirmed; scope frozen", now)
        self._store.save(bundle)
        return mission

    def confirm_locator(self, mission_id: str, cmd: ConfirmLocatorCmd) -> Target:
        bundle = self._store.get(mission_id)
        if not bundle.scope.frozen:
            raise LocatorRejected("locator change requires a frozen mission scope")
        if bundle.mission.status is MissionStatus.CREATED:
            raise LocatorRejected("confirm the mission before changing locators")
        now = self._clock()
        previous = bundle.target.current_locator or bundle.target.normalized
        updated = apply_confirm_locator(
            bundle.target,
            bundle.scope,
            cmd.locator,
            now=now,
            actor=cmd.actor,
            mode=bundle.mission.mode,
        )
        host = host_for_locator(
            bundle.mission.mission_id,
            updated.current_locator or cmd.locator,
            now,
            labels=_identity_labels(updated, current=True),
        )
        if host is not None:
            keys = {a.canonical_key for a in bundle.seed_assets}
            if host.canonical_key not in keys:
                bundle.seed_assets.append(host)
        bundle.target = updated
        bundle.mission = bundle.mission.model_copy(update={"updated_at": now})
        message = f"operator confirmed locator {previous} -> {updated.current_locator}"
        self._append(bundle, TimelineKind.OPERATOR, message, now)
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.LOCATOR_CONFIRMED,
                mission_id=mission_id,
                at=now,
                payload={
                    "previous": previous,
                    "current": updated.current_locator or "",
                    "identity": updated.identity_key(),
                    "actor": cmd.actor,
                },
            ),
        )
        self._store.save(bundle)
        return updated

    def observe_locator(
        self,
        mission_id: str,
        locator: str,
        *,
        source: str = "recon",
        evidence_ids: list[str] | None = None,
    ) -> Target:
        bundle = self._store.get(mission_id)
        now = self._clock()
        updated = apply_observe_locator(
            bundle.target,
            locator,
            now=now,
            source=source,
            evidence_ids=evidence_ids,
        )
        if updated.locator_history == bundle.target.locator_history:
            return bundle.target
        bundle.target = updated
        bundle.mission = bundle.mission.model_copy(update={"updated_at": now})
        self._store.save(bundle)
        return updated

    def mark_locator_unreachable(self, mission_id: str, locator: str) -> Target:
        bundle = self._store.get(mission_id)
        now = self._clock()
        updated = apply_unreachable(bundle.target, locator, now=now)
        if updated.locator_history == bundle.target.locator_history:
            return bundle.target
        bundle.target = updated
        bundle.mission = bundle.mission.model_copy(update={"updated_at": now})
        self._append(
            bundle,
            TimelineKind.NETWORK,
            f"locator unreachable {locator} (identity unchanged)",
            now,
        )
        self._store.save(bundle)
        return updated

    def start(self, mission_id: str) -> Mission:
        return self._transition(
            mission_id,
            MissionCommand.START,
            extra={},
            message="mission started",
            set_started=True,
        )

    def pause(self, mission_id: str) -> Mission:
        return self._transition(
            mission_id,
            MissionCommand.PAUSE,
            extra={"pause_requested": True},
            message="mission paused",
        )

    def resume(self, mission_id: str) -> Mission:
        return self._transition(
            mission_id,
            MissionCommand.RESUME,
            extra={"pause_requested": False},
            message="mission resumed",
        )

    def stop(self, mission_id: str, reason: StopReason = StopReason.OPERATOR) -> Mission:
        return self._transition(
            mission_id,
            MissionCommand.STOP,
            extra={"stop_reason": reason},
            message=f"mission stopped ({reason.value})",
            terminal=True,
        )

    def complete(self, mission_id: str, reason: StopReason) -> Mission:
        return self._transition(
            mission_id,
            MissionCommand.COMPLETE,
            extra={"stop_reason": reason},
            message=f"mission completed ({reason.value})",
            terminal=True,
        )

    def fail(self, mission_id: str, reason: StopReason = StopReason.ERROR) -> Mission:
        return self._transition(
            mission_id,
            MissionCommand.FAIL,
            extra={"stop_reason": reason},
            message="mission failed",
            terminal=True,
        )

    def bump_iteration(self, mission_id: str) -> Mission:
        bundle = self._store.get(mission_id)
        now = self._clock()
        bundle.mission = bundle.mission.model_copy(
            update={"iteration": bundle.mission.iteration + 1, "updated_at": now}
        )
        self._store.save(bundle)
        return bundle.mission

    def _transition(
        self,
        mission_id: str,
        command: MissionCommand,
        *,
        extra: dict,
        message: str,
        terminal: bool = False,
        set_started: bool = False,
    ) -> Mission:
        bundle = self._store.get(mission_id)
        dest = assert_command(bundle.mission.status, command)

        now = self._clock()
        patch = {"status": dest, "updated_at": now, **extra}
        if set_started:
            patch["started_at"] = bundle.mission.started_at or now
        if terminal:
            patch["ended_at"] = now
            patch["pause_requested"] = False
        if dest is MissionStatus.PAUSED:
            patch["pause_requested"] = True
        if dest is MissionStatus.RUNNING:
            patch["pause_requested"] = False
        bundle.mission = bundle.mission.model_copy(update=patch)
        self._append(bundle, TimelineKind.MISSION_STATUS, message, now)
        self._store.save(bundle)
        return bundle.mission

    def _append(
        self, bundle: MissionBundle, kind: TimelineKind, message: str, now: datetime
    ) -> None:
        bundle.timeline.append(
            TimelineEvent(
                event_id=new_id(PREFIX_TIMELINE),
                mission_id=bundle.mission.mission_id,
                kind=kind,
                message=message,
                at=now,
            )
        )
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.MISSION_STATUS,
                mission_id=bundle.mission.mission_id,
                at=now,
                payload={"status": bundle.mission.status.value, "message": message},
            ),
        )


def _identity_labels(target: Target, *, current: bool) -> list[str]:
    labels = [target.identity_key()]
    if current:
        labels.append("current_locator")
    else:
        labels.append("historical")
    return labels
