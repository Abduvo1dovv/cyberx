"""Nmap ToolAdapter. Builds argv, runs the binary, returns a RawArtifact. No World Model."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Any

from cyberx.domain.errors import AdapterUnavailable, DomainValidationError
from cyberx.domain.ids import PREFIX_ARTIFACT, PREFIX_TOOL_RUN, new_id
from cyberx.domain.models.actions import Action
from cyberx.ports.events import DomainEvent, EventSink, EventType, NullEventSink, emit_safe
from cyberx.ports.execution import ExecutionContext, RawArtifact
from cyberx.recon.nmap.argv import (
    NMAP_ACTION_TYPES,
    build_nmap_argv,
    drop_interface,
    drop_source_address,
)
from cyberx.recon.nmap.process import (
    CommandResult,
    ProcessRunner,
    looks_like_nsock_bind_error,
    looks_like_process_error,
)


class NmapAdapter:
    name = "nmap_adapter"
    action_types: tuple[str, ...] = NMAP_ACTION_TYPES

    def __init__(
        self,
        *,
        binary: str = "nmap",
        runner: ProcessRunner | Any | None = None,
        events: EventSink | None = None,
        max_bytes: int = 5_000_000,
        max_retries: int = 1,
        available: bool | None = None,
    ) -> None:
        self._binary = binary
        self._runner = runner or ProcessRunner()
        self._events = events or NullEventSink()
        self._max_bytes = max_bytes
        self._max_retries = max_retries
        self._forced_available = available
        self._last_argv: list[str] = []
        self._last_result: CommandResult | None = None

    def is_available(self) -> bool:
        if self._forced_available is not None:
            return self._forced_available
        path = Path(self._binary)
        if path.is_file():
            return True
        return shutil.which(self._binary) is not None

    def build_argv(
        self,
        action: Action,
        xml_path: str = "scan.xml",
        timeout_s: int = 180,
        source_interface: str | None = None,
        source_address: str | None = None,
    ) -> list[str]:
        return build_nmap_argv(
            action,
            binary=self._binary,
            xml_path=xml_path,
            timeout_s=timeout_s,
            max_retries=self._max_retries,
            source_interface=source_interface,
            source_address=source_address,
        )

    def run(self, action: Action, ctx: ExecutionContext) -> RawArtifact:
        if action.action_type not in self.action_types:
            raise DomainValidationError(f"nmap adapter does not run {action.action_type}")
        if not self.is_available():
            emit_safe(
                self._events,
                DomainEvent(
                    event_type=EventType.NMAP_UNAVAILABLE,
                    mission_id=action.mission_id,
                    payload={"adapter": self.name, "binary": self._binary},
                ),
            )
            raise AdapterUnavailable(self.name)

        tool_run_id = new_id(PREFIX_TOOL_RUN)
        if ctx.workdir:
            workdir = Path(ctx.workdir)
        else:
            workdir = Path("data") / "missions" / action.mission_id
        art_dir = workdir / "artifacts" / tool_run_id
        art_dir.mkdir(parents=True, exist_ok=True)
        xml_path = art_dir / "scan.xml"
        timeout_s = max(1, int(ctx.timeout_s or 180))
        source_iface = None
        if (ctx.reachability or "") == "REACHABLE":
            source_iface = ctx.source_interface
        argv = self.build_argv(
            action,
            xml_path=str(xml_path),
            timeout_s=timeout_s,
            source_interface=source_iface,
            source_address=None,
        )
        self._last_argv = argv
        emit_safe(
            self._events,
            DomainEvent(
                event_type=EventType.NMAP_STARTED,
                mission_id=action.mission_id,
                payload={
                    "action_id": action.action_id,
                    "action_type": action.action_type,
                    "timeout_s": timeout_s,
                },
            ),
        )
        result = self._runner.run(argv, timeout_s=timeout_s, cwd=str(workdir))
        if looks_like_process_error(result.stderr) and not result.timed_out and "-S" in argv:
            fallback = drop_source_address(argv)
            if fallback != argv:
                retry = self._runner.run(fallback, timeout_s=timeout_s, cwd=str(workdir))
                if not retry.timed_out and (
                    retry.exit_code in {0, None} or not looks_like_process_error(retry.stderr)
                ):
                    argv = fallback
                    result = retry
                    self._last_argv = argv
        if looks_like_nsock_bind_error(result.stderr) and not result.timed_out and "-e" in argv:
            fallback = drop_interface(argv)
            if fallback != argv:
                retry = self._runner.run(fallback, timeout_s=timeout_s, cwd=str(workdir))
                argv = fallback
                result = retry
                self._last_argv = argv
        self._last_result = result
        artifact = self._artifact(action, tool_run_id, xml_path, art_dir, result)
        self._emit_finished(action, result, artifact)
        return artifact

    def _artifact(
        self,
        action: Action,
        tool_run_id: str,
        xml_path: Path,
        art_dir: Path,
        result: CommandResult,
    ) -> RawArtifact:
        body = b""
        if xml_path.is_file():
            body = xml_path.read_bytes()
        elif result.stdout.strip().startswith(b"<?xml") or b"<nmaprun" in result.stdout[:200]:
            body = result.stdout
            xml_path.write_bytes(body)
        truncated = False
        if len(body) > self._max_bytes:
            body = body[: self._max_bytes]
            truncated = True
            xml_path.write_bytes(body)
        if result.stderr:
            (art_dir / "stderr.txt").write_bytes(result.stderr[: self._max_bytes])
        digest = hashlib.sha256(body).hexdigest() if body else hashlib.sha256(b"").hexdigest()
        locator = action.target.canonical_locator or action.target.asset_id
        return RawArtifact(
            artifact_id=new_id(PREFIX_ARTIFACT),
            tool_run_id=tool_run_id,
            adapter_name=self.name,
            media_type="application/xml",
            sha256=digest,
            byte_size=len(body),
            truncated=truncated,
            body=body or None,
            path=str(xml_path) if xml_path.is_file() else None,
            stdout_path=None,
            stderr_path=str(art_dir / "stderr.txt") if result.stderr else None,
            mission_id=action.mission_id,
            source_locator=locator,
        )

    def _emit_finished(self, action: Action, result: CommandResult, artifact: RawArtifact) -> None:
        if result.timed_out:
            kind = EventType.NMAP_FAILED
            payload = {
                "action_id": action.action_id,
                "reason": "timeout",
                "bytes": artifact.byte_size,
            }
        elif result.exit_code not in {0, None} and artifact.byte_size == 0:
            kind = EventType.NMAP_FAILED
            payload = {
                "action_id": action.action_id,
                "reason": "exit",
                "exit_code": result.exit_code,
                "bytes": 0,
            }
        else:
            kind = EventType.NMAP_COMPLETED
            payload = {
                "action_id": action.action_id,
                "exit_code": result.exit_code,
                "bytes": artifact.byte_size,
                "timed_out": result.timed_out,
            }
        emit_safe(
            self._events,
            DomainEvent(event_type=kind, mission_id=action.mission_id, payload=payload),
        )
