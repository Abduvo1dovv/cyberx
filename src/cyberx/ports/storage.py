"""Persistence ports. Application code depends on these, not on sqlite3."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import AbstractContextManager
from typing import Any, Protocol, runtime_checkable

from cyberx.domain.models.actions import Action, ActionResult, ToolRun
from cyberx.domain.models.assets import Asset
from cyberx.domain.models.evidence import Claim, Evidence, KnowledgeGap, Observation
from cyberx.domain.models.findings import Finding, Hypothesis, TimelineEvent
from cyberx.domain.models.mission import Mission, Scope, Target
from cyberx.evidence.redactor import SecretRef
from cyberx.ports.execution import RawArtifact


class ClaimHistoryRecord:
    """Persistence DTO — not a World Model claim."""

    __slots__ = (
        "mission_id",
        "claim_id",
        "old_status",
        "new_status",
        "evidence_id",
        "confidence",
        "at",
    )

    def __init__(
        self,
        mission_id: str,
        claim_id: str,
        new_status: str,
        *,
        old_status: str | None = None,
        evidence_id: str | None = None,
        confidence: float | None = None,
        at: str = "",
    ) -> None:
        self.mission_id = mission_id
        self.claim_id = claim_id
        self.old_status = old_status
        self.new_status = new_status
        self.evidence_id = evidence_id
        self.confidence = confidence
        self.at = at


class ArtifactMeta:
    __slots__ = (
        "artifact_id",
        "mission_id",
        "tool_run_id",
        "adapter_name",
        "media_type",
        "sha256",
        "byte_size",
        "truncated",
        "path",
        "source_locator",
    )

    def __init__(
        self,
        artifact_id: str,
        mission_id: str,
        tool_run_id: str,
        adapter_name: str,
        media_type: str,
        sha256: str,
        byte_size: int,
        truncated: bool = False,
        path: str | None = None,
        source_locator: str | None = None,
    ) -> None:
        self.artifact_id = artifact_id
        self.mission_id = mission_id
        self.tool_run_id = tool_run_id
        self.adapter_name = adapter_name
        self.media_type = media_type
        self.sha256 = sha256
        self.byte_size = byte_size
        self.truncated = truncated
        self.path = path
        self.source_locator = source_locator


class MissionRepo(Protocol):
    def save_mission(self, mission: Mission) -> None: ...

    def get_mission(self, mission_id: str) -> Mission: ...

    def save_target(self, target: Target) -> None: ...

    def get_target(self, mission_id: str) -> Target: ...

    def save_scope(self, scope: Scope) -> None: ...

    def get_scope(self, mission_id: str) -> Scope: ...

    def save_seed_assets(self, mission_id: str, assets: Sequence[Asset]) -> None: ...

    def list_seed_assets(self, mission_id: str) -> list[Asset]: ...


class EvidenceRepo(Protocol):
    def insert_observation(self, observation: Observation) -> bool: ...

    def insert_evidence(self, evidence: Evidence) -> bool: ...

    def list_observations(self, mission_id: str) -> list[Observation]: ...

    def list_evidence(self, mission_id: str, *, after_id: str | None = None) -> list[Evidence]: ...


class WorldRepo(Protocol):
    def save_assets(self, mission_id: str, assets: Sequence[Asset]) -> None: ...

    def list_assets(self, mission_id: str) -> list[Asset]: ...

    def save_claims(self, mission_id: str, claims: Sequence[Claim]) -> None: ...

    def list_claims(self, mission_id: str) -> list[Claim]: ...

    def insert_claim_history(self, row: ClaimHistoryRecord) -> None: ...

    def list_claim_history(self, mission_id: str) -> list[ClaimHistoryRecord]: ...

    def save_gaps(self, mission_id: str, gaps: Sequence[KnowledgeGap]) -> None: ...

    def list_gaps(self, mission_id: str) -> list[KnowledgeGap]: ...

    def save_hypotheses(self, mission_id: str, hyps: Sequence[Hypothesis]) -> None: ...

    def list_hypotheses(self, mission_id: str) -> list[Hypothesis]: ...

    def save_findings(self, mission_id: str, findings: Sequence[Finding]) -> None: ...

    def list_findings(self, mission_id: str) -> list[Finding]: ...

    def save_coverage(self, mission_id: str, coverage: dict[str, str]) -> None: ...

    def get_coverage(self, mission_id: str) -> dict[str, str]: ...

    def save_snapshot(
        self,
        mission_id: str,
        revision: int,
        digest: str,
        last_evidence_id: str | None,
        payload: str,
    ) -> None: ...

    def latest_snapshot_payload(
        self, mission_id: str
    ) -> tuple[int, str, str | None, str] | None: ...


class ActionRepo(Protocol):
    def save_action(self, action: Action) -> None: ...

    def save_result(self, result: ActionResult) -> None: ...

    def save_tool_run(self, run: ToolRun) -> None: ...

    def list_actions(self, mission_id: str) -> list[Action]: ...

    def list_results(self, mission_id: str) -> list[ActionResult]: ...

    def list_tool_runs(self, mission_id: str) -> list[ToolRun]: ...


class ArtifactStore(Protocol):
    def put(self, artifact: RawArtifact) -> str: ...

    def get_body(self, artifact_id: str, mission_id: str) -> bytes: ...

    def save_meta(self, artifact: RawArtifact, path: str | None) -> None: ...

    def get_meta(self, artifact_id: str) -> ArtifactMeta | None: ...

    def list_meta(self, mission_id: str) -> list[ArtifactMeta]: ...


class AuditRepo(Protocol):
    def append_timeline(self, event: TimelineEvent) -> None: ...

    def list_timeline(self, mission_id: str) -> list[TimelineEvent]: ...

    def save_decision_trace(self, mission_id: str, iteration: int, payload: str) -> None: ...

    def list_decision_traces(self, mission_id: str) -> list[str]: ...

    def insert_secret_ref(self, mission_id: str, ref: SecretRef) -> None: ...

    def list_secret_refs(self, mission_id: str) -> list[SecretRef]: ...


class Persistence(Protocol):
    """Unit-of-work facade. Engine depends on this, never sqlite3."""

    def transaction(self) -> AbstractContextManager[None]: ...

    def close(self) -> None: ...


@runtime_checkable
class EnginePersistence(Protocol):
    """Capabilities MissionEngine requires when a store is attached.

    In-memory missions pass None. SQLite implements this Protocol structurally.
    Optional duck-typing (hasattr / store_has) is forbidden in the engine.
    """

    def transaction(self) -> AbstractContextManager[None]: ...

    def persist_world(self, world: Any) -> None: ...

    def resume_world(self, mission_id: str) -> Any: ...

    def save_runtime(
        self,
        mission_id: str,
        consecutive_failures: int,
        stall_cycles: int,
        last_revision: int,
        last_evidence_count: int,
    ) -> None: ...

    def get_runtime(self, mission_id: str) -> tuple[int, int, int, int]: ...

    def save_action(self, action: Action) -> None: ...

    def save_result(self, result: ActionResult) -> None: ...

    def save_tool_run(self, run: ToolRun) -> None: ...

    def put(self, artifact: RawArtifact) -> str: ...

    def insert_observation(self, observation: Observation) -> bool: ...

    def insert_evidence(self, evidence: Evidence) -> bool: ...

    def append_timeline(self, event: TimelineEvent) -> None: ...

    def save_decision_trace(self, mission_id: str, iteration: int, payload: str) -> None: ...


def iter_protocol_names() -> Iterator[str]:
    yield from (
        "MissionRepo",
        "EvidenceRepo",
        "WorldRepo",
        "ActionRepo",
        "ArtifactStore",
        "AuditRepo",
        "Persistence",
        "EnginePersistence",
    )
