"""SQLite-backed repositories. Explicit mapping; domain classes are not ORM models."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from cyberx.domain.errors import MissionNotFound, StorageError
from cyberx.domain.models.actions import Action, ActionResult, ToolRun
from cyberx.domain.models.assets import Asset
from cyberx.domain.models.evidence import Claim, Evidence, KnowledgeGap, Observation
from cyberx.domain.models.findings import Finding, Hypothesis, TimelineEvent
from cyberx.domain.models.mission import Mission, Scope, Target
from cyberx.domain.time import utcnow
from cyberx.evidence.redactor import SecretRef
from cyberx.mission.ports import MissionBundle
from cyberx.ports.execution import RawArtifact
from cyberx.ports.storage import ArtifactMeta, ClaimHistoryRecord
from cyberx.storage.artifacts import FileArtifactStore
from cyberx.storage.codec import (
    dump_asset,
    dump_model,
    load_action,
    load_asset,
    load_claim,
    load_evidence,
    load_finding,
    load_gap,
    load_hypothesis,
    load_mission,
    load_observation,
    load_result,
    load_scope,
    load_target,
    load_timeline,
    load_tool_run,
)
from cyberx.storage.schema import SCHEMA_SQL
from cyberx.world.model import InMemoryWorldModel
from cyberx.world.replay import Replay
from cyberx.world.restore import hydrate_from_snapshot
from cyberx.world.snapshot import WorldSnapshot


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


class SqliteStore:
    """Implements MissionStore plus the persistence ports (structural Protocol)."""

    def __init__(self, path: str | Path, *, data_dir: str | Path | None = None) -> None:
        self.path = str(path)
        parent = Path(self.path).parent
        if parent.as_posix() not in {"", "."}:
            parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        try:
            self._conn = _connect(self.path)
            self._conn.executescript(SCHEMA_SQL)
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(
                f"database could not be opened: {type(exc).__name__}",
                code="database_corrupt",
            ) from exc
        self._tx_depth = 0
        root = data_dir if data_dir is not None else parent
        self.files = FileArtifactStore(root)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            self._tx_depth += 1
            try:
                yield
                if self._tx_depth == 1:
                    self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                self._tx_depth -= 1

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        try:
            cur = self._conn.execute(sql, params)
            if self._tx_depth == 0:
                self._conn.commit()
            return cur
        except sqlite3.Error as exc:
            if self._tx_depth == 0:
                try:
                    self._conn.rollback()
                except sqlite3.Error:
                    pass
            message = str(exc).lower()
            code = (
                "database_corrupt"
                if "malformed" in message or "not a database" in message
                else "sqlite"
            )
            raise StorageError(str(exc), code=code) from exc

    # --- MissionStore (existing MissionService contract) ---

    def save(self, bundle: MissionBundle) -> None:
        with self.transaction():
            self.save_mission(bundle.mission)
            self.save_target(bundle.target)
            self.save_scope(bundle.scope)
            if bundle.seed_assets:
                self.save_seed_assets(bundle.mission.mission_id, bundle.seed_assets)
            for event in bundle.timeline:
                self.append_timeline(event)

    def get(self, mission_id: str) -> MissionBundle:
        mission = self.get_mission(mission_id)
        return MissionBundle(
            mission,
            self.get_target(mission_id),
            self.get_scope(mission_id),
            timeline=self.list_timeline(mission_id),
            seed_assets=self.list_seed_assets(mission_id),
        )

    # --- MissionRepo ---

    def save_mission(self, mission: Mission) -> None:
        self._execute(
            """
            INSERT INTO missions(mission_id, status, iteration, created_at, updated_at, payload)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(mission_id) DO UPDATE SET
                status=excluded.status,
                iteration=excluded.iteration,
                updated_at=excluded.updated_at,
                payload=excluded.payload
            """,
            (
                mission.mission_id,
                mission.status.value,
                mission.iteration,
                mission.created_at.isoformat(),
                mission.updated_at.isoformat() if mission.updated_at else None,
                dump_model(mission),
            ),
        )

    def get_mission(self, mission_id: str) -> Mission:
        row = self._execute(
            "SELECT payload FROM missions WHERE mission_id=?", (mission_id,)
        ).fetchone()
        if row is None:
            raise MissionNotFound(mission_id)
        return load_mission(row["payload"])

    def list_missions(self) -> list[Mission]:
        rows = self._execute("SELECT payload FROM missions ORDER BY created_at DESC").fetchall()
        return [load_mission(row["payload"]) for row in rows]

    def save_target(self, target: Target) -> None:
        self._execute(
            """
            INSERT INTO targets(target_id, mission_id, payload)
            VALUES (?, ?, ?)
            ON CONFLICT(target_id) DO UPDATE SET payload=excluded.payload
            """,
            (target.target_id, target.mission_id, dump_model(target)),
        )

    def get_target(self, mission_id: str) -> Target:
        row = self._execute(
            "SELECT payload FROM targets WHERE mission_id=?", (mission_id,)
        ).fetchone()
        if row is None:
            raise MissionNotFound(mission_id)
        return load_target(row["payload"])

    def save_scope(self, scope: Scope) -> None:
        self._execute(
            """
            INSERT INTO scopes(scope_id, mission_id, frozen, payload)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(scope_id) DO UPDATE SET
                frozen=excluded.frozen,
                payload=excluded.payload
            """,
            (scope.scope_id, scope.mission_id, int(scope.frozen), dump_model(scope)),
        )

    def get_scope(self, mission_id: str) -> Scope:
        row = self._execute(
            "SELECT payload FROM scopes WHERE mission_id=?", (mission_id,)
        ).fetchone()
        if row is None:
            raise MissionNotFound(mission_id)
        return load_scope(row["payload"])

    def save_seed_assets(self, mission_id: str, assets: Sequence[Asset]) -> None:
        self.save_assets(mission_id, assets, is_seed=True)

    def list_seed_assets(self, mission_id: str) -> list[Asset]:
        rows = self._execute(
            "SELECT kind, payload FROM assets WHERE mission_id=? AND is_seed=1",
            (mission_id,),
        ).fetchall()
        return [load_asset(row["kind"], row["payload"]) for row in rows]

    # --- EvidenceRepo ---

    def insert_observation(self, observation: Observation) -> bool:
        cur = self._execute(
            """
            INSERT OR IGNORE INTO observations(
                observation_id, mission_id, parser_id, predicate, payload
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                observation.observation_id,
                observation.mission_id,
                observation.parser_id,
                observation.predicate,
                dump_model(observation),
            ),
        )
        return cur.rowcount > 0

    def insert_evidence(self, evidence: Evidence) -> bool:
        cur = self._execute(
            """
            INSERT OR IGNORE INTO evidence(
                evidence_id, mission_id, observation_id, artifact_id, tool_run_id,
                parser_id, reliability, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence.evidence_id,
                evidence.mission_id,
                evidence.observation_id,
                evidence.artifact_id,
                evidence.tool_run_id,
                evidence.parser_id,
                evidence.reliability,
                dump_model(evidence),
            ),
        )
        return cur.rowcount > 0

    def list_observations(self, mission_id: str) -> list[Observation]:
        rows = self._execute(
            "SELECT payload FROM observations WHERE mission_id=?", (mission_id,)
        ).fetchall()
        return [load_observation(row["payload"]) for row in rows]

    def list_evidence(self, mission_id: str, *, after_id: str | None = None) -> list[Evidence]:
        rows = self._execute(
            "SELECT evidence_id, payload FROM evidence WHERE mission_id=? ORDER BY seq",
            (mission_id,),
        ).fetchall()
        items = [load_evidence(row["payload"]) for row in rows]
        if after_id is None:
            return items
        out: list[Evidence] = []
        seen = False
        for item in items:
            if seen:
                out.append(item)
            elif item.evidence_id == after_id:
                seen = True
        return out

    # --- WorldRepo ---

    def save_assets(
        self, mission_id: str, assets: Sequence[Asset], *, is_seed: bool = False
    ) -> None:
        for asset in assets:
            self._execute(
                """
                INSERT INTO assets(asset_id, mission_id, kind, canonical_key, is_seed, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    kind=excluded.kind,
                    canonical_key=excluded.canonical_key,
                    payload=excluded.payload,
                    is_seed=CASE WHEN assets.is_seed=1 THEN 1 ELSE excluded.is_seed END
                """,
                (
                    asset.asset_id,
                    mission_id,
                    asset.kind.value,
                    asset.canonical_key,
                    int(is_seed),
                    dump_asset(asset),
                ),
            )

    def list_assets(self, mission_id: str) -> list[Asset]:
        rows = self._execute(
            "SELECT kind, payload FROM assets WHERE mission_id=?", (mission_id,)
        ).fetchall()
        return [load_asset(row["kind"], row["payload"]) for row in rows]

    def save_claims(self, mission_id: str, claims: Sequence[Claim]) -> None:
        existing = {c.claim_id: c for c in self.list_claims(mission_id)}
        now = utcnow().isoformat()
        for claim in claims:
            old = existing.get(claim.claim_id)
            self._execute(
                """
                INSERT INTO claims(
                    claim_id, mission_id, subject_id, predicate, epistemic_status,
                    confidence, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(claim_id) DO UPDATE SET
                    subject_id=excluded.subject_id,
                    predicate=excluded.predicate,
                    epistemic_status=excluded.epistemic_status,
                    confidence=excluded.confidence,
                    payload=excluded.payload
                """,
                (
                    claim.claim_id,
                    mission_id,
                    claim.subject_id,
                    claim.predicate,
                    claim.epistemic_status.value,
                    claim.confidence,
                    dump_model(claim),
                ),
            )
            old_status = old.epistemic_status.value if old is not None else None
            changed = old is None or (
                old.epistemic_status != claim.epistemic_status
                or old.evidence_ids != claim.evidence_ids
                or old.confidence != claim.confidence
            )
            if changed:
                eid = claim.evidence_ids[-1] if claim.evidence_ids else None
                self.insert_claim_history(
                    ClaimHistoryRecord(
                        mission_id,
                        claim.claim_id,
                        claim.epistemic_status.value,
                        old_status=old_status,
                        evidence_id=eid,
                        confidence=claim.confidence,
                        at=now,
                    )
                )

    def list_claims(self, mission_id: str) -> list[Claim]:
        rows = self._execute(
            "SELECT payload FROM claims WHERE mission_id=?", (mission_id,)
        ).fetchall()
        return [load_claim(row["payload"]) for row in rows]

    def insert_claim_history(self, row: ClaimHistoryRecord) -> None:
        self._execute(
            """
            INSERT INTO claim_history(
                mission_id, claim_id, old_status, new_status, evidence_id, confidence, at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row.mission_id,
                row.claim_id,
                row.old_status,
                row.new_status,
                row.evidence_id,
                row.confidence,
                row.at,
            ),
        )

    def list_claim_history(self, mission_id: str) -> list[ClaimHistoryRecord]:
        rows = self._execute(
            """
            SELECT mission_id, claim_id, old_status, new_status, evidence_id, confidence, at
            FROM claim_history WHERE mission_id=? ORDER BY seq
            """,
            (mission_id,),
        ).fetchall()
        return [
            ClaimHistoryRecord(
                r["mission_id"],
                r["claim_id"],
                r["new_status"],
                old_status=r["old_status"],
                evidence_id=r["evidence_id"],
                confidence=r["confidence"],
                at=r["at"],
            )
            for r in rows
        ]

    def save_gaps(self, mission_id: str, gaps: Sequence[KnowledgeGap]) -> None:
        for gap in gaps:
            self._execute(
                """
                INSERT INTO gaps(gap_id, mission_id, kind, closed, payload)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(gap_id) DO UPDATE SET
                    kind=excluded.kind,
                    closed=excluded.closed,
                    payload=excluded.payload
                """,
                (
                    gap.gap_id,
                    mission_id,
                    gap.kind,
                    int(gap.closed),
                    dump_model(gap),
                ),
            )

    def list_gaps(self, mission_id: str) -> list[KnowledgeGap]:
        rows = self._execute(
            "SELECT payload FROM gaps WHERE mission_id=?", (mission_id,)
        ).fetchall()
        return [load_gap(row["payload"]) for row in rows]

    def save_hypotheses(self, mission_id: str, hyps: Sequence[Hypothesis]) -> None:
        for hyp in hyps:
            self._execute(
                """
                INSERT INTO hypotheses(hypothesis_id, mission_id, status, payload)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hypothesis_id) DO UPDATE SET
                    status=excluded.status,
                    payload=excluded.payload
                """,
                (hyp.hypothesis_id, mission_id, hyp.status.value, dump_model(hyp)),
            )

    def list_hypotheses(self, mission_id: str) -> list[Hypothesis]:
        rows = self._execute(
            "SELECT payload FROM hypotheses WHERE mission_id=?", (mission_id,)
        ).fetchall()
        return [load_hypothesis(row["payload"]) for row in rows]

    def save_findings(self, mission_id: str, findings: Sequence[Finding]) -> None:
        for finding in findings:
            self._execute(
                """
                INSERT INTO findings(finding_id, mission_id, kind, status, payload)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    kind=excluded.kind,
                    status=excluded.status,
                    payload=excluded.payload
                """,
                (
                    finding.finding_id,
                    mission_id,
                    finding.kind.value,
                    finding.status.value,
                    dump_model(finding),
                ),
            )

    def list_findings(self, mission_id: str) -> list[Finding]:
        rows = self._execute(
            "SELECT payload FROM findings WHERE mission_id=?", (mission_id,)
        ).fetchall()
        return [load_finding(row["payload"]) for row in rows]

    def save_coverage(self, mission_id: str, coverage: dict[str, str]) -> None:
        for key, status in coverage.items():
            self._execute(
                """
                INSERT INTO coverage(mission_id, coverage_key, status)
                VALUES (?, ?, ?)
                ON CONFLICT(mission_id, coverage_key) DO UPDATE SET status=excluded.status
                """,
                (mission_id, key, status),
            )

    def get_coverage(self, mission_id: str) -> dict[str, str]:
        rows = self._execute(
            "SELECT coverage_key, status FROM coverage WHERE mission_id=?",
            (mission_id,),
        ).fetchall()
        return {row["coverage_key"]: row["status"] for row in rows}

    def save_snapshot(
        self,
        mission_id: str,
        revision: int,
        digest: str,
        last_evidence_id: str | None,
        payload: str,
    ) -> None:
        self._execute(
            """
            INSERT INTO world_snapshots(
                mission_id, revision, digest, last_evidence_id, created_at, payload
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(mission_id, revision) DO UPDATE SET
                digest=excluded.digest,
                last_evidence_id=excluded.last_evidence_id,
                payload=excluded.payload
            """,
            (
                mission_id,
                revision,
                digest,
                last_evidence_id,
                utcnow().isoformat(),
                payload,
            ),
        )

    def latest_snapshot_payload(self, mission_id: str) -> tuple[int, str, str | None, str] | None:
        row = self._execute(
            """
            SELECT revision, digest, last_evidence_id, payload
            FROM world_snapshots WHERE mission_id=?
            ORDER BY revision DESC LIMIT 1
            """,
            (mission_id,),
        ).fetchone()
        if row is None:
            return None
        return row["revision"], row["digest"], row["last_evidence_id"], row["payload"]

    def latest_snapshot(self, mission_id: str) -> WorldSnapshot | None:
        packed = self.latest_snapshot_payload(mission_id)
        if packed is None:
            return None
        return WorldSnapshot.model_validate_json(packed[3])

    # --- ActionRepo ---

    def save_action(self, action: Action) -> None:
        self._execute(
            """
            INSERT INTO actions(action_id, mission_id, action_type, coverage_key, status, payload)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                status=excluded.status,
                payload=excluded.payload
            """,
            (
                action.action_id,
                action.mission_id,
                action.action_type,
                action.coverage_key,
                action.status.value,
                dump_model(action),
            ),
        )

    def save_result(self, result: ActionResult) -> None:
        mission_id = self._mission_for_action(result.action_id)
        self._execute(
            """
            INSERT INTO action_results(
                result_id, mission_id, action_id, tool_run_id, status, payload
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(result_id) DO UPDATE SET
                status=excluded.status,
                payload=excluded.payload
            """,
            (
                result.result_id,
                mission_id,
                result.action_id,
                result.tool_run_id,
                result.status.value,
                dump_model(result),
            ),
        )

    def save_tool_run(self, run: ToolRun) -> None:
        mission_id = self._mission_for_action(run.action_id)
        self._execute(
            """
            INSERT INTO tool_runs(tool_run_id, mission_id, action_id, adapter_name, status, payload)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tool_run_id) DO UPDATE SET
                status=excluded.status,
                payload=excluded.payload
            """,
            (
                run.tool_run_id,
                mission_id,
                run.action_id,
                run.adapter_name,
                run.status,
                dump_model(run),
            ),
        )

    def list_actions(self, mission_id: str) -> list[Action]:
        rows = self._execute(
            "SELECT payload FROM actions WHERE mission_id=?", (mission_id,)
        ).fetchall()
        return [load_action(row["payload"]) for row in rows]

    def list_results(self, mission_id: str) -> list[ActionResult]:
        rows = self._execute(
            "SELECT payload FROM action_results WHERE mission_id=?", (mission_id,)
        ).fetchall()
        return [load_result(row["payload"]) for row in rows]

    def list_tool_runs(self, mission_id: str) -> list[ToolRun]:
        rows = self._execute(
            "SELECT payload FROM tool_runs WHERE mission_id=?", (mission_id,)
        ).fetchall()
        return [load_tool_run(row["payload"]) for row in rows]

    def _mission_for_action(self, action_id: str) -> str:
        row = self._execute(
            "SELECT mission_id FROM actions WHERE action_id=?", (action_id,)
        ).fetchone()
        return row["mission_id"] if row is not None else ""

    # --- ArtifactStore ---

    def put(self, artifact: RawArtifact) -> str:
        path = self.files.put(artifact)
        self.save_meta(artifact, path)
        return path

    def get_body(self, artifact_id: str, mission_id: str) -> bytes:
        meta = self.get_meta(artifact_id)
        if meta is not None and meta.path:
            stored = Path(meta.path)
            if stored.is_file():
                return stored.read_bytes()
        return self.files.get(artifact_id, mission_id)

    def save_meta(self, artifact: RawArtifact, path: str | None) -> None:
        self._execute(
            """
            INSERT INTO artifacts(
                artifact_id, mission_id, tool_run_id, adapter_name, media_type,
                sha256, byte_size, truncated, path, source_locator
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
                path=excluded.path,
                sha256=excluded.sha256,
                byte_size=excluded.byte_size
            """,
            (
                artifact.artifact_id,
                artifact.mission_id,
                artifact.tool_run_id,
                artifact.adapter_name,
                artifact.media_type,
                artifact.sha256,
                artifact.byte_size,
                int(artifact.truncated),
                path,
                artifact.source_locator,
            ),
        )

    def get_meta(self, artifact_id: str) -> ArtifactMeta | None:
        row = self._execute(
            "SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,)
        ).fetchone()
        if row is None:
            return None
        return ArtifactMeta(
            artifact_id=row["artifact_id"],
            mission_id=row["mission_id"],
            tool_run_id=row["tool_run_id"],
            adapter_name=row["adapter_name"],
            media_type=row["media_type"],
            sha256=row["sha256"],
            byte_size=row["byte_size"],
            truncated=bool(row["truncated"]),
            path=row["path"],
            source_locator=row["source_locator"],
        )

    def list_meta(self, mission_id: str) -> list[ArtifactMeta]:
        rows = self._execute("SELECT * FROM artifacts WHERE mission_id=?", (mission_id,)).fetchall()
        return [
            ArtifactMeta(
                artifact_id=r["artifact_id"],
                mission_id=r["mission_id"],
                tool_run_id=r["tool_run_id"],
                adapter_name=r["adapter_name"],
                media_type=r["media_type"],
                sha256=r["sha256"],
                byte_size=r["byte_size"],
                truncated=bool(r["truncated"]),
                path=r["path"],
                source_locator=r["source_locator"],
            )
            for r in rows
        ]

    # --- AuditRepo ---

    def append_timeline(self, event: TimelineEvent) -> None:
        self._execute(
            """
            INSERT OR IGNORE INTO timeline_events(event_id, mission_id, kind, at, payload)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.mission_id,
                event.kind.value,
                event.at.isoformat(),
                dump_model(event),
            ),
        )

    def list_timeline(self, mission_id: str) -> list[TimelineEvent]:
        rows = self._execute(
            "SELECT payload FROM timeline_events WHERE mission_id=? ORDER BY at",
            (mission_id,),
        ).fetchall()
        return [load_timeline(row["payload"]) for row in rows]

    def save_decision_trace(self, mission_id: str, iteration: int, payload: str) -> None:
        self._execute(
            "INSERT INTO decision_traces(mission_id, iteration, payload) VALUES (?, ?, ?)",
            (mission_id, iteration, payload),
        )

    def list_decision_traces(self, mission_id: str) -> list[str]:
        rows = self._execute(
            "SELECT payload FROM decision_traces WHERE mission_id=? ORDER BY seq",
            (mission_id,),
        ).fetchall()
        return [row["payload"] for row in rows]

    def insert_secret_ref(self, mission_id: str, ref: SecretRef) -> None:
        self._execute(
            """
            INSERT INTO secret_refs(mission_id, kind, location_hint, sha256, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (mission_id, ref.kind, ref.location_hint, ref.sha256, utcnow().isoformat()),
        )

    def list_secret_refs(self, mission_id: str) -> list[SecretRef]:
        rows = self._execute(
            "SELECT kind, location_hint, sha256 FROM secret_refs WHERE mission_id=?",
            (mission_id,),
        ).fetchall()
        return [
            SecretRef(kind=r["kind"], location_hint=r["location_hint"], sha256=r["sha256"])
            for r in rows
        ]

    def save_runtime(
        self,
        mission_id: str,
        consecutive_failures: int,
        stall_cycles: int,
        last_revision: int,
        last_evidence_count: int,
    ) -> None:
        self._execute(
            """
            INSERT INTO mission_runtime(
                mission_id, consecutive_failures, stall_cycles, last_revision, last_evidence_count
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(mission_id) DO UPDATE SET
                consecutive_failures=excluded.consecutive_failures,
                stall_cycles=excluded.stall_cycles,
                last_revision=excluded.last_revision,
                last_evidence_count=excluded.last_evidence_count
            """,
            (
                mission_id,
                consecutive_failures,
                stall_cycles,
                last_revision,
                last_evidence_count,
            ),
        )

    def get_runtime(self, mission_id: str) -> tuple[int, int, int, int]:
        row = self._execute(
            """
            SELECT consecutive_failures, stall_cycles, last_revision, last_evidence_count
            FROM mission_runtime WHERE mission_id=?
            """,
            (mission_id,),
        ).fetchone()
        if row is None:
            return 0, 0, 0, 0
        return (
            int(row["consecutive_failures"]),
            int(row["stall_cycles"]),
            int(row["last_revision"]),
            int(row["last_evidence_count"]),
        )

    # --- rebuild / resume ---

    def persist_world(self, world: InMemoryWorldModel) -> None:
        snap = world.snapshot()
        mid = world.mission_id
        self.save_assets(mid, list(world.iter_assets_raw()))
        self.save_claims(mid, world.get_claims(include_invalidated=True))
        self.save_gaps(mid, world.get_gaps())
        self.save_hypotheses(mid, world.get_hypotheses())
        self.save_findings(mid, world.get_findings())
        self.save_coverage(mid, world.get_coverage())
        self.save_snapshot(
            mid,
            snap.revision,
            snap.digest,
            snap.last_evidence_id,
            snap.model_dump_json(),
        )

    def rebuild_from_evidence(self, mission_id: str) -> InMemoryWorldModel:
        seeds = self.list_seed_assets(mission_id)
        evidence = self.list_evidence(mission_id)
        world = Replay().rebuild(mission_id, evidence, seed_assets=seeds)
        for key, status in self.get_coverage(mission_id).items():
            world.record_coverage(key, status)
        for hyp in self.list_hypotheses(mission_id):
            world.record_hypothesis(hyp)
        return world

    def resume_world(self, mission_id: str) -> InMemoryWorldModel:
        snap = self.latest_snapshot(mission_id)
        seeds = self.list_seed_assets(mission_id)
        evidence = self.list_evidence(mission_id)
        if snap is None:
            return self.rebuild_from_evidence(mission_id)
        included = evidence
        if snap.last_evidence_id:
            included = []
            for item in evidence:
                included.append(item)
                if item.evidence_id == snap.last_evidence_id:
                    break
        world = hydrate_from_snapshot(snap, seed_assets=seeds, evidence=included)
        tail = self.list_evidence(mission_id, after_id=snap.last_evidence_id)
        for item in tail:
            world.apply_evidence(item)
        return world
