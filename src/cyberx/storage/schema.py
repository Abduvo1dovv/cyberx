"""SQLite schema. Domain models are never ORM-mapped."""

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS missions (
    mission_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    iteration INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_missions_status ON missions(status);

CREATE TABLE IF NOT EXISTS targets (
    target_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_targets_mission ON targets(mission_id);

CREATE TABLE IF NOT EXISTS scopes (
    scope_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    frozen INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_scopes_mission ON scopes(mission_id);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    canonical_key TEXT NOT NULL,
    is_seed INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id),
    UNIQUE (mission_id, canonical_key)
);
CREATE INDEX IF NOT EXISTS idx_assets_mission ON assets(mission_id);

CREATE TABLE IF NOT EXISTS claims (
    claim_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    predicate TEXT NOT NULL,
    epistemic_status TEXT NOT NULL,
    confidence REAL NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_claims_mission ON claims(mission_id);
CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(mission_id, epistemic_status);

CREATE TABLE IF NOT EXISTS claim_history (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT NOT NULL,
    evidence_id TEXT,
    confidence REAL,
    at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_claim_history_mission ON claim_history(mission_id, claim_id);

CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    parser_id TEXT NOT NULL,
    predicate TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_obs_mission ON observations(mission_id);

CREATE TABLE IF NOT EXISTS evidence (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL UNIQUE,
    mission_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    tool_run_id TEXT NOT NULL,
    parser_id TEXT NOT NULL,
    reliability REAL NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_mission ON evidence(mission_id, seq);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    tool_run_id TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    media_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0,
    path TEXT,
    source_locator TEXT,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_mission ON artifacts(mission_id);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    coverage_key TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_actions_mission ON actions(mission_id);
CREATE INDEX IF NOT EXISTS idx_actions_coverage ON actions(mission_id, coverage_key);

CREATE TABLE IF NOT EXISTS action_results (
    result_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    tool_run_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_results_mission ON action_results(mission_id);
CREATE INDEX IF NOT EXISTS idx_results_action ON action_results(action_id);

CREATE TABLE IF NOT EXISTS tool_runs (
    tool_run_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_runs_mission ON tool_runs(mission_id);

CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_hyps_mission ON hypotheses(mission_id);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_mission ON findings(mission_id);

CREATE TABLE IF NOT EXISTS gaps (
    gap_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    closed INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_gaps_mission ON gaps(mission_id);

CREATE TABLE IF NOT EXISTS coverage (
    mission_id TEXT NOT NULL,
    coverage_key TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (mission_id, coverage_key),
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);

CREATE TABLE IF NOT EXISTS timeline_events (
    event_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    at TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_timeline_mission ON timeline_events(mission_id, at);

CREATE TABLE IF NOT EXISTS world_snapshots (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    digest TEXT NOT NULL,
    last_evidence_id TEXT,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id),
    UNIQUE (mission_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_mission ON world_snapshots(mission_id, revision);

CREATE TABLE IF NOT EXISTS decision_traces (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id TEXT NOT NULL,
    iteration INTEGER NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_traces_mission ON decision_traces(mission_id, iteration);

CREATE TABLE IF NOT EXISTS secret_refs (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    location_hint TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
CREATE INDEX IF NOT EXISTS idx_secrets_mission ON secret_refs(mission_id);

CREATE TABLE IF NOT EXISTS mission_runtime (
    mission_id TEXT PRIMARY KEY,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    stall_cycles INTEGER NOT NULL DEFAULT 0,
    last_revision INTEGER NOT NULL DEFAULT 0,
    last_evidence_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
);
"""
