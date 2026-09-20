UPDATE app_metadata SET value = 'p0_core' WHERE key = 'schema_stage';

CREATE TABLE scan_sessions (
    id TEXT PRIMARY KEY,
    requested_paths_json TEXT NOT NULL,
    options_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','running','completed','cancelled','failed','partial')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    current_path TEXT,
    files_seen INTEGER NOT NULL DEFAULT 0,
    files_indexed INTEGER NOT NULL DEFAULT 0,
    files_skipped INTEGER NOT NULL DEFAULT 0,
    bytes_seen INTEGER NOT NULL DEFAULT 0,
    error_summary_json TEXT NOT NULL DEFAULT '[]',
    cancel_requested INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    scan_session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX idx_scan_events_session_id ON scan_events(scan_session_id, id);

CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    scan_session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    abs_path TEXT NOT NULL,
    path_hash TEXT NOT NULL,
    file_hash TEXT,
    partial_hash TEXT,
    hash_status TEXT NOT NULL DEFAULT 'not_started',
    size_bytes INTEGER NOT NULL,
    ext TEXT NOT NULL,
    mime TEXT,
    category TEXT NOT NULL,
    source_hint TEXT NOT NULL,
    created_at TEXT,
    modified_at TEXT,
    modified_ns INTEGER,
    accessed_at TEXT,
    device_id INTEGER,
    status TEXT NOT NULL DEFAULT 'active',
    risk_level TEXT NOT NULL DEFAULT 'medium',
    risk_flags_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(scan_session_id, abs_path)
);
CREATE INDEX idx_assets_session ON assets(scan_session_id, status);
CREATE INDEX idx_assets_size ON assets(scan_session_id, size_bytes);
CREATE INDEX idx_assets_hash ON assets(scan_session_id, file_hash);

CREATE TABLE asset_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    raw_json TEXT,
    UNIQUE(asset_id, key)
);

CREATE TABLE duplicate_groups (
    id TEXT PRIMARY KEY,
    scan_session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT 'exact',
    file_hash TEXT NOT NULL,
    keep_asset_id TEXT NOT NULL REFERENCES assets(id),
    reason TEXT NOT NULL,
    total_size_bytes INTEGER NOT NULL,
    reclaimable_size_bytes INTEGER NOT NULL
);
CREATE INDEX idx_duplicate_groups_session ON duplicate_groups(scan_session_id);

CREATE TABLE duplicate_members (
    group_id TEXT NOT NULL REFERENCES duplicate_groups(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    similarity REAL NOT NULL DEFAULT 1.0,
    reason TEXT,
    risk_level TEXT NOT NULL,
    PRIMARY KEY(group_id, asset_id)
);

CREATE TABLE suggestions (
    id TEXT PRIMARY KEY,
    scan_session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
    dup_group_id TEXT REFERENCES duplicate_groups(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    proposed_action TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    reversible INTEGER NOT NULL DEFAULT 1,
    default_selected INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
CREATE INDEX idx_suggestions_session ON suggestions(scan_session_id, risk_level);

CREATE TABLE operation_plans (
    id TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    target_policy TEXT NOT NULL,
    status TEXT NOT NULL,
    reversible INTEGER NOT NULL DEFAULT 1,
    summary_json TEXT NOT NULL,
    risk_summary_json TEXT NOT NULL,
    warnings_json TEXT NOT NULL,
    version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE operation_plan_items (
    plan_id TEXT NOT NULL REFERENCES operation_plans(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    suggestion_id TEXT REFERENCES suggestions(id),
    display_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    modified_ns INTEGER,
    file_hash TEXT,
    device_id INTEGER,
    risk_level TEXT NOT NULL,
    reversible INTEGER NOT NULL,
    warnings_json TEXT NOT NULL,
    PRIMARY KEY(plan_id, asset_id)
);

CREATE TABLE operation_receipts (
    id TEXT PRIMARY KEY,
    operation_plan_id TEXT NOT NULL REFERENCES operation_plans(id),
    action_type TEXT NOT NULL,
    status TEXT NOT NULL,
    reversible INTEGER NOT NULL DEFAULT 1,
    file_count INTEGER NOT NULL,
    total_size_bytes INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    affects_cloud_sync INTEGER NOT NULL DEFAULT 0,
    rule_version TEXT,
    provider_version TEXT,
    idempotency_key TEXT UNIQUE
);

CREATE TABLE operation_file_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL REFERENCES operation_receipts(id) ON DELETE CASCADE,
    phase TEXT NOT NULL DEFAULT 'execute',
    asset_id TEXT NOT NULL REFERENCES assets(id),
    status TEXT NOT NULL,
    original_path TEXT,
    quarantine_item_id TEXT,
    error_json TEXT
);
CREATE INDEX idx_operation_results_operation ON operation_file_results(operation_id, id);

CREATE TABLE quarantine_items (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES operation_receipts(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL UNIQUE,
    original_mtime TEXT,
    original_mtime_ns INTEGER,
    original_size_bytes INTEGER NOT NULL,
    file_hash TEXT NOT NULL,
    device_id INTEGER,
    status TEXT NOT NULL,
    error_message TEXT
);
CREATE INDEX idx_quarantine_operation ON quarantine_items(operation_id, status);
