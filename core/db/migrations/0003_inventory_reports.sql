UPDATE app_metadata SET value = 'inventory_reports_v1' WHERE key = 'schema_stage';

CREATE TABLE inventory_scan_profiles (
    scan_id TEXT PRIMARY KEY,
    profile TEXT NOT NULL CHECK (profile = 'inventory_metadata'),
    platform TEXT NOT NULL,
    content_read INTEGER NOT NULL CHECK (content_read = 0),
    hash_mode TEXT NOT NULL CHECK (hash_mode = 'none'),
    coverage_json TEXT NOT NULL,
    rules_version TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE inventory_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES inventory_scan_profiles(scan_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('running','completed','cancelled','partial','failed')),
    last_relative_path TEXT,
    collected_entries INTEGER NOT NULL CHECK (collected_entries >= 0),
    skipped_entries INTEGER NOT NULL CHECK (skipped_entries >= 0),
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE governance_objects (
    object_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES inventory_scan_profiles(scan_id) ON DELETE CASCADE,
    schema_version TEXT NOT NULL,
    object_type TEXT NOT NULL,
    parent_object_id TEXT REFERENCES governance_objects(object_id),
    logical_size_bytes INTEGER NOT NULL CHECK (logical_size_bytes >= 0),
    allocated_size_bytes INTEGER CHECK (allocated_size_bytes IS NULL OR allocated_size_bytes >= 0),
    reclaimable_estimate_bytes INTEGER CHECK (
        reclaimable_estimate_bytes IS NULL OR reclaimable_estimate_bytes >= 0
    ),
    payload_json TEXT NOT NULL
);
CREATE INDEX idx_governance_objects_scan ON governance_objects(scan_id, object_type);

CREATE TABLE governance_evidence (
    evidence_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES inventory_scan_profiles(scan_id) ON DELETE CASCADE,
    object_id TEXT NOT NULL REFERENCES governance_objects(object_id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX idx_governance_evidence_object ON governance_evidence(object_id);

CREATE TABLE report_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES inventory_scan_profiles(scan_id),
    schema_version TEXT NOT NULL,
    snapshot_sha256 TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE analysis_packets (
    packet_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES report_snapshots(snapshot_id),
    schema_version TEXT NOT NULL,
    artifact_privacy_mode TEXT NOT NULL CHECK (
        artifact_privacy_mode IN ('local_full','share_safe')
    ),
    packet_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(snapshot_id, artifact_privacy_mode, packet_sha256)
);

CREATE TABLE ai_analyses (
    analysis_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL REFERENCES analysis_packets(packet_id),
    schema_version TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('none','fake')),
    model TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('deterministic_only','ai_complete','ai_failed_fallback')
    ),
    cache_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(packet_id, provider, model, cache_key)
);

CREATE TABLE model_call_receipts (
    receipt_id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL REFERENCES ai_analyses(analysis_id),
    provider TEXT NOT NULL CHECK (provider IN ('none','fake')),
    status TEXT NOT NULL,
    provider_calls INTEGER NOT NULL CHECK (provider_calls >= 0),
    network_calls INTEGER NOT NULL CHECK (network_calls = 0),
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE report_artifacts (
    artifact_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL UNIQUE,
    snapshot_id TEXT NOT NULL REFERENCES report_snapshots(snapshot_id),
    packet_id TEXT NOT NULL REFERENCES analysis_packets(packet_id),
    analysis_id TEXT NOT NULL REFERENCES ai_analyses(analysis_id),
    schema_version TEXT NOT NULL,
    artifact_privacy_mode TEXT NOT NULL CHECK (
        artifact_privacy_mode IN ('local_full','share_safe')
    ),
    filename TEXT NOT NULL,
    workbook_sha256 TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
