CREATE TABLE app_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO app_metadata(key, value) VALUES ('schema_stage', 'stage_1_scaffold');
