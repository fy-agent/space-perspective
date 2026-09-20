UPDATE app_metadata
SET value = 'synthetic_provider_consent_v1'
WHERE key = 'schema_stage';

CREATE TABLE analysis_consent_receipts (
    consent_receipt_id TEXT PRIMARY KEY,
    client_action_id TEXT NOT NULL UNIQUE,
    packet_id TEXT NOT NULL REFERENCES analysis_packets(packet_id),
    packet_sha256 TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    receipt_json TEXT,
    analysis_id TEXT REFERENCES ai_analyses(analysis_id),
    model_receipt_id TEXT REFERENCES model_call_receipts(receipt_id),
    status TEXT NOT NULL CHECK (status IN ('reserved','consumed')),
    created_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE INDEX idx_analysis_consents_packet
ON analysis_consent_receipts(packet_id, packet_sha256);
