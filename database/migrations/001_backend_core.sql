CREATE TABLE IF NOT EXISTS app_users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('forwarder', 'analyst', 'admin')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ingestion_jobs (
    id UUID PRIMARY KEY,
    submitted_by UUID REFERENCES app_users(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('submitted', 'queued', 'processing', 'completed', 'completed_with_errors', 'failed', 'interrupted')),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    total_lines INTEGER NOT NULL DEFAULT 0 CHECK (total_lines >= 0),
    accepted_lines INTEGER NOT NULL DEFAULT 0 CHECK (accepted_lines >= 0),
    rejected_lines INTEGER NOT NULL DEFAULT 0 CHECK (rejected_lines >= 0),
    safe_error_code TEXT,
    idempotency_key TEXT,
    CHECK (accepted_lines + rejected_lines <= total_lines)
);
CREATE UNIQUE INDEX IF NOT EXISTS ingestion_jobs_submitter_idempotency_idx
    ON ingestion_jobs (submitted_by, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS ingestion_jobs_status_submitted_idx
    ON ingestion_jobs (status, submitted_at DESC);

CREATE TABLE IF NOT EXISTS security_logs (
    occurred_at TIMESTAMPTZ NOT NULL,
    log_id UUID NOT NULL,
    schema_version SMALLINT NOT NULL CHECK (schema_version > 0),
    source_asset_id TEXT,
    destination_asset_id TEXT,
    event_type TEXT NOT NULL,
    encrypted_sensitive_bundle BYTEA NOT NULL,
    safe_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    ingestion_job_id UUID REFERENCES ingestion_jobs(id) ON DELETE SET NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (occurred_at, log_id)
);
SELECT create_hypertable('security_logs', by_range('occurred_at'), if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS security_logs_time_idx ON security_logs (occurred_at DESC);
CREATE INDEX IF NOT EXISTS security_logs_source_time_idx ON security_logs (source_asset_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS security_logs_destination_time_idx ON security_logs (destination_asset_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS security_logs_type_time_idx ON security_logs (event_type, occurred_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    log_id UUID NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    signature_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    explanation TEXT NOT NULL,
    safe_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (occurred_at, log_id, signature_id),
    FOREIGN KEY (occurred_at, log_id) REFERENCES security_logs (occurred_at, log_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS alerts_detected_idx ON alerts (detected_at DESC, id);
CREATE INDEX IF NOT EXISTS alerts_severity_detected_idx ON alerts (severity, detected_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id UUID REFERENCES app_users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    safe_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS audit_events_time_idx ON audit_events (occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_actor_time_idx ON audit_events (actor_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS topology_nodes (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    tier TEXT NOT NULL,
    is_high_value BOOLEAN NOT NULL DEFAULT FALSE,
    safe_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS topology_edges (
    source_id TEXT NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
    destination_id TEXT NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
    risk_score SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 10),
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    is_discovered BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, destination_id),
    CHECK (source_id <> destination_id)
);

INSERT INTO topology_nodes (id, label, asset_type, tier, is_high_value) VALUES
    ('internet', 'Internet', 'external', 'external', FALSE),
    ('edge-firewall', 'Edge Firewall', 'firewall', 'dmz', FALSE),
    ('web-server-01', 'Web Server 01', 'server', 'dmz', FALSE),
    ('app-server-01', 'Application Server 01', 'server', 'internal', FALSE),
    ('db-server-01', 'Database Server 01', 'database', 'restricted', TRUE),
    ('workstation-01', 'Analyst Workstation 01', 'workstation', 'internal', FALSE)
ON CONFLICT (id) DO NOTHING;

INSERT INTO topology_edges (source_id, destination_id, risk_score) VALUES
    ('internet', 'edge-firewall', 1),
    ('edge-firewall', 'web-server-01', 2),
    ('web-server-01', 'app-server-01', 3),
    ('app-server-01', 'db-server-01', 2),
    ('workstation-01', 'app-server-01', 2)
ON CONFLICT (source_id, destination_id) DO NOTHING;
