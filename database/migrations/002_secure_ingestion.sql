ALTER TABLE ingestion_jobs
    ADD COLUMN IF NOT EXISTS source_filename TEXT NOT NULL DEFAULT 'upload.jsonl',
    ADD COLUMN IF NOT EXISTS content_sha256 CHAR(64);

ALTER TABLE security_logs
    ADD COLUMN IF NOT EXISTS key_id TEXT;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS source_asset_id TEXT,
    ADD COLUMN IF NOT EXISTS destination_asset_id TEXT;

CREATE TABLE IF NOT EXISTS security_log_id_registry (
    log_id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    ingestion_job_id UUID REFERENCES ingestion_jobs(id) ON DELETE SET NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_log_id_registry_job_idx
    ON security_log_id_registry (ingestion_job_id);

-- Preserve global log ID uniqueness when this migration follows a database
-- that already contains security logs.
INSERT INTO security_log_id_registry (log_id, occurred_at, ingestion_job_id)
SELECT DISTINCT ON (log_id) log_id, occurred_at, ingestion_job_id
FROM security_logs
ORDER BY log_id, occurred_at
ON CONFLICT (log_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS ingestion_job_line_errors (
    job_id UUID NOT NULL REFERENCES ingestion_jobs(id) ON DELETE CASCADE,
    line_number INTEGER NOT NULL CHECK (line_number > 0),
    error_code TEXT NOT NULL,
    PRIMARY KEY (job_id, line_number)
);

CREATE TABLE IF NOT EXISTS detection_signatures (
    signature_id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL CHECK (length(pattern) > 0),
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    rule_version TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

INSERT INTO detection_signatures
    (signature_id, pattern, category, severity, rule_version)
VALUES
    ('SIG-SQLI-UNION-SELECT', 'UNION SELECT', 'sql_injection', 'high', '1'),
    ('SIG-XSS-SCRIPT-TAG', '<script>', 'cross_site_scripting', 'high', '1'),
    ('SIG-XSS-ONERROR', 'onerror=', 'cross_site_scripting', 'medium', '1'),
    ('SIG-CMD-BIN-SH', '/bin/sh', 'command_execution', 'high', '1'),
    ('SIG-CMD-POWERSHELL', 'powershell.exe', 'command_execution', 'high', '1')
ON CONFLICT (signature_id) DO NOTHING;
