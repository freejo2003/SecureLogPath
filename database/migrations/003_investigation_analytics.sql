CREATE TABLE IF NOT EXISTS benchmark_runs (
    id UUID PRIMARY KEY,
    actor_id UUID REFERENCES app_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    dataset_size INTEGER NOT NULL CHECK (dataset_size BETWEEN 100 AND 20000),
    seed BIGINT NOT NULL CHECK (seed BETWEEN 0 AND 4294967295),
    sample_fraction DOUBLE PRECISION NOT NULL CHECK (sample_fraction BETWEEN 0.01 AND 0.30),
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS benchmark_runs_created_idx
    ON benchmark_runs (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS benchmark_runs_actor_created_idx
    ON benchmark_runs (actor_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS alerts_stream_cursor_idx
    ON alerts (detected_at, id);
CREATE INDEX IF NOT EXISTS alerts_category_detected_idx
    ON alerts (category, detected_at DESC, id DESC);
