-- A committed expiry fence precedes object deletion. Keep metadata, audit and
-- unique ID reservations; this is not metadata retention or an owner reaper.
CREATE TABLE execution_recording_retention (
    execution_id TEXT PRIMARY KEY REFERENCES execution_executions(execution_id),
    recording_id TEXT NOT NULL UNIQUE,
    end_time TIMESTAMPTZ NOT NULL,
    planned_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CHECK (completed_at IS NULL OR completed_at >= planned_at)
);

CREATE INDEX idx_execution_recording_retention_pending
    ON execution_recording_retention(execution_id) WHERE completed_at IS NULL;
