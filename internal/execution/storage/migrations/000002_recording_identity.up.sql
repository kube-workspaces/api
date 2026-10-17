CREATE UNIQUE INDEX IF NOT EXISTS idx_execution_recording_identity
    ON execution_executions (recording_id);
