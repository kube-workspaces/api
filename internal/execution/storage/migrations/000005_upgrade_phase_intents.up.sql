-- Exact protected-recording acknowledgments, followed by one-shot phase claims.
-- No guest work is triggered by these rows.
CREATE TABLE agent_upgrade_phase_intents (
    attempt_id TEXT NOT NULL REFERENCES agent_upgrade_attempts(attempt_id),
    action_sequence BIGINT NOT NULL CHECK (action_sequence BETWEEN 1 AND 1000000),
    owner TEXT NOT NULL,
    owner_fence BIGINT NOT NULL CHECK (owner_fence BETWEEN 1 AND 1000000),
    plan_sha256 TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL,
    checkpoint BYTEA NOT NULL CHECK (octet_length(checkpoint) BETWEEN 1 AND 16384),
    recording_id TEXT NOT NULL,
    chunk_index BIGINT NOT NULL CHECK (chunk_index >= 0),
    chunk_sha256 TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ,
    challenge TEXT UNIQUE,
    peer_sha256 TEXT,
    permit_sha256 TEXT,
    PRIMARY KEY (attempt_id, action_sequence),
    UNIQUE (recording_id, chunk_index)
);
