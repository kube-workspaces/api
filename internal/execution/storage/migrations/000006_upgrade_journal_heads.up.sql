CREATE TABLE agent_upgrade_journal_heads (
    attempt_id TEXT PRIMARY KEY REFERENCES agent_upgrade_attempts(attempt_id),
    plan_sha256 TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL,
    checkpoint BYTEA NOT NULL CHECK (octet_length(checkpoint) BETWEEN 1 AND 16384),
    sequence BIGINT NOT NULL CHECK (sequence BETWEEN 0 AND 1000000),
    owner_fence BIGINT NOT NULL CHECK (owner_fence BETWEEN 1 AND 1000000)
);

CREATE TABLE agent_upgrade_journal_steps (
    attempt_id TEXT NOT NULL REFERENCES agent_upgrade_journal_heads(attempt_id),
    sequence BIGINT NOT NULL CHECK (sequence BETWEEN 1 AND 1000000),
    previous_sha256 TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL,
    checkpoint BYTEA NOT NULL CHECK (octet_length(checkpoint) BETWEEN 1 AND 16384),
    event_kind TEXT NOT NULL,
    owner TEXT NOT NULL,
    owner_fence BIGINT NOT NULL,
    recording_id TEXT NOT NULL,
    chunk_index BIGINT NOT NULL CHECK (chunk_index >= 0),
    chunk_sha256 TEXT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (attempt_id, sequence),
    UNIQUE (recording_id, chunk_index)
);
