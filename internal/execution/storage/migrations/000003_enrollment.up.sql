CREATE TABLE IF NOT EXISTS execution_enrollment (
    token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    namespace TEXT NOT NULL,
    workspace_name TEXT NOT NULL,
    workspace_uid TEXT NOT NULL,
    generation TEXT NOT NULL,
    revocation_epoch NUMERIC(20,0) NOT NULL CHECK (revocation_epoch >= 0 AND revocation_epoch <= 18446744073709551615),
    expires_at TIMESTAMPTZ NOT NULL,
    csr_hash TEXT CHECK (csr_hash ~ '^[0-9a-f]{64}$'),
    certificate_der BYTEA,
    CHECK ((csr_hash IS NULL AND certificate_der IS NULL)
        OR (csr_hash IS NOT NULL AND certificate_der IS NOT NULL AND octet_length(certificate_der) BETWEEN 1 AND 16384))
);

CREATE INDEX IF NOT EXISTS idx_enrollment_expiry ON execution_enrollment (expires_at);
CREATE INDEX IF NOT EXISTS idx_enrollment_workspace ON execution_enrollment (workspace_uid, generation);
