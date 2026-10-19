-- Durable agent-upgrade attempts: one exclusive active reservation per VM UID,
-- idempotent start admission and worker lease fencing.
CREATE TABLE IF NOT EXISTS agent_upgrade_attempts (
    attempt_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    namespace TEXT NOT NULL,
    workspace_name TEXT NOT NULL,
    workspace_uid TEXT NOT NULL,
    vm_uid TEXT NOT NULL,
    actor_uid TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_manifest_sha256 TEXT NOT NULL CHECK (target_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    expected_installed_inventory_sha256 TEXT NOT NULL CHECK (expected_installed_inventory_sha256 ~ '^[0-9a-f]{64}$'),
    expected_revocation_epoch NUMERIC(20,0) NOT NULL CHECK (expected_revocation_epoch >= 0 AND expected_revocation_epoch <= 18446744073709551615),
    allow_reboot BOOLEAN NOT NULL,
    execution_id TEXT NOT NULL,
    recording_id TEXT NOT NULL,
    state TEXT NOT NULL,
    phase_times JSONB NOT NULL DEFAULT '{}'::jsonb,
    cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
    journal_sequence NUMERIC(20,0) NOT NULL DEFAULT 0 CHECK (journal_sequence >= 0 AND journal_sequence <= 18446744073709551615),
    error_code TEXT NOT NULL DEFAULT '',
    predecessor_target_id TEXT NOT NULL DEFAULT '',
    predecessor_manifest_sha256 TEXT NOT NULL DEFAULT '',
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_expires_at TIMESTAMPTZ,
    lease_fence BIGINT NOT NULL DEFAULT 0 CHECK (lease_fence >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (predecessor_manifest_sha256 = '' OR predecessor_manifest_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_upgrades_idem
    ON agent_upgrade_attempts (namespace, workspace_name, idempotency_key);

-- One reservation-holding attempt per VM UID: active progress states plus the
-- uncertain states an administrator must clear before another admission.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_upgrades_active_vm
    ON agent_upgrade_attempts (vm_uid)
    WHERE state IN (
        'admitted', 'staging', 'prepared', 'installing', 'verifying',
        'awaiting_reboot', 'rollback_pending', 'rolling_back',
        'manual_recovery_required', 'unknown', 'recording_lost'
    );

CREATE INDEX IF NOT EXISTS idx_agent_upgrades_workspace
    ON agent_upgrade_attempts (namespace, workspace_name, created_at DESC);
