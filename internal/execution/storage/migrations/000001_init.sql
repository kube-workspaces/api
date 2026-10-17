CREATE TABLE IF NOT EXISTS execution_executions (
	execution_id TEXT PRIMARY KEY,
	actor_id TEXT NOT NULL,
	operation TEXT NOT NULL,
	namespace TEXT NOT NULL,
	workspace_name TEXT NOT NULL,
	workspace_uid TEXT NOT NULL,
	workspace_generation BIGINT NOT NULL,
	grant_version TEXT NOT NULL,
	os_identity TEXT NOT NULL,
	elevated BOOLEAN NOT NULL,
	recording_id TEXT NOT NULL,
	mode TEXT NOT NULL,
	durability TEXT NOT NULL,
	admission_time TIMESTAMPTZ NOT NULL,
	admitted BOOLEAN NOT NULL,
	deny_reason TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL DEFAULT 'admitted',
	start_time TIMESTAMPTZ,
	end_time TIMESTAMPTZ,
	exit_code INTEGER,
	termination TEXT NOT NULL DEFAULT '',
	recording_lost BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_execution_admission ON execution_executions (admission_time DESC);
CREATE INDEX IF NOT EXISTS idx_execution_namespace ON execution_executions (namespace, admission_time DESC);
CREATE INDEX IF NOT EXISTS idx_execution_workspace ON execution_executions (namespace, workspace_name, admission_time DESC);
CREATE INDEX IF NOT EXISTS idx_execution_actor ON execution_executions (actor_id, admission_time DESC);

CREATE TABLE IF NOT EXISTS execution_audit (
	execution_id TEXT NOT NULL,
	seq BIGSERIAL,
	ts TIMESTAMPTZ NOT NULL,
	kind TEXT NOT NULL,
	actor_id TEXT NOT NULL DEFAULT '',
	detail JSONB NOT NULL DEFAULT '{}'::jsonb,
	PRIMARY KEY (execution_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON execution_audit (ts DESC);
