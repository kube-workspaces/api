-- Minimal lifetime ID reservations survive metadata expiry. No original actor,
-- workspace scope, invocation or result is copied into this deletion receipt.
CREATE TABLE execution_identities (
    execution_id TEXT PRIMARY KEY,
    recording_id TEXT NOT NULL UNIQUE,
    metadata_purged_at TIMESTAMPTZ,
    metadata_cutoff TIMESTAMPTZ,
    recording_expired_at TIMESTAMPTZ,
    audit_events_deleted BIGINT,
    system_actor TEXT,
    CHECK (
        (metadata_purged_at IS NULL AND metadata_cutoff IS NULL AND recording_expired_at IS NULL AND audit_events_deleted IS NULL AND system_actor IS NULL)
        OR
        (metadata_purged_at IS NOT NULL AND metadata_cutoff IS NOT NULL AND recording_expired_at IS NOT NULL
         AND audit_events_deleted IS NOT NULL AND audit_events_deleted >= 0 AND system_actor IS NOT NULL
         AND system_actor = 'system:execution-retention' AND metadata_cutoff < metadata_purged_at AND recording_expired_at < metadata_cutoff)
    )
);

INSERT INTO execution_identities(execution_id,recording_id)
    SELECT execution_id,recording_id FROM execution_executions;

-- Enforce reservations for all writers, including older binaries that do not
-- understand metadata retention. Lock order: identity before execution row.
CREATE FUNCTION execution_reserve_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    reserved_recording TEXT;
    purged TIMESTAMPTZ;
BEGIN
    INSERT INTO execution_identities(execution_id,recording_id)
        VALUES(NEW.execution_id,NEW.recording_id) ON CONFLICT DO NOTHING;
    SELECT recording_id,metadata_purged_at INTO reserved_recording,purged
        FROM execution_identities WHERE execution_id=NEW.execution_id FOR UPDATE;
    IF NOT FOUND OR reserved_recording <> NEW.recording_id OR purged IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='execution identity is reserved';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER execution_identity_reservation BEFORE INSERT ON execution_executions
    FOR EACH ROW EXECUTE FUNCTION execution_reserve_identity();

-- Serialize every audit insert with metadata purging, even on legacy writers.
-- Historical orphan audit rows are not rewritten by this additive migration.
CREATE FUNCTION execution_audit_live_parent() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM execution_id FROM execution_executions WHERE execution_id=NEW.execution_id FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='23503', MESSAGE='execution audit parent is unavailable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER execution_audit_parent BEFORE INSERT ON execution_audit
    FOR EACH ROW EXECUTE FUNCTION execution_audit_live_parent();
