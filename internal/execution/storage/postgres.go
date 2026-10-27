package storage

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	pgxdriver "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var terminalStateList = []State{
	StateSucceeded, StateFailed, StateCancelled, StateTimedOut, StateRevoked, StateRecordingLost,
}

func terminalStatesSQL() string {
	s := "("
	for i, st := range terminalStateList {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("'%s'", st)
	}
	return s + ")"
}

// NewPostgresMetadata opens the durable metadata/audit store. It applies
// embedded migrations, then returns a pool-backed store. Any failure surfaces
// as an error so admission stays fail-closed.
func NewPostgresMetadata(ctx context.Context, databaseURL string) (MetadataStore, error) {
	if err := runMigrations(databaseURL); err != nil {
		return nil, fmt.Errorf("apply execution migrations: %w", err)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%w: %v", ErrNotReady, err)
	}
	return &postgresMetadata{pool: pool}, nil
}

func runMigrations(databaseURL string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	drv, err := pgxdriver.WithInstance(db, &pgxdriver.Config{})
	if err != nil {
		return err
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", drv)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

type postgresMetadata struct {
	pool *pgxpool.Pool
}

const executionColumns = `execution_id, actor_id, operation, namespace, workspace_name, workspace_uid,
	workspace_generation, grant_version, os_identity, elevated, recording_id, mode, durability,
	admission_time, admitted, deny_reason, state, start_time, end_time, exit_code, termination, recording_lost`

const insertExecution = `INSERT INTO execution_executions (` + executionColumns + `)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
	ON CONFLICT (execution_id) DO NOTHING`

func (m *postgresMetadata) Create(ctx context.Context, rec ExecutionRecord) error {
	return m.create(ctx, rec, false)
}

func (m *postgresMetadata) Reserve(ctx context.Context, rec ExecutionRecord) error {
	return m.create(ctx, rec, true)
}

func (m *postgresMetadata) create(ctx context.Context, rec ExecutionRecord, exclusive bool) error {
	tag, err := m.pool.Exec(ctx, insertExecution,
		rec.ExecutionID, rec.ActorID, string(rec.Operation), rec.Namespace, rec.WorkspaceName,
		rec.WorkspaceUID, rec.WorkspaceGeneration, rec.GrantVersion, rec.OSIdentity, rec.Elevated,
		rec.RecordingID, rec.Mode, string(rec.Durability), rec.AdmissionTime, rec.Admitted,
		rec.DenyReason, string(StateAdmitted), nil, nil, nil, "", false)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrConflict
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		if exclusive {
			return ErrConflict
		}
		// Already present; idempotent when identical, conflicting otherwise.
		existing, _, err := m.Get(ctx, rec.ExecutionID)
		if err != nil {
			return err
		}
		if sameRecord(existing, rec) {
			return nil
		}
		return ErrConflict
	}
	return nil
}

func (m *postgresMetadata) Transition(ctx context.Context, id string, outcome ExecutionOutcome) error {
	state, err := m.currentState(ctx, id)
	if err != nil {
		return err
	}
	if !validTransition(state, outcome.State) {
		return ErrConflict
	}
	return updateExecution(ctx, m.pool, id, state, outcome)
}

type executionExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func updateExecution(ctx context.Context, db executionExecer, id string, state State, outcome ExecutionOutcome) error {
	q := `UPDATE execution_executions
		SET state=$2, start_time=$3, end_time=$4, exit_code=$5, termination=$6, recording_lost=$7
		WHERE execution_id=$1 AND state=$8`
	var exit sql.NullInt32
	if outcome.ExitCode != nil {
		exit = sql.NullInt32{Int32: int32(*outcome.ExitCode), Valid: true}
	}
	var start, end sql.NullTime
	if !outcome.StartTime.IsZero() {
		start = sql.NullTime{Time: outcome.StartTime, Valid: true}
	}
	if !outcome.EndTime.IsZero() {
		end = sql.NullTime{Time: outcome.EndTime, Valid: true}
	}
	tag, err := db.Exec(ctx, q, id, string(outcome.State), start, end, exit, outcome.Termination, outcome.RecordingLost, string(state))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

func (m *postgresMetadata) Complete(ctx context.Context, id string, outcome ExecutionOutcome) error {
	if !validCompletion(outcome) {
		return ErrConflict
	}
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Serialize competing completions and legacy state transitions. Audit is
	// never appended for a loser, including a rewrite of an unknown outcome.
	rec, current, err := scanExecution(tx.QueryRow(ctx, `SELECT `+executionColumns+` FROM execution_executions WHERE execution_id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !validTransition(current.State, outcome.State) {
		if sameOutcome(current, outcome) {
			var recovered bool
			err := tx.QueryRow(ctx, `SELECT
				EXISTS (SELECT 1 FROM execution_audit WHERE execution_id=$1 AND kind='finished' AND actor_id=$2 AND detail->>'state'=$3)
				AND EXISTS (SELECT 1 FROM execution_audit WHERE execution_id=$1 AND kind='completion.recovered' AND actor_id='system:execution-recovery' AND detail->>'state'=$3)`, id, rec.ActorID, string(outcome.State)).Scan(&recovered)
			if err != nil {
				return err
			}
			if recovered {
				return nil
			}
		}
		return ErrConflict
	}
	if err := updateExecution(ctx, tx, id, current.State, outcome); err != nil {
		return err
	}
	for _, event := range completionEvents(id, rec.ActorID, outcome) {
		if err := insertExecutionAudit(ctx, tx, event); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (m *postgresMetadata) currentState(ctx context.Context, id string) (State, error) {
	var state string
	err := m.pool.QueryRow(ctx, `SELECT state FROM execution_executions WHERE execution_id=$1`, id).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return State(state), nil
}

func (m *postgresMetadata) Get(ctx context.Context, id string) (ExecutionRecord, ExecutionOutcome, error) {
	q := `SELECT ` + executionColumns + ` FROM execution_executions WHERE execution_id=$1`
	row := m.pool.QueryRow(ctx, q, id)
	rec, outcome, err := scanExecution(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ExecutionRecord{}, ExecutionOutcome{}, ErrNotFound
	}
	return rec, outcome, err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanExecution(row rowScanner) (ExecutionRecord, ExecutionOutcome, error) {
	var rec ExecutionRecord
	var op, dur, state, termination string
	var start, end sql.NullTime
	var exit sql.NullInt32
	var lost bool
	if err := row.Scan(
		&rec.ExecutionID, &rec.ActorID, &op, &rec.Namespace, &rec.WorkspaceName,
		&rec.WorkspaceUID, &rec.WorkspaceGeneration, &rec.GrantVersion, &rec.OSIdentity, &rec.Elevated,
		&rec.RecordingID, &rec.Mode, &dur, &rec.AdmissionTime, &rec.Admitted,
		&rec.DenyReason, &state, &start, &end, &exit, &termination, &lost); err != nil {
		return ExecutionRecord{}, ExecutionOutcome{}, err
	}
	rec.Operation = Operation(op)
	rec.Durability = Durability(dur)
	outcome := ExecutionOutcome{State: State(state), Termination: termination, RecordingLost: lost}
	if start.Valid {
		outcome.StartTime = start.Time
	}
	if end.Valid {
		outcome.EndTime = end.Time
	}
	if exit.Valid {
		code := int(exit.Int32)
		outcome.ExitCode = &code
	}
	return rec, outcome, nil
}

func (m *postgresMetadata) Audit(ctx context.Context, ev AuditEvent) error {
	return insertExecutionAudit(ctx, m.pool, ev)
}

func insertExecutionAudit(ctx context.Context, db executionExecer, ev AuditEvent) error {
	detail, err := json.Marshal(ev.Detail)
	if err != nil {
		return err
	}
	const q = `INSERT INTO execution_audit (execution_id, ts, kind, actor_id, detail) VALUES ($1,$2,$3,$4,$5)`
	_, err = db.Exec(ctx, q, ev.ExecutionID, ev.Time, ev.Kind, ev.ActorID, detail)
	return err
}

func (m *postgresMetadata) List(ctx context.Context, f Filter) ([]ExecutionRecord, error) {
	q := `SELECT ` + executionColumns + ` FROM execution_executions WHERE 1=1`
	args := []any{}
	add := func(cond string, val any) {
		args = append(args, val)
		q += fmt.Sprintf(" AND %s=$%d", cond, len(args))
	}
	if f.Namespace != "" {
		add("namespace", f.Namespace)
	}
	if f.WorkspaceName != "" {
		add("workspace_name", f.WorkspaceName)
	}
	if f.ActorID != "" {
		add("actor_id", f.ActorID)
	}
	if !f.Since.IsZero() {
		add("admission_time >=", f.Since)
	}
	q += " ORDER BY admission_time DESC"
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit)
	q += fmt.Sprintf(" LIMIT $%d", len(args))
	rows, err := m.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExecutionRecord
	for rows.Next() {
		rec, _, err := scanExecution(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (m *postgresMetadata) Ready(ctx context.Context) error {
	if err := m.pool.Ping(ctx); err != nil {
		return ErrNotReady
	}
	return nil
}

func (m *postgresMetadata) Close() error {
	m.pool.Close()
	return nil
}
