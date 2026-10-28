package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	pgxdriver "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testMetadataRetentionMigration(t *testing.T, dsn string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	name := fmt.Sprintf("metadata_migration_%d", time.Now().UnixNano())
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	}()
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() == "" {
		t.Fatal("migration test requires a disposable PostgreSQL URL")
	}
	u.Path, u.RawPath = "/"+name, ""
	func() {
		src, err := iofs.New(migrationsFS, "migrations")
		if err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("pgx", u.String())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		drv, err := pgxdriver.WithInstance(db, &pgxdriver.Config{})
		if err != nil {
			t.Fatal(err)
		}
		migration, err := migrate.NewWithInstance("iofs", src, "pgx5", drv)
		if err != nil {
			t.Fatal(err)
		}
		defer migration.Close()
		if err := migration.Steps(7); err != nil {
			t.Fatal(err)
		}
	}()
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	legacy := &postgresMetadata{pool: pool}
	rec := sampleRecord("legacy-execution")
	rec.RecordingID = "legacy-recording"
	rec.AdmissionTime = rec.AdmissionTime.UTC().Truncate(time.Microsecond)
	if err := legacy.Reserve(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Audit(ctx, AuditEvent{ExecutionID: rec.ExecutionID, Time: time.Now(), Kind: "admitted", ActorID: rec.ActorID}); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Audit(ctx, AuditEvent{ExecutionID: "historical-orphan", Time: time.Now(), Kind: "legacy-test"}); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(u.String()); err != nil {
		t.Fatal(err)
	}
	var recordingID string
	var purged *time.Time
	if err := pool.QueryRow(ctx, `SELECT recording_id,metadata_purged_at FROM execution_identities WHERE execution_id=$1`, rec.ExecutionID).Scan(&recordingID, &purged); err != nil || recordingID != rec.RecordingID || purged != nil {
		t.Fatal("migration did not backfill a live identity reservation")
	}
	if err := legacy.Create(ctx, rec); err != nil {
		t.Fatalf("migration broke an identical active create retry: %v", err)
	}
	if err := legacy.Reserve(ctx, rec); !errors.Is(err, ErrConflict) {
		t.Fatal("migration forgot an existing reservation")
	}
	if err := legacy.Audit(ctx, AuditEvent{ExecutionID: rec.ExecutionID, Time: time.Now(), Kind: "after-migration"}); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Audit(ctx, AuditEvent{ExecutionID: "new-orphan", Time: time.Now(), Kind: "late-test"}); err == nil {
		t.Fatal("migration allowed a new orphan audit row")
	}
	var historical int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM execution_audit WHERE execution_id='historical-orphan'`).Scan(&historical); err != nil || historical != 1 {
		t.Fatal("additive migration rewrote historical orphan evidence")
	}
}
