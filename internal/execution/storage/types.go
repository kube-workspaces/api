// Package storage implements the durable-and-ephemeral execution store: a
// searchable metadata/audit layer (PostgreSQL in persistent modes, bounded
// in-memory in ephemeral mode) plus an encrypted, hash-chained recording chunk
// store (S3-compatible in persistent modes, bounded encrypted temp files in
// ephemeral mode).
//
// Admission must be fail-closed: a store that is not Ready can never be treated
// as permitting execution, and a storage outage in a persistent mode never
// downgrades to ephemeral.
package storage

import (
	"context"
	"errors"
	"time"
)

// Operation identifies the kind of admitted work.
type Operation string

// MaxChunkBytes bounds recording buffers and per-request playback responses.
const MaxChunkBytes = 1 << 20

const (
	OperationCommand Operation = "command"
	OperationScript  Operation = "script"
	OperationShell   Operation = "shell"
	// OperationUpgrade admits the mandatory recording of one durable agent
	// upgrade attempt; it never runs a process by itself.
	OperationUpgrade Operation = "upgrade"
)

// State is the monotonic lifecycle state of an execution.
type State string

const (
	// StateAdmitted means accepted into the recording sink before process
	// creation. Process start must not precede a durable admission in
	// persistent modes.
	StateAdmitted State = "admitted"
	StateRunning  State = "running"
	// StateUnknown is an uncertain or lost outcome (for example guest loss).
	// Callers must never auto-rerun from an unknown outcome.
	StateUnknown State = "unknown"

	StateSucceeded     State = "succeeded"
	StateFailed        State = "failed"
	StateCancelled     State = "cancelled"
	StateTimedOut      State = "timed_out"
	StateRevoked       State = "revoked"
	StateRecordingLost State = "recording_lost"
)

// Terminal reports whether the state is a final outcome. StateUnknown is
// terminal: the synchronous pilot transports have no late-outcome channel, so
// a lost guest transport is a permanently uncertain final result that must
// never be silently rerun or overwritten.
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateCancelled, StateTimedOut, StateRevoked, StateRecordingLost, StateUnknown:
		return true
	default:
		return false
	}
}

func validTransition(from, to State) bool {
	if from.Terminal() {
		return false
	}
	if to.Terminal() {
		return true
	}
	switch from {
	case "", StateAdmitted:
		return to == StateRunning
	case StateRunning:
		return to == StateRunning
	}
	return false
}

// Durability advertises whether execution state/history is retained.
type Durability string

const (
	DurabilityNone    Durability = "none" // ephemeral: no retained history guarantee
	DurabilityDurable Durability = "durable"
)

// ExecutionRecord is the off-guest admission metadata for one execution. It is
// searchable and durable in persistent modes.
type ExecutionRecord struct {
	ExecutionID         string
	ActorID             string
	Operation           Operation
	Namespace           string
	WorkspaceName       string
	WorkspaceUID        string
	WorkspaceGeneration int64
	GrantVersion        string
	OSIdentity          string
	Elevated            bool
	RecordingID         string
	Mode                string
	Durability          Durability
	AdmissionTime       time.Time
	Admitted            bool
	DenyReason          string
}

// ExecutionOutcome is the terminal (or last known) result of an execution.
type ExecutionOutcome struct {
	State         State
	StartTime     time.Time
	EndTime       time.Time
	ExitCode      *int
	Termination   string
	RecordingLost bool
}

// AuditEvent is a single ordered entry in the off-guest audit trail.
type AuditEvent struct {
	ExecutionID string
	Time        time.Time
	Kind        string
	ActorID     string
	// Detail carries non-sensitive structured context. It must never contain
	// command bodies, stdin, output or terminal content.
	Detail map[string]string
}

// Filter narrows List queries. Empty fields mean "unfiltered".
type Filter struct {
	Namespace     string
	WorkspaceName string
	ActorID       string
	Since         time.Time
	Limit         int
}

// Common store failures.
var (
	ErrDisabled         = errors.New("execution storage is disabled")
	ErrNotReady         = errors.New("execution storage is not ready")
	ErrNotFound         = errors.New("execution record not found")
	ErrConflict         = errors.New("execution record conflicts with existing record")
	ErrTampered         = errors.New("recording chunk failed integrity verification")
	ErrTruncated        = errors.New("recording is missing chunks")
	ErrSeqGap           = errors.New("recording chunk sequence is not contiguous")
	ErrFinalized        = errors.New("recording is already finalized")
	ErrOverCapacity     = errors.New("ephemeral storage capacity exceeded")
	ErrNotFinalized     = errors.New("recording is not finalized")
	ErrChunkTooLarge    = errors.New("recording chunk exceeds maximum size")
	ErrNoTerminalIntent = errors.New("recording has no terminal recovery intent")
)

// MetadataStore persists searchable execution metadata and the audit trail.
type MetadataStore interface {
	// Reserve atomically claims a new execution and recording identity. Unlike
	// Create, even identical retries conflict, so only one caller may start work.
	Reserve(ctx context.Context, rec ExecutionRecord) error
	// Create inserts a new execution record. It is idempotent on ExecutionID
	// when the content is identical, and returns ErrConflict when it differs.
	Create(ctx context.Context, rec ExecutionRecord) error
	// Transition applies a monotonic state change. A transition to a terminal
	// state is final; later transitions return ErrConflict.
	Transition(ctx context.Context, id string, outcome ExecutionOutcome) error
	// Complete atomically applies a terminal outcome and its canonical finished
	// audit (plus recording.lost when applicable), bound to the admitted actor.
	// It rejects nonterminal/missing-end-time outcomes and terminal rewrites.
	// An error can mean an uncertain commit; callers must never rerun a guest.
	Complete(ctx context.Context, id string, outcome ExecutionOutcome) error
	// Get returns the record and its last known outcome.
	Get(ctx context.Context, id string) (ExecutionRecord, ExecutionOutcome, error)
	// Audit appends an ordered audit event.
	Audit(ctx context.Context, ev AuditEvent) error
	// List returns records matching the filter, most recent admission first.
	List(ctx context.Context, f Filter) ([]ExecutionRecord, error)
	// Ready probes the backing store. It must fail when the store is unusable.
	Ready(ctx context.Context) error
	Close() error
}

// Recorder writes one live recording's encrypted chunks and finalizes its
// hash-chained manifest. Implementations are single-writer per recording.
type Recorder interface {
	// PutChunk encrypts and stores plaintext as index. Indices must start at 0
	// and advance by exactly one; gaps return ErrSeqGap.
	PutChunk(ctx context.Context, index uint64, plaintext []byte) error
	// Finalize writes the manifest binding the chunk count and hash chain.
	Finalize(ctx context.Context, meta FinalizeMeta) error
	// Abort discards partial data for this recording.
	Abort(ctx context.Context) error
}

// FinalizeMeta supplies optional protected terminal evidence. It does not replace
// a committed metadata outcome or authorize guest redispatch/reconciliation.
type FinalizeMeta struct {
	ActorID  string
	EndTime  time.Time
	Terminal *TerminalIntent
}

// Manifest is the authoritative integrity record for a finalized recording.
type Manifest struct {
	Authentication string    `json:"authentication"`
	Version        int       `json:"version"`
	RecordingID    string    `json:"recordingID"`
	KeyID          string    `json:"keyID"`
	Chunks         uint64    `json:"chunks"`
	PlaintextBytes int64     `json:"plaintextBytes"`
	Chain          string    `json:"chain"`
	CreatedAt      time.Time `json:"createdAt"`
	FinalizedAt    time.Time `json:"finalizedAt"`
	// Version 2 only: encrypted, admission-bound terminal recovery evidence.
	Terminal []byte `json:"terminal,omitempty"`
}

// Reader opens a finalized recording for replay. Callers must verify before
// trusting content, and must treat replay as sensitive evidence.
type Reader interface {
	Manifest() Manifest
	// ReadChunk returns the decrypted plaintext for index after verifying its
	// ciphertext and position.
	ReadChunk(ctx context.Context, index uint64) ([]byte, error)
	// Verify recomputes the hash chain over every chunk and confirms it matches
	// the manifest, detecting tampering and truncation.
	Verify(ctx context.Context) error
	// TerminalIntent verifies the full recording before decrypting terminal
	// evidence. Legacy v1 recordings return ErrNoTerminalIntent, never a guess.
	TerminalIntent(ctx context.Context) (*TerminalIntent, error)
	Close() error
}

// RecordingStore manages the lifecycle of encrypted recordings.
type RecordingStore interface {
	// Begin opens a new recorder for recordingID.
	Begin(ctx context.Context, recordingID string) (Recorder, error)
	// Open returns a verified reader for a finalized recording.
	Open(ctx context.Context, recordingID string) (Reader, error)
	Ready(ctx context.Context) error
	Close() error
}

// Store is the combined metadata + recording surface returned by Open.
type Store interface {
	Metadata() MetadataStore
	Recording() RecordingStore
	Mode() string
	Durability() Durability
	Ready(ctx context.Context) error
	Close() error
}
