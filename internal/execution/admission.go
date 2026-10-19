package execution

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

// ErrAdmissionDenied is returned when an execution may not proceed. In every
// case the caller must treat it as fail-closed and must not start a process.
var ErrAdmissionDenied = errors.New("execution admission denied")

// AdmissionRequest is the off-guest, already-authorized description of one
// execution. The caller must have authenticated the actor and checked the
// controller-owned grants BEFORE calling Admit; the service only enforces
// storage readiness, durability and recording.
type AdmissionRequest struct {
	ExecutionID         string
	RecordingID         string
	ActorID             string
	Operation           storage.Operation
	Namespace           string
	WorkspaceName       string
	WorkspaceUID        string
	WorkspaceGeneration int64
	GrantVersion        string
	OSIdentity          string
	Elevated            bool
}

// ReplayAuthorizer decides whether a principal may replay a recording. It must
// re-check workspace.execution.recordings.read against the record's namespace
// and workspace on every call; it must never trust a previously-admitted
// execution ID as authority on its own.
type ReplayAuthorizer interface {
	AuthorizeReplay(ctx context.Context, actorID string, rec storage.ExecutionRecord) error
}

type denyAll struct{}

func (denyAll) AuthorizeReplay(context.Context, string, storage.ExecutionRecord) error {
	return ErrAdmissionDenied
}

// Service is the execution admission and recording coordinator. A zero-value or
// disabled store can never admit work, and a persistent store that is not Ready
// is never treated as permission to run.
type Service struct {
	store storage.Store
	authz ReplayAuthorizer
	now   func() time.Time
}

// NewService builds the coordinator. A nil store disables admission entirely
// (every Admit fails closed with ErrAdmissionDenied). Replay is denied until a
// ReplayAuthorizer is supplied via WithReplayAuthorizer.
func NewService(store storage.Store) *Service {
	return &Service{store: store, authz: denyAll{}, now: time.Now}
}

// WithReplayAuthorizer installs the replay policy and returns the service.
func (s *Service) WithReplayAuthorizer(a ReplayAuthorizer) *Service {
	if a != nil {
		s.authz = a
	}
	return s
}

// Ready reports whether the backing store can admit work. It is safe to call on
// a nil-store service and returns the store error otherwise.
func (s *Service) Ready(ctx context.Context) error {
	_, err := s.readyStore(ctx)
	return err
}

// Mode and Durability describe the active store, or disabled when unset.
func (s *Service) Mode() string {
	if s.store == nil {
		return string(StorageDisabled)
	}
	return s.store.Mode()
}

func (s *Service) Durability() storage.Durability {
	if s.store == nil {
		return storage.DurabilityNone
	}
	return s.store.Durability()
}

// readyStore enforces fail-closed admission: no store, a disabled store, an
// unknown mode or an unready store all deny.
func (s *Service) readyStore(ctx context.Context) (storage.Store, error) {
	if s.store == nil {
		return nil, fmt.Errorf("%w: %w", ErrAdmissionDenied, storage.ErrDisabled)
	}
	if err := s.store.Ready(ctx); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrAdmissionDenied, storage.ErrNotReady, err)
	}
	return s.store, nil
}

func (r AdmissionRequest) validate() error {
	if strings.TrimSpace(r.ExecutionID) == "" || strings.TrimSpace(r.RecordingID) == "" {
		return fmt.Errorf("%w: execution and recording ids are required", ErrAdmissionDenied)
	}
	if strings.TrimSpace(r.ActorID) == "" {
		return fmt.Errorf("%w: actor is required", ErrAdmissionDenied)
	}
	switch r.Operation {
	case storage.OperationCommand, storage.OperationScript, storage.OperationShell, storage.OperationUpgrade:
	default:
		return fmt.Errorf("%w: unknown operation", ErrAdmissionDenied)
	}
	if strings.TrimSpace(r.Namespace) == "" || strings.TrimSpace(r.WorkspaceName) == "" {
		return fmt.Errorf("%w: namespace and workspace are required", ErrAdmissionDenied)
	}
	return nil
}

// Admit durably records the admission before any process is created, opens the
// mandatory recording, and returns a session for streaming output and audit.
// The returned error always wraps ErrAdmissionDenied so callers cannot mistake
// a failure for permission to run.
func (s *Service) Admit(ctx context.Context, req AdmissionRequest) (*Session, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	store, err := s.readyStore(ctx)
	if err != nil {
		return nil, err
	}
	// An already-known execution ID must never be re-admitted: a duplicate
	// would desynchronize the recording's single-writer invariant.
	if _, _, err := store.Metadata().Get(ctx, req.ExecutionID); err == nil {
		return nil, fmt.Errorf("%w: execution %q already exists", ErrAdmissionDenied, req.ExecutionID)
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("%w: cannot check existing execution: %v", ErrAdmissionDenied, err)
	}
	rec := storage.ExecutionRecord{
		ExecutionID:         req.ExecutionID,
		ActorID:             req.ActorID,
		Operation:           req.Operation,
		Namespace:           req.Namespace,
		WorkspaceName:       req.WorkspaceName,
		WorkspaceUID:        req.WorkspaceUID,
		WorkspaceGeneration: req.WorkspaceGeneration,
		GrantVersion:        req.GrantVersion,
		OSIdentity:          req.OSIdentity,
		Elevated:            req.Elevated,
		RecordingID:         req.RecordingID,
		Mode:                store.Mode(),
		Durability:          store.Durability(),
		AdmissionTime:       s.now().UTC(),
		Admitted:            true,
	}
	if err := store.Metadata().Reserve(ctx, rec); err != nil {
		return nil, fmt.Errorf("%w: cannot record admission: %v", ErrAdmissionDenied, err)
	}
	writer, err := store.Recording().Begin(ctx, req.RecordingID)
	if err != nil {
		_ = store.Metadata().Transition(ctx, req.ExecutionID, storage.ExecutionOutcome{State: storage.StateRecordingLost, RecordingLost: true, EndTime: s.now().UTC()})
		return nil, fmt.Errorf("%w: cannot open recording", ErrAdmissionDenied)
	}
	detail := map[string]string{
		"operation":   string(req.Operation),
		"namespace":   req.Namespace,
		"workspace":   req.WorkspaceName,
		"osIdentity":  req.OSIdentity,
		"elevated":    strconv.FormatBool(req.Elevated),
		"mode":        rec.Mode,
		"recordingID": req.RecordingID,
	}
	if err := store.Metadata().Audit(ctx, storage.AuditEvent{
		ExecutionID: req.ExecutionID,
		Time:        s.now().UTC(),
		Kind:        "admitted",
		ActorID:     req.ActorID,
		Detail:      detail,
	}); err != nil {
		// Metadata audit is mandatory; a failure to record must abort the
		// execution and the recording.
		_ = writer.Abort(ctx)
		_ = store.Metadata().Transition(ctx, req.ExecutionID, storage.ExecutionOutcome{State: storage.StateFailed, EndTime: s.now().UTC(), Termination: "admission audit unavailable"})
		return nil, fmt.Errorf("%w: cannot record admission audit: %v", ErrAdmissionDenied, err)
	}
	return &Session{record: rec, writer: writer, meta: store.Metadata(), now: s.now}, nil
}

// Session serializes recording and lifecycle operations for one admission.
type Session struct {
	record       storage.ExecutionRecord
	meta         storage.MetadataStore
	writer       storage.Recorder
	now          func() time.Time
	mu           sync.Mutex
	next         uint64
	startTime    time.Time
	ended        bool
	recordingErr error
}

// Record returns a copy of the admission record bound to this session.
func (s *Session) Record() storage.ExecutionRecord { return s.record }

// Start marks the process as running. It is idempotent.
func (s *Session) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return storage.ErrFinalized
	}
	if s.startTime.IsZero() {
		s.startTime = s.now().UTC()
	}
	return s.meta.Transition(ctx, s.record.ExecutionID, storage.ExecutionOutcome{
		State:     storage.StateRunning,
		StartTime: s.startTime,
	})
}

// AppendChunk encrypts and stores the next contiguous recording chunk. Plaintext
// ordering is preserved; a gap is impossible because indices are session-owned.
func (s *Session) AppendChunk(ctx context.Context, plaintext []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return storage.ErrFinalized
	}
	if s.recordingErr != nil {
		return s.recordingErr
	}
	if err := s.writer.PutChunk(ctx, s.next, plaintext); err != nil {
		s.recordingErr = err
		return err
	}
	s.next++
	return nil
}

// Audit appends a non-sensitive audit event for this execution.
func (s *Session) Audit(ctx context.Context, kind string, detail map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta.Audit(ctx, storage.AuditEvent{
		ExecutionID: s.record.ExecutionID,
		Time:        s.now().UTC(),
		Kind:        kind,
		ActorID:     s.record.ActorID,
		Detail:      detail,
	})
}

// Finish finalizes the recording and writes the terminal outcome. If finalizing
// the recording fails the outcome is marked recording_lost; the execution is
// still finalized so the state never silently stays running.
func (s *Session) Finish(ctx context.Context, outcome storage.ExecutionOutcome) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return storage.ErrFinalized
	}
	if outcome.State == "" {
		outcome.State = storage.StateFailed
	}
	if !outcome.State.Terminal() {
		return storage.ErrConflict
	}
	s.ended = true
	if outcome.StartTime.IsZero() {
		outcome.StartTime = s.startTime
	}
	if outcome.EndTime.IsZero() {
		outcome.EndTime = s.now().UTC()
	}
	finalizeErr := s.writer.Finalize(ctx, storage.FinalizeMeta{ActorID: s.record.ActorID, EndTime: outcome.EndTime})
	recordingErr := errors.Join(s.recordingErr, finalizeErr)
	if recordingErr != nil {
		outcome.State = storage.StateRecordingLost
		outcome.RecordingLost = true
		_ = s.meta.Audit(ctx, storage.AuditEvent{
			ExecutionID: s.record.ExecutionID,
			Time:        s.now().UTC(),
			Kind:        "recording.lost",
			ActorID:     s.record.ActorID,
			Detail:      map[string]string{"reason": "recording storage failure"},
		})
	}
	if err := s.meta.Transition(ctx, s.record.ExecutionID, outcome); err != nil {
		return err
	}
	return errors.Join(recordingErr, s.meta.Audit(ctx, storage.AuditEvent{
		ExecutionID: s.record.ExecutionID,
		Time:        s.now().UTC(),
		Kind:        "finished",
		ActorID:     s.record.ActorID,
		Detail:      map[string]string{"state": string(outcome.State)},
	}))
}

// Abort preserves partial evidence and marks the execution failed. The caller
// must terminate any running process; this coordinator never owns a process.
func (s *Session) Abort(ctx context.Context, reason string) error {
	// Preserve partial evidence rather than deleting input/output on disconnect.
	return s.Finish(ctx, storage.ExecutionOutcome{
		State:       storage.StateFailed,
		Termination: reason,
	})
}

// Replay authorizes, verifies, and audits access before returning any recording.
func (s *Service) Replay(ctx context.Context, actorID, executionID string) (storage.Reader, storage.ExecutionRecord, error) {
	store, err := s.readyStore(ctx)
	if err != nil {
		return nil, storage.ExecutionRecord{}, err
	}
	if strings.TrimSpace(actorID) == "" {
		return nil, storage.ExecutionRecord{}, fmt.Errorf("%w: actor is required", ErrAdmissionDenied)
	}
	rec, _, err := store.Metadata().Get(ctx, executionID)
	if err != nil {
		return nil, storage.ExecutionRecord{}, err
	}
	if err := s.authz.AuthorizeReplay(ctx, actorID, rec); err != nil {
		_ = store.Metadata().Audit(ctx, storage.AuditEvent{
			ExecutionID: rec.ExecutionID,
			Time:        s.now().UTC(),
			Kind:        "replay.denied",
			ActorID:     actorID,
			Detail:      map[string]string{"recordingID": rec.RecordingID},
		})
		if errors.Is(err, ErrAdmissionDenied) {
			return nil, rec, err
		}
		return nil, rec, fmt.Errorf("%w: %v", ErrAdmissionDenied, err)
	}
	reader, err := s.store.Recording().Open(ctx, rec.RecordingID)
	if err != nil {
		return nil, rec, err
	}
	if reader.Manifest().RecordingID != rec.RecordingID {
		reader.Close()
		return nil, rec, storage.ErrTampered
	}
	if err := reader.Verify(ctx); err != nil {
		reader.Close()
		return nil, rec, err
	}
	if err := s.store.Metadata().Audit(ctx, storage.AuditEvent{
		ExecutionID: rec.ExecutionID,
		Time:        s.now().UTC(),
		Kind:        "replay.authorized",
		ActorID:     actorID,
		Detail:      map[string]string{"actor": actorID, "recordingID": rec.RecordingID},
	}); err != nil {
		reader.Close()
		return nil, rec, fmt.Errorf("%w: cannot record replay audit: %v", ErrAdmissionDenied, err)
	}
	return reader, rec, nil
}

// Close releases the backing store, if any.
func (s *Service) Close() error {
	if s.store == nil {
		return nil
	}
	return s.store.Close()
}
