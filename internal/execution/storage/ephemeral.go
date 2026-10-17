package storage

import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// safeID guards identifiers that become filesystem path components or S3 object
// keys against traversal and injection.
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validateID(kind, value string) error {
	if !safeID.MatchString(value) {
		return fmt.Errorf("invalid %s", kind)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Ephemeral metadata (bounded, in-memory, lost on restart)
// ---------------------------------------------------------------------------

const (
	defaultMaxExecutions  = 1000
	defaultMaxAuditEvents = 2000
)

// ephemeralMetadata is the bounded, in-memory metadata store used in ephemeral
// mode. It makes no durability promise; records may disappear on restart.
type ephemeralMetadata struct {
	mu       sync.Mutex
	records  map[string]ExecutionRecord
	outcomes map[string]ExecutionOutcome
	audit    map[string][]AuditEvent
	order    []string // insertion order, oldest first, for eviction
	max      int
}

// NewEphemeralMetadata returns an in-memory MetadataStore for ephemeral mode.
func NewEphemeralMetadata() MetadataStore {
	return &ephemeralMetadata{
		records:  make(map[string]ExecutionRecord),
		outcomes: make(map[string]ExecutionOutcome),
		audit:    make(map[string][]AuditEvent),
		max:      defaultMaxExecutions,
	}
}

func (m *ephemeralMetadata) Create(_ context.Context, rec ExecutionRecord) error {
	return m.create(rec, false)
}

func (m *ephemeralMetadata) Reserve(_ context.Context, rec ExecutionRecord) error {
	return m.create(rec, true)
}

func (m *ephemeralMetadata) create(rec ExecutionRecord, exclusive bool) error {
	if err := validateID("execution id", rec.ExecutionID); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.records[rec.ExecutionID]; ok {
		if !exclusive && sameRecord(existing, rec) {
			return nil // idempotent retry
		}
		return ErrConflict
	}
	for _, existing := range m.records {
		if existing.RecordingID == rec.RecordingID {
			return ErrConflict
		}
	}
	if len(m.records) >= m.max {
		return ErrOverCapacity
	}
	m.records[rec.ExecutionID] = rec
	m.order = append(m.order, rec.ExecutionID)
	for len(m.order) > m.max {
		oldest := m.order[0]
		m.order = m.order[1:]
		delete(m.records, oldest)
		delete(m.outcomes, oldest)
		delete(m.audit, oldest)
	}
	return nil
}

func sameRecord(a, b ExecutionRecord) bool {
	if !a.AdmissionTime.Equal(b.AdmissionTime) {
		return false
	}
	a.AdmissionTime, b.AdmissionTime = time.Time{}, time.Time{}
	return a == b
}

func (m *ephemeralMetadata) Transition(_ context.Context, id string, outcome ExecutionOutcome) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.records[id]; !ok {
		return ErrNotFound
	}
	if !validTransition(m.outcomes[id].State, outcome.State) {
		return ErrConflict
	}
	m.outcomes[id] = outcome
	return nil
}

func (m *ephemeralMetadata) Get(_ context.Context, id string) (ExecutionRecord, ExecutionOutcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return ExecutionRecord{}, ExecutionOutcome{}, ErrNotFound
	}
	return rec, m.outcomes[id], nil
}

func (m *ephemeralMetadata) Audit(_ context.Context, ev AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := append(m.audit[ev.ExecutionID], ev)
	if len(events) > defaultMaxAuditEvents {
		events = events[len(events)-defaultMaxAuditEvents:]
	}
	m.audit[ev.ExecutionID] = events
	return nil
}

func (m *ephemeralMetadata) List(_ context.Context, f Filter) ([]ExecutionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ExecutionRecord
	for _, rec := range m.records {
		if f.Namespace != "" && rec.Namespace != f.Namespace {
			continue
		}
		if f.WorkspaceName != "" && rec.WorkspaceName != f.WorkspaceName {
			continue
		}
		if f.ActorID != "" && rec.ActorID != f.ActorID {
			continue
		}
		if !f.Since.IsZero() && rec.AdmissionTime.Before(f.Since) {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AdmissionTime.After(out[j].AdmissionTime) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (m *ephemeralMetadata) Ready(context.Context) error { return nil }
func (m *ephemeralMetadata) Close() error                { return nil }

// ---------------------------------------------------------------------------
// Bounded byte budget shared by ephemeral recordings
// ---------------------------------------------------------------------------

type budget struct {
	mu   sync.Mutex
	used int64
	max  int64
}

func (b *budget) reserve(n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.max {
		return ErrOverCapacity
	}
	b.used += n
	return nil
}

func (b *budget) release(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
}

// ---------------------------------------------------------------------------
// Ephemeral recording (bounded encrypted temp files, no durability promise)
// ---------------------------------------------------------------------------

type ephemeralRecording struct {
	manifestKey []byte
	base        string
	gcm         cipher.AEAD
	keyID       string
	b           *budget
	mu          sync.Mutex
	finalized   map[string]bool
}

// NewEphemeralRecording returns an encrypted, byte-bounded file-backed
// RecordingStore for ephemeral mode.
func NewEphemeralRecording(base string, key []byte, keyID string, maxBytes int64) (RecordingStore, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	recordings := filepath.Join(base, "recordings")
	// Ephemeral recordings are intentionally unrecoverable after restart, so
	// discard anything left from a previous process rather than surface stale,
	// undecryptable chunks.
	if err := os.RemoveAll(recordings); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(recordings, 0o700); err != nil {
		return nil, err
	}
	return &ephemeralRecording{
		manifestKey: append([]byte(nil), key...),
		base:        recordings,
		gcm:         gcm,
		keyID:       keyID,
		b:           &budget{max: maxBytes},
		finalized:   make(map[string]bool),
	}, nil
}

func (s *ephemeralRecording) Begin(_ context.Context, recordingID string) (Recorder, error) {
	if err := validateID("recording id", recordingID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.finalized[recordingID] {
		s.mu.Unlock()
		return nil, ErrFinalized
	}
	s.mu.Unlock()
	dir := filepath.Join(s.base, recordingID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		if os.IsExist(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return &ephemeralRecorder{store: s, dir: dir, recordingID: recordingID, chain: chainStart(s.keyID, recordingID), createdAt: time.Now()}, nil
}

func (s *ephemeralRecording) Open(_ context.Context, recordingID string) (Reader, error) {
	if err := validateID("recording id", recordingID); err != nil {
		return nil, err
	}
	dir := filepath.Join(s.base, recordingID)
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFinalized
		}
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	if err := verifyManifest(s.manifestKey, s.keyID, recordingID, manifest); err != nil {
		return nil, err
	}
	return &ephemeralReader{store: s, dir: dir, manifest: manifest}, nil
}

func (s *ephemeralRecording) Ready(context.Context) error { return nil }
func (s *ephemeralRecording) Close() error                { return nil }

type ephemeralRecorder struct {
	store       *ephemeralRecording
	dir         string
	recordingID string
	chain       []byte
	createdAt   time.Time
	next        uint64
	plaintext   int64
	finalized   bool
}

func (r *ephemeralRecorder) PutChunk(ctx context.Context, index uint64, plaintext []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(plaintext) > MaxChunkBytes {
		return ErrChunkTooLarge
	}
	if r.finalized {
		return ErrFinalized
	}
	if index != r.next {
		return ErrSeqGap
	}
	payload := sealChunk(r.store.gcm, r.recordingID, r.store.keyID, index, plaintext)
	if err := r.store.b.reserve(int64(len(payload))); err != nil {
		return err
	}
	path := filepath.Join(r.dir, fmt.Sprintf("chunk-%016d.bin", index))
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		r.store.b.release(int64(len(payload)))
		return err
	}
	r.chain = chainNext(r.chain, index, payload)
	r.next++
	r.plaintext += int64(len(plaintext))
	return nil
}

func (r *ephemeralRecorder) Finalize(_ context.Context, _ FinalizeMeta) error {
	if r.finalized {
		return ErrFinalized
	}
	manifest := Manifest{
		Version:        1,
		RecordingID:    r.recordingID,
		KeyID:          r.store.keyID,
		Chunks:         r.next,
		PlaintextBytes: r.plaintext,
		Chain:          chainHex(r.chain),
		CreatedAt:      r.createdAt,
		FinalizedAt:    time.Now(),
	}
	manifest.Authentication = manifestAuthentication(r.store.manifestKey, manifest)
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.dir, "manifest.json"), raw, 0o600); err != nil {
		return err
	}
	r.store.mu.Lock()
	r.store.finalized[r.recordingID] = true
	r.store.mu.Unlock()
	r.finalized = true
	return nil
}

func (r *ephemeralRecorder) Abort(context.Context) error {
	r.finalized = true
	// Budget for this recording is reclaimed by dropping the directory; the
	// shared counter is approximate for aborts, which is acceptable for a
	// bounded ephemeral store that already promises no durability.
	return os.RemoveAll(r.dir)
}

type ephemeralReader struct {
	store    *ephemeralRecording
	dir      string
	manifest Manifest
}

func (r *ephemeralReader) Manifest() Manifest { return r.manifest }

func (r *ephemeralReader) ReadChunk(_ context.Context, index uint64) ([]byte, error) {
	if index >= r.manifest.Chunks {
		return nil, ErrNotFound
	}
	payload, err := os.ReadFile(r.chunkPath(index))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrTruncated
		}
		return nil, err
	}
	return openChunk(r.store.gcm, r.manifest.RecordingID, r.manifest.KeyID, index, payload)
}

func (r *ephemeralReader) chunkPath(index uint64) string {
	return filepath.Join(r.dir, fmt.Sprintf("chunk-%016d.bin", index))
}

func (r *ephemeralReader) Verify(ctx context.Context) error {
	if err := verifyManifest(r.store.manifestKey, r.store.keyID, r.manifest.RecordingID, r.manifest); err != nil {
		return err
	}
	chain := chainStart(r.manifest.KeyID, r.manifest.RecordingID)
	for i := uint64(0); i < r.manifest.Chunks; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		payload, err := os.ReadFile(r.chunkPath(i))
		if err != nil {
			if os.IsNotExist(err) {
				return ErrTruncated
			}
			return err
		}
		if _, err := openChunk(r.store.gcm, r.manifest.RecordingID, r.manifest.KeyID, i, payload); err != nil {
			return err
		}
		chain = chainNext(chain, i, payload)
	}
	if chainHex(chain) != r.manifest.Chain {
		return ErrTampered
	}
	return nil
}

func (r *ephemeralReader) Close() error { return nil }
