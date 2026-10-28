package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// Options is the decoupled storage configuration passed to Open. It mirrors the
// deployment config without importing the configuration package, keeping this
// package reusable and free of import cycles.
type Options struct {
	Mode                  string // "ephemeral" | "external" | "bundled"
	EphemeralDir          string
	EphemeralMaxBytes     int64
	DatabaseURL           string
	S3                    S3Options
	RecordingKey          []byte
	PreviousRecordingKeys [][]byte
	KeyID                 string
}

// String keeps active/read-only keys and storage credentials out of logs.
func (o Options) String() string { return fmt.Sprintf("execution storage options mode=%s", o.Mode) }

// S3Options is the object-store configuration for recording chunks.
type S3Options struct {
	Endpoint       string
	Region         string
	Bucket         string
	CAFile         string
	AccessKey      string
	SecretKey      string
	ForcePathStyle bool
	CreateBucket   bool
}

// String redacts credentials so options can be logged safely.
func (o S3Options) String() string { return "S3 options (credentials redacted)" }

// DeriveKeyID returns the public fingerprint for a recording key.
func DeriveKeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:16])
}

// Open builds the mode-appropriate Store. Disabled and unknown modes return
// ErrDisabled/error so admission cannot proceed. The returned Store is not
// ready until Ready succeeds.
func Open(ctx context.Context, opts Options) (Store, error) {
	switch opts.Mode {
	case "ephemeral":
		if len(opts.PreviousRecordingKeys) != 0 {
			return nil, fmt.Errorf("ephemeral recording does not accept persistent read-only keys")
		}
		key, keyID, err := ephemeralKey(opts.RecordingKey, opts.KeyID)
		if err != nil {
			return nil, err
		}
		rec, err := NewEphemeralRecording(opts.EphemeralDir, key, keyID, opts.EphemeralMaxBytes)
		if err != nil {
			return nil, err
		}
		return &store{mode: opts.Mode, durability: DurabilityNone, meta: NewEphemeralMetadata(), rec: rec}, nil
	case "external", "bundled":
		if len(opts.RecordingKey) == 0 {
			return nil, fmt.Errorf("persistent execution storage requires a recording key")
		}
		meta, err := NewPostgresMetadata(ctx, opts.DatabaseURL)
		if err != nil {
			return nil, err
		}
		rec, err := NewS3Recording(opts.S3, opts.RecordingKey, opts.KeyID, opts.PreviousRecordingKeys...)
		if err != nil {
			meta.Close()
			return nil, err
		}
		return &store{mode: opts.Mode, durability: DurabilityDurable, meta: meta, rec: rec}, nil
	case "", "disabled":
		return nil, ErrDisabled
	default:
		return nil, fmt.Errorf("unknown execution storage mode %q", opts.Mode)
	}
}

// ephemeralKey uses the supplied key when present, otherwise generates a
// process-lifetime random key. Ephemeral recordings are intentionally not
// decryptable after restart.
func ephemeralKey(key []byte, keyID string) ([]byte, string, error) {
	if len(key) == 0 {
		key = make([]byte, keySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, "", err
		}
	}
	if keyID == "" {
		keyID = DeriveKeyID(key)
	}
	return key, keyID, nil
}

type store struct {
	mode       string
	durability Durability
	meta       MetadataStore
	rec        RecordingStore
}

func (s *store) Metadata() MetadataStore   { return s.meta }
func (s *store) Recording() RecordingStore { return s.rec }
func (s *store) Mode() string              { return s.mode }
func (s *store) Durability() Durability    { return s.durability }

func (s *store) Ready(ctx context.Context) error {
	if err := s.meta.Ready(ctx); err != nil {
		return err
	}
	return s.rec.Ready(ctx)
}

func (s *store) Close() error {
	var first error
	if s.rec != nil {
		if err := s.rec.Close(); err != nil {
			first = err
		}
	}
	if s.meta != nil {
		if err := s.meta.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
