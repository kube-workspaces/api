package storage

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const recordingPrefix = "executions"

// s3Recording is the durable, encrypted recording chunk store on S3-compatible
// object storage (RustFS, SeaweedFS, MinIO, AWS).
type s3Recording struct {
	manifestKey []byte
	client      *minio.Client
	bucket      string
	gcm         cipher.AEAD
	keyID       string
}

// NewS3Recording opens an S3-backed RecordingStore. It verifies the key and
// (unless createBucket is set) that the bucket exists, and returns ErrNotReady
// when the store cannot be used.
func NewS3Recording(cfg S3Options, key []byte, keyID string) (RecordingStore, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	transport, err := s3Transport(cfg)
	if err != nil {
		return nil, err
	}
	useTLS := false
	endpoint := cfg.Endpoint
	if cfg.Endpoint != "" {
		parsed, err := url.Parse(cfg.Endpoint)
		if err != nil {
			return nil, err
		}
		useTLS = parsed.Scheme == "https"
		endpoint = parsed.Host
	}
	lookup := minio.BucketLookupAuto
	if cfg.ForcePathStyle {
		lookup = minio.BucketLookupPath
	}
	client, err := minio.New(endpoint, &minio.Options{
		BucketLookup: lookup,
		Creds:        credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure:       useTLS,
		Region:       cfg.Region,
		Transport:    transport,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotReady, err)
	}
	if !exists {
		if !cfg.CreateBucket {
			return nil, ErrNotReady
		}
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotReady, err)
		}
	}
	return &s3Recording{manifestKey: append([]byte(nil), key...), client: client, bucket: cfg.Bucket, gcm: gcm, keyID: keyID}, nil
}

func s3Transport(cfg S3Options) (http.RoundTripper, error) {
	if cfg.CAFile == "" {
		return http.DefaultTransport, nil
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("invalid S3 CA bundle")
	}
	base := http.DefaultTransport
	transport, ok := base.(*http.Transport)
	if !ok {
		return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, nil
	}
	clone := transport.Clone()
	clone.TLSClientConfig = &tls.Config{RootCAs: pool}
	return clone, nil
}

func (s *s3Recording) chunkObject(recordingID string, index uint64) string {
	return fmt.Sprintf("%s/%s/chunks/%016d.chunk", recordingPrefix, recordingID, index)
}

func (s *s3Recording) manifestObject(recordingID string) string {
	return fmt.Sprintf("%s/%s/manifest.json", recordingPrefix, recordingID)
}

func (s *s3Recording) Begin(ctx context.Context, recordingID string) (Recorder, error) {
	if err := validateID("recording id", recordingID); err != nil {
		return nil, err
	}
	// Prove write admission before a process can start, not merely bucket-read
	// permission. Recording IDs have already been atomically reserved in metadata.
	if err := s.putContext(ctx, fmt.Sprintf("%s/%s/pending", recordingPrefix, recordingID), []byte("recording-v1")); err != nil {
		return nil, err
	}
	return &s3Recorder{store: s, recordingID: recordingID, chain: chainStart(s.keyID, recordingID), createdAt: time.Now()}, nil
}

func (s *s3Recording) Open(ctx context.Context, recordingID string) (Reader, error) {
	if err := validateID("recording id", recordingID); err != nil {
		return nil, err
	}
	raw, err := s.getContext(ctx, s.manifestObject(recordingID))
	if err != nil {
		if isNoSuchKey(err) {
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
	return &s3Reader{store: s, manifest: manifest}, nil
}

func (s *s3Recording) get(object string) ([]byte, error) {
	return s.getContext(context.Background(), object)
}

func (s *s3Recording) getContext(parent context.Context, object string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	obj, err := s.client.GetObject(ctx, s.bucket, object, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	// Includes GCM nonce/tag overhead; manifests are bounded by the same cap.
	data, err := io.ReadAll(io.LimitReader(obj, MaxChunkBytes+1025))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxChunkBytes+1024 {
		return nil, ErrChunkTooLarge
	}
	return data, nil
}

func (s *s3Recording) put(object string, data []byte) error {
	return s.putContext(context.Background(), object, data)
}

func (s *s3Recording) putContext(parent context.Context, object string, data []byte) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	_, err := s.client.PutObject(ctx, s.bucket, object, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{})
	return err
}

func (s *s3Recording) remove(object string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.client.RemoveObject(ctx, s.bucket, object, minio.RemoveObjectOptions{})
}

func isNoSuchKey(err error) bool {
	// minio returns an error whose message contains "NoSuchKey".
	if err == nil {
		return false
	}
	return bytes.Contains([]byte(err.Error()), []byte("NoSuchKey"))
}

func (s *s3Recording) Ready(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil || !exists {
		return ErrNotReady
	}
	return nil
}

func (s *s3Recording) Close() error { return nil }

type s3Recorder struct {
	store       *s3Recording
	recordingID string
	chain       []byte
	createdAt   time.Time
	next        uint64
	plaintext   int64
	finalized   bool
}

func (r *s3Recorder) PutChunk(ctx context.Context, index uint64, plaintext []byte) error {
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
	if err := r.store.putContext(ctx, r.store.chunkObject(r.recordingID, index), payload); err != nil {
		return err
	}
	r.chain = chainNext(r.chain, index, payload)
	r.next++
	r.plaintext += int64(len(plaintext))
	return nil
}

func (r *s3Recorder) Finalize(ctx context.Context, meta FinalizeMeta) error {
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
	if err := protectTerminalIntent(&manifest, r.store.manifestKey, meta); err != nil {
		return err
	}
	manifest.Authentication = manifestAuthentication(r.store.manifestKey, manifest)
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := r.store.putContext(ctx, r.store.manifestObject(r.recordingID), raw); err != nil {
		return err
	}
	r.finalized = true
	return nil
}

func (r *s3Recorder) Abort(context.Context) error {
	r.finalized = true
	for i := uint64(0); i < r.next; i++ {
		_ = r.store.remove(r.store.chunkObject(r.recordingID, i))
	}
	_ = r.store.remove(r.store.manifestObject(r.recordingID))
	return nil
}

type s3Reader struct {
	store    *s3Recording
	manifest Manifest
}

func (r *s3Reader) Manifest() Manifest { return cloneManifest(r.manifest) }

func (r *s3Reader) TerminalIntent(ctx context.Context) (*VerifiedTerminalIntent, error) {
	if err := r.Verify(ctx); err != nil {
		return nil, err
	}
	if r.manifest.Version == 1 {
		return nil, ErrNoTerminalIntent
	}
	i, err := openTerminalIntent(r.store.manifestKey, r.manifest.KeyID, r.manifest.RecordingID, r.manifest.Terminal)
	if err != nil {
		return nil, err
	}
	return &VerifiedTerminalIntent{intent: *i}, nil
}

func (r *s3Reader) ReadChunk(ctx context.Context, index uint64) ([]byte, error) {
	if index >= r.manifest.Chunks {
		return nil, ErrNotFound
	}
	payload, err := r.store.getContext(ctx, r.store.chunkObject(r.manifest.RecordingID, index))
	if err != nil {
		if isNoSuchKey(err) {
			return nil, ErrTruncated
		}
		return nil, err
	}
	return openChunk(r.store.gcm, r.manifest.RecordingID, r.manifest.KeyID, index, payload)
}

func (r *s3Reader) Verify(ctx context.Context) error {
	if err := verifyManifest(r.store.manifestKey, r.store.keyID, r.manifest.RecordingID, r.manifest); err != nil {
		return err
	}
	chain := chainStart(r.manifest.KeyID, r.manifest.RecordingID)
	for i := uint64(0); i < r.manifest.Chunks; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		payload, err := r.store.getContext(ctx, r.store.chunkObject(r.manifest.RecordingID, i))
		if err != nil {
			if isNoSuchKey(err) {
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

func (r *s3Reader) Close() error { return nil }
