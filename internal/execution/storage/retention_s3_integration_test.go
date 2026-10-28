package storage

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

func testS3RecordingRetention(t *testing.T, cfg S3Options) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := NewS3Recording(cfg, make([]byte, 32), "retention-test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	backing := s.(*s3Recording)
	id := fmt.Sprintf("retention-%d", time.Now().UnixNano())
	neighbor := id + "-neighbor"
	for _, recording := range []string{id, neighbor} {
		w, err := s.Begin(ctx, recording)
		if err != nil {
			t.Fatal(err)
		}
		for i := uint64(0); i < 3; i++ {
			if err := w.PutChunk(ctx, i, []byte("protected retention output")); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Finalize(ctx, FinalizeMeta{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []string{"", "../escape", "safe/../neighbor"} {
		if _, err := backing.DeleteRecording(ctx, invalid, 2); err == nil {
			t.Fatal("unsafe deletion prefix accepted")
		}
	}
	if done, err := backing.DeleteRecording(ctx, id, 2); err != nil || done {
		t.Fatalf("first bounded deletion did not report partial progress: %v %v", done, err)
	}
	complete := false
	for i := 0; i < 5; i++ {
		done, err := backing.DeleteRecording(ctx, id, 2)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			complete = true
			break
		}
	}
	if !complete {
		t.Fatal("bounded deletion did not converge")
	}
	if done, err := backing.DeleteRecording(ctx, id, 2); err != nil || !done {
		t.Fatal("repeated deletion was not idempotent")
	}
	if _, err := backing.Open(ctx, id); !errors.Is(err, ErrNotFinalized) {
		t.Fatalf("expired recording manifest remains: %v", err)
	}
	r, err := backing.Open(ctx, neighbor)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Verify(ctx); err != nil {
		t.Fatal("exact-prefix deletion damaged neighboring recording")
	}
	// A separate bucket avoids changing the policy of any other fixture.
	versionedCfg := cfg
	versionedCfg.Bucket = fmt.Sprintf("retention-versioned-%d", time.Now().UnixNano())
	versioned, err := NewS3Recording(versionedCfg, make([]byte, 32), "versioned-test")
	if err != nil {
		t.Fatal(err)
	}
	defer versioned.Close()
	v := versioned.(*s3Recording)
	if err := v.client.SetBucketVersioning(ctx, v.bucket, minio.BucketVersioningConfiguration{Status: "Enabled"}); err != nil {
		t.Fatal(err)
	}
	if done, err := v.DeleteRecording(ctx, id, 2); !errors.Is(err, ErrConflict) || done {
		t.Fatal("versioned bucket falsely claimed physical recording deletion")
	}
}
