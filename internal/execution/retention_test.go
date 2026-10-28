package execution

import (
	"context"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
)

func TestRecordingRetentionRejectsUnsupportedStoresAndBounds(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Mode: "ephemeral", EphemeralDir: t.TempDir(), EphemeralMaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, service := range []*Service{NewService(nil), NewService(store)} {
		if stop, err := service.StartRecordingRetention(ctx, time.Hour); err == nil || stop != nil {
			t.Fatal("retention started on a disabled/ephemeral store")
		}
		for _, tt := range []struct {
			duration time.Duration
			limit    int
		}{{0, 1}, {-1, 1}, {time.Hour, 0}, {time.Hour, 101}, {time.Hour, 1}} {
			if _, _, err := service.ExpireRecordingsBatch(ctx, "", tt.duration, tt.limit); err == nil {
				t.Fatal("unsupported/unbounded retention sweep succeeded")
			}
		}
	}
}
