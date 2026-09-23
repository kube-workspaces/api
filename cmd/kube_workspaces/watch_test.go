package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sseClient reads event frames (terminated by a blank line) from a live SSE
// stream until ctx ends.
type sseClient struct {
	cancel context.CancelFunc
	frames chan string
}

func dialSSE(t *testing.T, handler http.HandlerFunc) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Cleanup(cancel)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("dial SSE: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	c := &sseClient{cancel: cancel, frames: make(chan string, 16)}
	go func() {
		defer close(c.frames)
		sc := bufio.NewReader(resp.Body)
		for {
			var sb strings.Builder
			for {
				line, err := sc.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\n" {
					break
				}
				sb.WriteString(line)
			}
			select {
			case c.frames <- sb.String():
			case <-ctx.Done():
				return
			}
		}
	}()
	return c
}

func (c *sseClient) next(t *testing.T) string {
	t.Helper()
	select {
	case f, ok := <-c.frames:
		if !ok {
			t.Fatal("SSE stream closed unexpectedly")
		}
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SSE frame")
		return ""
	}
}

func fastTimings() watchTimings {
	return watchTimings{debounce: 5 * time.Millisecond, heartbeat: time.Hour, poll: 10 * time.Millisecond}
}

func TestWatchSendsSnapshotThenUpdate(t *testing.T) {
	var calls atomic.Int32
	list := func(ctx context.Context) ([]byte, error) {
		n := calls.Add(1)
		return []byte(fmt.Sprintf(`[{"v":%d}]`, n)), nil
	}
	changed := make(chan struct{}, 1)
	changes := func(ctx context.Context) (<-chan struct{}, error) { return changed, nil }

	c := dialSSE(t, WorkspaceWatchHandler(list, changes, fastTimings()))
	defer c.cancel()

	first := c.next(t)
	if !strings.Contains(first, "event: snapshot") || !strings.Contains(first, `[{"v":1}]`) {
		t.Fatalf("first frame = %q, want snapshot v1", first)
	}
	changed <- struct{}{}
	second := c.next(t)
	if !strings.Contains(second, `[{"v":2}]`) {
		t.Fatalf("second frame = %q, want snapshot v2", second)
	}
}

func TestWatchDebouncesBursts(t *testing.T) {
	var calls atomic.Int32
	list := func(ctx context.Context) ([]byte, error) {
		return []byte(fmt.Sprintf(`[%d]`, calls.Add(1))), nil
	}
	changed := make(chan struct{}, 1)
	changes := func(ctx context.Context) (<-chan struct{}, error) { return changed, nil }

	c := dialSSE(t, WorkspaceWatchHandler(list, changes, fastTimings()))
	defer c.cancel()
	c.next(t) // initial

	// A burst of 5 changes inside the debounce window yields exactly one more
	// snapshot, not five.
	for i := 0; i < 5; i++ {
		changed <- struct{}{}
	}
	frame := c.next(t)
	if !strings.Contains(frame, "[2]") {
		t.Fatalf("frame = %q, want single resnapshot [2]", frame)
	}
	select {
	case f := <-c.frames:
		t.Fatalf("unexpected extra frame %q after burst (debounce failed)", f)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWatchFallsBackToPoll(t *testing.T) {
	var calls atomic.Int32
	list := func(ctx context.Context) ([]byte, error) {
		return []byte(fmt.Sprintf(`[%d]`, calls.Add(1))), nil
	}
	changes := func(ctx context.Context) (<-chan struct{}, error) {
		return nil, fmt.Errorf("watch unavailable")
	}

	c := dialSSE(t, WorkspaceWatchHandler(list, changes, fastTimings()))
	defer c.cancel()
	c.next(t) // initial
	second := c.next(t)
	if !strings.Contains(second, "[2]") {
		t.Fatalf("poll frame = %q, want [2]", second)
	}
}

func TestWatchListErrorIs500(t *testing.T) {
	h := WorkspaceWatchHandler(
		func(ctx context.Context) ([]byte, error) { return nil, fmt.Errorf("boom") },
		func(ctx context.Context) (<-chan struct{}, error) { return nil, fmt.Errorf("unreachable") },
		fastTimings(),
	)
	req := httptest.NewRequest(http.MethodGet, "/v1/workspaces/watch", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
