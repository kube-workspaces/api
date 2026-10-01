package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	workspacessvr "github.com/kube-workspaces/api/gen/http/workspaces/server"
	"github.com/kube-workspaces/api/gen/workspaces"
	goahttp "goa.design/goa/v3/http"
)

func TestWorkspaceSnapshotMatchesListHTTPWireFormat(t *testing.T) {
	state, started, created := "running", "2026-10-01T00:00:00Z", "2026-09-01T00:00:00Z"
	items := []*workspaces.Workspace{{
		Name: "vm", Namespace: "team", Type: "vm", Image: "example/image", ReadyReplicas: 1, CreatedAt: &created,
		ContainerState: &workspaces.ContainerState{State: &state, StartedAt: &started},
		Conditions:     []*workspaces.WorkspaceCondition{{LastTransitionTime: &started}},
		VolumeMounts:   []*workspaces.VolumeMount{{Name: "data", MountPath: "/data"}},
		RemoteDesktop:  &workspaces.ImageRemoteDesktop{Protocol: "selkies", Port: 8080, Path: "/desktop"},
	}}
	for _, result := range [][]*workspaces.Workspace{items, nil} {
		payload := &workspaces.ListPayload{Namespace: "team"}
		endpoint := func(_ context.Context, value any) (any, error) {
			if value != payload {
				t.Fatal("snapshot lost list filtering payload")
			}
			return result, nil
		}
		snapshot, err := workspaceListSnapshot(endpoint, payload)(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		if err := workspacessvr.EncodeListResponse(goahttp.ResponseEncoder)(context.Background(), rec, result); err != nil {
			t.Fatal(err)
		}
		var got, want any
		if err := json.Unmarshal(snapshot, &got); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("SSE differs from GET list transport: snapshot=%s, list=%s", snapshot, rec.Body.Bytes())
		}
		if len(result) == 0 && string(snapshot) != "[]" {
			t.Fatalf("empty snapshot = %s, want []", snapshot)
		}
		if len(result) > 0 {
			var decoded []map[string]any
			if err := json.Unmarshal(snapshot, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded[0]["name"] != "vm" || decoded[0]["ready_replicas"] != float64(1) || decoded[0]["remote_desktop"] == nil || decoded[0]["container_state"] == nil || decoded[0]["volume_mounts"] == nil {
				t.Fatal("required snake_case fields missing")
			}
		}
	}
}

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

func TestWatchRecoversFromInitialFailureAndClosedWatch(t *testing.T) {
	for _, initialFailure := range []bool{true, false} {
		t.Run(fmt.Sprintf("initial_failure=%t", initialFailure), func(t *testing.T) {
			var available atomic.Bool
			var calls atomic.Int32
			firstWatch := make(chan struct{})
			recovered := make(chan struct{}, 1)
			connected := make(chan struct{}, 1)
			var attempts atomic.Int32
			changes := func(context.Context) (<-chan struct{}, error) {
				attempt := attempts.Add(1)
				if attempt == 1 && !initialFailure {
					return firstWatch, nil
				}
				if !available.Load() {
					return nil, fmt.Errorf("unavailable")
				}
				connected <- struct{}{}
				return recovered, nil
			}
			list := func(context.Context) ([]byte, error) { return []byte(fmt.Sprintf(`[%d]`, calls.Add(1))), nil }
			timings := fastTimings()
			timings.heartbeat = 3 * time.Millisecond
			c := dialSSE(t, WorkspaceWatchHandler(list, changes, timings))
			defer c.cancel()
			c.next(t)
			if !initialFailure {
				close(firstWatch)
			}
			// Both heartbeat and polling must keep running during an outage.
			heartbeat, snapshot := false, false
			for !heartbeat || !snapshot {
				frame := c.next(t)
				heartbeat = heartbeat || strings.Contains(frame, ": heartbeat")
				snapshot = snapshot || strings.Contains(frame, "event: snapshot")
			}
			available.Store(true)
			select {
			case <-connected:
			case <-time.After(time.Second):
				t.Fatal("upstream watch was never re-established")
			}
			// Allow the gap snapshot to complete, then prove the fallback stops
			// listing while the recovered watch is healthy.
			time.Sleep(timings.poll)
			before := calls.Load()
			time.Sleep(2 * timings.poll)
			if after := calls.Load(); after != before {
				t.Fatalf("healthy recovered watch still polls: %d -> %d", before, after)
			}
			recovered <- struct{}{}
			for {
				if strings.Contains(c.next(t), fmt.Sprintf("data: [%d]", before+1)) {
					break
				}
			}
		})
	}
}
