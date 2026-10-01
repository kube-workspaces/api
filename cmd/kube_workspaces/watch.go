package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	workspacessvr "github.com/kube-workspaces/api/gen/http/workspaces/server"
	"github.com/kube-workspaces/api/gen/workspaces"
)

// This file implements a live workspace list over Server-Sent Events:
//
//	GET /v1/workspaces/watch?namespace=<ns|_all>  →  text/event-stream
//
// The desktop shell currently polls `GET /v1/workspaces?namespace=_all` every
// 5 s to refresh its list. Polling is correct but wasteful (a full list +
// image join per tick per client) and 5 s stale by construction. The watch
// route sends the same payload as `list` as `event: snapshot` — first
// immediately, then again whenever a Workspace CR changes — so clients render
// updates after a 250 ms debounce with zero polling while healthy.
//
// Shape, deliberately minimal:
//
//	event: snapshot
//	data: [{"name":..., "namespace":..., ...}, ...]
//
//	: heartbeat
//
// Snapshots reuse the Goa `list` endpoint itself, so auth filtering,
// `ready_replicas`, image capability adverts and every future list field stay
// identical between poll and watch by construction — there is exactly one
// list implementation. The watch only decides *when* to re-list: a dynamic
// client Watch on the Workspace CRs (debounced 250 ms), with a 5 s poll
// fallback when Watch is unavailable and re-establishment when the server
// closes the stream. Heartbeat comments every 25 s keep intermediaries from
// idle-timing-out the stream (nginx default 60 s).
//
// Auth rides the existing middleware: the route lives under `/v1/`, so the
// session check already ran, and the list endpoint re-applies its own
// namespace filtering per snapshot.

// watchTimings configures the SSE loop; production values are the defaults,
// tests shrink them.
type watchTimings struct {
	debounce  time.Duration
	heartbeat time.Duration
	poll      time.Duration
}

var defaultWatchTimings = watchTimings{
	debounce:  250 * time.Millisecond,
	heartbeat: 25 * time.Second,
	poll:      5 * time.Second,
}

// WorkspaceWatchHandler streams list snapshots as SSE. list returns the
// current list payload (already serialised); changes returns a channel that
// fires on every upstream change, or an error when Watch is unavailable (the
// handler then polls). Both are re-invoked as needed over the stream's life.
func WorkspaceWatchHandler(list func(ctx context.Context) ([]byte, error), changes func(ctx context.Context) (<-chan struct{}, error), timings watchTimings) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		// Establish the watch before listing so a change between the initial
		// snapshot and watch setup cannot be missed.
		changed, err := changes(ctx)
		if err != nil {
			changed = nil
		}

		// Snapshot before committing to 200: a broken lister must still be
		// able to answer 500.
		first, err := list(ctx)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to list workspaces: %v", err), http.StatusInternalServerError)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		if err := writeSnapshot(w, first); err != nil {
			return
		}
		flusher.Flush()

		// This ticker stays active to retry failed/closed upstream watches.
		// It only lists while disconnected; a healthy watch never polls.
		pollTicker := time.NewTicker(timings.poll)
		defer pollTicker.Stop()
		heartbeat := time.NewTicker(timings.heartbeat)
		defer heartbeat.Stop()
		var debounce *time.Timer
		var debounceCh <-chan time.Time
		defer func() {
			if debounce != nil {
				debounce.Stop()
			}
		}()
		snapshot := func() bool {
			snap, err := list(ctx)
			if err != nil {
				// Reconnect through middleware rather than keeping an apparently
				// healthy stream of stale data after listing/auth failures.
				return false
			}
			if err := writeSnapshot(w, snap); err != nil {
				return false
			}
			flusher.Flush()
			return true
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.C:
				if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
					return
				}
				flusher.Flush()
			case <-pollTicker.C:
				if changed != nil {
					continue
				}
				if ch, err := changes(ctx); err == nil {
					changed = ch
				}
				// Always re-list across a watch gap, even when reconnect succeeds.
				if !snapshot() {
					return
				}
			case _, ok := <-changed:
				if !ok {
					changed = nil
					continue
				}
				// Coalesce bursts without starving heartbeats or snapshots under
				// continuous activity: bound the delay from the first event.
				if debounceCh == nil {
					if debounce == nil {
						debounce = time.NewTimer(timings.debounce)
					} else {
						debounce.Reset(timings.debounce)
					}
					debounceCh = debounce.C
				}
			case <-debounceCh:
				debounceCh = nil
				if !snapshot() {
					return
				}
			}
		}
	}
}

func writeSnapshot(w http.ResponseWriter, payload []byte) error {
	_, err := fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", payload)
	return err
}

// workspaceListSnapshot calls the Goa list endpoint and serialises the result
// for SSE. It lives here (not inline in the route) so the route stays thin.
func workspaceListSnapshot(listEndpoint func(context.Context, any) (any, error), payload any) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		res, err := listEndpoint(ctx, payload)
		if err != nil {
			return nil, err
		}
		items, ok := res.([]*workspaces.Workspace)
		if !ok {
			return nil, fmt.Errorf("unexpected workspace list result %T", res)
		}
		// Service result types have no JSON tags. Use the same generated HTTP
		// body as GET /v1/workspaces, including snake_case nested fields.
		return json.Marshal(workspacessvr.NewListResponseBody(items))
	}
}
