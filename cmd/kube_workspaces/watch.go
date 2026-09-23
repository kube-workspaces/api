package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
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
// updates in ~100 ms with zero polling.
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
		ctx := r.Context()

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
		writeSnapshot(w, first)
		flusher.Flush()

		changed, err := changes(ctx)
		polling := err != nil
		var pollTicker *time.Ticker
		var pollCh <-chan time.Time
		if polling {
			pollTicker = time.NewTicker(timings.poll)
			defer pollTicker.Stop()
			pollCh = pollTicker.C
		}
		heartbeat := time.NewTicker(timings.heartbeat)
		defer heartbeat.Stop()

		for {
			if !polling && changed == nil {
				// The server closed the watch stream; re-establish it, falling
				// back to polling if it stays down.
				retry := time.NewTicker(time.Second)
			retryLoop:
				for {
					select {
					case <-ctx.Done():
						retry.Stop()
						return
					case <-retry.C:
						if ch, err := changes(ctx); err == nil {
							changed = ch
							retry.Stop()
							break retryLoop
						}
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-heartbeat.C:
				_, _ = fmt.Fprint(w, ": heartbeat\n\n")
				flusher.Flush()
			case <-pollCh:
				if snap, err := list(ctx); err == nil {
					writeSnapshot(w, snap)
					flusher.Flush()
				}
			case _, ok := <-changed:
				if !ok {
					changed = nil
					continue
				}
				// Debounce: a rollout touches several objects at once; one
				// snapshot per burst, not one per object.
				timer := time.NewTimer(timings.debounce)
			debounce:
				for {
					select {
					case _, ok := <-changed:
						if !ok {
							changed = nil
							if !timer.Stop() {
								<-timer.C
							}
							break debounce
						}
						if !timer.Stop() {
							<-timer.C
						}
						timer.Reset(timings.debounce)
					case <-timer.C:
						break debounce
					case <-ctx.Done():
						timer.Stop()
						return
					}
				}
				if snap, err := list(ctx); err == nil {
					writeSnapshot(w, snap)
					flusher.Flush()
				}
			}
		}
	}
}

func writeSnapshot(w http.ResponseWriter, payload []byte) {
	_, _ = fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", payload)
}

// workspaceListSnapshot calls the Goa list endpoint and serialises the result
// for SSE. It lives here (not inline in the route) so the route stays thin.
func workspaceListSnapshot(listEndpoint func(context.Context, any) (any, error), payload any) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		res, err := listEndpoint(ctx, payload)
		if err != nil {
			return nil, err
		}
		return json.Marshal(res)
	}
}
