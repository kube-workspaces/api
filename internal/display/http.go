package display

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// ServeHTTP requires the enclosing route to authorize editor/namespace access
// and resolve the VM. Claim IDs are workspace-scoped, high-entropy capabilities
// in a header, never a URL/query string or a credential sent to the guest.
func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request, ns, name, action string) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	var result any
	var err error
	switch action {
	case "claim":
		var id string
		id, err = s.Claim(ctx, ns, name, "tier1")
		result = map[string]any{"id": id, "ttl_ms": ClientTTL / time.Millisecond, "protocol": 1}
	case "renew":
		err = s.Renew(ctx, ns, name, r.Header.Get("X-KW-Display-Claim"))
		result = map[string]any{"ttl_ms": ClientTTL / time.Millisecond, "protocol": 1}
	case "release":
		err = s.Release(ctx, ns, name, r.Header.Get("X-KW-Display-Claim"))
		result = map[string]bool{"ok": err == nil}
	case "status":
		var inUse bool
		inUse, err = s.InUse(ctx, ns, name)
		result = map[string]bool{"inUse": inUse}
	case "takeover":
		var inUse bool
		inUse, err = s.Revoke(ctx, ns, name)
		result = map[string]bool{"ok": err == nil, "wasInUse": inUse}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrBusy) || errors.Is(err, ErrRevoked) {
			status = http.StatusConflict
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(status)})
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}
