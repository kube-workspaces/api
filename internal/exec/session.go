package exec

import (
	"sync"
)

// sessionHandle tracks one active bridge session (serial console or VNC) for a
// workspace. closeAndCancel force-tears down the underlying connections so a
// take-over or shutdown ends the session promptly rather than waiting on
// blocked socket reads.
type sessionHandle struct {
	id     uint64
	cancel func()
	close  func()
}

// sessionRegistry guards single-session VM bridges. KubeVirt's serial console
// is single-session with last-wins behaviour — a fresh dial silently severs the
// client that was already connected — so without a guard an automated probe or
// a second browser tab would kick the session the user is actually looking at.
// The registry turns that into a clean "in use" signal the UI can prompt on
// (serial console take-over with consent) or reject outright (strict VNC guard).
type sessionRegistry struct {
	mu     sync.Mutex
	active map[string]*sessionHandle
	nextID uint64
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{active: make(map[string]*sessionHandle)}
}

// acquire registers handle as the active session for key when none is active.
// It returns (handle, true) on success, or (existing, false) when the slot is
// already taken so the caller can refuse or prompt.
func (s *sessionRegistry) acquire(key string, handle *sessionHandle) (*sessionHandle, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.active[key]; ok {
		return cur, false
	}
	s.nextID++
	handle.id = s.nextID
	s.active[key] = handle
	return handle, true
}

// held reports whether a session is currently active for key.
func (s *sessionRegistry) held(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.active[key]
	return ok
}

// stillCurrent reports whether handle still owns the slot for key. Used after a
// bridge is fully established to detect whether a take-over superseded us
// during the (sub-second) setup window.
func (s *sessionRegistry) stillCurrent(key string, handle *sessionHandle) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[key] == handle
}

// forceRelease ends any active session for key and returns whether one was
// active. Used by the serial console take-over endpoint to evict the current
// user before the taker opens their own session.
func (s *sessionRegistry) forceRelease(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.active[key]
	if !ok {
		return false
	}
	delete(s.active, key)
	cur.closeAndCancel()
	return true
}

// release removes the session for key when handle still owns the slot. The id
// guard prevents a superseded session (already evicted via a take-over) from
// unregistering its successor when it finally unwinds.
func (s *sessionRegistry) release(key string, handle *sessionHandle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.active[key]; ok && cur == handle {
		delete(s.active, key)
	}
}

func (h *sessionHandle) closeAndCancel() {
	if h == nil {
		return
	}
	if h.close != nil {
		h.close()
	}
	if h.cancel != nil {
		h.cancel()
	}
}

func consoleKey(namespace, name string) string {
	return namespace + "/" + name
}

var (
	serialSessions = newSessionRegistry()
	vncSessions    = newSessionRegistry()
)

// SerialConsoleInUse reports whether a serial console bridge is currently
// active for the workspace.
func SerialConsoleInUse(namespace, name string) bool {
	return serialSessions.held(consoleKey(namespace, name))
}

// TakeOverSerialConsole force-ends the active serial console bridge for the
// workspace, if any, so the caller can open a fresh session. It returns
// whether a session was active.
func TakeOverSerialConsole(namespace, name string) bool {
	return serialSessions.forceRelease(consoleKey(namespace, name))
}
