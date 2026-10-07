package agent

// Short-lived attach tickets for the workspace-agent transport.
//
// Trust model (do not weaken silently):
//   - Tickets are HMAC-SHA256 bearers minted by the API with the platform
//     session keys (rotation-safe: current key signs, predecessors verify).
//     The HMAC proves API issuance to key holders (the proxy edge).
//   - The guest agent holds no platform keys and never sees them. It
//     validates binding (workspace UID/generation, role, epoch, audience)
//     and freshness only. An empty ticket session id means "whoever holds
//     the live claim": the proxy bridges exactly one session per workspace
//     and the guest admits exactly one controller, so a stolen ticket is
//     confined to the workspace it names while unexpired.
//   - Renew/release correlate on the API session id, carried in the
//     X-KW-Agent-Session header between proxy and API — never to the guest.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Protocol is the wire protocol version this ticket store serves.
const Protocol = 1

// DefaultTTL is the ticket lifetime; the proxy renews at half of it.
const DefaultTTL = 60 * time.Second

// Ticket binds one attach grant. JSON tags are camelCase to match the
// guest agent's wire structs exactly.
type Ticket struct {
	WorkspaceUID        string `json:"workspaceUid"`
	WorkspaceGeneration string `json:"workspaceGeneration"`
	SessionID           string `json:"sessionId"`
	Participant         string `json:"participant"`
	Role                string `json:"role"`
	ControlEpoch        uint64 `json:"controlEpoch"`
	Audience            string `json:"audience"`
	IssuedAtNs          int64  `json:"issuedAtNs"`
	ExpiresAtNs         int64  `json:"expiresAtNs"`
}

// Session is a server-side attach record: the id the proxy renews and
// releases by, plus a snapshot of the ticket it was minted from.
type Session struct {
	ID        string
	Ticket    Ticket
	ExpiresAt time.Time
}

// Store mints, validates and tracks ticket sessions in memory. Sessions end
// with the process; clients fall back to the console path (documented in the
// indicator contract — no silent persistence is claimed).
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	now      func() time.Time
	ttl      time.Duration
}

// NewStore returns a Store with the default TTL and real clock.
func NewStore() *Store {
	return &Store{sessions: map[string]*Session{}, now: time.Now, ttl: DefaultTTL}
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func signPayload(payload []byte, key []byte) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("signing key is not configured")
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Mint creates a session and returns its id plus the signed ticket string
// ("id.payload.signature"). The ticket's SessionID is empty: it binds the
// live claim, correlated server-side by id.
func (s *Store) Mint(workspaceUID, workspaceGeneration, participant string, epoch uint64, keys [][]byte) (id, ticket string, err error) {
	if len(keys) == 0 || len(keys[0]) == 0 {
		return "", "", fmt.Errorf("signing key is not configured")
	}
	id, err = newID()
	if err != nil {
		return "", "", err
	}
	now := s.now()
	payload := Ticket{
		WorkspaceUID:        workspaceUID,
		WorkspaceGeneration: workspaceGeneration,
		Participant:         participant,
		Role:                "controller",
		ControlEpoch:        epoch,
		Audience:            "workspace-agent",
		IssuedAtNs:          now.UnixNano(),
		ExpiresAtNs:         now.Add(s.ttl).UnixNano(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	signed, err := signPayload(raw, keys[0])
	if err != nil {
		return "", "", err
	}
	s.mu.Lock()
	s.sessions[id] = &Session{ID: id, Ticket: payload, ExpiresAt: now.Add(s.ttl)}
	s.mu.Unlock()
	return id, id + "." + signed, nil
}

// Parse validates signature (any rotation key) and expiry, returning the
// ticket payload. It does not check workspace binding — the caller does.
func (s *Store) Parse(signed string, keys [][]byte) (Ticket, error) {
	var ticket Ticket
	parts := strings.SplitN(signed, ".", 3)
	if len(parts) != 3 || parts[0] == "" {
		return ticket, fmt.Errorf("invalid ticket format")
	}
	valid := false
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(parts[1]))
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(parts[2]), []byte(expected)) {
			valid = true
			break
		}
	}
	if !valid {
		return ticket, fmt.Errorf("invalid ticket signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ticket, fmt.Errorf("invalid ticket encoding: %w", err)
	}
	if err := json.Unmarshal(raw, &ticket); err != nil {
		return ticket, fmt.Errorf("invalid ticket payload: %w", err)
	}
	if s.now().UnixNano() > ticket.ExpiresAtNs {
		return ticket, fmt.Errorf("ticket expired")
	}
	return ticket, nil
}

// Lookup returns the live session record for renew/release correlation.
func (s *Store) Lookup(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok || s.now().After(session.ExpiresAt) {
		return nil, false
	}
	return session, true
}

// Renew extends a live session by one TTL. Expired or unknown ids fail
// closed (the proxy drops the bridge; the viewer re-attaches).
func (s *Store) Renew(id string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok || s.now().After(session.ExpiresAt) {
		delete(s.sessions, id)
		return time.Time{}, false
	}
	session.ExpiresAt = s.now().Add(s.ttl)
	return session.ExpiresAt, true
}

// Active counts live (unexpired) sessions bound to a workspace UID.
// Expired records are swept as observed, never resurrected.
func (s *Store) Active(workspaceUID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for id, session := range s.sessions {
		if s.now().After(session.ExpiresAt) {
			delete(s.sessions, id)
			continue
		}
		if session.Ticket.WorkspaceUID == workspaceUID {
			count++
		}
	}
	return count
}
func (s *Store) Release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}
