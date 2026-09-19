package display

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	// SessionProtocol is the display session API/protocol revision advertised
	// to clients.
	SessionProtocol = 1

	// MaxParticipants caps simultaneous members (controller + observers) per
	// workspace display session. Chosen to keep capture framebuffer fan-out and
	// per-observer outbound queues bounded while allowing practical collabo-desk
	// sessions.
	MaxParticipants = 8

	// MaxWidth/MaxHeight bound the advertised guest framebuffer used for
	// validation and memory bounding.
	MaxWidth  = 4096
	MaxHeight = 2160

	// HandshakeTimeout bounds each observer's display stream negotiation.
	HandshakeTimeout = 10 * time.Second

	// IdleMembershipTTL is how long a participant may remain inactive before the
	// registry drops it. Observer streams keep this refreshed via heartbeat
	// touch; a joined-but-never-attached participant also expires.
	IdleMembershipTTL = 15 * time.Minute
)

const (
	// RoleObserver is a view-only participant.
	RoleObserver = "observer"
	// RoleController can inject input and is the single writer.
	RoleController = "controller"
)

var (
	// ErrCapacity means the workspace display session reached MaxParticipants.
	ErrCapacity = errors.New("display session participant limit reached")
	// ErrParticipantNotFound means the workspace or participant id is unknown.
	ErrParticipantNotFound = errors.New("display participant not found")
	// ErrControllerPresent means a controller already holds the display.
	ErrControllerPresent = errors.New("display already controlled")
	// ErrNotController means the acting participant does not hold control.
	ErrNotController = errors.New("participant is not the current controller")
	// ErrAlreadyController means the acting participant already holds control.
	ErrAlreadyController = errors.New("participant is already the controller")
	// ErrBadTarget is returned when a transfer target is missing or not an observer.
	ErrBadTarget = errors.New("transfer target must be an observer participant")
	// ErrInvalidRole is returned for an unknown join role.
	ErrInvalidRole = errors.New("invalid display participant role")
)

// Participant is a snapshot of a workspace display session member.
type Participant struct {
	ID        string
	Role      string
	Connected bool
	JoinedAt  time.Time
}

// Capability describes the session limits plus a live count snapshot.
type Capability struct {
	Protocol          int
	Transports        []string
	MaxParticipants   int
	MaxWidth          int
	MaxHeight         int
	HandshakeTimeout  time.Duration
	IdleMembershipTTL time.Duration
	Participants      int
	ControllerPresent bool
}

// Status is a point-in-time membership snapshot for one workspace.
type Status struct {
	Protocol     int
	Epoch        string
	Controller   *Participant
	Observers    []*Participant
	Participants int
}

type session struct {
	epoch      string
	controller string
	members    map[string]*Participant
	lastSeen   map[string]time.Time
}

func (s *session) activeParticipant() *Participant {
	if s.controller == "" {
		return nil
	}
	return s.members[s.controller]
}

// Sessions is the in-memory membership registry for shared display sessions.
// It enforces the "one controller plus view-only observers" invariant and keeps
// participants bounded. B later binds control back to the coordination Lease
// store when proving multi-replica safety; this registry alone is local only.
type Sessions struct {
	mu       sync.Mutex
	sessions map[string]*session // key: ns + "/" + name
	now      func() time.Time
}

// NewSessions returns an empty registry.
func NewSessions() *Sessions {
	return &Sessions{sessions: make(map[string]*session), now: time.Now}
}

func (s *Sessions) key(ns, name string) string { return ns + "/" + name }

// purge removes expired participants from a session and deletes the session
// once empty. Callers must hold s.mu.
func (s *Sessions) purge(key string, sess *session) *session {
	if sess == nil {
		return s.sessions[key]
	}
	now := s.now()
	for id := range sess.members {
		if now.Sub(sess.lastSeen[id]) >= IdleMembershipTTL {
			delete(sess.members, id)
			delete(sess.lastSeen, id)
			if sess.controller == id {
				sess.controller = ""
			}
		}
	}
	if len(sess.members) == 0 {
		delete(s.sessions, key)
		return nil
	}
	return sess
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Capability returns the static limits and a live snapshot. The returned
// Capability is safe for concurrent use.
func (s *Sessions) Capability(ns, name string) Capability {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.purge(s.key(ns, name), s.sessions[s.key(ns, name)])
	c := Capability{
		Protocol:          SessionProtocol,
		Transports:        []string{"rfb", "tier1"},
		MaxParticipants:   MaxParticipants,
		MaxWidth:          MaxWidth,
		MaxHeight:         MaxHeight,
		HandshakeTimeout:  HandshakeTimeout,
		IdleMembershipTTL: IdleMembershipTTL,
	}
	if sess != nil {
		c.Participants = len(sess.members)
		c.ControllerPresent = sess.controller != ""
	}
	return c
}

// Status returns the live membership snapshot, or the zero Status plus nil when
// no session exists.
func (s *Sessions) Status(ns, name string) (Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key(ns, name)
	sess := s.purge(key, s.sessions[key])
	if sess == nil {
		return Status{}, false
	}
	st := Status{Protocol: SessionProtocol, Epoch: sess.epoch, Participants: len(sess.members)}
	if ctrl := sess.activeParticipant(); ctrl != nil {
		c := *ctrl
		st.Controller = &c
	}
	for id, m := range sess.members {
		if id == sess.controller {
			continue
		}
		c := *m
		st.Observers = append(st.Observers, &c)
	}
	sort.Slice(st.Observers, func(i, j int) bool {
		return st.Observers[i].JoinedAt.Before(st.Observers[j].JoinedAt)
	})
	return st, true
}

// Join adds a participant. role is RoleObserver or RoleController. Requesting
// controller on an occupied display yields ErrControllerPresent.
func (s *Sessions) Join(ns, name, role string) (*Participant, error) {
	if role != RoleObserver && role != RoleController {
		return nil, fmt.Errorf("%w: %q", ErrInvalidRole, role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key(ns, name)
	sess := s.purge(key, s.sessions[key])
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	if sess == nil {
		epoch, err := randomID()
		if err != nil {
			return nil, err
		}
		sess = &session{epoch: epoch, members: make(map[string]*Participant), lastSeen: make(map[string]time.Time)}
		s.sessions[key] = sess
	}
	if len(sess.members) >= MaxParticipants {
		return nil, ErrCapacity
	}
	now := s.now()
	m := &Participant{ID: id, Role: role, JoinedAt: now}
	if role == RoleController {
		if sess.controller != "" {
			return nil, ErrControllerPresent
		}
		sess.controller = id
	}
	sess.members[id] = m
	sess.lastSeen[id] = now
	c := *m
	return &c, nil
}

// Lookup returns a live snapshot of an existing participant, updating its idle
// deadline. It is used by the stream route to bind a WebSocket connection to a
// participant registered through the REST membership API.
func (s *Sessions) Lookup(ns, name, id string) (*Participant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key(ns, name)
	sess := s.purge(key, s.sessions[key])
	if sess == nil || sess.members[id] == nil {
		return nil, ErrParticipantNotFound
	}
	sess.lastSeen[id] = s.now()
	c := *sess.members[id]
	return &c, nil
}

// Leave removes a participant, clearing control first when the departing member
// held it. Observers are unaffected.
func (s *Sessions) Leave(ns, name, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key(ns, name)
	sess := s.purge(key, s.sessions[key])
	if sess == nil || sess.members[id] == nil {
		return ErrParticipantNotFound
	}
	if sess.controller == id {
		sess.controller = ""
	}
	delete(sess.members, id)
	delete(sess.lastSeen, id)
	s.purge(key, sess)
	return nil
}

// Touch refreshes a participant's idle deadline.
func (s *Sessions) Touch(ns, name, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[s.key(ns, name)]
	if sess == nil || sess.members[id] == nil {
		return ErrParticipantNotFound
	}
	sess.lastSeen[id] = s.now()
	return nil
}

// Acquire makes id the controller. Without force an occupied display yields
// ErrControllerPresent; with force the current controller is demoted to
// observer. Returns the effective controller and whether control was held
// before the transition.
func (s *Sessions) Acquire(ns, name, id string, force bool) (*Participant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key(ns, name)
	sess := s.purge(key, s.sessions[key])
	if sess == nil || sess.members[id] == nil {
		return nil, false, ErrParticipantNotFound
	}
	wasHeld := sess.controller != ""
	if sess.controller == id {
		return nil, wasHeld, ErrAlreadyController
	}
	if wasHeld && !force {
		return nil, true, ErrControllerPresent
	}
	if wasHeld {
		if prev := sess.members[sess.controller]; prev != nil {
			prev.Role = RoleObserver
		}
	}
	sess.controller = id
	sess.members[id].Role = RoleController
	sess.lastSeen[id] = s.now()
	return s.controllerCopy(sess), wasHeld, nil
}

// Release clears control when id is the current controller, demoting it to
// observer. Non-controller participants acting on release get ErrNotController.
func (s *Sessions) Release(ns, name, id string) (*Participant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key(ns, name)
	sess := s.purge(key, s.sessions[key])
	if sess == nil || sess.members[id] == nil {
		return nil, false, ErrParticipantNotFound
	}
	wasHeld := sess.controller != ""
	if sess.controller != id {
		return nil, wasHeld, ErrNotController
	}
	sess.members[id].Role = RoleObserver
	sess.controller = ""
	sess.lastSeen[id] = s.now()
	return nil, wasHeld, nil
}

// Transfer moves control from the current controller id to observer to.
// Returns the new controller and whether control was held before.
func (s *Sessions) Transfer(ns, name, id, to string) (*Participant, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key(ns, name)
	sess := s.purge(key, s.sessions[key])
	if sess == nil {
		return nil, false, ErrParticipantNotFound
	}
	target := sess.members[to]
	if target == nil {
		return nil, sess.controller != "", ErrParticipantNotFound
	}
	wasHeld := sess.controller != ""
	if sess.controller != id {
		return nil, wasHeld, ErrNotController
	}
	if to == id {
		return nil, wasHeld, ErrAlreadyController
	}
	if sess.members[id].Role != RoleController || target.Role != RoleObserver {
		return nil, wasHeld, ErrBadTarget
	}
	sess.members[id].Role = RoleObserver
	target.Role = RoleController
	sess.controller = to
	sess.lastSeen[id] = s.now()
	sess.lastSeen[to] = s.now()
	return s.controllerCopy(sess), wasHeld, nil
}

// SetConnected marks participant attachment state.
func (s *Sessions) SetConnected(ns, name, id string, connected bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[s.key(ns, name)]
	if sess == nil || sess.members[id] == nil {
		return ErrParticipantNotFound
	}
	sess.members[id].Connected = connected
	sess.lastSeen[id] = s.now()
	return nil
}

func (s *Sessions) controllerCopy(sess *session) *Participant {
	if ctr := sess.activeParticipant(); ctr != nil {
		c := *ctr
		return &c
	}
	return nil
}
