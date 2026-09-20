package exec

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kube-workspaces/api/internal/broker"
	"github.com/kube-workspaces/api/internal/display"
	"k8s.io/client-go/rest"
)

// sharedRuntime is one broker generation for a workspace: a single upstream
// dial to the VM VNC console serves every participant attached to the display.
// The seat/control leases and the session registry live in internal/display.
type sharedRuntime struct {
	guard  *display.Guard
	broker *broker.Broker
	cancel context.CancelFunc
	done   chan struct{}
	count  int
	// full reports whether this generation holds the interactive seat, so
	// participants may attach as controller. An observer-only generation
	// (capture held, seat held by a Tier 1 session) serves view-only
	// participants until its seat upgrade lands.
	full atomic.Bool
}

// SharedDisplay serves the shared-display WebSocket route
// GET /v1/workspaces/{name}/display/ws. The route must have been authorized
// (editor/admin + namespace access) and confirmed VM-only before Handle runs.
// role=controller (query) joins as the controlling participant, whose input is
// gated by the display control lease; anything else joins as a view-only
// observer. No viewer accepts role=controller while another controller exists.
type SharedDisplay struct {
	opts *Options

	// dial opens the upstream VM stream while the seat lease is held. It is a
	// field so tests can inject a synthetic upstream without a live cluster.
	dial func(ctx context.Context, ns, name string) (broker.Stream, error)

	// hop forwards a request to the replica that owns the display generation
	// when this one does not. Nil answers the 409/owner contract instead.
	hop *OwnerHop

	mu   sync.Mutex
	live map[string]*sharedRuntime
}

// NewSharedDisplay creates the shared-display route runtime.
func NewSharedDisplay(opts *Options) *SharedDisplay {
	return &SharedDisplay{
		opts: opts,
		dial: func(ctx context.Context, ns, name string) (broker.Stream, error) {
			conn, err := dialVMConn(ctx, opts.RESTConfig, ns, name)
			if err != nil {
				return nil, err
			}
			return broker.NewWebSocketStream(conn), nil
		},
		hop:  NewOwnerHop(opts.Clientset),
		live: make(map[string]*sharedRuntime),
	}
}

// instance returns this replica's identity: the same value the display store
// records on leases it claims, so an OwnershipError for our own id is a local
// race rather than a cross-replica routing case.
func (s *SharedDisplay) instance() string {
	if s.opts.Display != nil {
		return s.opts.Display.Owner()
	}
	return ""
}

// ownedElsewhere reports whether err says the display is generated on another
// API replica, returning that replica's identity.
func ownedElsewhere(err error, instance string) (string, bool) {
	var oe *display.OwnershipError
	if errors.As(err, &oe) && oe.Owner != "" && oe.Owner != instance {
		return oe.Owner, true
	}
	return "", false
}

// anyDisplayOwner returns the sibling replica recorded as owning this
// workspace's display routing markers — membership first (the registry the
// client joined), then seat/capture (an existing generation) — or "" when no
// other replica owns it. Self-owned markers mean the local registry is
// authoritative and the 404 path is correct.
func (s *SharedDisplay) anyDisplayOwner(ctx context.Context, ns, name string) string {
	if s.opts.Display == nil {
		return ""
	}
	own := s.instance()
	for _, ownerOf := range []func(context.Context, string, string) (string, error){
		s.opts.Display.MembershipOwner,
		s.opts.Display.SeatOwner,
		s.opts.Display.CaptureOwner,
	} {
		lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		owner, err := ownerOf(lctx, ns, name)
		cancel()
		if err == nil && owner != "" && owner != own {
			return owner
		}
	}
	return ""
}

func (s *SharedDisplay) key(ns, name string) string { return ns + "/" + name }

// Handle upgrades the client to a WebSocket and serves it an RFB shared-display
// stream. It blocks until disconnect, broker shutdown or cancellation.
func (s *SharedDisplay) Handle(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "workspaces"
	}
	name := r.PathValue("name")
	if name == "" {
		http.Error(w, "workspace name is required", http.StatusBadRequest)
		return
	}
	role := r.URL.Query().Get("role")
	if role == "" {
		role = display.RoleObserver
	}
	if role != display.RoleObserver && role != display.RoleController {
		http.Error(w, "role must be observer or controller", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if s.opts.SharedDisplayDisabled {
		http.Error(w, "shared display sessions are not enabled on this platform", http.StatusNotFound)
		return
	}
	if s.opts.Display == nil || s.opts.Sessions == nil {
		http.Error(w, "display ownership unavailable", http.StatusServiceUnavailable)
		return
	}

	// 1. Bind to the membership registry first: either an existing participant
	// the client registered via the REST join endpoint (?participant=) or a
	// freshly joined one. Control occupancy and the participant cap are decided
	// here, independent of the media path.
	leave := true
	bound := false
	var p *display.Participant
	if participantID := r.URL.Query().Get("participant"); participantID != "" {
		// The stream is bound to a REST-joined participant so the client can
		// drive control transitions with the id it already knows. A bound
		// participant must not already be attached elsewhere and its role must
		// match the requested stream role.
		bound = true
		var err error
		p, err = s.opts.Sessions.Lookup(namespace, name, participantID)
		if err != nil {
			if errors.Is(err, display.ErrParticipantNotFound) {
				// The registry is in-memory per replica: when the membership
				// (or generation) is owned by a sibling replica, the client
				// joined there and this attach must be forwarded, not 404'd.
				if owner := s.anyDisplayOwner(r.Context(), namespace, name); owner != "" {
					if s.hop != nil {
						s.hop.Forward(w, r, owner)
						return
					}
					writeOwnerConflict(w, owner)
					return
				}
				http.Error(w, "display participant not found", http.StatusNotFound)
			} else {
				http.Error(w, "failed to resolve display participant", http.StatusServiceUnavailable)
			}
			return
		}
		if p.Connected {
			http.Error(w, "display participant is already attached to a stream", http.StatusConflict)
			return
		}
		if p.Role != role {
			http.Error(w, "participant role does not match the requested stream role", http.StatusConflict)
			return
		}
	} else {
		var err error
		p, err = s.opts.Sessions.Join(namespace, name, role)
		if err != nil {
			// A fresh join claims the membership-owner lease; losing that
			// claim means the membership lives on a sibling replica and this
			// attach must be forwarded there.
			if owner, ok := ownedElsewhere(err, s.instance()); ok {
				if s.hop != nil {
					s.hop.Forward(w, r, owner)
					return
				}
				writeOwnerConflict(w, owner)
				return
			}
			s.joinError(w, err)
			return
		}
	}
	defer func() {
		if leave {
			if bound {
				// A bound participant's membership survives a stream drop so the
				// client can reconnect with the same id; SetConnected already ran.
				_ = s.opts.Sessions.SetConnected(namespace, name, p.ID, false)
			} else {
				_ = s.opts.Sessions.Leave(namespace, name, p.ID)
			}
		}
	}()

	// 2. Ensure a broker generation exists (claim the seat lease + dial the VM),
	// then bind this participant's stream to it.
	rt, err := s.attach(ctx, namespace, name)
	if err != nil {
		if owner, ok := ownedElsewhere(err, s.instance()); ok {
			// Another API replica generates this display: forward the request
			// to it rather than dialing a second VNC console. When the hop is
			// not configured (tests), fall back to the 409/owner contract.
			if s.hop != nil {
				s.hop.Forward(w, r, owner)
				return
			}
			writeOwnerConflict(w, owner)
			return
		}
		if errors.Is(err, display.ErrBusy) {
			http.Error(w, "interactive display unavailable", http.StatusConflict)
		} else {
			http.Error(w, "failed to open a display session", http.StatusServiceUnavailable)
		}
		return
	}
	defer s.detach(namespace, name, rt)

	// 2b. A controller stream needs the interactive seat held by this
	// generation. While a Tier 1 session owns the seat the generation is
	// observer-only: watching is fine, driving is not.
	if role == display.RoleController && !rt.full.Load() {
		http.Error(w, "display is driven by a Tier 1 session; join as an observer", http.StatusConflict)
		return
	}

	// 3. Upgrade the client.
	clientConn, err := vncUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote the error response
	}

	// 4. A controller holds the control lease: its input delivery is fenced
	// against that lease + the local registry (see internal/display.Fence).
	// force=1 revokes any existing holder; a takeover reconnect pairs with the
	// REST acquire(force=true) role change the client made first.
	var fence *display.Fence
	if role == display.RoleController {
		force := r.URL.Query().Get("force") != "" && r.URL.Query().Get("force") != "0" && r.URL.Query().Get("force") != "false"
		fence, err = display.AcquireControl(ctx, s.opts.Display, s.opts.Sessions, namespace, name, p.ID, force)
		if err != nil {
			if errors.Is(err, display.ErrBusy) || errors.Is(err, display.ErrControllerPresent) {
				clientConn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "control already held"), time.Now().Add(time.Second))
			} else {
				clientConn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "control setup failed"), time.Now().Add(time.Second))
			}
			clientConn.Close()
			return
		}
	}
	defer func() {
		if fence != nil {
			fence.Close()
		}
	}()

	if err := s.opts.Sessions.SetConnected(namespace, name, p.ID, true); err != nil {
		return
	}
	defer func() { _ = s.opts.Sessions.SetConnected(namespace, name, p.ID, false) }()

	// 5. Serve the participant stream. ServeParticipant forwards a controller's
	// guest-mutating RFB messages upstream only through the fence.
	_ = rt.broker.ServeParticipant(ctx, broker.NewWebSocketStream(clientConn), role == display.RoleController, fence)

	// Drop membership immediately: a fresh-join participant is gone; a bound
	// participant's stream detaches and keeps its membership for reconnect. The
	// deferred cleanup is therefore a no-op for the fresh case.
	if !bound {
		_ = s.opts.Sessions.Leave(namespace, name, p.ID)
	}
	leave = false
}

func (s *SharedDisplay) joinError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, display.ErrCapacity):
		http.Error(w, "display session participant limit reached", http.StatusTooManyRequests)
	case errors.Is(err, display.ErrControllerPresent):
		http.Error(w, "display is already controlled; join as an observer first", http.StatusConflict)
	case errors.Is(err, display.ErrInvalidRole):
		http.Error(w, "role must be observer or controller", http.StatusBadRequest)
	default:
		http.Error(w, "failed to join display session", http.StatusInternalServerError)
	}
}

// attach returns the live broker generation for ns/name, creating one when
// none is live. The capture lease is the console-side claim every generation
// holds: exactly one generation may dial a VM's VNC console. The interactive
// seat decides the generation's mode: free (or held by an expired claimant)
// means a full shared display, while a tier1-held seat means an observer-only
// generation that watches the desktop the Tier 1 session drives.
func (s *SharedDisplay) attach(ctx context.Context, ns, name string) (*sharedRuntime, error) {
	key := s.key(ns, name)
	s.mu.Lock()
	if rt := s.live[key]; rt != nil {
		rt.count++
		s.mu.Unlock()
		return rt, nil
	}
	s.mu.Unlock()

	tier, seatHeld, err := s.opts.Display.SeatTier(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	observerOnly := seatHeld && tier == "tier1"

	var guard *display.Guard
	if observerOnly {
		guard, err = display.AcquireCapture(ctx, s.opts.Display, ns, name)
	} else {
		guard, err = display.Acquire(ctx, s.opts.Display, ns, name)
	}
	if err != nil {
		return nil, err
	}
	upstream, err := s.dial(ctx, ns, name)
	if err != nil {
		guard.Close()
		return nil, err
	}
	bro := broker.New(upstream)
	// The generation outlives any one participant's request: it ends on the
	// last detach, on the guard losing its claims, or on process shutdown —
	// not when the participant that happened to create it disconnects.
	rtCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = bro.Run(rtCtx)
		close(done)
	}()
	rt := &sharedRuntime{guard: guard, broker: bro, cancel: cancel, done: done, count: 1}
	rt.full.Store(!observerOnly)

	s.mu.Lock()
	if prev := s.live[key]; prev != nil {
		// Lost a creation race; the other generation wins the capture lease.
		s.mu.Unlock()
		cancel()
		<-done
		guard.Close()
		prev.count++
		return prev, nil
	}
	s.live[key] = rt
	s.mu.Unlock()

	// Losing the claims behind the generation (takeover, expiry, lost
	// capture) ends it: nobody may keep a console they cannot renew, and the
	// fenced successor needs the console free to dial.
	go func() {
		<-guard.Done()
		rt.cancel()
	}()

	if observerOnly {
		if s.opts.Sessions != nil {
			s.opts.Sessions.SetControlLocked(ns, name, true)
		}
		go s.watchSeat(rtCtx, ns, name, rt)
	}
	return rt, nil
}

// watchSeat upgrades an observer-only generation once the interactive seat
// frees: the Tier 1 session ended (or its claim fenced out), so this
// generation claims the seat and becomes the full shared display, letting
// participants drive again. A legacy exclusive client racing for the same
// seat wins the claim and the generation keeps watching.
func (s *SharedDisplay) watchSeat(ctx context.Context, ns, name string, rt *sharedRuntime) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tier, held, err := s.opts.Display.SeatTier(ctx, ns, name)
			if err != nil || (held && tier == "tier1") {
				continue
			}
			if err := rt.guard.EnsureSeat(ctx); err != nil {
				continue
			}
			rt.full.Store(true)
			if s.opts.Sessions != nil {
				s.opts.Sessions.SetControlLocked(ns, name, false)
			}
			return
		}
	}
}

// detach drops one participant reference. The last reference cancels the broker
// generation and releases the seat/capture leases (after capture has stopped).
func (s *SharedDisplay) detach(ns, name string, rt *sharedRuntime) {
	key := s.key(ns, name)
	s.mu.Lock()
	if rt.count <= 1 && s.live[key] == rt {
		delete(s.live, key)
		s.mu.Unlock()
		rt.cancel()
		<-rt.done
		rt.guard.Close()
		if s.opts.Sessions != nil {
			// A generation that never upgraded leaves no lock behind.
			s.opts.Sessions.SetControlLocked(ns, name, false)
		}
		return
	}
	rt.count--
	s.mu.Unlock()
}

// dialVMConn opens the KubeVirt VMI VNC subresource WebSocket for a workspace.
// It mirrors the legacy single-session bridge's dial step; SharedDisplay must
// hold the seat lease before calling it.
func dialVMConn(ctx context.Context, cfg *rest.Config, namespace, name string) (*websocket.Conn, error) {
	vncURL, err := vmVNCURL(cfg, namespace, name)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := rest.TLSConfigFor(cfg)
	if err != nil {
		return nil, err
	}
	dialer := websocket.Dialer{
		Subprotocols:    []string{"plain.kubevirt.io"},
		TLSClientConfig: tlsCfg,
		Proxy:           http.ProxyFromEnvironment,
	}
	headers := http.Header{}
	if tok := consoleToken(cfg); tok != "" {
		headers.Set("Authorization", "Bearer "+tok)
	}
	conn, _, err := dialer.DialContext(ctx, vncURL, headers)
	return conn, err
}
