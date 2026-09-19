package exec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
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
	if s.opts.Display == nil || s.opts.Sessions == nil {
		http.Error(w, "display ownership unavailable", http.StatusServiceUnavailable)
		return
	}

	// 1. Join the membership registry first: control occupancy and the
	// participant cap are decided there, independent of the media path.
	p, err := s.opts.Sessions.Join(namespace, name, role)
	if err != nil {
		s.joinError(w, err)
		return
	}
	leave := true
	defer func() {
		if leave {
			_ = s.opts.Sessions.Leave(namespace, name, p.ID)
		}
	}()

	// 2. Ensure a broker generation exists (claim the seat lease + dial the VM),
	// then bind this participant's stream to it.
	rt, err := s.attach(ctx, namespace, name)
	if err != nil {
		if owner, ok := ownedElsewhere(err, s.instance()); ok {
			// Another API replica generates this display. Tell the caller which
			// one instead of dialing a second VNC console; a routing layer can
			// re-issue this request against the owner.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "interactive display is owned by another replica",
				"owner": owner,
			})
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

	// 3. Upgrade the client.
	clientConn, err := vncUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote the error response
	}

	// 4. A controller holds the control lease: its input delivery is fenced
	// against that lease + the local registry (see internal/display.Fence).
	var fence *display.Fence
	if role == display.RoleController {
		fence, err = display.AcquireControl(ctx, s.opts.Display, s.opts.Sessions, namespace, name, p.ID, false)
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

	// Leave explicitly so the empty-session prune is immediate; the deferred
	// Leave is therefore a no-op.
	_ = s.opts.Sessions.Leave(namespace, name, p.ID)
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

// attach returns the live broker generation for ns/name, creating one (seat
// lease + upstream dial + broker run) when none is live. The seat lease is the
// capture-side claim: exactly one generation may own a VM's VNC console.
func (s *SharedDisplay) attach(ctx context.Context, ns, name string) (*sharedRuntime, error) {
	key := s.key(ns, name)
	s.mu.Lock()
	if rt := s.live[key]; rt != nil {
		rt.count++
		s.mu.Unlock()
		return rt, nil
	}
	s.mu.Unlock()

	guard, err := display.Acquire(ctx, s.opts.Display, ns, name)
	if err != nil {
		return nil, err
	}
	upstream, err := s.dial(ctx, ns, name)
	if err != nil {
		guard.Close()
		return nil, err
	}
	bro := broker.New(upstream)
	rtCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		_ = bro.Run(rtCtx)
		close(done)
	}()
	rt := &sharedRuntime{guard: guard, broker: bro, cancel: cancel, done: done, count: 1}

	s.mu.Lock()
	if prev := s.live[key]; prev != nil {
		// Lost a creation race; the other generation wins the seat lease.
		s.mu.Unlock()
		cancel()
		<-done
		guard.Close()
		prev.count++
		return prev, nil
	}
	s.live[key] = rt
	s.mu.Unlock()
	return rt, nil
}

// detach drops one participant reference. The last reference cancels the broker
// generation and releases the seat lease (after capture has stopped).
func (s *SharedDisplay) detach(ns, name string, rt *sharedRuntime) {
	key := s.key(ns, name)
	s.mu.Lock()
	if rt.count <= 1 && s.live[key] == rt {
		delete(s.live, key)
		s.mu.Unlock()
		rt.cancel()
		<-rt.done
		rt.guard.Close()
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
