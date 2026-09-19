package exec

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kube-workspaces/api/internal/broker"
	"github.com/kube-workspaces/api/internal/display"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// roundTripperFunc adapts a function to http.RoundTripper for test hops.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ownerPod registers a pod with an IP in the fake clientset, so the hop can
// resolve it like the real pods API.
func ownerPod(t *testing.T, cs *fake.Clientset, ns, name, ip string) {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Create(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Status:     corev1.PodStatus{PodIP: ip},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create owner pod: %v", err)
	}
}

func TestOwnerHopForwardsToOwner(t *testing.T) {
	cs := fake.NewClientset()
	hop := &OwnerHop{clientset: cs, namespace: "test-ns"}
	ownerPod(t, cs, "test-ns", "replica-b", "10.0.0.7")

	var got struct {
		path  string
		query string
		auth  string
		hop   string
	}
	var hit atomic.Int32
	owner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		got.path, got.query, got.auth, got.hop = r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get(hopHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer owner.Close()
	hop.transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		// The director already aimed the request at the resolved pod IP; the
		// test transport answers it with the owner server instead.
		if !strings.Contains(r.URL.Host, "10.0.0.7") {
			t.Errorf("request was not directed at the owner pod IP: %s", r.URL.Host)
		}
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(owner.URL, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})

	req := httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws?role=observer", nil)
	req.Header.Set("Authorization", "Bearer token-123")
	rec := httptest.NewRecorder()
	hop.Forward(rec, req, "replica-b")

	if hit.Load() != 1 {
		t.Fatalf("owner was not hit exactly once: %d", hit.Load())
	}
	if got.path != "/v1/workspaces/vm-a/display/ws" || got.query != "role=observer" {
		t.Fatalf("forwarded request mutated: %s?%s", got.path, got.query)
	}
	if got.auth != "Bearer token-123" {
		t.Fatalf("client credentials were not preserved: %q", got.auth)
	}
	if got.hop == "" {
		t.Fatal("forwarded request did not carry the hop mark")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("forwarded response: %d", rec.Code)
	}
}

// A request that already traveled one hop must never be forwarded again: a
// stale lease read on both pods at once resolves to one 409, not a loop.
func TestOwnerHopRefusesSecondHop(t *testing.T) {
	hop := &OwnerHop{clientset: fake.NewClientset(), namespace: "test-ns"}
	hit := false
	hop.transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		hit = true
		return nil, errors.New("must not forward")
	})

	req := httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws", nil)
	req.Header.Set(hopHeader, "1")
	rec := httptest.NewRecorder()
	hop.Forward(rec, req, "replica-b")

	if hit {
		t.Fatal("a hopped request was forwarded again")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("second hop: got %d want %d", rec.Code, http.StatusConflict)
	}
	var body struct {
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Owner != "replica-b" {
		t.Fatalf("second hop did not answer the 409/owner contract: %q", rec.Body.String())
	}
}

// An owner that cannot be resolved (the pod died between the lease read and
// the forward) degrades to the same 409/owner answer, so the client's retry
// re-reads a fresher lease.
func TestOwnerHopUnresolvableOwnerWrites409(t *testing.T) {
	hop := &OwnerHop{clientset: fake.NewClientset(), namespace: "test-ns"}
	req := httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws", nil)
	rec := httptest.NewRecorder()
	hop.Forward(rec, req, "replica-ghost")

	if rec.Code != http.StatusConflict {
		t.Fatalf("unresolvable owner: got %d want %d", rec.Code, http.StatusConflict)
	}
	var body struct {
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Owner != "replica-ghost" {
		t.Fatalf("unresolvable owner body: %q", rec.Body.String())
	}
}

func TestDisplayRESTName(t *testing.T) {
	for _, tt := range []struct {
		path string
		name string
		ok   bool
	}{
		{"/v1/workspaces/vm-a/display", "vm-a", true},
		{"/v1/workspaces/vm-a/display/status", "vm-a", true},
		{"/v1/workspaces/vm-a/display/join", "vm-a", true},
		{"/v1/workspaces/vm-a/display/sessions/p1", "vm-a", true},
		{"/v1/workspaces/vm-a/display/control/acquire", "vm-a", true},
		{"/v1/workspaces/vm-a/display/ws", "", false},
		{"/v1/workspaces/vm-a/vnc", "", false},
		{"/v1/workspaces", "", false},
		{"/v1/images", "", false},
	} {
		name, ok := displayRESTName(tt.path)
		if name != tt.name || ok != tt.ok {
			t.Errorf("displayRESTName(%q) = %q, %v; want %q, %v", tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

// The middleware sends display REST calls to the owning replica and lets
// everything else fall through to the local handler.
func TestDisplayOwnerMiddlewareRoutesToOwner(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	ownerStore := display.NewStoreWithOwner(cs, "replica-b")
	if _, err := ownerStore.Claim(ctx, "workspaces", "vm-a", "vnc"); err != nil {
		t.Fatalf("owner seat claim: %v", err)
	}
	localStore := display.NewStoreWithOwner(cs, "replica-a")

	var forwarded, served bool
	owner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		_, _ = w.Write([]byte(`{"owner":true}`))
	}))
	defer owner.Close()
	hop := &OwnerHop{clientset: cs, namespace: "test-ns", transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(owner.URL, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})}
	ownerPod(t, cs, "test-ns", "replica-b", "10.0.0.9")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = true
		_, _ = w.Write([]byte(`{"local":true}`))
	})
	h := DisplayOwnerMiddleware(localStore, "replica-a", hop, next)

	// A membership call with an owner elsewhere is forwarded.
	req := httptest.NewRequest("POST", "/v1/workspaces/vm-a/display/join", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !forwarded || served {
		t.Fatalf("join was not routed to the owner (forwarded=%v served=%v)", forwarded, served)
	}

	// The same call arriving with the hop mark is answered locally (this pod
	// is the owner's side of the conversation).
	forwarded = false
	req = httptest.NewRequest("POST", "/v1/workspaces/vm-a/display/join", nil)
	req.Header.Set(hopHeader, "1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if forwarded || !served {
		t.Fatalf("hopped join was re-forwarded (forwarded=%v served=%v)", forwarded, served)
	}

	// A display call for an unowned workspace is answered locally.
	served = false
	req = httptest.NewRequest("GET", "/v1/workspaces/vm-b/display/status", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if forwarded || !served {
		t.Fatalf("unowned status was forwarded (forwarded=%v served=%v)", forwarded, served)
	}

	// Non-display paths never consult the store.
	served = false
	req = httptest.NewRequest("GET", "/v1/workspaces/vm-a", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if forwarded || !served {
		t.Fatalf("non-display path was forwarded (forwarded=%v served=%v)", forwarded, served)
	}
}

// End to end at the stream route: replica A owns the generation, replica B's
// route forwards the client to A instead of answering 409.
func TestSharedDisplayHandleForwardsToOwner(t *testing.T) {
	cs := fake.NewClientset()
	storeA := display.NewStoreWithOwner(cs, "replica-a")
	storeB := display.NewStoreWithOwner(cs, "replica-b")
	ctx := context.Background()

	sdA := &SharedDisplay{
		opts: &Options{Display: storeA},
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			client, server := net.Pipe()
			_ = client.Close()
			return server, nil
		},
	}
	rt, err := sdA.attach(ctx, "workspaces", "vm-a")
	if err != nil {
		t.Fatalf("replica A attach: %v", err)
	}
	defer sdA.detach("workspaces", "vm-a", rt)

	owner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(hopHeader) == "" {
			t.Error("the forwarded request lost its hop mark")
		}
		_, _ = w.Write([]byte(`{"servedBy":"replica-a"}`))
	}))
	defer owner.Close()
	hopB := &OwnerHop{clientset: cs, namespace: "test-ns", transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(owner.URL, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})}
	ownerPod(t, cs, "test-ns", "replica-a", "10.0.0.3")

	sdB := &SharedDisplay{
		opts: &Options{Display: storeB, Sessions: display.NewSessions()},
		hop:  hopB,
		live: make(map[string]*sharedRuntime),
		dial: func(context.Context, string, string) (broker.Stream, error) {
			t.Fatal("replica B must not dial a second VNC console")
			return nil, errors.New("unreachable")
		},
	}

	req := httptest.NewRequest("GET", "/v1/workspaces/vm-a/display/ws", nil)
	req.SetPathValue("name", "vm-a")
	rec := httptest.NewRecorder()
	sdB.Handle(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("replica B did not forward the request: %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "replica-a") {
		t.Fatalf("the response did not come from the owner: %q", rec.Body.String())
	}
}
