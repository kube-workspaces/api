package exec

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kube-workspaces/api/internal/agent"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type agentHopTransport func(*http.Request) (*http.Response, error)

func (f agentHopTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAgentLifecycleRoutesToAuthenticatedIssuer(t *testing.T) {
	keys := [][]byte{[]byte("issuer-key")}
	issuer := agent.NewOwnedStore("api-one")
	id, _, err := issuer.Mint("workspace", "generation", "viewer", 1, keys)
	if err != nil {
		t.Fatal(err)
	}
	hop := &OwnerHop{namespace: "system", clientset: fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-one", Namespace: "system"}, Status: corev1.PodStatus{PodIP: "192.0.2.1"}})}
	forwarded := 0
	hop.transport = agentHopTransport(func(r *http.Request) (*http.Response, error) {
		forwarded++
		if r.URL.Host != "192.0.2.1:8080" || r.Header.Get("Authorization") != "Bearer viewer" || r.Header.Get(hopHeader) != "1" {
			t.Fatalf("bad hop: %v %v", r.URL, r.Header)
		}
		if !issuer.RenewBound(r.Header.Get("X-KW-Agent-Session"), "workspace", "generation") {
			t.Fatal("issuer lost grant")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	local := 0
	h := AgentOwnerMiddleware("api-two", func(context.Context) ([][]byte, error) { return keys, nil }, hop, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { local++; w.WriteHeader(404) }))
	for _, suffix := range []string{"", "tampered"} {
		r := httptest.NewRequest("POST", "/v1/workspaces/ws/agent/renew?namespace=workspaces", strings.NewReader(`{}`))
		r.Header.Set("X-KW-Agent-Session", id+suffix)
		r.Header.Set("Authorization", "Bearer viewer")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if forwarded != 1 || local != 1 {
		t.Fatalf("forwarded=%d local=%d", forwarded, local)
	}
	r := httptest.NewRequest("POST", "/v1/workspaces/ws/agent/release", nil)
	r.Header.Set("X-KW-Agent-Session", id)
	r.Header.Set(hopHeader, "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 || forwarded != 1 {
		t.Fatal("forward loop was not fenced")
	}
}
