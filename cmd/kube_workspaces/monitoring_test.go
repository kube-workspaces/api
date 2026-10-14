package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"github.com/kube-workspaces/api/internal/monitoring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

type monitoringRoundTrip func(*http.Request) (*http.Response, error)

func (f monitoringRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMonitoringReplicaAggregationPartialCoverageAndRestart(t *testing.T) {
	reg := monitoring.New("api")
	local := reg.Snapshot()
	m := monitoring.Metadata{WorkspaceUID: "uid", Namespace: "ws", Name: "desktop", WorkspaceType: "vm", Category: "display", Transport: "shared_rfb", Tier: "0", ByteLayer: "websocket_stream"}
	for i := 0; i < 3; i++ {
		s := reg.Start(m)
		s.Establish("observer")
	}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Workspace", "metadata": map[string]interface{}{"name": "desktop", "namespace": "ws", "uid": "uid"}, "spec": map[string]interface{}{"type": "vm"}, "status": map[string]interface{}{"readyReplicas": int64(1)}}}
	gvr := schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "workspaces"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gvr: "WorkspaceList"}, obj)
	pod := func(name, component, ip string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-workspaces-system", Labels: map[string]string{"app.kubernetes.io/name": "kube-workspaces", "app.kubernetes.io/component": component}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip}}
	}
	core := k8s.NewCoreClientFor(kubefake.NewClientset(pod(local.Owner, "api", "10.0.0.1"), pod("proxy-1", "proxy", "10.0.0.2")))
	c := newMonitoringCollector(reg, k8s.NewWorkspaceClientFor(dyn), core)
	c.token = "test"
	proxy := monitoring.Snapshot{Protocol: 1, Component: "proxy", Owner: "proxy-1", BootID: "boot", ObservedAt: time.Now().UTC(), Connections: []monitoring.Connection{{Metadata: monitoring.Metadata{WorkspaceUID: "uid", Category: "agent", Transport: "agent", Tier: "1"}, ID: "agent", State: "established"}}, Traffic: []monitoring.Traffic{{Metadata: m, ToClient: 100}}}
	unavailable := false
	c.client.Transport = monitoringRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer test" {
			t.Error("missing private authentication")
		}
		if unavailable {
			return nil, errors.New("down")
		}
		b, _ := json.Marshal(proxy)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
	})
	c.collect(context.Background())
	if !c.view.Complete || len(c.view.Workspaces) != 1 || len(c.view.Workspaces[0].Connections) != 4 || c.view.RatesReady {
		t.Fatalf("incorrect initial inventory: %+v", c.view)
	}
	old := c.previous["proxy/proxy-1/boot"]
	old.ObservedAt = proxy.ObservedAt.Add(-5 * time.Second)
	c.previous["proxy/proxy-1/boot"] = old
	proxy.Traffic[0].ToClient = 150
	c.collect(context.Background())
	if rate := c.view.Workspaces[0].ToClientRate; rate != 10 {
		t.Fatalf("rate %v want 10", rate)
	}
	unavailable = true
	c.collect(context.Background())
	// Sources are sorted by owner, so locate the proxy report instead of
	// assuming it lands at a fixed index (hostnames vary across machines).
	proxyAvailable := false
	proxyFound := false
	for _, s := range c.view.Sources {
		if s.Owner == "proxy-1" && s.Component == "proxy" {
			proxyFound = true
			proxyAvailable = s.Available
		}
	}
	if c.view.Complete || len(c.view.Workspaces[0].Connections) != 3 || !proxyFound || proxyAvailable {
		t.Fatalf("missing replica reported as complete or stale connections retained: %+v", c.view)
	}
	unavailable = false
	proxy.BootID = "restart"
	proxy.Traffic[0].ToClient = 20
	c.collect(context.Background())
	if !c.view.Complete || c.view.RatesReady || c.view.Workspaces[0].ToClientRate != 0 {
		t.Fatalf("counter restart treated as traffic: %+v", c.view)
	}
}

func TestMonitoringAdminAuthorizationAndFixedHistoryQueries(t *testing.T) {
	for _, role := range []string{"viewer", "editor"} {
		req := httptest.NewRequest("GET", "/admin/monitoring/overview", nil).WithContext(auth.ContextWithUser(context.Background(), &auth.UserInfo{Role: role}))
		w := httptest.NewRecorder()
		(&monitoringCollector{}).ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatalf("%s read monitoring", role)
		}
		w = httptest.NewRecorder()
		monitoringHistory(w, req)
		if w.Code != 403 {
			t.Fatalf("%s read history", role)
		}
	}
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" {
			t.Errorf("unexpected path %s", r.URL)
		}
		q := r.URL.Query().Get("query")
		if strings.Contains(q, "kubeworkspaces_") && !strings.Contains(q, `kw_platform="test/release"`) {
			t.Errorf("unscoped platform query %s", r.URL)
		}
		for _, want := range []string{"container_network_receive_bytes_total", "container_network_receive_packets_total", "kubevirt_vmi_network_receive_bytes_total", "kubevirt_vmi_network_receive_packets_total"} {
			if strings.Contains(r.URL.Query().Get("query"), want) && !strings.Contains(q, "direction") {
				t.Errorf("network query without direction %s", q)
			}
		}
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
	}))
	defer prom.Close()
	t.Setenv("KW_PROMETHEUS_URL", prom.URL)
	t.Setenv("KW_MONITORING_PLATFORM", "test/release")
	for _, tc := range []struct {
		query  string
		status int
	}{{"metric=connections&range=15m", 200}, {"metric=toward_workspace&range=1h", 200}, {"metric=network_container_bytes&range=15m", 200}, {"metric=network_container_packets&range=1h", 200}, {"metric=network_vmi_bytes&range=1h", 200}, {"metric=network_vmi_packets&range=24h", 200}, {"metric=arbitrary&range=15m", 400}, {"metric=connections&range=100y", 400}, {"metric=rate(container_network_receive_bytes_total[1m])&range=15m", 400}} {
		w := httptest.NewRecorder()
		monitoringHistory(w, httptest.NewRequest("GET", "/admin/monitoring/series?"+tc.query, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.query, w.Code)
		}
	}
}
