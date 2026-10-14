package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"github.com/kube-workspaces/api/internal/monitoring"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// bridgeMonitoring runs inside authentication and outside the route handlers.
// Only the terminating bridge calls Establish; owner forwarding is ignored.
func bridgeMonitoring(reg *monitoring.Registry, workspaces *k8s.WorkspaceClient, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if r.Method != "GET" || len(parts) < 4 || parts[0] != "v1" || parts[1] != "workspaces" {
			next.ServeHTTP(w, r)
			return
		}
		suffix := strings.Join(parts[3:], "/")
		m := monitoring.Metadata{Name: parts[2], Namespace: r.URL.Query().Get("namespace"), ByteLayer: "websocket_stream"}
		if m.Namespace == "" {
			m.Namespace = "workspaces"
		}
		switch suffix {
		case "exec":
			m.Category = "terminal"
			m.Transport = "exec"
		case "vnc":
			m.Category = "display"
			m.Transport = "rfb"
			m.Tier = "0"
		case "display/ws":
			m.Category = "display"
			m.Transport = "shared_rfb"
			m.Tier = "0"
		case "ssh":
			m.Category = "console"
			m.Transport = "ssh"
		case "tcp":
			m.Category = "console"
			m.Transport = "tcp"
		default:
			next.ServeHTTP(w, r)
			return
		}
		if user := auth.UserFromContext(r.Context()); user != nil {
			m.User = user.Email
		}
		if obj, err := workspaces.GetWorkspace(r.Context(), m.Namespace, m.Name); err == nil {
			m.WorkspaceUID = string(obj.GetUID())
			m.WorkspaceType, _, _ = unstructured.NestedString(obj.Object, "spec", "type")
			if m.WorkspaceType == "" {
				m.WorkspaceType = "container"
			}
		}
		if suffix == "exec" && m.WorkspaceType == "vm" {
			m.Category = "console"
			m.Transport = "serial"
		}
		s := reg.Start(m)
		defer s.End()
		r = r.WithContext(monitoring.WithSession(r.Context(), s))
		next.ServeHTTP(&monitoring.Writer{ResponseWriter: w, Session: s}, r)
	})
}

type monitoringConnection struct {
	monitoring.Connection
	Owner     string `json:"owner"`
	Component string `json:"component"`
}
type monitoringWorkspace struct {
	UID             string                 `json:"uid"`
	Name            string                 `json:"name"`
	Namespace       string                 `json:"namespace"`
	Type            string                 `json:"type"`
	State           string                 `json:"state"`
	Connections     []monitoringConnection `json:"connections"`
	ToWorkspaceRate float64                `json:"to_workspace_bytes_per_second"`
	ToClientRate    float64                `json:"to_client_bytes_per_second"`
}
type monitoringSource struct {
	Owner      string     `json:"owner"`
	Component  string     `json:"component"`
	Available  bool       `json:"available"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Message    string     `json:"message,omitempty"`
}
type monitoringView struct {
	Components        map[string]componentStatus `json:"components"`
	SetupFailures     uint64                     `json:"setup_failures"`
	ObservedAt        time.Time                  `json:"observed_at"`
	Complete          bool                       `json:"complete"`
	RatesReady        bool                       `json:"rates_ready"`
	Workspaces        []monitoringWorkspace      `json:"workspaces"`
	Sources           []monitoringSource         `json:"sources"`
	Messages          []string                   `json:"messages"`
	HistoryConfigured bool                       `json:"history_configured"`
}
type monitoringCollector struct {
	mu                         sync.RWMutex
	view                       monitoringView
	previous                   map[string]monitoring.Snapshot
	registry                   *monitoring.Registry
	workspaces                 *k8s.WorkspaceClient
	core                       *k8s.CoreClient
	client                     *http.Client
	token, namespace, selector string
}

func newMonitoringCollector(reg *monitoring.Registry, ws *k8s.WorkspaceClient, core *k8s.CoreClient) *monitoringCollector {
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "kube-workspaces-system"
	}
	selector := os.Getenv("KW_MONITORING_SELECTOR")
	if selector == "" {
		selector = "app.kubernetes.io/name=kube-workspaces"
	}
	return &monitoringCollector{registry: reg, workspaces: ws, core: core, namespace: ns, selector: selector, token: os.Getenv("KW_MONITORING_TOKEN"), client: &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, previous: map[string]monitoring.Snapshot{}, view: monitoringView{Complete: false, Workspaces: []monitoringWorkspace{}, Sources: []monitoringSource{}, Messages: []string{"Initial collection in progress"}}}
}
func (c *monitoringCollector) Run(ctx context.Context) {
	c.collect(ctx)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}
func (c *monitoringCollector) collect(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	v := monitoringView{ObservedAt: time.Now().UTC(), Complete: true, RatesReady: len(c.previous) > 0, Workspaces: []monitoringWorkspace{}, Sources: []monitoringSource{}, Messages: []string{}, HistoryConfigured: os.Getenv("KW_PROMETHEUS_URL") != ""}
	rows := map[string]*monitoringWorkspace{}
	list, err := c.workspaces.ListWorkspaces(ctx, "")
	if err != nil {
		v.Complete = false
		v.Messages = append(v.Messages, "Workspace inventory unavailable")
	} else {
		for _, obj := range list.Items {
			wsType, _, _ := unstructured.NestedString(obj.Object, "spec", "type")
			if wsType == "" {
				wsType = "container"
			}
			ready, _, _ := unstructured.NestedInt64(obj.Object, "status", "readyReplicas")
			state := "starting"
			if ready > 0 {
				state = "running"
			}
			if _, stopped := obj.GetAnnotations()["kubeworkspaces.io/stopped"]; stopped {
				state = "stopped"
			}
			rows[string(obj.GetUID())] = &monitoringWorkspace{UID: string(obj.GetUID()), Name: obj.GetName(), Namespace: obj.GetNamespace(), Type: wsType, State: state, Connections: []monitoringConnection{}}
		}
	}
	local := c.registry.Snapshot()
	snapshots := []monitoring.Snapshot{local}
	v.Sources = append(v.Sources, monitoringSource{Owner: local.Owner, Component: "api", Available: true, ObservedAt: &local.ObservedAt})
	pods, err := c.core.ListPods(ctx, c.namespace, c.selector)
	if err != nil {
		v.Complete = false
		v.Messages = append(v.Messages, "Replica discovery unavailable")
	} else {
		v.Components = map[string]componentStatus{}
		for _, component := range []string{"api", "proxy", "controller", "frontend"} {
			var group []corev1.Pod
			for _, p := range pods.Items {
				if p.Labels["app.kubernetes.io/component"] == component {
					group = append(group, p)
				}
			}
			v.Components[component] = summarizeComponent(group)
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, 8)
		proxyFound := false
		for _, pod := range pods.Items {
			component := pod.Labels["app.kubernetes.io/component"]
			if component != "api" && component != "proxy" {
				continue
			}
			if pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
				continue
			}
			if component == "proxy" {
				proxyFound = true
			}
			if pod.Name == local.Owner && component == "api" {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				source := monitoringSource{Owner: pod.Name, Component: component}
				var snap monitoring.Snapshot
				if c.token == "" {
					source.Message = "Monitoring token not configured"
				} else if pod.Status.PodIP == "" {
					source.Message = "Replica has no pod address"
				} else {
					select {
					case semaphore <- struct{}{}:
						defer func() { <-semaphore }()
					case <-ctx.Done():
						source.Message = "Collection timed out"
					}
					if source.Message == "" {
						req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+net.JoinHostPort(pod.Status.PodIP, "9090")+"/snapshot", nil)
						req.Header.Set("Authorization", "Bearer "+c.token)
						resp, e := c.client.Do(req)
						if e != nil {
							source.Message = "Replica monitoring unavailable"
						} else {
							e = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&snap)
							resp.Body.Close()
							if resp.StatusCode != 200 || e != nil || snap.Protocol != 1 || snap.Owner != pod.Name || snap.Component != component || snap.BootID == "" || time.Since(snap.ObservedAt) > 15*time.Second || time.Until(snap.ObservedAt) > 15*time.Second {
								source.Message = "Invalid or stale replica report"
							} else {
								source.Available = true
								source.ObservedAt = &snap.ObservedAt
							}
						}
					}
				}
				mu.Lock()
				defer mu.Unlock()
				v.Sources = append(v.Sources, source)
				if source.Available {
					snapshots = append(snapshots, snap)
				} else {
					v.Complete = false
				}
			}()
		}
		wg.Wait()
		if !proxyFound {
			v.Complete = false
			v.Messages = append(v.Messages, "No proxy replicas discovered")
		}
	}
	next := map[string]monitoring.Snapshot{}
	for _, snap := range snapshots {
		v.SetupFailures += snap.SetupFailures
		key := snap.Component + "/" + snap.Owner + "/" + snap.BootID
		next[key] = snap
		for _, conn := range snap.Connections {
			row := rows[conn.WorkspaceUID]
			if row == nil {
				uid := conn.WorkspaceUID
				if uid == "" {
					uid = conn.Namespace + "/" + conn.Name
				}
				row = rows[uid]
				if row == nil {
					row = &monitoringWorkspace{UID: uid, Namespace: conn.Namespace, Name: conn.Name, Type: conn.WorkspaceType, State: "unknown", Connections: []monitoringConnection{}}
					rows[uid] = row
				}
			}
			row.Connections = append(row.Connections, monitoringConnection{Connection: conn, Owner: snap.Owner, Component: snap.Component})
		}
		previous, ok := c.previous[key]
		if !ok {
			v.RatesReady = false
			continue
		}
		seconds := snap.ObservedAt.Sub(previous.ObservedAt).Seconds()
		if seconds <= 0 {
			continue
		}
		old := map[string]monitoring.Traffic{}
		for _, t := range previous.Traffic {
			old[trafficKey(t)] = t
		}
		for _, t := range snap.Traffic {
			row := rows[t.WorkspaceUID]
			if row == nil {
				continue
			}
			p, exists := old[trafficKey(t)]
			if !exists {
				p = monitoring.Traffic{}
			}
			if t.ToWorkspace >= p.ToWorkspace {
				row.ToWorkspaceRate += float64(t.ToWorkspace-p.ToWorkspace) / seconds
			}
			if t.ToClient >= p.ToClient {
				row.ToClientRate += float64(t.ToClient-p.ToClient) / seconds
			}
		}
	}
	c.previous = next
	for _, row := range rows {
		sort.Slice(row.Connections, func(i, j int) bool { return row.Connections[i].ID < row.Connections[j].ID })
		v.Workspaces = append(v.Workspaces, *row)
	}
	sort.Slice(v.Workspaces, func(i, j int) bool {
		a, b := v.Workspaces[i], v.Workspaces[j]
		return a.Namespace+"/"+a.Name+a.UID < b.Namespace+"/"+b.Name+b.UID
	})
	sort.Slice(v.Sources, func(i, j int) bool { return v.Sources[i].Owner < v.Sources[j].Owner })
	c.mu.Lock()
	c.view = v
	c.mu.Unlock()
}
func trafficKey(t monitoring.Traffic) string {
	return t.WorkspaceUID + "/" + t.Namespace + "/" + t.Name + "/" + t.Category + "/" + t.Transport + "/" + t.Tier + "/" + t.ByteLayer
}
func (c *monitoringCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !auth.IsAdmin(r.Context()) {
		http.Error(w, "admin access required", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	c.mu.RLock()
	view := c.view
	c.mu.RUnlock()
	_ = json.NewEncoder(w).Encode(view)
}

// Only fixed platform/tier queries are exposed; the browser cannot submit PromQL.
func monitoringHistory(w http.ResponseWriter, r *http.Request) {
	if !auth.IsAdmin(r.Context()) {
		http.Error(w, "admin access required", 403)
		return
	}
	origin := os.Getenv("KW_PROMETHEUS_URL")
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "Prometheus history is not configured", 503)
		return
	}
	scope := "kw_platform=" + strconv.Quote(os.Getenv("KW_MONITORING_PLATFORM"))
	queries := map[string]string{"connections": "sum by (tier, transport, category) (kubeworkspaces_connections_active{" + scope + ",category!=\"http\"})", "toward_workspace": "sum by (tier, transport, category) (rate(kubeworkspaces_traffic_bytes_total{" + scope + ",direction=\"toward_workspace\"}[1m]))", "toward_client": "sum by (tier, transport, category) (rate(kubeworkspaces_traffic_bytes_total{" + scope + ",direction=\"toward_client\"}[1m]))",
		// Phase 5: workspace/interface network counters from existing cluster
		// telemetry, kept separate from proxy stream bytes. Container metrics
		// come from kubelet/cAdvisor; VMI metrics come from the KubeVirt
		// prometheus-metrics Service. Neither carries kw_platform, so these
		// are cluster-level sums: receive maps to toward_workspace and
		// transmit maps to toward_client. Do not add them to proxy totals;
		// virt-launcher pod traffic also appears under container_network_*.
		"network_container_bytes":   "sum by (direction) (label_replace(sum(rate(container_network_receive_bytes_total[1m])), \"direction\", \"toward_workspace\", \"__name__\", \".+\") or label_replace(sum(rate(container_network_transmit_bytes_total[1m])), \"direction\", \"toward_client\", \"__name__\", \".+\"))",
		"network_container_packets": "sum by (direction) (label_replace(sum(rate(container_network_receive_packets_total[1m])), \"direction\", \"toward_workspace\", \"__name__\", \".+\") or label_replace(sum(rate(container_network_transmit_packets_total[1m])), \"direction\", \"toward_client\", \"__name__\", \".+\"))",
		"network_vmi_bytes":         "sum by (direction) (label_replace(sum(rate(kubevirt_vmi_network_receive_bytes_total[1m])), \"direction\", \"toward_workspace\", \"__name__\", \".+\") or label_replace(sum(rate(kubevirt_vmi_network_transmit_bytes_total[1m])), \"direction\", \"toward_client\", \"__name__\", \".+\"))",
		"network_vmi_packets":       "sum by (direction) (label_replace(sum(rate(kubevirt_vmi_network_receive_packets_total[1m])), \"direction\", \"toward_workspace\", \"__name__\", \".+\") or label_replace(sum(rate(kubevirt_vmi_network_transmit_packets_total[1m])), \"direction\", \"toward_client\", \"__name__\", \".+\"))"}
	query, ok := queries[r.URL.Query().Get("metric")]
	if !ok {
		http.Error(w, "invalid metric", 400)
		return
	}
	window, err := parseWindow(r.URL.Query().Get("range"))
	if err != nil {
		http.Error(w, "invalid range", 400)
		return
	}
	end := time.Now()
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/query_range"
	q := url.Values{"query": {query}, "start": {fmt.Sprint(end.Add(-window).Unix())}, "end": {fmt.Sprint(end.Unix())}, "step": {fmt.Sprint(max(15, int(window.Seconds()/120)))}}
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if token := os.Getenv("KW_PROMETHEUS_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Prometheus history unavailable", 502)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		http.Error(w, "Prometheus query failed", 502)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 4<<20))
}
