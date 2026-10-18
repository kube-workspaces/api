package monitoring

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestLifecycleReservationsForwardingAndRetainedTraffic(t *testing.T) {
	r := New("api")
	m := Metadata{WorkspaceUID: "uid", Namespace: "ns", Name: "vm", Category: "display", Transport: "rfb", Tier: "0", ByteLayer: "websocket_stream", User: "private-user"}
	s := r.Start(m)
	s.Add(true, 99)
	if got := r.Snapshot().Connections[0]; got.State != "connecting" || got.ToWorkspace != 0 {
		t.Fatalf("reservation counted as usage: %+v", got)
	}
	s.Establish("controller")
	s.Establish("controller")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Add(true, 2)
				s.Add(false, 3)
				_ = r.Snapshot()
			}
		}()
	}
	wg.Wait()
	snap := r.Snapshot()
	if len(snap.Connections) != 1 || snap.Connections[0].ToClient != 2400 {
		t.Fatalf("wrong concurrency counters: %+v", snap)
	}
	s.End()
	s.End()
	if snap = r.Snapshot(); len(snap.Connections) != 0 || snap.Traffic[0].ToWorkspace != 1600 {
		t.Fatalf("ended traffic lost: %+v", snap)
	}
	hop := r.Start(m)
	Ignore(WithSession(context.Background(), hop))
	hop.Establish("")
	hop.Add(false, 100)
	hop.End()
	failed := r.Start(m)
	failed.End()
	if r.Snapshot().SetupFailures != 1 {
		t.Fatal("forwarding counted as failed attach")
	}
	w := httptest.NewRecorder()
	r.ServeMetrics(w, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(w.Body.String(), "private-user") || strings.Contains(w.Body.String(), "workspace_uid") || !strings.Contains(w.Body.String(), "direction=\"toward_client\"} 2400") {
		t.Fatalf("invalid aggregate metrics: %s", w.Body.String())
	}
}

func TestPrivateReportsRequireTokenEvenWithDisabledAuth(t *testing.T) {
	for _, token := range []string{"", "secret"} {
		h := PrivateHandler(New("api"), token)
		for _, path := range []string{"/snapshot", "/metrics"} {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != 401 {
				t.Fatal("unprotected telemetry")
			}
			req.Header.Set("Authorization", "Bearer secret")
			w = httptest.NewRecorder()
			h.ServeHTTP(w, req)
			want := 200
			if token == "" {
				want = 401
			}
			if w.Code != want {
				t.Fatalf("status %d want %d", w.Code, want)
			}
		}
	}
}

func TestHijackedStreamCountsOnceAndShutdownRemovesConnection(t *testing.T) {
	r := New("api")
	ready := make(chan struct{})
	echoed := make(chan struct{})
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s := r.Start(Metadata{Category: "console", Transport: "tcp", ByteLayer: "websocket_stream"})
		defer s.End()
		defer close(done)
		writer := &Writer{ResponseWriter: w, Session: s}
		c, rw, err := writer.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n\r\n")
		_ = rw.Flush()
		s.Establish("")
		close(ready)
		buf := make([]byte, 4)
		if _, err := io.ReadFull(rw, buf); err != nil {
			t.Error(err)
			return
		}
		_, _ = c.Write(buf)
		close(echoed)
		_, _ = c.Read(make([]byte, 1))
	}))
	defer server.Close()
	c, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	<-ready
	// Consume only the handshake before sending the bytes to be counted.
	b := make([]byte, len("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
	_, _ = io.ReadFull(c, b)
	_, _ = c.Write([]byte("test"))
	_, _ = io.ReadFull(c, make([]byte, 4))
	// Receiving TCP bytes does not synchronize with the wrapper's accounting,
	// which runs after the underlying Write returns.
	<-echoed
	snap := r.Snapshot()
	if len(snap.Connections) != 1 || snap.Connections[0].ToWorkspace != 4 || snap.Connections[0].ToClient != 4 {
		t.Fatalf("stream or handshake double-counted: %+v", snap)
	}
	r.Close()
	<-done
	if len(r.Snapshot().Connections) != 0 {
		t.Fatal("shutdown retained stream")
	}
}

func TestHTTPInformationalHeadersDoNotConsumeFinalStatus(t *testing.T) {
	reg := New("api")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := reg.Start(Metadata{Category: "http"})
		defer s.End()
		writer := &Writer{ResponseWriter: w, Session: s}
		writer.WriteHeader(http.StatusEarlyHints)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("informational header consumed final status: %d", resp.StatusCode)
	}
}
