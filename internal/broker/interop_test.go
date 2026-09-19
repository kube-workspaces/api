package broker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestExternalClients runs opt-in real RFB clients against a local WS broker.
// Each executable receives a ws:// URL and must check a full red/green frame
// followed by blue/green and then a 1x2 white/blue resize. It must exit nonzero
// on protocol/pixel failures. Sources are in testdata/interop.
// Native and browser executables are test dependencies, never service deps.
func TestExternalClients(t *testing.T) {
	native, browser := os.Getenv("KW_BROKER_NATIVE_CLIENT"), os.Getenv("KW_BROKER_BROWSER_CLIENT")
	if native == "" || browser == "" {
		t.Skip("set KW_BROKER_NATIVE_CLIENT and KW_BROKER_BROWSER_CLIENT to interoperability test executables")
	}
	b, updates := startFixture(t)
	updates <- rawUpdate(0, 0, 2, 1, []byte{255, 0, 0, 0, 0, 255, 0, 0})
	awaitVersion(t, b, 1)
	var wg sync.WaitGroup
	arrivals := make(chan struct{}, 2)
	upgrader := websocket.Upgrader{Subprotocols: []string{"binary"}, CheckOrigin: func(*http.Request) bool { return true }} // loopback test only
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		wg.Add(1)
		defer wg.Done()
		arrivals <- struct{}{}
		_ = b.ServeObserver(r.Context(), NewWebSocketStream(c))
	}))
	defer func() { b.Close(); server.Close(); wg.Wait() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	done := make(chan error, 2)
	run := func(path string) {
		cmd := exec.CommandContext(ctx, path, url)
		output, err := cmd.CombinedOutput()
		t.Logf("client %s: %s", path, output)
		done <- err
	}
	go run(native)
	select {
	case <-arrivals:
	case <-ctx.Done():
		t.Fatal("native client never connected")
	}
	go run(browser) // actual late attachment to the same capture generation
	select {
	case <-arrivals:
	case <-ctx.Done():
		t.Fatal("browser client never connected")
	}
	// Clients need time to finish their handshakes and request the first frame.
	// Their own pixel assertions fail if either state is missed.
	time.Sleep(time.Second)
	updates <- rawUpdate(0, 0, 1, 1, []byte{0, 0, 255, 0})
	time.Sleep(time.Second)
	updates <- append([]byte{0, 0, 0, 1}, rectangleHeader(0, 0, 1, 2, -223)...)
	updates <- rawUpdate(0, 0, 1, 2, []byte{255, 255, 255, 0, 0, 0, 255, 0})
	for range 2 {
		if err := <-done; err != nil {
			t.Errorf("external client: %v", err)
		}
	}
}

func BenchmarkPublish1080p(b *testing.B) {
	broker := New(nil)
	pixels := make([]byte, 1920*1080*4)
	b.ReportAllocs()
	b.SetBytes(int64(len(pixels)))
	b.ResetTimer()
	for range b.N {
		broker.publish(1920, 1080, pixels)
	}
}
