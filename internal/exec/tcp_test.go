package exec

import (
	"testing"
)

func TestParseTCPPort(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"22", 22, false},
		{"8080", 8080, false},
		{"1", 1, false},
		{"65535", 65535, false},
		{"", 0, true},
		{"0", 0, true},
		{"65536", 0, true},
		{"-1", 0, true},
		{"http", 0, true},
		{"80,443", 0, true},
		{" 8080", 0, true},
	} {
		got, err := ParseTCPPort(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseTCPPort(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseTCPPort(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestTCPRegistryIsPerPort(t *testing.T) {
	if TCPInUse("ns", "ws", 8080) {
		t.Fatal("TCPInUse true on empty registry")
	}
	h1 := &sessionHandle{}
	key := tcpKey("ns", "ws", 8080)
	if _, ok := tcpSessions.acquire(key, h1); !ok {
		t.Fatal("acquire failed")
	}
	if !TCPInUse("ns", "ws", 8080) {
		t.Error("TCPInUse false after acquire")
	}
	if TCPInUse("ns", "ws", 9090) {
		t.Error("TCPInUse true for different port")
	}
	h2 := &sessionHandle{}
	if _, ok := tcpSessions.acquire(key, h2); ok {
		t.Error("second acquire on same port succeeded, want 409 behavior")
	}
	if !TakeOverTCP("ns", "ws", 8080) {
		t.Error("TakeOverTCP = false, want true")
	}
	if TCPInUse("ns", "ws", 8080) {
		t.Error("TCPInUse true after takeover")
	}
	tcpSessions.release(key, h1)
}
