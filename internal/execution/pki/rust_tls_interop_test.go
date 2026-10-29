package pki

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in Go API client ↔ Rust guest server proof. Build kw-management's
// tests/tls_probe.rs with cargo test --test tls_probe --no-run, then set the
// absolute test-executable path in KW_MANAGEMENT_RUST_TLS_PROBE. Only synthetic
// ephemeral test keys travel over child stdin; no live credentials are loaded.
func TestRustManagementTLSInterop(t *testing.T) {
	probe := os.Getenv("KW_MANAGEMENT_RUST_TLS_PROBE")
	if probe == "" {
		t.Skip("set KW_MANAGEMENT_RUST_TLS_PROBE to the built Rust tls_probe test executable")
	}
	if !filepath.IsAbs(probe) {
		t.Fatal("Rust probe must be an explicitly selected absolute executable path")
	}
	for _, scenario := range []string{"success", "missing-client-cert", "foreign-client-ca", "wrong-client-purpose", "wrong-private-key", "unauthorized-api", "authority-outage", "authority-lost-after-handshake", "missing-alpn", "wrong-alpn", "tls12"} {
		t.Run(scenario, func(t *testing.T) {
			ca := authority(t)
			guestCert := leaf(t, ca, guest())
			apiCert := leaf(t, ca, api())
			config, err := ClientTLS(apiCert, ca.roots, guest(), func(Identity) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing-client-cert":
				config.Certificates = nil
			case "foreign-client-ca":
				config.Certificates = []tls.Certificate{leaf(t, authority(t), api())}
			case "wrong-client-purpose":
				config.Certificates = []tls.Certificate{leaf(t, ca, guest())}
			case "wrong-private-key":
				config.Certificates[0].PrivateKey = leaf(t, ca, api()).PrivateKey
			case "unauthorized-api":
				config.Certificates = []tls.Certificate{leaf(t, ca, Identity{Role: RoleAPI, ReplicaID: "other-api"})}
			case "missing-alpn":
				config.NextProtos = nil
				config.VerifyConnection = nil
			case "wrong-alpn":
				config.NextProtos = []string{"desktop-protocol"}
				config.VerifyConnection = nil
			case "tls12":
				config.MinVersion = tls.VersionTLS12
				config.MaxVersion = tls.VersionTLS12
			}
			key, err := x509.MarshalPKCS8PrivateKey(guestCert.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			uri, _ := guest().URI()
			input, err := json.Marshal(struct {
				Roots        [][]byte `json:"roots"`
				Certificates [][]byte `json:"certificates"`
				PrivateKey   []byte   `json:"private_key"`
				Enrolled     string   `json:"enrolled"`
				Deny         bool     `json:"deny"`
				DenyOnFinish bool     `json:"deny_on_finish"`
			}{[][]byte{ca.der}, guestCert.Certificate, key, uri.String(), scenario == "authority-outage", scenario == "authority-lost-after-handshake"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, probe, "--exact", "rust_tls_probe_child", "--ignored", "--nocapture", "--format", "terse")
			cmd.Env = append(os.Environ(), "KW_MANAGEMENT_TLS_PROBE=1")
			cmd.Stdin = bytes.NewReader(input)
			// Never include child stderr or synthetic private material in failures.
			cmd.Stderr = io.Discard
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal("could not start selected Rust TLS probe")
			}
			defer func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			var accepted, sawResult, sawReady bool
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				line := scanner.Text()
				start := strings.IndexByte(line, '{')
				if start < 0 {
					continue
				}
				var event struct {
					Event       string `json:"event"`
					Address     string `json:"address"`
					Accepted    bool   `json:"accepted"`
					Identity    string `json:"identity"`
					Fingerprint string `json:"fingerprint"`
					Stage       string `json:"stage"`
				}
				if json.Unmarshal([]byte(line[start:]), &event) != nil {
					t.Fatal("invalid sanitized Rust probe event")
				}
				if event.Event == "ready" {
					if sawReady {
						t.Fatal("duplicate Rust probe readiness")
					}
					sawReady = true
					host, _, err := net.SplitHostPort(event.Address)
					if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
						t.Fatal("Rust probe must bind loopback only")
					}
					conn, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: config}).DialContext(ctx, "tcp", event.Address)
					if err == nil {
						_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
						_, err = conn.Write([]byte{0x51})
						if err == nil {
							var reply [1]byte
							_, err = io.ReadFull(conn, reply[:])
							if err == nil && reply[0] != 0x52 {
								t.Fatal("unexpected Rust TLS application proof")
							}
						}
						_ = conn.Close()
					}
					if scenario == "success" && err != nil {
						t.Fatal("Go↔Rust authenticated application exchange failed")
					}
					if scenario != "success" && err == nil {
						t.Fatal("denied TLS scenario completed application exchange")
					}
				} else if event.Event == "result" {
					wantStage := "handshake"
					if scenario == "success" {
						wantStage = "application"
					}
					if scenario == "missing-alpn" || scenario == "authority-lost-after-handshake" {
						wantStage = "finish"
					}
					if event.Stage != wantStage {
						t.Fatalf("Rust TLS failed at %s, wanted %s", event.Stage, wantStage)
					}
					accepted, sawResult = event.Accepted, true
					if accepted {
						fingerprint, err := APIClientFingerprint(apiCert)
						if err != nil || event.Fingerprint != fingerprint {
							t.Fatal("Rust peer fingerprint is not the Go client leaf")
						}
						if event.Identity != "spiffe://kubeworkspaces.io/management/v1/apis/api-1" {
							t.Fatal("Rust peer identity drifted")
						}
					}
				}
			}
			if scanner.Err() != nil || cmd.Wait() != nil || !sawReady || !sawResult || accepted != (scenario == "success") {
				t.Fatalf("Rust TLS result mismatch for %s (accepted=%t result=%t)", scenario, accepted, sawResult)
			}
		})
	}
}
