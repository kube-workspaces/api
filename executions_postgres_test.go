package kubeworkspaces

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

// A TCP fault gate cuts existing PostgreSQL sessions as well as new connections.
// It does not fake metadata errors or require permission to stop a database.
type postgresFaultGate struct {
	listener net.Listener
	mu       sync.Mutex
	blocked  bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

func newPostgresFaultGate(t *testing.T, address string) *postgresFaultGate {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &postgresFaultGate{listener: listener, conns: make(map[net.Conn]struct{})}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			g.wg.Add(1)
			go func() {
				defer g.wg.Done()
				defer client.Close()
				server, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					return
				}
				defer server.Close()
				g.mu.Lock()
				if g.blocked {
					g.mu.Unlock()
					return
				}
				g.conns[client], g.conns[server] = struct{}{}, struct{}{}
				g.mu.Unlock()
				defer func() {
					g.mu.Lock()
					delete(g.conns, client)
					delete(g.conns, server)
					g.mu.Unlock()
				}()
				copied := make(chan struct{})
				go func() {
					_, _ = io.Copy(server, client)
					_ = server.Close()
					close(copied)
				}()
				_, _ = io.Copy(client, server)
				_ = client.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		g.setBlocked(true)
		g.wg.Wait()
	})
	return g
}

func (g *postgresFaultGate) setBlocked(blocked bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blocked = blocked
	if blocked {
		for conn := range g.conns {
			_ = conn.Close()
		}
	}
}

// Opt-in actual connection-loss proof against disposable PostgreSQL/S3. The
// guest transport is a fixture; this never contacts a VM or deployment.
func TestExecutionPostgresOutageIntegration(t *testing.T) {
	dsn, endpoint := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL"), os.Getenv("KW_EXECUTION_TEST_S3_ENDPOINT")
	if dsn == "" || endpoint == "" {
		t.Skip("set KW_EXECUTION_TEST_DATABASE_URL and KW_EXECUTION_TEST_S3_ENDPOINT for disposable storage")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" {
		t.Fatal("this connection-loss campaign requires a PostgreSQL URL")
	}
	address := u.Host
	if u.Port() == "" {
		address = net.JoinHostPort(u.Hostname(), "5432")
	}
	for _, phase := range []string{"before-admission", "during-result", "recovered-before-result", "terminal-audit-failure"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			gate := newPostgresFaultGate(t, address)
			throughGate := *u
			throughGate.Host = gate.listener.Addr().String()
			query := throughGate.Query()
			query.Set("connect_timeout", "2")
			throughGate.RawQuery = query.Encode()
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			s, err := storage.Open(ctx, storage.Options{Mode: "external", DatabaseURL: throughGate.String(), RecordingKey: key, KeyID: storage.DeriveKeyID(key), S3: storage.S3Options{
				Endpoint: endpoint, Region: "us-east-1", Bucket: "execution-http-integration", CreateBucket: true, ForcePathStyle: true,
				AccessKey: os.Getenv("KW_EXECUTION_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KW_EXECUTION_TEST_S3_SECRET_KEY"),
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			code := 0
			stub := &stubQGA{target: eligibleTarget(), result: &qga.GuestResult{Outcome: "completed", ExitCode: &code, Stdout: []byte("recorded outcome")}}
			stack := newStoredStartStack(t, "team", "vm", []string{string(auth.PermissionExec), string(auth.PermissionElevated), string(auth.PermissionReadRecordings)}, enabledElevatedPolicy(), stub, s)
			if phase == "before-admission" {
				gate.setBlocked(true)
			} else {
				stub.execute = func(ctx context.Context, _ qga.Target, cmd qga.Command) (*qga.GuestResult, error) {
					if phase == "terminal-audit-failure" {
						// Reject only this execution's finished audit after its
						// terminal UPDATE, to prove the entire commit rolls back.
						conn, err := pgx.Connect(ctx, dsn)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = conn.Close(context.Background()) })
						if _, err := conn.Exec(ctx, `CREATE FUNCTION pg_temp.reject_terminal_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'disposable terminal audit fault'; END $$`); err != nil {
							t.Fatal(err)
						}
						trigger := pgx.Identifier{"reject_" + cmd.ExecutionID}.Sanitize()
						if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON execution_audit FOR EACH ROW WHEN (NEW.execution_id = '%s' AND NEW.kind = 'finished') EXECUTE FUNCTION pg_temp.reject_terminal_audit()`, trigger, cmd.ExecutionID)); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() {
							if _, err := conn.Exec(context.Background(), `DROP TRIGGER `+trigger+` ON execution_audit`); err != nil {
								t.Error(err)
							}
						})
						return stub.result, nil
					}
					gate.setBlocked(true)
					if err := s.Metadata().Ready(ctx); err == nil {
						t.Fatal("fault did not cut the live database connection")
					}
					if phase == "recovered-before-result" {
						gate.setBlocked(false)
					}
					return stub.result, nil
				}
			}
			response := stack.postCtx(ctx, `{"namespace":"team","workspace_name":"vm","executable":"cmd.exe","args":["/c","echo proof"]}`)
			wantHTTP, wantDispatch := 503, 1
			if phase == "before-admission" {
				wantDispatch = 0
			}
			if phase == "recovered-before-result" {
				wantHTTP = 200
			}
			if response.Code != wantHTTP || len(stub.commands) != wantDispatch {
				t.Fatalf("connection-loss outcome HTTP %d, dispatches %d; want %d/%d: %s", response.Code, len(stub.commands), wantHTTP, wantDispatch, response.Body.String())
			}
			gate.setBlocked(false)
			if err := s.Ready(ctx); err != nil {
				t.Fatalf("storage did not recover: %v", err)
			}
			if s.Mode() != "external" || s.Durability() != storage.DurabilityDurable {
				t.Fatal("persistent storage silently downgraded")
			}
			if wantDispatch == 0 {
				return
			}
			cmd := stub.commands[0]
			rec, outcome, err := s.Metadata().Get(ctx, cmd.ExecutionID)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := s.Recording().Open(ctx, cmd.RecordingID)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			intent, err := reader.TerminalIntent(ctx)
			if err != nil || !intent.MatchesAdmission(rec) || intent.Outcome.State != storage.StateSucceeded || intent.Outcome.ExitCode == nil || *intent.Outcome.ExitCode != 0 {
				t.Fatalf("database loss did not retain admission-bound terminal intent: %+v %v", intent, err)
			}
			if phase == "during-result" || phase == "terminal-audit-failure" {
				// With PostgreSQL unavailable at finalization, the API must not
				// invent success. Owner-loss reconciliation is separate work:
				// the last durable state can remain running, despite a complete
				// protected result in S3. Never resubmit this execution.
				if outcome.State == storage.StateSucceeded {
					t.Fatal("database/audit failure fabricated committed success")
				}
			} else if outcome.State != storage.StateSucceeded {
				t.Fatalf("recovered result not persisted: %+v", outcome)
			}
			playback := stack.getCtx(ctx, "/v1/executions/"+cmd.ExecutionID+"/recording/chunks/1", true)
			var chunk struct {
				Data []byte `json:"data"`
			}
			var result recordingResult
			if playback.Code != 200 || json.Unmarshal(playback.Body.Bytes(), &chunk) != nil || json.Unmarshal(chunk.Data, &result) != nil || result.Outcome != "completed" || result.ExitCode == nil || *result.ExitCode != 0 {
				t.Fatalf("protected known result lost across database outage: HTTP %d %s", playback.Code, playback.Body.String())
			}
			if len(stub.commands) != 1 || result.StdoutB64 != base64.StdEncoding.EncodeToString(stub.result.Stdout) {
				t.Fatal("recovery reran or lost the result")
			}
		})
	}
}
