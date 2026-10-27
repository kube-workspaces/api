package kubeworkspaces

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Opt-in proof of the production HTTP admission/recording path, using real
// disposable PostgreSQL/S3. Only guest execution and account/policy lookup are
// fixtures. Never discover deployment credentials or use this on production
// storage: the test deliberately corrupts its own recording objects.
func TestExecutionPersistentIntegration(t *testing.T) {
	dsn, endpoint := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL"), os.Getenv("KW_EXECUTION_TEST_S3_ENDPOINT")
	if dsn == "" || endpoint == "" {
		t.Skip("set KW_EXECUTION_TEST_DATABASE_URL and KW_EXECUTION_TEST_S3_ENDPOINT for disposable storage")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(ctx) })
	checkAudit := func(id, kind string) {
		t.Helper()
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM execution_audit WHERE execution_id=$1 AND kind=$2 AND actor_id=$3`, id, kind, "operator-uid").Scan(&count); err != nil || count == 0 {
			t.Fatalf("missing durable %s audit: count=%d err=%v", kind, count, err)
		}
	}
	upstream, err := url.Parse(endpoint)
	if err != nil || upstream.Host == "" {
		t.Fatal("invalid disposable S3 endpoint")
	}
	// Reject selected actual S3 operations without replacing the recording
	// implementation. AccessDenied is nonretryable and keeps outage tests fast.
	var blocked atomic.Value
	blocked.Store("")
	var rejected atomic.Int64
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rule := blocked.Load().(string)
		if rule == "all" || (r.Method == http.MethodPut && rule != "" && strings.HasSuffix(r.URL.Path, rule)) {
			rejected.Add(1)
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>disposable storage fault</Message></Error>")
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(gate.Close)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	opts := storage.Options{Mode: "external", DatabaseURL: dsn, RecordingKey: key, KeyID: storage.DeriveKeyID(key), S3: storage.S3Options{
		Endpoint: gate.URL, Region: "us-east-1", Bucket: "execution-http-integration", CreateBucket: true, ForcePathStyle: true,
		AccessKey: os.Getenv("KW_EXECUTION_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KW_EXECUTION_TEST_S3_SECRET_KEY"),
	}}
	open := func() storage.Store {
		t.Helper()
		s, err := storage.Open(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	permissions := []string{string(auth.PermissionExec), string(auth.PermissionElevated), string(auth.PermissionReadRecordings), string(auth.PermissionManage)}
	stackFor := func(s storage.Store, stub *stubQGA, grants []string) *startStack {
		return newStoredStartStack(t, "team", "vm", grants, enabledElevatedPolicy(), stub, s)
	}
	// Access raw objects independently to verify encryption and tamper detection.
	raw, err := minio.New(upstream.Host, &minio.Options{Secure: upstream.Scheme == "https", Region: "us-east-1", BucketLookup: minio.BucketLookupPath,
		Creds: credentials.NewStaticV4(opts.S3.AccessKey, opts.S3.SecretKey, "")})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"command", "linux-script", "windows-script"} {
		t.Run(kind, func(t *testing.T) {
			s := open()
			target := eligibleTarget()
			target.Linux = kind == "linux-script"
			code := 0
			secret := "protected-input-" + kind
			output := "protected-output-" + kind
			stub := &stubQGA{target: target, result: &qga.GuestResult{Outcome: "completed", ExitCode: &code, Stdout: []byte(output), Stderr: []byte("private stderr"), DurationMS: 42}}
			stack := stackFor(s, stub, permissions)
			stub.execute = func(ctx context.Context, _ qga.Target, cmd qga.Command) (*qga.GuestResult, error) {
				// A separate database pool and S3 client must see admission and
				// exact protected input before the guest transport is called.
				observer := open()
				defer observer.Close()
				rec, outcome, err := observer.Metadata().Get(ctx, cmd.ExecutionID)
				if err != nil || outcome.State != storage.StateRunning || rec.Durability != storage.DurabilityDurable {
					t.Fatalf("dispatch preceded persistent admission: %+v %v", outcome, err)
				}
				checkAudit(cmd.ExecutionID, "admitted")
				metadata, _ := json.Marshal(rec)
				if bytes.Contains(metadata, []byte(secret)) {
					t.Fatal("protected input leaked into metadata")
				}
				obj, err := raw.GetObject(ctx, opts.S3.Bucket, fmt.Sprintf("executions/%s/chunks/%016d.chunk", cmd.RecordingID, 0), minio.GetObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				ciphertext, err := io.ReadAll(obj)
				_ = obj.Close()
				if err != nil || len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte(secret)) {
					t.Fatal("input was not committed encrypted before dispatch")
				}
				return stub.result, nil
			}
			payload := map[string]any{"namespace": "team", "workspace_name": "vm", "deadline_seconds": 10}
			if kind == "command" {
				payload["executable"], payload["args"] = "cmd.exe", []string{"/c", "echo", secret}
			} else {
				marker := "#!/bin/sh\n"
				if !target.Linux {
					marker = "#!powershell\n"
				}
				payload["script"] = map[string]any{"body": marker + "echo " + secret + "\n"}
			}
			body, _ := json.Marshal(payload)
			w := stack.post(string(body), "")
			var result struct {
				ExecutionID string `json:"execution_id"`
				RecordingID string `json:"recording_id"`
				State       string `json:"state"`
				Mode        string `json:"mode"`
				Durability  string `json:"durability"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.State != "succeeded" || result.Mode != "external" || result.Durability != "durable" || len(stub.commands) != 1 {
				t.Fatalf("persistent execution: HTTP %d %s", w.Code, w.Body.String())
			}
			// Close every serving connection, then recreate storage and HTTP
			// service. No start is submitted to the new service.
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := open()
			replay := stackFor(reopened, nil, permissions)
			checkAudit(result.ExecutionID, "finished")
			path := "/v1/executions/" + result.ExecutionID
			if w := replay.get(path, true); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"succeeded"`) {
				t.Fatalf("persistent metadata after reopen: %d %s", w.Code, w.Body.String())
			}
			for _, suffix := range []string{"/recording", "/recording/chunks/0", "/recording/chunks/1"} {
				w := replay.get(path+suffix, true)
				// Cache headers belong to cmd/kube_workspaces middleware and
				// have their own tests; this stack mounts the Goa service only.
				if w.Code != 200 {
					t.Fatalf("protected replay after reopen: %d %s", w.Code, w.Body.String())
				}
				if strings.Contains(suffix, "/chunks/") {
					var chunk struct {
						Data []byte `json:"data"`
					}
					if json.Unmarshal(w.Body.Bytes(), &chunk) != nil || (strings.HasSuffix(suffix, "/0") && !bytes.Contains(chunk.Data, []byte(secret))) || (strings.HasSuffix(suffix, "/1") && !bytes.Contains(chunk.Data, []byte(base64.StdEncoding.EncodeToString([]byte(output))))) {
						t.Fatal("replay lost exact protected input/output")
					}
					if strings.HasSuffix(suffix, "/0") {
						var input recordingStart
						if json.Unmarshal(chunk.Data, &input) != nil || input.ProvisioningGeneration != target.VMUID || input.DeadlineSeconds != 10 || (kind != "command" && (input.Script == nil || input.Script.Body != payload["script"].(map[string]any)["body"])) {
							t.Fatal("replay lost script body or VM/deadline binding")
						}
					} else {
						var recorded recordingResult
						if json.Unmarshal(chunk.Data, &recorded) != nil || recorded.StdoutB64 != base64.StdEncoding.EncodeToString([]byte(output)) || recorded.StderrB64 != base64.StdEncoding.EncodeToString(stub.result.Stderr) || recorded.ExitCode == nil || *recorded.ExitCode != 0 || recorded.DurationMS != 42 {
							t.Fatal("replay lost result/streams/timing")
						}
					}
				} else {
					var manifest struct {
						Chunks   int  `json:"chunks"`
						Verified bool `json:"verified"`
					}
					if json.Unmarshal(w.Body.Bytes(), &manifest) != nil || manifest.Chunks != 2 || !manifest.Verified {
						t.Fatal("replay returned incomplete/unverified manifest")
					}
				}
			}
			checkAudit(result.ExecutionID, "replay.authorized")
			for _, grants := range [][]string{{string(auth.PermissionManage)}, {string(auth.PermissionExec), string(auth.PermissionElevated)}} {
				denied := stackFor(reopened, nil, grants)
				for _, suffix := range []string{"/recording", "/recording/chunks/0", "/recording/chunks/1"} {
					if w := denied.get(path+suffix, true); w.Code != 403 {
						t.Fatalf("recording disclosed without read grant: %d", w.Code)
					}
				}
			}
			checkAudit(result.ExecutionID, "replay.denied")
			if w := replay.get(path+"/recording", false); w.Code != 401 {
				t.Fatalf("anonymous replay: %d", w.Code)
			}
			// Corruption must prevent even a verified manifest being returned.
			object := fmt.Sprintf("executions/%s/chunks/%016d.chunk", result.RecordingID, 1)
			if _, err := raw.PutObject(ctx, opts.S3.Bucket, object, strings.NewReader("corrupted"), 9, minio.PutObjectOptions{}); err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{"/recording", "/recording/chunks/0"} {
				if w := replay.get(path+suffix, true); w.Code == 200 || bytes.Contains(w.Body.Bytes(), []byte(secret)) {
					t.Fatal("tampered recording disclosed")
				}
			}
		})
	}
	for _, phase := range []string{"all", "/pending", "/chunks/0000000000000000.chunk", "/chunks/0000000000000001.chunk", "/manifest.json"} {
		t.Run("storage-failure"+phase, func(t *testing.T) {
			s := open()
			code := 0
			stub := &stubQGA{target: eligibleTarget(), result: &qga.GuestResult{Outcome: "completed", ExitCode: &code}}
			stack := stackFor(s, stub, permissions)
			before := rejected.Load()
			blocked.Store(phase)
			defer blocked.Store("")
			w := stack.post(`{"namespace":"team","workspace_name":"vm","executable":"cmd.exe","args":["/c","echo proof"]}`, "")
			if w.Code != 503 || rejected.Load() == before {
				t.Fatalf("storage failure returned success or missed fault: HTTP %d %s", w.Code, w.Body.String())
			}
			wantDispatch := 0
			if phase == "/chunks/0000000000000001.chunk" || phase == "/manifest.json" {
				wantDispatch = 1
			}
			if len(stub.commands) != wantDispatch {
				t.Fatalf("dispatch count %d, want %d (never retry)", len(stub.commands), wantDispatch)
			}
			if wantDispatch == 1 {
				_, outcome, err := s.Metadata().Get(ctx, stub.commands[0].ExecutionID)
				if err != nil || outcome.State != storage.StateRecordingLost || !outcome.RecordingLost {
					t.Fatalf("missing explicit recording loss: %+v %v", outcome, err)
				}
				checkAudit(stub.commands[0].ExecutionID, "recording.lost")
			}
		})
	}
}
