package kubeworkspaces

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gen "github.com/kube-workspaces/api/gen/executions"
	svr "github.com/kube-workspaces/api/gen/http/executions/server"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/platform"
	goahttp "goa.design/goa/v3/http"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

// stubQGA scripts the pilot transport behind the start endpoint.
type stubQGA struct {
	target     qga.Target
	result     *qga.GuestResult
	execErr    error
	resolveErr error
	commands   []qga.Command
	resolved   [][2]string
}

func (s *stubQGA) Resolve(_ context.Context, namespace, name string) (qga.Target, error) {
	s.resolved = append(s.resolved, [2]string{namespace, name})
	if s.resolveErr != nil {
		return qga.Target{}, s.resolveErr
	}
	return s.target, nil
}

func (s *stubQGA) Execute(_ context.Context, _ qga.Target, command qga.Command) (*qga.GuestResult, error) {
	s.commands = append(s.commands, command)
	return s.result, s.execErr
}

type startStack struct {
	stub  *stubQGA
	store storage.Store
	post  func(body string, credential string) *httptest.ResponseRecorder
}

func newStartStack(t *testing.T, permissions []string, policy map[string]interface{}, stub *stubQGA) *startStack {
	t.Helper()
	ctx := context.Background()
	key := "start-test-signing-key-32-bytes"
	permissionValues := make([]interface{}, len(permissions))
	for i, permission := range permissions {
		permissionValues[i] = permission
	}
	grants := []interface{}{map[string]interface{}{
		"namespace": "team", "workspaces": []interface{}{"vm"},
		"permissions": permissionValues,
	}}
	user := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "User",
		"metadata": map[string]interface{}{"name": "operator", "uid": "operator-uid"},
		"spec": map[string]interface{}{
			"email": "operator@example.com", "role": "viewer",
			"namespaceAccess": []interface{}{map[string]interface{}{"namespace": "team", "role": "viewer"}},
			"executionGrants": grants,
		},
	}}
	cfg := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "AuthConfig",
		"metadata": map[string]interface{}{"name": "default"},
		"spec": map[string]interface{}{"enabled": true, "session": map[string]interface{}{
			"signingKey": map[string]interface{}{"name": "session-key", "key": "key"},
		}},
	}}
	secret := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]interface{}{"name": "session-key", "namespace": auth.LocalAuthSystemNamespace},
		"data":     map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte(key))},
	}}
	platformConfig := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "PlatformConfig",
		"metadata": map[string]interface{}{"name": "default"},
		"spec":     map[string]interface{}{"vmExecution": policy},
	}}
	users := schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "users"}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{users: "UserList"}, user, cfg, secret, platformConfig)
	provider := auth.NewConfigProvider(client)
	store, err := storage.Open(ctx, storage.Options{Mode: "ephemeral", EphemeralDir: t.TempDir(), EphemeralMaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	var options []ExecutionsOption
	if stub != nil {
		options = append(options, WithQGA(stub))
	}
	svc := NewExecutions(execution.NewService(store), platform.NewConfigProvider(client), options...)
	mux := goahttp.NewMuxer()
	server := svr.New(gen.NewEndpoints(svc), mux, goahttp.RequestDecoder, goahttp.ResponseEncoder, nil, nil)
	svr.Mount(mux, server)
	handler := auth.Middleware(provider)(mux)
	token, err := auth.CreateSessionToken("operator@example.com", "Operator", "viewer", nil, []byte(key), time.Hour, "operator-uid")
	if err != nil {
		t.Fatal(err)
	}
	return &startStack{
		stub:  stub,
		store: store,
		post: func(body, _ string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, "/v1/executions/start", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			return w
		},
	}
}

func eligibleTarget() qga.Target {
	return qga.Target{
		Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "workspace-uid",
		VMUID: "vm-uid", PodName: "virt-launcher-vm", PodUID: "pod-uid", Domain: "team_vm",
	}
}

func enabledElevatedPolicy() map[string]interface{} {
	return map[string]interface{}{"enabled": true, "allowElevated": true}
}

func TestStartExecutesRecordsAndReturnsOutcome(t *testing.T) {
	code := 0
	stub := &stubQGA{
		target: eligibleTarget(),
		result: &qga.GuestResult{Outcome: "completed", ExitCode: &code, Stdout: []byte("hello\n"), DurationMS: 42},
	}
	stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
	w := stack.post(`{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[]}`, "operator-uid")
	if w.Code != http.StatusOK {
		t.Fatalf("start failed: %d %s", w.Code, w.Body.String())
	}
	var response struct {
		ExecutionID   string  `json:"execution_id"`
		RecordingID   string  `json:"recording_id"`
		Namespace     string  `json:"namespace"`
		WorkspaceName string  `json:"workspace_name"`
		WorkspaceUID  string  `json:"workspace_uid"`
		Outcome       string  `json:"outcome"`
		State         string  `json:"state"`
		ExitCode      *int    `json:"exit_code"`
		Stdout        string  `json:"stdout"`
		DurationMS    *uint64 `json:"duration_ms"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(response.ExecutionID, "exec_") || !strings.HasPrefix(response.RecordingID, "rec_") ||
		response.Namespace != "team" || response.WorkspaceName != "vm" || response.WorkspaceUID != "workspace-uid" ||
		response.Outcome != "succeeded" || response.State != "succeeded" || response.ExitCode == nil || *response.ExitCode != 0 ||
		response.DurationMS == nil || *response.DurationMS != 42 {
		t.Fatalf("unexpected response: %s", w.Body.String())
	}
	stdout, err := base64.StdEncoding.DecodeString(response.Stdout)
	if err != nil || string(stdout) != "hello\n" {
		t.Fatalf("unexpected stdout: %q (%v)", stdout, err)
	}
	if len(stub.commands) != 1 {
		t.Fatalf("expected one executed command, got %d", len(stub.commands))
	}
	command := stub.commands[0]
	if command.ActorUID != "operator-uid" || command.ExecutionID != response.ExecutionID || command.RecordingID != response.RecordingID ||
		command.Executable != "whoami" || command.DeadlineSeconds != 20 {
		t.Fatalf("unexpected command: %+v", command)
	}
	// The admission record and both recording chunks must be durable before
	// the success response returned.
	rec, outcome, err := stack.store.Metadata().Get(context.Background(), response.ExecutionID)
	if err != nil || outcome.State != storage.StateSucceeded || rec.RecordingID != response.RecordingID || !rec.Elevated || rec.OSIdentity != "SYSTEM" {
		t.Fatalf("unexpected stored record: %+v %+v %v", rec, outcome, err)
	}
	reader, err := stack.store.Recording().Open(context.Background(), response.RecordingID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reader.Manifest().Chunks != 2 {
		t.Fatalf("expected start and result chunks, got %d", reader.Manifest().Chunks)
	}
	startChunk, err := reader.ReadChunk(context.Background(), 0)
	if err != nil || !strings.Contains(string(startChunk), `"executable":"whoami"`) || !strings.Contains(string(startChunk), `"type":"start"`) || !strings.Contains(string(startChunk), `"provisioning_generation":"vm-uid"`) || !strings.Contains(string(startChunk), `"revocation_epoch":0`) {
		t.Fatalf("unexpected start chunk: %q (%v)", startChunk, err)
	}
	resultChunk, err := reader.ReadChunk(context.Background(), 1)
	if err != nil || !strings.Contains(string(resultChunk), `"type":"result"`) || !strings.Contains(string(resultChunk), `"outcome":"completed"`) {
		t.Fatalf("unexpected result chunk: %q (%v)", resultChunk, err)
	}
}

func TestStartMapsGuestOutcomes(t *testing.T) {
	for name, script := range map[string]struct {
		result       *qga.GuestResult
		execErr      error
		wantOutcome  string
		wantState    string
		wantDenial   string
		wantExitCode *int
	}{
		"guest-failure": {
			result:      &qga.GuestResult{Outcome: "completed", ExitCode: intPtr(7)},
			wantOutcome: "failed", wantState: "failed", wantExitCode: intPtr(7),
		},
		"deadline": {
			result:      &qga.GuestResult{Outcome: "deadline"},
			wantOutcome: "timed_out", wantState: "timed_out",
		},
		"denied-by-runner": {
			result:      &qga.GuestResult{Outcome: "denied", Denial: "workspace UID does not match"},
			wantOutcome: "failed", wantState: "failed", wantDenial: "denied:workspace UID does not match",
		},
		"output-limit": {
			result:      &qga.GuestResult{Outcome: "output-limit", Truncated: true},
			wantOutcome: "failed", wantState: "failed",
		},
		"runner-error": {
			result:      &qga.GuestResult{Outcome: "runner-error", Denial: "keys file unreadable"},
			wantOutcome: "failed", wantState: "failed", wantDenial: "keys file unreadable",
		},
		"unrecognized-outcome": {
			result:      &qga.GuestResult{Outcome: "side-channel"},
			wantOutcome: "unknown", wantState: "unknown", wantDenial: "unrecognized runner outcome",
		},
		"transport-loss": {
			execErr:     errors.New("pod exec failed"),
			wantOutcome: "unknown", wantState: "unknown", wantDenial: "transport lost; do not rerun",
		},
		"revoked-before-dispatch": {
			execErr:     qga.ErrDenied,
			wantOutcome: "failed", wantState: "revoked", wantDenial: "execution authority changed before dispatch",
		},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &stubQGA{target: eligibleTarget(), result: script.result, execErr: script.execErr}
			stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
			w := stack.post(`{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[]}`, "operator-uid")
			if w.Code != http.StatusOK {
				t.Fatalf("start failed: %d %s", w.Code, w.Body.String())
			}
			var response struct {
				ExecutionID string  `json:"execution_id"`
				Outcome     string  `json:"outcome"`
				State       string  `json:"state"`
				Denial      *string `json:"denial"`
				ExitCode    *int    `json:"exit_code"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Outcome != script.wantOutcome || response.State != script.wantState {
				t.Fatalf("unexpected outcome: %s", w.Body.String())
			}
			if script.wantDenial == "" && response.Denial != nil && *response.Denial != "" {
				t.Fatalf("unexpected denial: %s", w.Body.String())
			}
			if script.wantDenial != "" && (response.Denial == nil || *response.Denial != script.wantDenial) {
				t.Fatalf("expected denial %q: %s", script.wantDenial, w.Body.String())
			}
			_, outcome, err := stack.store.Metadata().Get(context.Background(), response.ExecutionID)
			if err != nil || string(outcome.State) != script.wantState {
				t.Fatalf("stored state drifted: %+v %v", outcome, err)
			}
		})
	}
}

func TestStartFailsClosed(t *testing.T) {
	permissions := []string{string(auth.PermissionExec), string(auth.PermissionElevated)}
	body := `{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[]}`
	t.Run("policy-disabled", func(t *testing.T) {
		stub := &stubQGA{target: eligibleTarget(), result: &qga.GuestResult{Outcome: "completed", ExitCode: intPtr(0)}}
		stack := newStartStack(t, permissions, map[string]interface{}{"enabled": false, "allowElevated": true}, stub)
		if w := stack.post(body, "operator-uid"); w.Code != http.StatusForbidden {
			t.Fatalf("expected forbidden, got %d %s", w.Code, w.Body.String())
		}
		if len(stub.commands) != 0 {
			t.Fatal("policy denial must not reach the guest")
		}
	})
	t.Run("missing-elevation-policy", func(t *testing.T) {
		stub := &stubQGA{target: eligibleTarget()}
		stack := newStartStack(t, permissions, map[string]interface{}{"enabled": true, "allowElevated": false}, stub)
		if w := stack.post(body, "operator-uid"); w.Code != http.StatusForbidden {
			t.Fatalf("expected forbidden, got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("missing-elevation-grant", func(t *testing.T) {
		stub := &stubQGA{target: eligibleTarget()}
		stack := newStartStack(t, []string{string(auth.PermissionExec)}, enabledElevatedPolicy(), stub)
		if w := stack.post(body, "operator-uid"); w.Code != http.StatusForbidden {
			t.Fatalf("expected forbidden, got %d %s", w.Code, w.Body.String())
		}
		if len(stub.commands) != 0 {
			t.Fatal("permission denial must not reach the guest")
		}
	})
	t.Run("missing-exec-grant", func(t *testing.T) {
		stub := &stubQGA{target: eligibleTarget()}
		stack := newStartStack(t, []string{string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
		if w := stack.post(body, "operator-uid"); w.Code != http.StatusForbidden {
			t.Fatalf("expected forbidden, got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("ineligible-workspace", func(t *testing.T) {
		stub := &stubQGA{resolveErr: qga.ErrDenied}
		stack := newStartStack(t, permissions, enabledElevatedPolicy(), stub)
		if w := stack.post(body, "operator-uid"); w.Code != http.StatusNotFound {
			t.Fatalf("expected not found, got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("workspace-unavailable", func(t *testing.T) {
		stub := &stubQGA{resolveErr: qga.ErrUnavailable}
		stack := newStartStack(t, permissions, enabledElevatedPolicy(), stub)
		if w := stack.post(body, "operator-uid"); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected unavailable, got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("transport-not-installed", func(t *testing.T) {
		// WithQGA(nil) leaves the transport absent.
		stack := newStartStack(t, permissions, enabledElevatedPolicy(), nil)
		if w := stack.post(body, "operator-uid"); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected unavailable, got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("invalid-payloads", func(t *testing.T) {
		stub := &stubQGA{target: eligibleTarget()}
		stack := newStartStack(t, permissions, enabledElevatedPolicy(), stub)
		tooManyArgs := make([]string, qga.MaxArgs+1)
		for i := range tooManyArgs {
			tooManyArgs[i] = "a"
		}
		excessive, err := json.Marshal(map[string]interface{}{
			"namespace": "team", "workspace_name": "vm", "executable": "whoami", "args": tooManyArgs,
		})
		if err != nil {
			t.Fatal(err)
		}
		for name, payload := range map[string]string{
			"missing-executable": `{"namespace":"team","workspace_name":"vm","args":[]}`,
			"padded-executable":  `{"namespace":"team","workspace_name":"vm","executable":" whoami","args":[]}`,
			"excessive-args":     string(excessive),
			"control-arg":        `{"namespace":"team","workspace_name":"vm","executable":"whoami","args":["a\nb"]}`,
			"blank-cwd":          `{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[],"cwd":" "}`,
			"zero-deadline":      `{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[],"deadline_seconds":0}`,
			"excessive-deadline": `{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[],"deadline_seconds":21}`,
		} {
			t.Run(name, func(t *testing.T) {
				if w := stack.post(payload, "operator-uid"); w.Code != http.StatusBadRequest {
					t.Fatalf("expected invalid, got %d %s", w.Code, w.Body.String())
				}
			})
		}
		if len(stub.commands) != 0 {
			t.Fatal("invalid payloads must not reach the guest")
		}
	})
}
