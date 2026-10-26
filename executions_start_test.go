package kubeworkspaces

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	target       qga.Target
	result       *qga.GuestResult
	execErr      error
	resolveErr   error
	commands     []qga.Command
	resolved     [][2]string
	preflightErr error
	preflight    func(qga.Command) error
	// execute overrides the scripted reply so a test can observe or disturb
	// the context the start path hands to the transport.
	execute func(ctx context.Context, target qga.Target, command qga.Command) (*qga.GuestResult, error)
}

func (s *stubQGA) PreflightScript(_ context.Context, _ qga.Target, cmd qga.Command) error {
	if s.preflight != nil {
		return s.preflight(cmd)
	}
	return s.preflightErr
}

func (s *stubQGA) Resolve(_ context.Context, namespace, name string) (qga.Target, error) {
	s.resolved = append(s.resolved, [2]string{namespace, name})
	if s.resolveErr != nil {
		return qga.Target{}, s.resolveErr
	}
	return s.target, nil
}

func (s *stubQGA) Execute(ctx context.Context, target qga.Target, command qga.Command) (*qga.GuestResult, error) {
	s.commands = append(s.commands, command)
	if s.execute != nil {
		return s.execute(ctx, target, command)
	}
	return s.result, s.execErr
}

type startStack struct {
	stub  *stubQGA
	store storage.Store
	post  func(body string, credential string) *httptest.ResponseRecorder
	// postCtx runs one start request on a caller-owned context so a test can
	// disconnect mid-flight.
	postCtx func(ctx context.Context, body string) *httptest.ResponseRecorder
}

func newStartStack(t *testing.T, permissions []string, policy map[string]interface{}, stub *stubQGA, options ...ExecutionsOption) *startStack {
	return newScopedStartStack(t, "team", "vm", permissions, policy, stub, options...)
}

func newScopedStartStack(t *testing.T, namespace, workspace string, permissions []string, policy map[string]interface{}, stub *stubQGA, options ...ExecutionsOption) *startStack {
	t.Helper()
	ctx := context.Background()
	key := "start-test-signing-key-32-bytes"
	permissionValues := make([]interface{}, len(permissions))
	for i, permission := range permissions {
		permissionValues[i] = permission
	}
	grants := []interface{}{map[string]interface{}{
		"namespace": namespace, "workspaces": []interface{}{workspace},
		"permissions": permissionValues,
	}}
	user := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "User",
		"metadata": map[string]interface{}{"name": "operator", "uid": "operator-uid"},
		"spec": map[string]interface{}{
			"email": "operator@example.com", "role": "viewer",
			"namespaceAccess": []interface{}{map[string]interface{}{"namespace": namespace, "role": "viewer"}},
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
	passwordSecret, provenance := methodCredentialFixture(user)
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{users: "UserList"}, user, cfg, secret, platformConfig, passwordSecret)
	provider := auth.NewConfigProvider(client)
	store, err := storage.Open(ctx, storage.Options{Mode: "ephemeral", EphemeralDir: t.TempDir(), EphemeralMaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	var svcOptions []ExecutionsOption
	if stub != nil {
		svcOptions = append(svcOptions, WithQGA(stub))
	}
	svcOptions = append(svcOptions, options...)
	svc := NewExecutions(execution.NewService(store), platform.NewConfigProvider(client), svcOptions...)
	mux := goahttp.NewMuxer()
	server := svr.New(gen.NewEndpoints(svc), mux, goahttp.RequestDecoder, goahttp.ResponseEncoder, nil, nil)
	svr.Mount(mux, server)
	handler := auth.Middleware(provider)(mux)
	token, err := auth.CreateSessionTokenWithProvenance("operator@example.com", "Operator", "viewer", nil, []byte(key), time.Hour, "operator-uid", provenance)
	if err != nil {
		t.Fatal(err)
	}
	startOn := func(ctx context.Context, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/executions/start", strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	return &startStack{
		stub:    stub,
		store:   store,
		post:    func(body, _ string) *httptest.ResponseRecorder { return startOn(context.Background(), body) },
		postCtx: startOn,
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

func TestStartRejectsUnsupportedScriptsBeforeAdmission(t *testing.T) {
	stub := &stubQGA{target: eligibleTarget()}
	stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
	w := stack.post(`{"namespace":"team","workspace_name":"vm","script":{"body":"#!/bin/sh\nid\n"}}`, "operator-uid")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "not supported") {
		t.Fatalf("unsupported script must fail explicitly: %d %s", w.Code, w.Body.String())
	}
	if len(stub.resolved) != 1 || len(stub.commands) != 0 {
		t.Fatal("unsupported script reached the guest transport")
	}
	records, err := stack.store.Metadata().List(context.Background(), storage.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatal("unsupported script created an admitted execution/recording")
	}
}

func TestStartScriptAdmissionAndProtectedRecording(t *testing.T) {
	target := eligibleTarget()
	target.Linux = true
	code := 0
	stub := &stubQGA{target: target, result: &qga.GuestResult{Outcome: "completed", ExitCode: &code, Stdout: []byte("script output\n")}}
	stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
	body := "#!/bin/sh\nprintf 'script output\\n'\n"
	stub.preflight = func(cmd qga.Command) error {
		records, err := stack.store.Metadata().List(context.Background(), storage.Filter{})
		if err != nil || len(records) != 0 {
			t.Fatal("preflight must precede admission")
		}
		if cmd.Script == nil || cmd.Script.Body != body || cmd.Script.InterpreterPolicy != qga.LinuxScriptPolicy {
			t.Fatal("preflight lost script")
		}
		return nil
	}
	stub.execute = func(ctx context.Context, _ qga.Target, cmd qga.Command) (*qga.GuestResult, error) {
		rec, _, err := stack.store.Metadata().Get(ctx, cmd.ExecutionID)
		if err != nil || rec.Operation != storage.OperationScript || rec.OSIdentity != "root" {
			t.Fatalf("script metadata: %+v %v", rec, err)
		}
		metadata, _ := json.Marshal(rec)
		if strings.Contains(string(metadata), "printf") {
			t.Fatal("script leaked into metadata")
		}
		return stub.result, nil
	}
	payload, _ := json.Marshal(map[string]any{"namespace": "team", "workspace_name": "vm", "script": map[string]any{"body": body, "name": "run.sh", "cwd": "/tmp"}})
	w := stack.post(string(payload), "operator-uid")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"succeeded"`) || len(stub.commands) != 1 {
		t.Fatalf("script failed: %d %s", w.Code, w.Body.String())
	}
	reader, err := stack.store.Recording().Open(context.Background(), stub.commands[0].RecordingID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	chunk, err := reader.ReadChunk(context.Background(), 0)
	var recorded recordingStart
	if err != nil || json.Unmarshal(chunk, &recorded) != nil || recorded.Script == nil || recorded.Script.Body != body || recorded.Script.Name != "run.sh" || recorded.Cwd == nil || *recorded.Cwd != "/tmp" {
		t.Fatalf("script must be fully recorded: %s %v", chunk, err)
	}
}

func TestStartScriptPreflightFailuresDoNotAdmitOrExecute(t *testing.T) {
	for _, failure := range []error{qga.ErrUnsupportedScripts, qga.ErrRequestTooLarge, qga.ErrDenied, qga.ErrUnavailable} {
		t.Run(failure.Error(), func(t *testing.T) {
			target := eligibleTarget()
			target.Linux = true
			stub := &stubQGA{target: target, preflightErr: failure}
			stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
			w := stack.post(`{"namespace":"team","workspace_name":"vm","script":{"body":"#!/bin/sh\nid\n"}}`, "operator-uid")
			want := http.StatusBadRequest
			if errors.Is(failure, qga.ErrUnavailable) {
				want = http.StatusServiceUnavailable
			}
			if w.Code != want || len(stub.commands) != 0 {
				t.Fatalf("unexpected dispatch: %d %s", w.Code, w.Body.String())
			}
			records, err := stack.store.Metadata().List(context.Background(), storage.Filter{})
			if err != nil || len(records) != 0 {
				t.Fatal("failed preflight admitted metadata")
			}
		})
	}
}

type unavailableExecutionStore struct{ storage.Store }

func (unavailableExecutionStore) Ready(context.Context) error { return storage.ErrNotReady }

func TestStartScriptCannotExecuteWithUnavailableRecordingStorage(t *testing.T) {
	target := eligibleTarget()
	target.Linux = true
	stub := &stubQGA{target: target}
	stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub,
		func(s *executionssrvc) { s.execSvc = execution.NewService(unavailableExecutionStore{}) })
	w := stack.post(`{"namespace":"team","workspace_name":"vm","script":{"body":"#!/bin/sh\nid\n"}}`, "operator-uid")
	if w.Code != http.StatusServiceUnavailable || len(stub.commands) != 0 {
		t.Fatalf("script ran without recording storage: %d %s", w.Code, w.Body.String())
	}
}

func TestStartScriptValidationAndAuthorization(t *testing.T) {
	for name, test := range map[string]struct {
		body     string
		elevated bool
		status   int
	}{
		"conflicting-cwd":     {`"cwd":"/tmp","script":{"body":"#!/bin/sh\nid\n","cwd":"/"}`, true, 400},
		"invalid-nested-cwd":  {`"script":{"body":"#!/bin/sh\nid\n","cwd":" "}`, true, 400},
		"conflicting-command": {`"executable":"id","script":{"body":"#!/bin/sh\nid\n"}`, true, 400},
		"unsupported-shebang": {`"script":{"body":"#!/usr/bin/env sh\nid\n"}`, true, 400},
		"invalid-name":        {`"script":{"body":"#!/bin/sh\nid\n","name":".."}`, true, 400},
		"no-elevation":        {`"script":{"body":"#!/bin/sh\nid\n"}`, false, 403},
	} {
		t.Run(name, func(t *testing.T) {
			target := eligibleTarget()
			target.Linux = true
			stub := &stubQGA{target: target}
			permissions := []string{string(auth.PermissionExec)}
			if test.elevated {
				permissions = append(permissions, string(auth.PermissionElevated))
			}
			stack := newStartStack(t, permissions, enabledElevatedPolicy(), stub)
			w := stack.post(`{"namespace":"team","workspace_name":"vm",`+test.body+`}`, "operator-uid")
			if w.Code != test.status || len(stub.resolved) != 0 || len(stub.commands) != 0 {
				t.Fatalf("invalid script reached target: %d %s", w.Code, w.Body.String())
			}
		})
	}
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
		result          *qga.GuestResult
		execErr         error
		wantOutcome     string
		wantState       string
		wantDenial      string
		wantTermination string
		wantExitCode    *int
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
			execErr: errors.New("pod exec failed"), wantOutcome: "unknown", wantState: "unknown",
			wantDenial: "transport lost; do not rerun", wantTermination: "transport lost; do not rerun",
		},
		"revoked-before-dispatch": {
			execErr: qga.ErrDenied, wantOutcome: "failed", wantState: "revoked",
			wantDenial: "execution authority changed before dispatch", wantTermination: "execution authority changed before dispatch",
		},
		"unavailable-before-dispatch": {
			execErr: qga.ErrUnavailable, wantOutcome: "failed", wantState: "failed",
			wantDenial: "workspace unavailable before dispatch; the command did not run", wantTermination: "not-dispatched",
		},
		"runner-absence": {
			execErr:     fmt.Errorf("%w: guest-exec: GenericError: The system cannot find the file specified", qga.ErrNotStarted),
			wantOutcome: "failed", wantState: "failed",
			wantDenial:      "runner could not be started: guest-exec: GenericError: The system cannot find the file specified",
			wantTermination: "runner-error",
		},
		"request-too-large": {
			execErr: qga.ErrRequestTooLarge, wantOutcome: "failed", wantState: "failed",
			wantDenial: "QGA pilot request is too large", wantTermination: "request-too-large",
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
			if script.wantTermination != "" && outcome.Termination != script.wantTermination {
				t.Fatalf("stored termination drifted: %+v", outcome)
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

// A caller that disconnects after dispatch must not fabricate a transport-loss
// unknown or a recording gap: the bounded command keeps running and the stored
// record still reflects the guest.
func TestStartSurvivesCallerDisconnection(t *testing.T) {
	code := 0
	caller, cancelCaller := context.WithCancel(context.Background())
	var runCtxErr error
	stub := &stubQGA{target: eligibleTarget()}
	stub.execute = func(runCtx context.Context, _ qga.Target, _ qga.Command) (*qga.GuestResult, error) {
		// The client's socket goes away while the guest command is running.
		cancelCaller()
		runCtxErr = runCtx.Err()
		return &qga.GuestResult{Outcome: "completed", ExitCode: &code, Stdout: []byte("hello\n"), DurationMS: 7}, nil
	}
	stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
	w := stack.postCtx(caller, `{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("start failed: %d %s", w.Code, w.Body.String())
	}
	if runCtxErr != nil {
		t.Fatalf("the guest run followed the caller's socket: %v", runCtxErr)
	}
	var response struct {
		ExecutionID string  `json:"execution_id"`
		RecordingID string  `json:"recording_id"`
		Outcome     string  `json:"outcome"`
		State       string  `json:"state"`
		Stdout      string  `json:"stdout"`
		DurationMs  *uint64 `json:"duration_ms"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Outcome != "succeeded" || response.State != "succeeded" {
		t.Fatalf("unexpected outcome: %s", w.Body.String())
	}
	_, outcome, err := stack.store.Metadata().Get(context.Background(), response.ExecutionID)
	if err != nil || outcome.State != storage.StateSucceeded {
		t.Fatalf("stored record lost the outcome: %+v %v", outcome, err)
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
		t.Fatalf("caller disconnection left a recording gap: %d chunks", reader.Manifest().Chunks)
	}
}

// The server lifecycle still fences a dispatched run: shutdown must not leave
// a guest command unbounded just because the caller is gone.
func TestStartLifecycleCancellationFencesGuestRun(t *testing.T) {
	lifecycle, stopLifecycle := context.WithCancel(context.Background())
	stub := &stubQGA{target: eligibleTarget()}
	stub.execute = func(runCtx context.Context, _ qga.Target, _ qga.Command) (*qga.GuestResult, error) {
		stopLifecycle()
		select {
		case <-runCtx.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("lifecycle cancellation did not fence the guest run")
		}
		return nil, fmt.Errorf("%w: %v", qga.ErrTransport, runCtx.Err())
	}
	stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub, WithLifecycleContext(lifecycle))
	w := stack.post(`{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[]}`, "operator-uid")
	if w.Code != http.StatusOK {
		t.Fatalf("start failed: %d %s", w.Code, w.Body.String())
	}
	var response struct {
		ExecutionID string  `json:"execution_id"`
		Outcome     string  `json:"outcome"`
		State       string  `json:"state"`
		Denial      *string `json:"denial"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Outcome != "unknown" || response.State != "unknown" ||
		response.Denial == nil || *response.Denial != "transport lost; do not rerun" {
		t.Fatalf("unexpected outcome: %s", w.Body.String())
	}
	_, outcome, err := stack.store.Metadata().Get(context.Background(), response.ExecutionID)
	if err != nil || outcome.State != storage.StateUnknown {
		t.Fatalf("stored record lost the unknown outcome: %+v %v", outcome, err)
	}
}
