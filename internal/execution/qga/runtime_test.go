package qga

import (
	"bytes"
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/grants"
)

type stubResolver struct {
	target  Target
	err     error
	called  [2]string
	invoked bool
}

func (s *stubResolver) Resolve(_ context.Context, namespace, name string) (Target, error) {
	s.called = [2]string{namespace, name}
	s.invoked = true
	return s.target, s.err
}

func testRuntime(t *testing.T, fake *fakeExec) (*Runtime, *stubResolver, *grants.Signer) {
	t.Helper()
	signer, err := grants.NewSigner(ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	resolver := &stubResolver{target: testTarget()}
	runtime, err := NewRuntimeWithExec(signer, resolver, fake.run)
	if err != nil {
		t.Fatal(err)
	}
	runtime.now = func() time.Time { return time.Unix(2_000_000_000, 0) }
	return runtime, resolver, signer
}

// capturedFile rebuilds one staged file from the recorded write chunks.
func (f *fakeExec) capturedFile(path string) []byte {
	var content []byte
	for _, call := range f.calls {
		var request struct {
			Execute   string          `json:"execute"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(call.stdin, &request)
		if request.Execute != "guest-file-write" {
			continue
		}
		var args struct {
			Handle  int64  `json:"handle"`
			DataB64 string `json:"buf-b64"`
		}
		_ = json.Unmarshal(request.Arguments, &args)
		if f.handles[args.Handle] != path {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(args.DataB64)
		if err != nil {
			return nil
		}
		content = append(content, data...)
	}
	return content
}

func TestExecuteIssuesVerifiableGrantOverQGA(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	runtime, resolver, signer := testRuntime(t, fake)
	resolver.target.RevocationEpoch = 7
	// The start endpoint resolves before executing; mirror that sequence.
	target, err := runtime.Resolve(context.Background(), "team", "vm")
	if err != nil {
		t.Fatal(err)
	}
	if !resolver.invoked || resolver.called != [2]string{"team", "vm"} {
		t.Fatalf("resolver was not consulted: %+v", resolver.called)
	}
	cwd := `C:\Temp`
	result, err := runtime.Execute(context.Background(), target, Command{
		ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1",
		Executable: `C:\Windows\System32\cmd.exe`, Args: []string{"/c", "echo hi"},
		Cwd: &cwd, DeadlineSeconds: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "completed" || string(result.Stdout) != "hello\n" {
		t.Fatalf("unexpected result: %+v", result)
	}
	keys := fake.capturedFile(keysFilePath)
	expectedKeys, err := publicKeyFileJSON(signer.PublicKey())
	if err != nil || string(keys) != string(expectedKeys) {
		t.Fatalf("staged keys file drifted:\ngot  %s\nwant %s (%v)", keys, expectedKeys, err)
	}
	envelope := fake.capturedFile(dataDirPath + `\qga-request-exec_1.json`)
	var framed struct {
		Grant   string          `json:"grant"`
		Request json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(envelope, &framed); err != nil || framed.Grant == "" || len(framed.Request) == 0 {
		t.Fatalf("staged envelope is malformed: %v", err)
	}
	var request qgaRequest
	if err := json.Unmarshal(framed.Request, &request); err != nil {
		t.Fatal(err)
	}
	// The guest relies on the exact field framing pinned by the Rust contract.
	raw := string(framed.Request)
	order := []string{`"version":`, `"challenge":`, `"transport_target_sha256":`, `"actor_uid":`, `"namespace":`, `"workspace_name":`, `"workspace_uid":`, `"provisioning_generation":`, `"execution_id":`, `"recording_id":`, `"operation":`, `"os_identity":`, `"elevated":`, `"policy_version":`, `"revocation_epoch":`, `"executable":`, `"args":`, `"cwd":`, `"deadline_seconds":`}
	previous := -1
	for _, field := range order {
		index := strings.Index(raw, field)
		if index < 0 || index <= previous {
			t.Fatalf("request field order drifted at %s:\n%s", field, raw)
		}
		previous = index
	}
	if !strings.Contains(raw, `"cwd":"C:\\Temp"`) || request.Cwd == nil || *request.Cwd != cwd {
		t.Fatalf("an explicit cwd must round-trip: %s", raw)
	}
	if request.Version != 1 || request.Operation != "command" || request.OSIdentity != "SYSTEM" || !request.Elevated ||
		request.PolicyVersion != policyVersion || request.DeadlineSeconds != 20 || request.ActorUID != "user-1" ||
		request.Namespace != "team" || request.WorkspaceName != "vm" || request.WorkspaceUID != "workspace-uid" ||
		request.ProvisioningGeneration != "vm-uid" || request.ExecutionID != "exec_1" || request.RecordingID != "rec_1" ||
		request.Executable != `C:\Windows\System32\cmd.exe` || len(request.Args) != 2 || request.RevocationEpoch != 7 {
		t.Fatalf("unexpected request: %+v", request)
	}
	// Reproduce the guest's expected binding from the digest-authenticated
	// request alone and consume the grant exactly once.
	expected := grants.BindingQGA{
		ActorUID:               request.ActorUID,
		Namespace:              request.Namespace,
		WorkspaceName:          request.WorkspaceName,
		WorkspaceUID:           request.WorkspaceUID,
		ProvisioningGeneration: request.ProvisioningGeneration,
		ExecutionID:            request.ExecutionID,
		RecordingID:            request.RecordingID,
		Operation:              request.Operation,
		OSIdentity:             request.OSIdentity,
		Elevated:               request.Elevated,
		PolicyVersion:          request.PolicyVersion,
		RevocationEpoch:        request.RevocationEpoch,
		Challenge:              request.Challenge,
		Transport:              grants.TransportQGAPodExec,
		TransportTargetSHA256:  request.TransportTargetSHA256,
		RequestSHA256:          grants.Digest(framed.Request),
	}
	if expected.TransportTargetSHA256 != grants.Digest([]byte("team/vm-uid/"+testPodUID)) {
		t.Fatalf("transport target digest is wrong: %s", expected.TransportTargetSHA256)
	}
	public := signer.PublicKey()
	verifier, err := grants.NewVerifier(map[string]ed25519.PublicKey{grants.KeyID(public): public}, 4)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	claims, err := verifier.ConsumeQGA(framed.Grant, expected, now)
	if err != nil {
		t.Fatalf("grant was not verifiable: %v", err)
	}
	if claims.Binding.ExecutionID != "exec_1" || claims.ExpiresAt-claims.IssuedAt != 60 {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if _, err := verifier.ConsumeQGA(framed.Grant, expected, now); !errors.Is(err, grants.ErrReplay) {
		t.Fatalf("expected single-use enforcement, got %v", err)
	}
}

func TestExecuteRejectsConflictingScriptFramingBeforeResolvingOrStaging(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	runtime, resolver, _ := testRuntime(t, fake)
	result, err := runtime.Execute(context.Background(), testTarget(), Command{
		ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1",
		Executable: "ignored", Args: []string{}, DeadlineSeconds: 20,
		Script: &Script{Body: "#!/bin/sh\nid\n"},
	})
	if !errors.Is(err, ErrDenied) || result != nil {
		t.Fatalf("unsupported script must be denied deterministically: result=%+v err=%v", result, err)
	}
	if resolver.invoked || len(fake.calls) != 0 {
		t.Fatal("unsupported script resolved a guest or staged bytes")
	}
}

func TestScriptPreflightAndSignedV2Dispatch(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	fake.capabilities = []byte(`{"version":1,"script_request_version":2,"interpreter_policy":"linux-shebang-v1"}`)
	runtime, resolver, signer := testRuntime(t, fake)
	resolver.target.Linux = true
	cwd := "/tmp"
	command := Command{ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", DeadlineSeconds: 20, Cwd: &cwd,
		Script: &Script{Body: "#!/bin/sh\nprintf 'hello\\n'\n", Name: "run.sh", InterpreterPolicy: LinuxScriptPolicy}}
	if err := runtime.PreflightScript(context.Background(), resolver.target, command); err != nil {
		t.Fatal(err)
	}
	if len(fake.files) != 0 {
		t.Fatal("preflight staged guest content")
	}
	result, err := runtime.Execute(context.Background(), resolver.target, command)
	if err != nil || result.Outcome != "completed" {
		t.Fatalf("script failed: %+v %v", result, err)
	}
	var envelope struct {
		Grant   string          `json:"grant"`
		Request json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(fake.capturedFile("/var/lib/workspace-agent/qga-request-exec_1.json"), &envelope); err != nil {
		t.Fatal(err)
	}
	var request qgaRequest
	if err := json.Unmarshal(envelope.Request, &request); err != nil {
		t.Fatal(err)
	}
	if request.Version != 2 || request.Operation != "script" || request.Script == nil || *request.Script != *command.Script || request.Executable != "" || len(request.Args) != 0 || request.OSIdentity != "root" {
		t.Fatalf("script framing drift: %+v", request)
	}
	binding := grants.BindingQGA{ActorUID: request.ActorUID, Namespace: request.Namespace, WorkspaceName: request.WorkspaceName,
		WorkspaceUID: request.WorkspaceUID, ProvisioningGeneration: request.ProvisioningGeneration, ExecutionID: request.ExecutionID,
		RecordingID: request.RecordingID, Operation: request.Operation, OSIdentity: request.OSIdentity, Elevated: true, PolicyVersion: request.PolicyVersion,
		RevocationEpoch: request.RevocationEpoch, Challenge: request.Challenge, Transport: grants.TransportQGAPodExec,
		TransportTargetSHA256: request.TransportTargetSHA256, RequestSHA256: grants.Digest(envelope.Request)}
	public := signer.PublicKey()
	verifier, _ := grants.NewVerifier(map[string]ed25519.PublicKey{grants.KeyID(public): public}, 4)
	if _, err := verifier.ConsumeQGA(envelope.Grant, binding, runtime.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.ConsumeQGA(envelope.Grant, binding, runtime.now()); !errors.Is(err, grants.ErrReplay) {
		t.Fatal("script replay accepted")
	}
	for _, mutate := range []func(*qgaRequest){
		func(r *qgaRequest) { r.Script.Body += "id\n" }, func(r *qgaRequest) { r.Script.Name = "other.sh" },
		func(r *qgaRequest) { r.Cwd = nil }, func(r *qgaRequest) { r.Script.InterpreterPolicy = "other" },
	} {
		var changed qgaRequest
		_ = json.Unmarshal(envelope.Request, &changed)
		mutate(&changed)
		raw, _ := json.Marshal(changed)
		changedBinding := binding
		changedBinding.RequestSHA256 = grants.Digest(raw)
		v, _ := grants.NewVerifier(map[string]ed25519.PublicKey{grants.KeyID(public): public}, 4)
		if _, err := v.ConsumeQGA(envelope.Grant, changedBinding, runtime.now()); !errors.Is(err, grants.ErrBinding) {
			t.Fatalf("tampered script accepted: %v", err)
		}
	}
}

func TestScriptPreflightRejectsEscapedEnvelopeBeforeGuestProbe(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	runtime, resolver, _ := testRuntime(t, fake)
	resolver.target.Linux = true
	cmd := Command{ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", DeadlineSeconds: 20,
		Script: &Script{Body: "#!/bin/sh\n" + strings.Repeat("\t", MaxScriptBytes-10), InterpreterPolicy: LinuxScriptPolicy}}
	if err := runtime.PreflightScript(context.Background(), resolver.target, cmd); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatal(err)
	}
	if len(fake.calls) != 0 {
		t.Fatal("oversized script reached guest")
	}
}

func TestScriptPreflightDeniesMissingOrIncompatibleGuestCapabilities(t *testing.T) {
	for _, caps := range []string{"", `{"version":1,"script_request_version":0,"interpreter_policy":""}`, `{"version":1,"script_request_version":2,"interpreter_policy":"linux-shebang-v1"} {}`} {
		fake := newFakeExec(successRunnerResult())
		fake.capabilities = []byte(caps)
		runtime, resolver, _ := testRuntime(t, fake)
		resolver.target.Linux = true
		cmd := Command{ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", DeadlineSeconds: 20,
			Script: &Script{Body: "#!/bin/sh\nid\n", InterpreterPolicy: LinuxScriptPolicy}}
		if err := runtime.PreflightScript(context.Background(), resolver.target, cmd); !errors.Is(err, ErrUnsupportedScripts) {
			t.Fatal(err)
		}
		if len(fake.files) != 0 {
			t.Fatal("unsupported guest received script content")
		}
	}
}

//go:embed testdata/linux-script-v2.json
var scriptInteropFixture []byte

func TestScriptInteropFixture(t *testing.T) {
	runtime, resolver, signer := testRuntime(t, newFakeExec(nil))
	resolver.target.Linux = true
	request := runtime.request(resolver.target, Command{ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", DeadlineSeconds: 20,
		Script: &Script{Body: "#!/bin/sh\nprintf 'hello\\n'\n", Name: "run.sh", InterpreterPolicy: LinuxScriptPolicy}}, strings.Repeat("A", 43))
	raw, _ := json.Marshal(request)
	binding := grants.BindingQGA{ActorUID: request.ActorUID, Namespace: request.Namespace, WorkspaceName: request.WorkspaceName,
		WorkspaceUID: request.WorkspaceUID, ProvisioningGeneration: request.ProvisioningGeneration, ExecutionID: request.ExecutionID,
		RecordingID: request.RecordingID, Operation: request.Operation, OSIdentity: request.OSIdentity, Elevated: true, PolicyVersion: request.PolicyVersion,
		RevocationEpoch: request.RevocationEpoch, Challenge: request.Challenge, Transport: grants.TransportQGAPodExec,
		TransportTargetSHA256: request.TransportTargetSHA256, RequestSHA256: grants.Digest(raw)}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "kw-management-grant+qga", "kid": grants.KeyID(signer.PublicKey())})
	claims, _ := json.Marshal(grants.ClaimsQGA{Version: 1, Issuer: grants.QGAIssuer, Audience: grants.QGAAudience, ID: request.Challenge, IssuedAt: 1800000000, ExpiresAt: 1800000030, Binding: binding})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(make([]byte, 32)), []byte(input)))
	fixture, _ := json.Marshal(map[string]any{"request": json.RawMessage(raw), "token": token, "public_key": base64.RawURLEncoding.EncodeToString(signer.PublicKey()), "now": 1800000000})
	if !bytes.Equal(bytes.TrimSpace(scriptInteropFixture), fixture) {
		t.Fatal("Go-issued Linux script fixture drift")
	}
}

func TestExecuteFencesRevocationSinceAdmissionBeforeGuestStaging(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	runtime, resolver, _ := testRuntime(t, fake)
	target := resolver.target
	resolver.target.RevocationEpoch++
	_, err := runtime.Execute(context.Background(), target, Command{ActorUID: "user", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "cmd.exe", DeadlineSeconds: 1})
	if !errors.Is(err, ErrDenied) || len(fake.calls) != 0 {
		t.Fatalf("stale admission reached guest: err=%v calls=%d", err, len(fake.calls))
	}
}

func TestExecuteSerializesNilCwdAsNullAndEmptyArgs(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	runtime, _, _ := testRuntime(t, fake)
	if _, err := runtime.Execute(context.Background(), testTarget(), Command{
		ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1",
		Executable: "whoami", Args: nil, Cwd: nil, DeadlineSeconds: 1,
	}); err != nil {
		t.Fatal(err)
	}
	raw := string(fake.capturedFile(dataDirPath + `\qga-request-exec_1.json`))
	if !strings.Contains(raw, `"cwd":null`) || !strings.Contains(raw, `"args":[]`) {
		t.Fatalf("nil cwd/args framing drifted: %s", raw)
	}
}

func TestExecuteRejectsUnstageableCommands(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	runtime, _, _ := testRuntime(t, fake)
	huge := strings.Repeat("a", MaxArgBytes+1)
	cwd := " x"
	for name, command := range map[string]Command{
		"missing-actor":       {ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami", DeadlineSeconds: 20},
		"missing-execution":   {ActorUID: "user-1", RecordingID: "rec_1", Executable: "whoami", DeadlineSeconds: 20},
		"hostile-execution":   {ActorUID: "user-1", ExecutionID: "../up", RecordingID: "rec_1", Executable: "whoami", DeadlineSeconds: 20},
		"missing-recording":   {ActorUID: "user-1", ExecutionID: "exec_1", Executable: "whoami", DeadlineSeconds: 20},
		"empty-executable":    {ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", DeadlineSeconds: 20},
		"padded-executable":   {ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: " whoami", DeadlineSeconds: 20},
		"executable-controls": {ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "who\x00ami", DeadlineSeconds: 20},
		"too-many-args":       {ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami", Args: make([]string, MaxArgs+1), DeadlineSeconds: 20},
		"oversized-arg":       {ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami", Args: []string{huge}, DeadlineSeconds: 20},
		"arg-controls":        {ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami", Args: []string{"a\nb"}, DeadlineSeconds: 20},
		"blank-cwd":           {ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami", Cwd: &cwd, DeadlineSeconds: 20},
		"zero-deadline":       {ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami"},
		"excessive-deadline":  {ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami", DeadlineSeconds: MaxDeadlineSeconds + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runtime.Execute(context.Background(), testTarget(), command); !errors.Is(err, ErrTransport) {
				t.Fatalf("expected ErrTransport, got %v", err)
			}
		})
	}
	if len(fake.calls) != 0 {
		t.Fatal("rejected commands must not reach the guest")
	}
}

func TestExecuteRejectsOversizedFraming(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	runtime, _, _ := testRuntime(t, fake)
	args := make([]string, MaxArgs)
	for i := range args {
		args[i] = strings.Repeat("a", MaxArgBytes)
	}
	if _, err := runtime.Execute(context.Background(), testTarget(), Command{
		ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1",
		Executable: "whoami", Args: args, DeadlineSeconds: 20,
	}); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("expected ErrRequestTooLarge, got %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatal("oversized requests must not reach the guest")
	}
}

func TestResolveDelegatesAndPropagatesFailures(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	runtime, resolver, _ := testRuntime(t, fake)
	target, err := runtime.Resolve(context.Background(), "team", "vm")
	if err != nil || target != testTarget() {
		t.Fatalf("unexpected resolved target: %+v, %v", target, err)
	}
	if !resolver.invoked || resolver.called != [2]string{"team", "vm"} {
		t.Fatalf("resolver was not consulted: %+v", resolver.called)
	}
	for name, resolverErr := range map[string]error{"denied": ErrDenied, "unavailable": ErrUnavailable} {
		t.Run(name, func(t *testing.T) {
			runtime.resolver = &stubResolver{err: resolverErr}
			if _, err := runtime.Resolve(context.Background(), "team", "vm"); !errors.Is(err, resolverErr) {
				t.Fatalf("expected %v, got %v", resolverErr, err)
			}
		})
	}
}

// A guest refusal to spawn the installed runner is deterministic: nothing ran,
// so it is reported as ErrNotStarted rather than an unknown transport loss.
func TestExecuteReportsRunnerAbsenceWithoutResult(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	fake.failExecute = "guest-exec"
	runtime, _, _ := testRuntime(t, fake)
	result, err := runtime.Execute(context.Background(), testTarget(), Command{
		ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami", DeadlineSeconds: 20,
	})
	if !errors.Is(err, ErrNotStarted) || errors.Is(err, ErrTransport) || result != nil {
		t.Fatalf("expected a nil not-started outcome, got %+v, %v", result, err)
	}
}

// A lost pod-exec transport with no runner result stays an unknown outcome.
func TestExecuteReturnsNothingWithoutRunnerResult(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	fake.podExecErr = errors.New("connection refused")
	runtime, _, _ := testRuntime(t, fake)
	result, err := runtime.Execute(context.Background(), testTarget(), Command{
		ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami", DeadlineSeconds: 20,
	})
	if !errors.Is(err, ErrTransport) || result != nil {
		t.Fatalf("expected a nil unknown outcome, got %+v, %v", result, err)
	}
}

func TestNewRuntimeRequiresExplicitEnablement(t *testing.T) {
	if _, err := NewRuntime(Config{}, nil, nil, nil, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
	if _, err := NewRuntimeWithExec(nil, &stubResolver{}, newFakeExec(nil).run); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
}
