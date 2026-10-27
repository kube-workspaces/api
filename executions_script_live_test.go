package kubeworkspaces

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/grants"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/platform"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Explicitly opt-in installed-guest proof for either OS. This stages a fresh
// management verification key, so use only a disposable proof workspace. HTTP
// authentication/account fixtures and encrypted ephemeral recording are local;
// policy, target resolution, Kubernetes/QGA, signed dispatch and guest execution
// are real. These variables intentionally differ from the command-only harness.
func TestScriptExecutionLive(t *testing.T) {
	ns, name := os.Getenv("KW_EXECUTION_SCRIPT_LIVE_NAMESPACE"), os.Getenv("KW_EXECUTION_SCRIPT_LIVE_WORKSPACE")
	if ns == "" || name == "" {
		t.Skip("set KW_EXECUTION_SCRIPT_LIVE_NAMESPACE and KW_EXECUTION_SCRIPT_LIVE_WORKSPACE for a disposable VM")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := qga.NewResolver(dyn, platform.NewConfigProvider(dyn))
	if err != nil {
		t.Fatal(err)
	}
	target, err := resolver.Resolve(ctx, ns, name)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := grants.NewSigner(private)
	if err != nil {
		t.Fatal(err)
	}
	exec, err := qga.KubernetesExecFunc(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := qga.NewRuntimeWithExec(signer, scriptProofResolver{TargetResolver: resolver, expected: target}, exec)
	if err != nil {
		t.Fatal(err)
	}
	stack := newScopedStartStack(t, ns, name, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), nil, WithQGA(runner), WithLifecycleContext(ctx))
	response := stack.getCtx(ctx, "/v1/executions/capabilities?"+url.Values{"namespace": {ns}, "workspace_name": {name}}.Encode(), true)
	var caps struct {
		Supported    bool   `json:"script_supported"`
		Version      int    `json:"script_request_version"`
		Policy       string `json:"interpreter_policy"`
		WorkspaceUID string `json:"workspace_uid"`
		Identity     string `json:"os_identity"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &caps) != nil || !caps.Supported || caps.Version != 2 || caps.Policy != qga.ScriptPolicy(target) || caps.WorkspaceUID != target.WorkspaceUID || caps.Identity != target.OSIdentity() {
		t.Fatalf("guest does not advertise the required bound script contract: HTTP %d %s", response.Code, response.Body.String())
	}
	if records, err := stack.store.Metadata().List(ctx, storage.Filter{}); err != nil || len(records) != 0 {
		t.Fatal("capability discovery admitted an execution")
	}

	cwd, hint, marker := "/tmp", "proof.sh", "#!/bin/sh\n"
	identity, identityOut := "id -u | tr -d '\\n'", "0"
	streams := "printf '%s' \"$PWD\"; printf err >&2; exit 7"
	unicode := "printf 'héllo ✓'"
	child := "sleep 60 & child=$!; printf 'child=%s\\n' \"$child\"; "
	sleep, flood := "wait", "while :; do printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done"
	if !target.Linux {
		cwd, hint, marker = `C:\Windows\Temp`, "proof.ps1", "#!powershell\n"
		identity, identityOut = "[Console]::Out.Write([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)", "S-1-5-18"
		streams = "[Console]::Out.Write((Get-Location).Path); [Console]::Error.Write('err'); exit 7"
		unicode = "[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); [Console]::Out.Write('héllo ✓')"
		child = `$child = Start-Process -FilePath "$env:SystemRoot\System32\ping.exe" -ArgumentList @('-n','60','127.0.0.1') -NoNewWindow -PassThru; [Console]::Out.WriteLine("child=$($child.Id)"); `
		sleep, flood = "Start-Sleep -Seconds 60", "[Console]::Out.Write(('x' * 65536)); Start-Sleep -Seconds 60"
	}
	for _, tc := range []struct {
		name, source, state, out, errOut string
		exit                             *int
		truncated, child                 bool
	}{
		{name: "identity", source: identity, state: "succeeded", out: identityOut, exit: intPtr(0)},
		{name: "cwd-streams-nonzero", source: streams, state: "failed", out: cwd, errOut: "err", exit: intPtr(7)},
		{name: "explicit-utf8-stream", source: unicode, state: "succeeded", out: "héllo ✓", exit: intPtr(0)},
		{name: "root-exit-tree", source: child + "exit 0", state: "succeeded", exit: intPtr(0), child: true},
		{name: "deadline-tree", source: child + sleep, state: "timed_out", child: true},
		{name: "output-limit-tree", source: child + flood, state: "failed", truncated: true, child: true},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			result := runInstalledScript(t, ctx, stack, target, marker+tc.source+"\n", hint, cwd)
			if result.State != tc.state || result.Truncated != tc.truncated || (tc.exit != nil && (result.ExitCode == nil || *result.ExitCode != *tc.exit)) {
				t.Fatalf("unexpected script outcome: %+v", result)
			}
			out, errOut := decodedScriptStreams(t, result)
			matches := out == tc.out
			if tc.name == "cwd-streams-nonzero" && !target.Linux {
				matches = strings.EqualFold(out, tc.out)
			}
			if !tc.child && (!matches || errOut != tc.errOut) {
				t.Fatalf("unexpected streams: %q %q", out, errOut)
			}
			if tc.child {
				match := regexp.MustCompile(`(?m)^child=([0-9]+)\r?$`).FindStringSubmatch(out)
				if len(match) != 2 {
					t.Fatal("child PID was not captured before supervision terminated the script")
				}
				pid, err := strconv.ParseUint(match[1], 10, 32)
				if err != nil || pid == 0 {
					t.Fatal("invalid child PID")
				}
				probe := fmt.Sprintf("if kill -0 %d >/dev/null 2>&1; then exit 9; fi; printf gone", pid)
				if !target.Linux {
					probe = fmt.Sprintf("if (Get-Process -Id %d -ErrorAction SilentlyContinue) { exit 9 }; [Console]::Out.Write('gone')", pid)
				}
				// This is a new, independently recorded read-only liveness check,
				// never a retry of the command whose result was just received.
				check := runInstalledScript(t, ctx, stack, target, marker+probe+"\n", hint, cwd)
				checkedOut, _ := decodedScriptStreams(t, check)
				if check.State != "succeeded" || check.ExitCode == nil || *check.ExitCode != 0 || checkedOut != "gone" {
					t.Fatal("script descendant remains alive")
				}
			}
		}) {
			t.Fatal("stopping installed proof after failure; no request was retried")
		}
	}
}

type installedScriptResult struct {
	ExecutionID string `json:"execution_id"`
	RecordingID string `json:"recording_id"`
	State       string `json:"state"`
	Outcome     string `json:"outcome"`
	ExitCode    *int   `json:"exit_code"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	Truncated   bool   `json:"truncated"`
	DurationMS  uint64 `json:"duration_ms"`
}

// Pin the whole proof to the originally selected guest/launcher/epoch. A reset,
// reboot or revocation stops the campaign before staging into a new incarnation.
type scriptProofResolver struct {
	qga.TargetResolver
	expected qga.Target
}

func (r scriptProofResolver) Resolve(ctx context.Context, namespace, name string) (qga.Target, error) {
	target, err := r.TargetResolver.Resolve(ctx, namespace, name)
	if err != nil {
		return qga.Target{}, err
	}
	if target != r.expected {
		return qga.Target{}, qga.ErrDenied
	}
	return target, nil
}

func runInstalledScript(t *testing.T, ctx context.Context, stack *startStack, target qga.Target, body, hint, cwd string) installedScriptResult {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"namespace": target.Namespace, "workspace_name": target.WorkspaceName, "deadline_seconds": 20, "script": map[string]any{"body": body, "name": hint, "cwd": cwd}})
	if err != nil {
		t.Fatal(err)
	}
	response := stack.postCtx(ctx, string(payload))
	if response.Code != 200 {
		t.Fatalf("script response HTTP %d; outcome may be uncertain, do not rerun: %s", response.Code, response.Body.String())
	}
	var result installedScriptResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.State == "unknown" || result.State == "recording_lost" || result.Outcome == "unknown" {
		t.Fatalf("script result uncertain; do not rerun: execution=%s recording=%s", result.ExecutionID, result.RecordingID)
	}
	rec, outcome, err := stack.store.Metadata().Get(ctx, result.ExecutionID)
	if err != nil || rec.Operation != storage.OperationScript || rec.OSIdentity != target.OSIdentity() || !rec.Elevated || rec.WorkspaceUID != target.WorkspaceUID || rec.RecordingID != result.RecordingID || string(outcome.State) != result.State || !scriptExitCodeEqual(outcome.ExitCode, result.ExitCode) {
		t.Fatalf("script admission/result mismatch: %+v %+v %v", rec, outcome, err)
	}
	reader, err := stack.store.Recording().Open(ctx, result.RecordingID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := reader.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if reader.Manifest().Chunks != 2 {
		t.Fatal("expected complete protected script input and result")
	}
	input, err := reader.ReadChunk(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	var recorded recordingStart
	if json.Unmarshal(input, &recorded) != nil || recorded.Script == nil || recorded.Script.Body != body || recorded.Script.Name != hint || recorded.Script.InterpreterPolicy != qga.ScriptPolicy(target) || recorded.Cwd == nil || *recorded.Cwd != cwd || recorded.ProvisioningGeneration != target.VMUID || recorded.RevocationEpoch != target.RevocationEpoch || recorded.DeadlineSeconds != 20 {
		t.Fatal("protected recording lost script input, policy, binding or bounds")
	}
	output, err := reader.ReadChunk(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	var final recordingResult
	if json.Unmarshal(output, &final) != nil || final.StdoutB64 != result.Stdout || final.StderrB64 != result.Stderr || final.Truncated != result.Truncated || final.DurationMS != result.DurationMS || !scriptExitCodeEqual(final.ExitCode, result.ExitCode) {
		t.Fatal("protected result recording does not match returned streams or exit status")
	}
	t.Logf("recorded %s script: state=%s execution=%s recording=%s", target.OSIdentity(), result.State, result.ExecutionID, result.RecordingID)
	return result
}

// Exercise the proof's HTTP decoding and protected-recording assertions without
// requiring a live guest. Only the guest transport is replaced here.
func TestInstalledScriptRecordingProofContract(t *testing.T) {
	for _, linux := range []bool{true, false} {
		target := qga.Target{Namespace: "proof", WorkspaceName: "vm", WorkspaceUID: "workspace-uid", VMUID: "vm-uid", RevocationEpoch: 3, Linux: linux}
		t.Run(target.OSIdentity(), func(t *testing.T) {
			stub := &stubQGA{target: target, result: &qga.GuestResult{Outcome: "completed", ExitCode: intPtr(7), Stdout: []byte("héllo ✓"), Stderr: []byte("err"), DurationMS: 123}}
			stack := newScopedStartStack(t, target.Namespace, target.WorkspaceName, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
			body, name, cwd := "#!/bin/sh\nprintf 'héllo ✓'; exit 7\n", "proof.sh", "/tmp"
			if !linux {
				body, name, cwd = "#!powershell\n[Console]::Out.Write('héllo ✓'); exit 7\n", "proof.ps1", `C:\Windows\Temp`
			}
			result := runInstalledScript(t, context.Background(), stack, target, body, name, cwd)
			out, stderr := decodedScriptStreams(t, result)
			if result.State != "failed" || result.ExitCode == nil || *result.ExitCode != 7 || out != "héllo ✓" || stderr != "err" || len(stub.commands) != 1 {
				t.Fatalf("proof did not preserve the guest result: %+v", result)
			}
		})
	}
}

func scriptExitCodeEqual(a, b *int) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func decodedScriptStreams(t *testing.T, result installedScriptResult) (string, string) {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(result.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	errOut, err := base64.StdEncoding.DecodeString(result.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if len(out)+len(errOut) > qga.MaxOutputBytes {
		t.Fatal("script result exceeds the combined output bound")
	}
	return string(out), string(errOut)
}
