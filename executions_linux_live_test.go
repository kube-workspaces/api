package kubeworkspaces

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/grants"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/platform"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Opt-in installed-Linux proof. The HTTP authentication/account fixtures and
// encrypted ephemeral recording store are local; policy, target resolution,
// Kubernetes pod exec, QGA, signed grants and the guest runner are real.
// Requires a disposable agent VM and an installed matching runner. The bridge
// stages a fresh test verification key, so never use a production workspace.
func TestLinuxExecutionLive(t *testing.T) {
	ns, name := os.Getenv("KW_EXECUTION_LIVE_NAMESPACE"), os.Getenv("KW_EXECUTION_LIVE_WORKSPACE")
	if ns == "" || name == "" {
		t.Skip("set KW_EXECUTION_LIVE_NAMESPACE and KW_EXECUTION_LIVE_WORKSPACE for a disposable Linux VM")
	}
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
	target, err := resolver.Resolve(context.Background(), ns, name)
	if err != nil {
		t.Fatal(err)
	}
	if !target.Linux {
		t.Fatal("live proof requires Linux")
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
	runner, err := qga.NewRuntimeWithExec(signer, resolver, exec)
	if err != nil {
		t.Fatal(err)
	}
	permissions := []string{string(auth.PermissionExec), string(auth.PermissionElevated)}
	stack := newScopedStartStack(t, ns, name, permissions, enabledElevatedPolicy(), nil, WithQGA(runner))
	for _, tc := range []struct {
		name, script, state, stdout, stderr string
		deadline                            int
		truncated                           bool
	}{
		{name: "identity", script: "id -u", state: "succeeded", stdout: "0\n", deadline: 5},
		{name: "argv-cwd-streams", script: "printf '%s' \"$1\"; pwd; printf err >&2; exit 7", state: "failed", stdout: "a b;$(false)/tmp\n", stderr: "err", deadline: 5},
		{name: "deadline-tree", script: "sleep 30 & wait", state: "timed_out", deadline: 1},
		{name: "output-flood", script: "while :; do printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done", state: "failed", deadline: 5, truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"namespace": ns, "workspace_name": name, "executable": "/bin/sh", "args": []string{"-c", tc.script, "sh", "a b;$(false)"}, "cwd": "/tmp", "deadline_seconds": tc.deadline})
			response := stack.post(string(body), "")
			if response.Code != 200 {
				t.Fatalf("HTTP %d: %s", response.Code, response.Body.String())
			}
			var result struct {
				ExecutionID string `json:"execution_id"`
				RecordingID string `json:"recording_id"`
				State       string `json:"state"`
				Stdout      string `json:"stdout"`
				Stderr      string `json:"stderr"`
				Truncated   bool   `json:"truncated"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.State != tc.state || result.Truncated != tc.truncated {
				t.Fatalf("unexpected result: %s", response.Body.String())
			}
			out, _ := base64.StdEncoding.DecodeString(result.Stdout)
			stderr, _ := base64.StdEncoding.DecodeString(result.Stderr)
			if !tc.truncated && (string(out) != tc.stdout || string(stderr) != tc.stderr) {
				t.Fatalf("unexpected streams: %q %q", out, stderr)
			}
			if len(out)+len(stderr) > qga.MaxOutputBytes {
				t.Fatal("output exceeded bound")
			}
			rec, outcome, err := stack.store.Metadata().Get(context.Background(), result.ExecutionID)
			if err != nil || rec.OSIdentity != "root" || !rec.Elevated || string(outcome.State) != tc.state {
				t.Fatalf("record mismatch: %+v %+v %v", rec, outcome, err)
			}
			recording, err := stack.store.Recording().Open(context.Background(), result.RecordingID)
			if err != nil {
				t.Fatal(err)
			}
			defer recording.Close()
			if err := recording.Verify(context.Background()); err != nil {
				t.Fatal(err)
			}
			if recording.Manifest().Chunks != 2 {
				t.Fatal("expected admitted invocation and terminal result")
			}
			startChunk, err := recording.ReadChunk(context.Background(), 0)
			if err != nil {
				t.Fatal(err)
			}
			var recordedStart recordingStart
			if err := json.Unmarshal(startChunk, &recordedStart); err != nil || recordedStart.Executable != "/bin/sh" || len(recordedStart.Args) < 2 || recordedStart.Args[1] != tc.script || recordedStart.Cwd == nil || *recordedStart.Cwd != "/tmp" {
				t.Fatal("recorded invocation does not match")
			}
			resultChunk, err := recording.ReadChunk(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
			}
			var recordedResult recordingResult
			if err := json.Unmarshal(resultChunk, &recordedResult); err != nil || recordedResult.StdoutB64 != result.Stdout || recordedResult.StderrB64 != result.Stderr || recordedResult.Truncated != result.Truncated {
				t.Fatal("recorded result does not match")
			}
			t.Logf("recorded Linux execution: state=%s bytes=%d truncated=%v", result.State, len(out)+len(stderr), result.Truncated)
		})
	}
}
