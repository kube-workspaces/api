package qga

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// Fixed installed-guest paths. The runner is the installed kw-agent binary;
// staged files live in the agent data dir, which exists on every enrolled
// guest (the runner independently denies a missing enrolled identity).
const (
	runnerPath   = `C:\Program Files\workspace-agent\kw-agent.exe`
	dataDirPath  = `C:\ProgramData\workspace-agent`
	keysFilePath = dataDirPath + `\management-grant-keys.json`

	// Pilot contract bounds, kept in step with kw-management's Rust constants.
	MaxDeadlineSeconds = 20
	MaxOutputBytes     = 16 * 1024
	MaxArgs            = 64
	MaxArgBytes        = 8 * 1024
	MaxExecutableBytes = 1024
	MaxCwdBytes        = 1024
	MaxEnvelopeBytes   = 96 * 1024

	// Transport-side bounds for one pod-exec QGA RPC.
	maxQGAResponseBytes = 64 * 1024
	maxKeysFileBytes    = 16 * 1024
	fileWriteChunkBytes = 8 * 1024
	pollInterval        = 250 * time.Millisecond
	pollGrace           = 10 * time.Second
	cleanupTimeout      = 5 * time.Second

	// stagingBudget bounds the file-staging RPCs that run before guest-exec.
	stagingBudget = 30 * time.Second
)

// ErrTransport reports a pod-exec/QGA protocol failure with no trustworthy
// runner result. The caller must record an unknown outcome, never success.
var ErrTransport = errors.New("QGA transport failed")

// ErrNotStarted reports a guest refusal before any runner process exists: the
// installed runner is missing or could not be spawned. Nothing ran, so the
// caller records a failed outcome rather than an uncertain transport loss.
var ErrNotStarted = errors.New("runner could not be started")

// RunBudget is the wall-clock bound for one bounded guest command: staging,
// the guest deadline, the poll grace and margin for the reply. The API derives
// its execution context from this budget so a disconnected caller cannot
// abandon a command mid-flight.
func RunBudget(deadlineSeconds int) time.Duration {
	return time.Duration(deadlineSeconds)*time.Second + pollGrace + stagingBudget
}

// ExecFunc runs one Kubernetes pod exec carrying the QGA JSON on stdin and
// returns bounded stdout/stderr. The injectable seam keeps the bridge
// unit-testable without a cluster.
type ExecFunc func(ctx context.Context, namespace, pod, container string, command []string, stdin []byte) (stdout, stderr []byte, err error)

// boundedOutput mirrors the controller's 64 KiB guest-agent RPC cap.
type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > maxQGAResponseBytes {
		return 0, fmt.Errorf("QGA response exceeds its limit")
	}
	return b.Buffer.Write(data)
}

// KubernetesExecFunc builds the production SPDY pod-exec transport. Grant and
// request bytes travel only on exec stdin through a fixed wrapper, so
// Kubernetes audit logs never carry them as command arguments.
func KubernetesExecFunc(config *rest.Config, client kubernetes.Interface) (ExecFunc, error) {
	if config == nil || client == nil {
		return nil, ErrUnavailable
	}
	return func(ctx context.Context, namespace, pod, container string, command []string, stdin []byte) ([]byte, []byte, error) {
		req := client.CoreV1().RESTClient().Post().
			Resource("pods").
			Namespace(namespace).
			Name(pod).
			SubResource("exec").
			VersionedParams(&corev1.PodExecOptions{
				Container: container,
				Command:   command,
				Stdin:     true,
				Stdout:    true,
				Stderr:    true,
				TTY:       false,
			}, scheme.ParameterCodec)
		executor, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
		if err != nil {
			return nil, nil, err
		}
		var stdout, stderr boundedOutput
		if err := executor.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin:  bytes.NewReader(stdin),
			Stdout: &stdout,
			Stderr: &stderr,
		}); err != nil {
			return nil, stderr.Bytes(), err
		}
		return stdout.Bytes(), stderr.Bytes(), nil
	}, nil
}

// podExecCommand is the fixed wrapper: it replaces its own image with virsh,
// taking the domain as a positional parameter and the QGA JSON from stdin.
func podExecCommand(domain string) []string {
	return []string{"sh", "-c", `exec virsh qemu-agent-command "$1" "$(cat)"`, "sh", domain}
}

// Bridge drives one launcher's QEMU guest agent through pod exec.
type Bridge struct {
	exec ExecFunc
	// Runtime installs an uncached resolver check for every RPC, including
	// cleanup. It is not an atomic UID precondition on Kubernetes pod exec.
	validateTarget func(context.Context, Target) error
}

// NewBridge validates the injected exec transport.
func NewBridge(exec ExecFunc) (*Bridge, error) {
	if exec == nil {
		return nil, ErrUnavailable
	}
	return &Bridge{exec: exec}, nil
}

type qgaError struct {
	Class string `json:"class"`
	Desc  string `json:"desc"`
}

type qgaResponse struct {
	Return json.RawMessage `json:"return"`
	Error  *qgaError       `json:"error"`
}

// qgaRefusal is a well-formed QGA error reply: the guest agent answered and
// refused the RPC, so the transport itself worked. Callers can therefore
// distinguish a deterministic guest refusal from a lost transport.
type qgaRefusal struct {
	execute string
	class   string
	desc    string
}

func (e *qgaRefusal) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.execute, e.class, e.desc)
}

// transportErr classifies one QGA reply for the callers where a guest refusal
// is still an unknown state (file staging, status polling). Only a guest-exec
// spawn refusal is a deterministic "not started" outcome.
func transportErr(err error) error {
	var refusal *qgaRefusal
	if errors.As(err, &refusal) {
		return fmt.Errorf("%w: %s", ErrTransport, refusal.Error())
	}
	return err
}

// qga performs one bounded QGA RPC over pod exec and decodes its return value.
func (b *Bridge) qga(ctx context.Context, target Target, execute string, arguments map[string]any, result any) error {
	command, err := json.Marshal(map[string]any{"execute": execute, "arguments": arguments})
	if err != nil {
		return fmt.Errorf("%w: cannot render %s request", ErrTransport, execute)
	}
	if b.validateTarget != nil {
		if err := b.validateTarget(ctx, target); err != nil {
			// Do not expose resolver diagnostics or treat a mid-flight identity
			// change as proof that a previously dispatched process never ran.
			return fmt.Errorf("%w: QGA target could not be revalidated", ErrTransport)
		}
	}
	stdout, _, err := b.exec(ctx, target.Namespace, target.PodName, "compute", podExecCommand(target.Domain), command)
	if err != nil {
		return fmt.Errorf("%w: %s pod exec failed: %v", ErrTransport, execute, err)
	}
	var response qgaResponse
	if err := json.Unmarshal(stdout, &response); err != nil {
		return fmt.Errorf("%w: %s returned an invalid QGA response", ErrTransport, execute)
	}
	if response.Error != nil {
		return &qgaRefusal{execute: execute, class: response.Error.Class, desc: response.Error.Desc}
	}
	if len(response.Return) == 0 {
		return fmt.Errorf("%w: %s returned no QGA result", ErrTransport, execute)
	}
	if result != nil && json.Unmarshal(response.Return, result) != nil {
		return fmt.Errorf("%w: %s returned an unreadable QGA result", ErrTransport, execute)
	}
	return nil
}

// stageFile overwrites one guest file with bounded chunked writes. The keys
// file is rewritten on every run, which also publishes key rotation without a
// separate provisioning path; concurrent runs may transiently interleave and
// fail closed in the guest rather than run unverified.
func (b *Bridge) stageFile(ctx context.Context, target Target, path string, content []byte) error {
	var handle int64
	if err := b.qga(ctx, target, "guest-file-open", map[string]any{"path": path, "mode": "w+"}, &handle); err != nil {
		return transportErr(err)
	}
	closeHandle := func() {
		_ = b.qga(ctx, target, "guest-file-close", map[string]any{"handle": handle}, nil)
	}
	for offset := 0; offset < len(content); offset += fileWriteChunkBytes {
		end := min(offset+fileWriteChunkBytes, len(content))
		// QGA advances the handle's file position itself. Its write schema uses
		// buf-b64 (not guest-exec's data spelling) and has no offset argument.
		write := map[string]any{"handle": handle, "buf-b64": base64.StdEncoding.EncodeToString(content[offset:end])}
		var written struct {
			Count int64 `json:"count"`
		}
		if err := b.qga(ctx, target, "guest-file-write", write, &written); err != nil {
			closeHandle()
			return transportErr(err)
		}
		if written.Count != int64(end-offset) {
			closeHandle()
			return fmt.Errorf("%w: guest-file-write returned an incomplete count", ErrTransport)
		}
	}
	if err := b.qga(ctx, target, "guest-file-flush", map[string]any{"handle": handle}, nil); err != nil {
		closeHandle()
		return transportErr(err)
	}
	if err := b.qga(ctx, target, "guest-file-close", map[string]any{"handle": handle}, nil); err != nil {
		return transportErr(err)
	}
	return nil
}

// GuestResult is one parsed runner JSON result. It is the authoritative guest
// outcome; the API must never invent success when it is absent.
type GuestResult struct {
	Outcome    string
	ExitCode   *int
	Stdout     []byte
	Stderr     []byte
	Truncated  bool
	DurationMS uint64
	Denial     string
}

// runnerResult mirrors kw-agent's management_exec::CommandResult JSON.
type runnerResult struct {
	Version    uint32 `json:"version"`
	Outcome    string `json:"outcome"`
	ExitCode   *int   `json:"exit_code"`
	StdoutB64  string `json:"stdout_b64"`
	StderrB64  string `json:"stderr_b64"`
	Truncated  bool   `json:"truncated"`
	DurationMS uint64 `json:"duration_ms"`
	Denial     string `json:"denial"`
}

const runnerResultVersion = 1

// guestExecStart is the QGA guest-exec reply.
type guestExecStart struct {
	PID int64 `json:"pid"`
}

// guestExecStatus is the QGA guest-exec-status reply; only meaningful fields
// appear once the process has exited.
type guestExecStatus struct {
	Exited       bool   `json:"exited"`
	ExitCode     *int   `json:"exitcode"`
	OutData      string `json:"out-data"`
	ErrData      string `json:"err-data"`
	Signal       int    `json:"signal"`
	OutTruncated bool   `json:"out-truncated"`
	ErrTruncated bool   `json:"err-truncated"`
}

// Run stages the pinned keys and the signed envelope, invokes the fixed
// installed runner through the QEMU guest agent, polls for its bounded JSON
// result and best-effort clears the staged envelope. A guest refusal to spawn
// the runner returns ErrNotStarted: a deterministic "nothing ran" failure. Any
// other protocol failure, incomplete capture or invalid result returns
// ErrTransport: an unknown outcome, never inferred success or a rerun.
func (b *Bridge) Run(ctx context.Context, target Target, executionID string, envelope, keysJSON []byte, deadlineSeconds int) (*GuestResult, error) {
	return b.runWithExtras(ctx, target, executionID, envelope, keysJSON, deadlineSeconds, nil)
}

func (b *Bridge) runWithExtras(ctx context.Context, target Target, executionID string, envelope, keysJSON []byte, deadlineSeconds int, extras map[string][]byte) (*GuestResult, error) {
	if !validExecutionID(executionID) {
		return nil, fmt.Errorf("%w: execution id is not safe to stage", ErrTransport)
	}
	if len(envelope) == 0 || len(envelope) > MaxEnvelopeBytes || len(keysJSON) == 0 || len(keysJSON) > maxKeysFileBytes {
		return nil, fmt.Errorf("%w: staged content is empty or oversized", ErrTransport)
	}
	runner, dataDir, keysFile := runnerPath, dataDirPath, keysFilePath
	envelopePath := dataDirPath + `\qga-request-` + executionID + `.json`
	if target.Linux {
		runner, dataDir = "/usr/local/bin/kw-agent", "/var/lib/workspace-agent"
		keysFile = dataDir + "/management-grant-keys.json"
		envelopePath = dataDir + "/qga-request-" + executionID + ".json"
	}
	if err := b.stageFile(ctx, target, keysFile, keysJSON); err != nil {
		return nil, err
	}
	// QGA has no guest-file-delete RPC. Truncate and close through supported
	// file operations to remove sensitive envelope bytes without a shell or a
	// second guest process. Install cleanup before staging so partial writes
	// are cleared too; cleanup survives request cancellation but stays bounded.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		_ = b.stageFile(cleanup, target, envelopePath, nil)
		for _, path := range extraPaths(dataDir, target.Linux, extras) {
			_ = b.stageFile(cleanup, target, path, nil)
		}
	}()
	if err := b.stageFile(ctx, target, envelopePath, envelope); err != nil {
		return nil, err
	}
	for path, content := range extras {
		if err := b.stageFile(ctx, target, path, content); err != nil {
			return nil, err
		}
	}
	var started guestExecStart
	start := map[string]any{
		"path":           runner,
		"arg":            []string{"management-exec", "--request-file", envelopePath, "--data-dir", dataDir},
		"capture-output": true,
	}
	if err := b.qga(ctx, target, "guest-exec", start, &started); err != nil {
		// A well-formed refusal means the guest agent never produced a pid:
		// the installed runner is missing or unspawnable, so the command
		// provably did not run and must not be recorded as a transport loss.
		var refusal *qgaRefusal
		if errors.As(err, &refusal) {
			return nil, fmt.Errorf("%w: %s", ErrNotStarted, refusal.Error())
		}
		return nil, transportErr(err)
	}
	if started.PID <= 0 {
		return nil, fmt.Errorf("%w: runner did not report a process", ErrTransport)
	}
	giveUp := time.Now().Add(time.Duration(deadlineSeconds)*time.Second + pollGrace)
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrTransport, ctx.Err())
		case <-time.After(pollInterval):
		}
		if time.Now().After(giveUp) {
			return nil, fmt.Errorf("%w: runner result did not arrive in time", ErrTransport)
		}
		var status guestExecStatus
		if err := b.qga(ctx, target, "guest-exec-status", map[string]any{"pid": started.PID}, &status); err != nil {
			// The runner existed; losing its status is an uncertain outcome.
			return nil, transportErr(err)
		}
		if !status.Exited {
			continue
		}
		if status.Signal != 0 {
			return nil, fmt.Errorf("%w: runner was killed by signal %d", ErrTransport, status.Signal)
		}
		if status.ExitCode == nil || *status.ExitCode != 0 || status.OutTruncated || status.ErrTruncated {
			return nil, fmt.Errorf("%w: runner capture is incomplete or unsuccessful", ErrTransport)
		}
		raw, err := base64.StdEncoding.DecodeString(status.OutData)
		if err != nil {
			return nil, fmt.Errorf("%w: runner result is not base64", ErrTransport)
		}
		return parseRunnerResult(raw)
	}
}

// maxRunnerResultBytes bounds the decoded runner JSON: two capped 16 KiB
// base64 streams plus structurally small framing.
const maxRunnerResultBytes = MaxOutputBytes*2*4/3 + 4096

func parseRunnerResult(raw []byte) (*GuestResult, error) {
	if len(raw) == 0 || len(raw) > maxRunnerResultBytes {
		return nil, fmt.Errorf("%w: runner result size is out of bounds", ErrTransport)
	}
	var parsed runnerResult
	if !decodeExactObject(raw, &parsed, runnerResultFields) {
		return nil, fmt.Errorf("%w: runner result is malformed", ErrTransport)
	}
	if parsed.Version != runnerResultVersion || parsed.Outcome == "" {
		return nil, fmt.Errorf("%w: runner result has an unsupported shape", ErrTransport)
	}
	switch parsed.Outcome {
	case "completed":
		if parsed.ExitCode == nil || parsed.Truncated {
			return nil, fmt.Errorf("%w: runner completion is incomplete or contradictory", ErrTransport)
		}
	case "output-limit":
		if !parsed.Truncated {
			return nil, fmt.Errorf("%w: output-limit result omits truncation", ErrTransport)
		}
	case "deadline", "denied", "runner-error", "spawn-failed":
	default:
		return nil, fmt.Errorf("%w: runner outcome is unsupported", ErrTransport)
	}
	if parsed.ExitCode != nil && (int64(*parsed.ExitCode) < -1<<31 || int64(*parsed.ExitCode) > 1<<31-1) {
		return nil, fmt.Errorf("%w: runner exit code is out of bounds", ErrTransport)
	}
	stdout, err := base64.StdEncoding.DecodeString(parsed.StdoutB64)
	if err != nil {
		return nil, fmt.Errorf("%w: runner stdout is not base64", ErrTransport)
	}
	stderr, err := base64.StdEncoding.DecodeString(parsed.StderrB64)
	if err != nil {
		return nil, fmt.Errorf("%w: runner stderr is not base64", ErrTransport)
	}
	if len(stdout)+len(stderr) > MaxOutputBytes {
		return nil, fmt.Errorf("%w: runner output exceeds its limit", ErrTransport)
	}
	return &GuestResult{
		Outcome:    parsed.Outcome,
		ExitCode:   parsed.ExitCode,
		Stdout:     stdout,
		Stderr:     stderr,
		Truncated:  parsed.Truncated,
		DurationMS: parsed.DurationMS,
		Denial:     parsed.Denial,
	}, nil
}

func extraPaths(dataDir string, linux bool, extras map[string][]byte) []string {
	if len(extras) == 0 {
		return nil
	}
	paths := make([]string, 0, len(extras))
	for path := range extras {
		paths = append(paths, path)
	}
	return paths
}

// RunWithExtras stages extras for tests/callers.
func (b *Bridge) RunWithExtras(ctx context.Context, target Target, executionID string, envelope, keysJSON []byte, deadlineSeconds int, extras map[string][]byte) (*GuestResult, error) {
	return b.runWithExtras(ctx, target, executionID, envelope, keysJSON, deadlineSeconds, extras)
}

// ScriptPath builds the script staging path for a target.
func ScriptPath(target Target, executionID, name string) string {
	name = sanitizeName(name)
	if target.Linux {
		if name == "" {
			name = "script.sh"
		}
		return "/var/lib/workspace-agent/script-" + executionID + "-" + name
	}
	if name == "" {
		name = "script.ps1"
	}
	return `C:\ProgramData\workspace-agent\script-` + executionID + "-" + name
}

func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r == '/' || r == '\\' || r == ':' || unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return ""
	}
	return b.String()
}

// validExecutionID keeps generated ids safe inside a fixed Windows path.
func validExecutionID(id string) bool {
	if len(id) < 5 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		ok := r == '_' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}
