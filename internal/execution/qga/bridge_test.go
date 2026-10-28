package qga

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type execCall struct {
	namespace string
	pod       string
	container string
	command   []string
	stdin     []byte
}

// fakeExec scripts the QEMU guest agent behind one launcher: it stages files
// through QGA file calls and replays a canned runner result.
type fakeExec struct {
	calls              []execCall
	files              map[string][]byte
	handles            map[int64]string
	nextHandle         int64
	statusCalls        int
	result             []byte
	failExecute        string
	rawExecute         string
	podExecErr         error
	pid                int64
	onGuestExec        func()
	statusOverride     func(calls int) ([]byte, []byte, error)
	shortEnvelopeWrite bool
	capabilities       []byte
	probing            bool
}

func newFakeExec(result []byte) *fakeExec {
	return &fakeExec{
		files:      map[string][]byte{},
		handles:    map[int64]string{},
		nextHandle: 10,
		result:     result,
		pid:        4242,
	}
}

func (f *fakeExec) run(ctx context.Context, namespace, pod, container string, command []string, stdin []byte) ([]byte, []byte, error) {
	f.calls = append(f.calls, execCall{namespace: namespace, pod: pod, container: container, command: command, stdin: append([]byte{}, stdin...)})
	if f.podExecErr != nil {
		return nil, nil, f.podExecErr
	}
	var request struct {
		Execute   string          `json:"execute"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(stdin, &request); err != nil {
		return nil, nil, fmt.Errorf("bad fake request: %w", err)
	}
	if request.Execute == f.rawExecute {
		return []byte("not json at all"), nil, nil
	}
	if request.Execute == f.failExecute {
		return []byte(`{"error":{"class":"GenericError","desc":"scripted failure"}}`), nil, nil
	}
	reply := func(value any) ([]byte, []byte, error) {
		raw, err := json.Marshal(map[string]any{"return": value})
		return raw, nil, err
	}
	switch request.Execute {
	case "guest-file-open":
		var args struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(request.Arguments, &args); err != nil || args.Mode != "w+" {
			return nil, nil, fmt.Errorf("unexpected open arguments")
		}
		handle := f.nextHandle
		f.nextHandle++
		f.handles[handle] = args.Path
		f.files[args.Path] = nil
		return reply(handle)
	case "guest-file-write":
		var args struct {
			Handle int64   `json:"handle"`
			BufB64 *string `json:"buf-b64"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(request.Arguments)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&args); err != nil || args.BufB64 == nil {
			return nil, nil, fmt.Errorf("unexpected write arguments")
		}
		path, open := f.handles[args.Handle]
		if !open {
			return nil, nil, fmt.Errorf("write to a closed handle")
		}
		data, err := base64.StdEncoding.DecodeString(*args.BufB64)
		if err != nil {
			return nil, nil, fmt.Errorf("write chunk is not standard base64")
		}
		f.files[path] = append(f.files[path], data...)
		if f.shortEnvelopeWrite && strings.Contains(path, `\qga-request-`) {
			return reply(map[string]any{"count": len(data) - 1})
		}
		return reply(map[string]any{"count": len(data)})
	case "guest-file-flush", "guest-file-close":
		return reply(map[string]any{})
	case "guest-exec":
		var args struct {
			Path          string   `json:"path"`
			Arg           []string `json:"arg"`
			CaptureOutput bool     `json:"capture-output"`
		}
		if err := json.Unmarshal(request.Arguments, &args); err != nil || (args.Path != runnerPath && args.Path != "/usr/local/bin/kw-agent") || !args.CaptureOutput || len(args.Arg) == 0 || args.Arg[0] != "management-exec" {
			return nil, nil, fmt.Errorf("unexpected guest-exec arguments")
		}
		f.probing = len(args.Arg) == 2 && args.Arg[1] == "--capabilities"
		f.statusCalls = 0
		if f.probing {
			return reply(map[string]any{"pid": f.pid})
		}
		if f.onGuestExec != nil {
			f.onGuestExec()
		}
		return reply(map[string]any{"pid": f.pid})
	case "guest-exec-status":
		f.statusCalls++
		if f.statusOverride != nil {
			return f.statusOverride(f.statusCalls)
		}
		if f.statusCalls == 1 {
			return reply(map[string]any{"exited": false})
		}
		result := f.result
		if f.probing {
			result = f.capabilities
		}
		return reply(map[string]any{
			"exited": true, "exitcode": 0,
			"out-data": base64.StdEncoding.EncodeToString(result),
			"err-data": "", "signal": 0,
		})
	}
	return nil, nil, fmt.Errorf("unexpected execute %q", request.Execute)
}

func successRunnerResult() []byte {
	code := 0
	raw, err := json.Marshal(runnerResult{
		Version: 1, Outcome: "completed", ExitCode: &code,
		StdoutB64: base64.StdEncoding.EncodeToString([]byte("hello\n")),
		StderrB64: "", Truncated: false, DurationMS: 12, Denial: "",
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func testTarget() Target {
	return Target{
		Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "workspace-uid",
		VMUID: "vm-uid", VMIUID: "vmi-uid", PodName: testPodName, PodUID: testPodUID, Domain: "team_vm",
	}
}

func executes(calls []execCall) []string {
	var names []string
	for _, call := range calls {
		var request struct {
			Execute string `json:"execute"`
		}
		_ = json.Unmarshal(call.stdin, &request)
		names = append(names, request.Execute)
	}
	return names
}

func TestBridgeRunStagesExecutesAndCleansUp(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	bridge, err := NewBridge(fake.run)
	if err != nil {
		t.Fatal(err)
	}
	keys := []byte(`{"version":1,"keys":["test-key"]}`)
	envelope := []byte(`{"grant":"token","request":{}}` + strings.Repeat(" ", 20*1024))
	result, err := bridge.Run(context.Background(), testTarget(), "exec_1", envelope, keys, 20)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "completed" || result.ExitCode == nil || *result.ExitCode != 0 || string(result.Stdout) != "hello\n" || result.DurationMS != 12 {
		t.Fatalf("unexpected guest result: %+v", result)
	}
	envelopePath := dataDirPath + `\qga-request-exec_1.json`
	if got := fake.files[keysFilePath]; string(got) != string(keys) {
		t.Fatalf("keys file was staged incorrectly: %q", got)
	}
	if got := fake.files[envelopePath]; len(got) != 0 {
		t.Fatal("staged envelope was not cleared")
	}
	names := executes(fake.calls)
	expected := []string{"guest-file-open", "guest-file-write", "guest-file-flush", "guest-file-close",
		"guest-file-open", "guest-file-write", "guest-file-write", "guest-file-write", "guest-file-flush", "guest-file-close",
		"guest-exec", "guest-exec-status", "guest-exec-status", "guest-file-open", "guest-file-flush", "guest-file-close"}
	if strings.Join(names, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected QGA sequence:\n%v", names)
	}
	first := fake.calls[0]
	if first.namespace != "team" || first.pod != testPodName || first.container != "compute" {
		t.Fatalf("unexpected exec target: %+v", first)
	}
	if len(first.command) != 5 || first.command[0] != "sh" || first.command[1] != "-c" ||
		first.command[2] != `exec virsh qemu-agent-command "$1" "$(cat)"` || first.command[3] != "sh" || first.command[4] != "team_vm" {
		t.Fatalf("unexpected pod-exec wrapper: %q", first.command)
	}
	for _, call := range fake.calls {
		if strings.Contains(strings.Join(call.command, " "), "token") {
			t.Fatal("grant material leaked into pod-exec arguments")
		}
	}
	// The 20 KiB envelope must have been written in three bounded chunks.
	writes := 0
	for _, call := range fake.calls {
		var request struct {
			Execute string `json:"execute"`
		}
		_ = json.Unmarshal(call.stdin, &request)
		if request.Execute == "guest-file-write" {
			writes++
		}
	}
	if writes != 1+3 {
		t.Fatalf("expected one keys chunk and three envelope chunks, got %d writes", writes)
	}
}

func TestBridgeRunRejectsUnstageableInputs(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	bridge, _ := NewBridge(fake.run)
	valid := []byte(`{"grant":"token","request":{}}`)
	keys := []byte(`{"version":1,"keys":["test-key"]}`)
	for name, args := range map[string]struct {
		id       string
		envelope []byte
		keys     []byte
	}{
		"empty-envelope": {id: "exec_1", envelope: nil, keys: keys},
		"empty-keys":     {id: "exec_1", envelope: valid, keys: nil},
		"hostile-id":     {id: `..\evil`, envelope: valid, keys: keys},
		"short-id":       {id: "e_1", envelope: valid, keys: keys},
		"oversized-keys": {id: "exec_1", envelope: valid, keys: []byte(strings.Repeat("k", maxKeysFileBytes+1))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := bridge.Run(context.Background(), testTarget(), args.id, args.envelope, args.keys, 20); !errors.Is(err, ErrTransport) {
				t.Fatalf("expected ErrTransport, got %v", err)
			}
		})
	}
	if len(fake.calls) != 0 {
		t.Fatal("invalid inputs must not reach the guest")
	}
}

func TestBridgeRejectsShortWriteAndClearsPartialEnvelope(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	fake.shortEnvelopeWrite = true
	bridge, _ := NewBridge(fake.run)
	_, err := bridge.Run(context.Background(), testTarget(), "exec_short", []byte(`{"grant":"sensitive","request":{}}`), []byte(`{"version":1,"keys":["k"]}`), 20)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("short write must fail closed: %v", err)
	}
	if len(fake.files[dataDirPath+`\qga-request-exec_short.json`]) != 0 {
		t.Fatal("partial staged envelope was not cleared")
	}
	for _, call := range executes(fake.calls) {
		if call == "guest-exec" {
			t.Fatal("incomplete file staging must never launch the runner")
		}
	}
}

func TestBridgeRunTransportFailuresAreUnknownOutcomes(t *testing.T) {
	oversized := []byte(strings.Repeat("x", maxRunnerResultBytes+1))
	for name, setup := range map[string]func(*fakeExec){
		// A staging refusal is still an unknown state: no runner was invoked,
		// but the guest side is not reporting a deterministic spawn failure.
		"qga-error":       func(f *fakeExec) { f.failExecute = "guest-file-open" },
		"status-refusal":  func(f *fakeExec) { f.failExecute = "guest-exec-status" },
		"malformed-reply": func(f *fakeExec) { f.rawExecute = "guest-file-open" },
		"no-pid":          func(f *fakeExec) { f.pid = 0 },
		"signal-death": func(f *fakeExec) {
			f.statusOverride = func(calls int) ([]byte, []byte, error) {
				if calls == 1 {
					return []byte(`{"return":{"exited":false}}`), nil, nil
				}
				return []byte(`{"return":{"exited":true,"exitcode":0,"out-data":"","err-data":"","signal":9}}`), nil, nil
			}
		},
		"out-data-not-base64": func(f *fakeExec) {
			f.statusOverride = func(calls int) ([]byte, []byte, error) {
				if calls == 1 {
					return []byte(`{"return":{"exited":false}}`), nil, nil
				}
				return []byte(`{"return":{"exited":true,"exitcode":0,"out-data":"%%%","err-data":"","signal":0}}`), nil, nil
			}
		},
		"empty-result":     func(f *fakeExec) { f.result = nil },
		"oversized-result": func(f *fakeExec) { f.result = oversized },
		"malformed-result": func(f *fakeExec) { f.result = []byte("{") },
		"unknown-field": func(f *fakeExec) {
			f.result = []byte(`{"version":1,"outcome":"completed","exit_code":0,"stdout_b64":"","stderr_b64":"","truncated":false,"duration_ms":1,"denial":"","extra":true}`)
		},
		"wrong-version": func(f *fakeExec) {
			f.result = []byte(`{"version":2,"outcome":"completed","exit_code":0,"stdout_b64":"","stderr_b64":"","truncated":false,"duration_ms":1,"denial":""}`)
		},
		"missing-outcome": func(f *fakeExec) {
			f.result = []byte(`{"version":1,"outcome":"","exit_code":0,"stdout_b64":"","stderr_b64":"","truncated":false,"duration_ms":1,"denial":""}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeExec(successRunnerResult())
			setup(fake)
			bridge, _ := NewBridge(fake.run)
			if _, err := bridge.Run(context.Background(), testTarget(), "exec_1", []byte(`{"grant":"token","request":{}}`), []byte(`{"version":1,"keys":["test-key"]}`), 20); !errors.Is(err, ErrTransport) {
				t.Fatalf("expected ErrTransport, got %v", err)
			}
		})
	}
}

// A guest refusal to spawn the installed runner is a deterministic failure —
// no pid was ever returned, so the command provably did not run. It must not
// be reported as a transport loss (which would forbid a legitimate retry).
func TestBridgeRunRunnerAbsenceIsNotAnUnknownOutcome(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	fake.failExecute = "guest-exec"
	bridge, _ := NewBridge(fake.run)
	result, err := bridge.Run(context.Background(), testTarget(), "exec_1", []byte(`{"grant":"token","request":{}}`), []byte(`{"version":1,"keys":["k"]}`), 20)
	if result != nil {
		t.Fatalf("runner absence must not invent a result: %+v", result)
	}
	if !errors.Is(err, ErrNotStarted) {
		t.Fatalf("expected ErrNotStarted, got %v", err)
	}
	if errors.Is(err, ErrTransport) {
		t.Fatalf("runner absence must not be a transport loss: %v", err)
	}
	if !strings.Contains(err.Error(), "GenericError: scripted failure") {
		t.Fatalf("refusal detail was dropped: %v", err)
	}
	for _, name := range executes(fake.calls) {
		if name == "guest-exec-status" {
			t.Fatal("no runner pid exists, so no status may be polled")
		}
	}
}

func TestBridgeRunStopsOnCancellation(t *testing.T) {
	fake := newFakeExec(successRunnerResult())
	ctx, cancel := context.WithCancel(context.Background())
	fake.onGuestExec = cancel
	bridge, _ := NewBridge(fake.run)
	if _, err := bridge.Run(ctx, testTarget(), "exec_1", []byte(`{"grant":"token","request":{}}`), []byte(`{"version":1,"keys":["k"]}`), 20); !errors.Is(err, ErrTransport) {
		t.Fatalf("expected ErrTransport, got %v", err)
	}
}

func TestKubernetesExecFuncRequiresDependencies(t *testing.T) {
	if _, err := KubernetesExecFunc(nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	if _, err := NewBridge(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}
