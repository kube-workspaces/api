package qga

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func resultObject(t *testing.T) map[string]any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(successRunnerResult(), &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func encodeResult(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRunnerResultRequiresExactCompleteObject(t *testing.T) {
	valid := successRunnerResult()
	for _, field := range []string{"version", "outcome", "exit_code", "stdout_b64", "stderr_b64", "truncated", "duration_ms", "denial"} {
		t.Run("missing/"+field, func(t *testing.T) {
			fields := resultObject(t)
			delete(fields, field)
			if result, err := parseRunnerResult(encodeResult(t, fields)); result != nil || !errors.Is(err, ErrTransport) {
				t.Fatal("incomplete result accepted")
			}
		})
		t.Run("duplicate/"+field, func(t *testing.T) {
			value, _ := json.Marshal(resultObject(t)[field])
			raw := strings.TrimSuffix(string(valid), "}") + `,"` + field + `":` + string(value) + `}`
			if result, err := parseRunnerResult([]byte(raw)); result != nil || !errors.Is(err, ErrTransport) {
				t.Fatal("duplicate field accepted")
			}
		})
		if field != "exit_code" && field != "denial" {
			t.Run("null/"+field, func(t *testing.T) {
				fields := resultObject(t)
				fields[field] = nil
				if result, err := parseRunnerResult(encodeResult(t, fields)); result != nil || !errors.Is(err, ErrTransport) {
					t.Fatal("null non-nullable field accepted")
				}
			})
		}
	}
	for _, raw := range [][]byte{
		[]byte("null"), []byte("[]"),
		append(append([]byte{}, valid...), []byte(` {"secret":"private-runner-marker"}`)...),
		append(append([]byte{}, valid...), []byte(` trailing-private-runner-marker`)...),
		[]byte(strings.Replace(string(valid), `"version":`, `"Version":`, 1)),
		[]byte(strings.TrimSuffix(string(valid), "}") + `,"\u0076ersion":1}`),
		[]byte(strings.Replace(string(valid), `"denial":""`, "\"denial\":\"\xff\"", 1)),
	} {
		result, err := parseRunnerResult(raw)
		if result != nil || !errors.Is(err, ErrTransport) {
			t.Fatal("non-exact result accepted")
		}
		if strings.Contains(err.Error(), "private-runner-marker") {
			t.Fatal("protocol error disclosed guest bytes")
		}
	}
	if _, err := parseRunnerResult(append(append([]byte(" \n"), valid...), []byte("\r\n ")...)); err != nil {
		t.Fatal("normal CLI whitespace rejected")
	}
}

func TestRunnerResultSemanticsAndOutputBounds(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"completion-without-exit":    func(f map[string]any) { f["exit_code"] = nil },
		"completion-truncated":       func(f map[string]any) { f["truncated"] = true },
		"output-limit-not-truncated": func(f map[string]any) { f["outcome"] = "output-limit" },
		"unknown-outcome":            func(f map[string]any) { f["outcome"] = "private-runner-marker" },
		"large-exit":                 func(f map[string]any) { f["exit_code"] = int64(1) << 31 },
		"negative-exit-overflow":     func(f map[string]any) { f["exit_code"] = -(int64(1) << 31) - 1 },
		"fractional-exit":            func(f map[string]any) { f["exit_code"] = 0.5 },
		"negative-duration":          func(f map[string]any) { f["duration_ms"] = -1 },
		"string-truncation":          func(f map[string]any) { f["truncated"] = "false" },
		"invalid-base64":             func(f map[string]any) { f["stdout_b64"] = "private-runner-marker!" },
		"oversized-stdout": func(f map[string]any) {
			f["stdout_b64"] = base64.StdEncoding.EncodeToString(make([]byte, MaxOutputBytes+1))
		},
		"combined-overflow": func(f map[string]any) {
			f["stdout_b64"] = base64.StdEncoding.EncodeToString(make([]byte, MaxOutputBytes))
			f["stderr_b64"] = "eA=="
		},
		"two-individually-bounded-streams": func(f map[string]any) {
			f["stdout_b64"] = base64.StdEncoding.EncodeToString(make([]byte, MaxOutputBytes))
			f["stderr_b64"] = f["stdout_b64"]
		},
	} {
		t.Run(name, func(t *testing.T) {
			fields := resultObject(t)
			mutate(fields)
			result, err := parseRunnerResult(encodeResult(t, fields))
			if result != nil || !errors.Is(err, ErrTransport) {
				t.Fatal("invalid result became authoritative")
			}
			if strings.Contains(err.Error(), "private-runner-marker") {
				t.Fatal("protocol error disclosed guest bytes")
			}
		})
	}
	for _, outcome := range []string{"completed", "deadline", "output-limit", "denied", "runner-error", "spawn-failed"} {
		fields := resultObject(t)
		fields["outcome"], fields["denial"] = outcome, nil // Real Rust Option::None serialization.
		fields["truncated"] = outcome == "output-limit"
		if outcome != "completed" {
			fields["exit_code"] = nil
		}
		if _, err := parseRunnerResult(encodeResult(t, fields)); err != nil {
			t.Fatalf("valid %s/null option rejected: %v", outcome, err)
		}
	}
	for _, code := range []int64{0, 7, -1 << 31, 1<<31 - 1} {
		fields := resultObject(t)
		fields["exit_code"] = code
		fields["stdout_b64"] = base64.StdEncoding.EncodeToString(make([]byte, MaxOutputBytes-1))
		fields["stderr_b64"] = "eA=="
		result, err := parseRunnerResult(encodeResult(t, fields))
		if err != nil || result.ExitCode == nil || int64(*result.ExitCode) != code || len(result.Stdout)+len(result.Stderr) != MaxOutputBytes {
			t.Fatalf("valid signed exit/boundary output rejected: %v", err)
		}
	}
}

func TestBridgeRejectsIncompleteRunnerCapture(t *testing.T) {
	for _, failure := range []string{"nonzero-agent-exit", "missing-agent-exit", "null-agent-exit", "stdout-truncated", "stderr-truncated", "trailing-result", "missing-completion-exit"} {
		t.Run(failure, func(t *testing.T) {
			guest := newFakeExec(successRunnerResult())
			guest.statusOverride = func(int) ([]byte, []byte, error) {
				code := 0
				status := guestExecStatus{Exited: true, ExitCode: &code, OutData: base64.StdEncoding.EncodeToString(successRunnerResult())}
				switch failure {
				case "nonzero-agent-exit":
					code = 1
				case "null-agent-exit":
					status.ExitCode = nil
				case "stdout-truncated":
					status.OutTruncated = true
				case "stderr-truncated":
					status.ErrTruncated = true
				case "trailing-result":
					status.OutData = base64.StdEncoding.EncodeToString(append(successRunnerResult(), []byte(" trailing-private-runner-marker")...))
				case "missing-completion-exit":
					fields := resultObject(t)
					fields["exit_code"] = nil
					status.OutData = base64.StdEncoding.EncodeToString(encodeResult(t, fields))
				}
				// guestExecStatus is a decode DTO, with QGA's external field names.
				reply := map[string]any{"exited": true, "exitcode": status.ExitCode, "out-data": status.OutData, "out-truncated": status.OutTruncated, "err-truncated": status.ErrTruncated}
				if failure == "missing-agent-exit" {
					delete(reply, "exitcode")
				}
				raw, err := json.Marshal(map[string]any{"return": reply})
				return raw, nil, err
			}
			bridge, _ := NewBridge(guest.run)
			result, err := bridge.Run(context.Background(), testTarget(), "exec_1", []byte(`{"grant":"protected","request":{}}`), []byte(`{"version":1,"keys":["public"]}`), 20)
			if result != nil || !errors.Is(err, ErrTransport) {
				t.Fatal("incomplete capture became authoritative success")
			}
			if strings.Contains(err.Error(), "private-runner-marker") {
				t.Fatal("capture error disclosed protected guest data")
			}
			starts := 0
			for _, call := range executes(guest.calls) {
				if call == "guest-exec" {
					starts++
				}
			}
			if starts != 1 || len(guest.files[dataDirPath+`\qga-request-exec_1.json`]) != 0 {
				t.Fatal("failed capture reran or retained sensitive envelope")
			}
		})
	}
}

func TestScriptCapabilitiesRejectAmbiguousObjects(t *testing.T) {
	valid := `{"version":1,"script_request_version":2,"interpreter_policy":"windows-powershell-v1"}`
	for _, raw := range []string{
		valid + ` {}`, strings.TrimSuffix(valid, "}") + `,"version":1}`,
		strings.Replace(valid, `"version":1`, `"Version":1`, 1),
		strings.Replace(valid, `"script_request_version":2`, `"script_request_version":null`, 1),
		`{"version":1,"interpreter_policy":"windows-powershell-v1"}`,
	} {
		guest := newFakeExec(nil)
		guest.capabilities = []byte(raw)
		bridge, _ := NewBridge(guest.run)
		if err := bridge.CheckScripts(context.Background(), testTarget()); !errors.Is(err, ErrUnsupportedScripts) {
			t.Fatal("ambiguous capability advertisement accepted")
		}
		if len(guest.files) != 0 {
			t.Fatal("capability rejection staged guest files")
		}
	}
}

func TestScriptCapabilitiesRequireCompleteSuccessfulCapture(t *testing.T) {
	for _, failure := range []string{"missing-exit", "null-exit", "nonzero-exit", "signal", "out-truncated", "err-truncated"} {
		t.Run(failure, func(t *testing.T) {
			guest := newFakeExec(nil)
			guest.statusOverride = func(int) ([]byte, []byte, error) {
				status := map[string]any{
					"exited": true, "exitcode": 0,
					"out-data": base64.StdEncoding.EncodeToString([]byte(`{"version":1,"script_request_version":2,"interpreter_policy":"windows-powershell-v1"}`)),
				}
				switch failure {
				case "missing-exit":
					delete(status, "exitcode")
				case "null-exit":
					status["exitcode"] = nil
				case "nonzero-exit":
					status["exitcode"] = 1
				case "signal":
					status["signal"] = 9
				default:
					status[failure] = true
				}
				raw, err := json.Marshal(map[string]any{"return": status})
				return raw, nil, err
			}
			bridge, _ := NewBridge(guest.run)
			if err := bridge.CheckScripts(context.Background(), testTarget()); !errors.Is(err, ErrUnsupportedScripts) {
				t.Fatal("incomplete capability capture accepted")
			}
			if len(guest.files) != 0 {
				t.Fatal("capability rejection staged guest files")
			}
		})
	}
}

func FuzzParseRunnerResult(f *testing.F) {
	f.Add(successRunnerResult())
	f.Add([]byte(`{"version":1,"outcome":"completed"}`))
	f.Add(append(successRunnerResult(), []byte(" {}")...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		result, err := parseRunnerResult(raw)
		if err != nil {
			if result != nil || !errors.Is(err, ErrTransport) {
				t.Fatal("invalid result escaped transport failure")
			}
			return
		}
		if result == nil || len(result.Stdout)+len(result.Stderr) > MaxOutputBytes || (result.Outcome == "completed" && (result.ExitCode == nil || result.Truncated)) {
			t.Fatal("accepted result violates completion/output contract")
		}
	})
}
