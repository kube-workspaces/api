package qga

import (
	"context"
	"encoding/base64"
	"errors"
	"time"
)

var ErrUnsupportedScripts = errors.New("installed guest does not support this script request v2 policy")

// CheckScripts probes only the fixed installed binary over authenticated QGA.
// It sends no tenant input and creates no execution grant or staged file.
func (b *Bridge) CheckScripts(ctx context.Context, target Target) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var started guestExecStart
	runner := runnerPath
	if target.Linux {
		runner = "/usr/local/bin/kw-agent"
	}
	if err := b.qga(ctx, target, "guest-exec", map[string]any{
		"path": runner, "arg": []string{"management-exec", "--capabilities"}, "capture-output": true,
	}, &started); err != nil || started.PID <= 0 {
		return ErrUnsupportedScripts
	}
	for {
		select {
		case <-ctx.Done():
			return ErrUnsupportedScripts
		case <-time.After(pollInterval):
		}
		var status guestExecStatus
		if err := b.qga(ctx, target, "guest-exec-status", map[string]any{"pid": started.PID}, &status); err != nil {
			return ErrUnsupportedScripts
		}
		if !status.Exited {
			continue
		}
		if status.ExitCode == nil || *status.ExitCode != 0 || status.Signal != 0 || status.OutTruncated || status.ErrTruncated {
			return ErrUnsupportedScripts
		}
		raw, err := base64.StdEncoding.DecodeString(status.OutData)
		if err != nil || len(raw) > 1024 {
			return ErrUnsupportedScripts
		}
		var caps struct {
			Version              int    `json:"version"`
			ScriptRequestVersion int    `json:"script_request_version"`
			InterpreterPolicy    string `json:"interpreter_policy"`
		}
		if !decodeExactObject(raw, &caps, scriptCapabilityFields) || caps.Version != 1 || caps.ScriptRequestVersion != 2 || caps.InterpreterPolicy != ScriptPolicy(target) {
			return ErrUnsupportedScripts
		}
		return nil
	}
}
