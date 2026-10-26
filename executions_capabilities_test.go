package kubeworkspaces

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	svr "github.com/kube-workspaces/api/gen/http/executions/server"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

func TestExecutionCapabilitiesScopeAndFailClosedDiscovery(t *testing.T) {
	for name, test := range map[string]struct {
		authenticated      bool
		elevated           bool
		policy             bool
		path               string
		storageUnavailable bool
		status             int
	}{
		"anonymous":           {false, true, true, "?namespace=team&workspace_name=vm", false, 401},
		"missing-elevation":   {true, false, true, "?namespace=team&workspace_name=vm", false, 403},
		"wrong-workspace":     {true, true, true, "?namespace=team&workspace_name=other", false, 403},
		"wrong-namespace":     {true, true, true, "?namespace=other&workspace_name=vm", false, 403},
		"policy-disabled":     {true, true, false, "?namespace=team&workspace_name=vm", false, 403},
		"storage-unavailable": {true, true, true, "?namespace=team&workspace_name=vm", true, 503},
		"missing-scope":       {true, true, true, "", false, 400},
	} {
		t.Run(name, func(t *testing.T) {
			target := eligibleTarget()
			target.Linux = true
			stub := &stubQGA{target: target}
			permissions := []string{string(auth.PermissionExec)}
			if test.elevated {
				permissions = append(permissions, string(auth.PermissionElevated))
			}
			var opts []ExecutionsOption
			if test.storageUnavailable {
				opts = append(opts, func(s *executionssrvc) { s.execSvc = execution.NewService(unavailableExecutionStore{}) })
			}
			stack := newStartStack(t, permissions, map[string]interface{}{"enabled": test.policy, "allowElevated": true}, stub, opts...)
			w := stack.get("/v1/executions/capabilities"+test.path, test.authenticated)
			if w.Code != test.status || len(stub.resolved) != 0 || stub.supportChecks != 0 {
				t.Fatalf("unauthorized discovery reached guest: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestExecutionCapabilitiesProbeCreatesNoExecution(t *testing.T) {
	for _, linux := range []bool{true, false} {
		for _, supported := range []bool{true, false} {
			target := eligibleTarget()
			target.Linux = linux
			stub := &stubQGA{target: target}
			if !supported {
				stub.supportErr = qga.ErrUnsupportedScripts
			}
			stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
			w := stack.get("/v1/executions/capabilities?namespace=team&workspace_name=vm", true)
			var caps svr.CapabilitiesResponseBody
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &caps) != nil {
				t.Fatalf("capabilities failed: %d %s", w.Code, w.Body.String())
			}
			if caps.ScriptSupported != (linux && supported) || caps.Namespace != "team" || caps.WorkspaceName != "vm" || caps.WorkspaceUID != target.WorkspaceUID || caps.OsIdentity != target.OSIdentity() {
				t.Fatalf("bad capability: %+v", caps)
			}
			if caps.ScriptSupported && (caps.ScriptRequestVersion != 2 || caps.InterpreterPolicy != qga.LinuxScriptPolicy || caps.MaxScriptBytes != 65536 || caps.Reason != "") {
				t.Fatalf("incomplete script support: %+v", caps)
			}
			if !caps.ScriptSupported && (caps.ScriptRequestVersion != 0 || caps.InterpreterPolicy != "" || caps.MaxScriptBytes != 0 || caps.Reason == "") {
				t.Fatalf("unsupported capability claims script support: %+v", caps)
			}
			checks := 0
			if linux {
				checks = 1
			}
			if stub.supportChecks != checks || len(stub.commands) != 0 {
				t.Fatal("discovery dispatched an execution")
			}
			records, err := stack.store.Metadata().List(context.Background(), storage.Filter{})
			if err != nil || len(records) != 0 {
				t.Fatal("discovery created recording/admission metadata")
			}
		}
	}
}

func TestExecutionCapabilitiesTargetChangesOrOutagesDoNotAdvertiseSupport(t *testing.T) {
	for _, failure := range []error{qga.ErrDenied, qga.ErrUnavailable} {
		target := eligibleTarget()
		target.Linux = true
		stub := &stubQGA{target: target, supportErr: failure}
		stack := newStartStack(t, []string{string(auth.PermissionExec), string(auth.PermissionElevated)}, enabledElevatedPolicy(), stub)
		w := stack.get("/v1/executions/capabilities?namespace=team&workspace_name=vm", true)
		want := 503
		if failure == qga.ErrDenied {
			want = 404
		}
		if w.Code != want {
			t.Fatalf("target failure advertised support: %d %s", w.Code, w.Body.String())
		}
	}
}
