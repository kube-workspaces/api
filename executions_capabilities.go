package kubeworkspaces

import (
	"context"
	"errors"
	"time"

	executions "github.com/kube-workspaces/api/gen/executions"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/qga"
)

type scriptSupportChecker interface {
	CheckScriptSupport(context.Context, qga.Target) error
}

func (s *executionssrvc) Capabilities(ctx context.Context, p *executions.CapabilitiesPayload) (*executions.ExecutionCapabilities, error) {
	user := auth.ExecutionPrincipal(ctx)
	if user == nil {
		return nil, executions.Unauthorized("sign in with a user-bound credential")
	}
	if p == nil || p.Namespace == "" || p.WorkspaceName == "" {
		return nil, executions.Invalid("namespace and workspace name are required")
	}
	now := time.Now()
	if !auth.HasExecutionPermission(user, p.Namespace, p.WorkspaceName, auth.PermissionExec, now) ||
		!auth.HasExecutionPermission(user, p.Namespace, p.WorkspaceName, auth.PermissionElevated, now) {
		return nil, executions.Forbidden("scoped execution and elevation permissions are required")
	}
	if s.plat == nil {
		return nil, executions.Unavailable("execution policy unavailable")
	}
	policy, err := s.plat.GetVMExecutionPolicy(ctx)
	if err != nil {
		return nil, executions.Unavailable("execution policy unavailable")
	}
	if !policy.Enabled || !policy.AllowElevated {
		return nil, executions.Forbidden("elevated execution is disabled by policy")
	}
	if s.execSvc.Ready(ctx) != nil {
		return nil, executions.Unavailable("execution recording storage unavailable")
	}
	if s.qga == nil {
		return nil, executions.Unavailable("the pilot execution transport is not enabled")
	}
	target, err := s.qga.Resolve(ctx, p.Namespace, p.WorkspaceName)
	if errors.Is(err, qga.ErrDenied) {
		return nil, executions.NotFound("not an eligible running agent-equipped VM")
	}
	if err != nil {
		return nil, executions.Unavailable("workspace is temporarily unavailable")
	}
	result := &executions.ExecutionCapabilities{
		Namespace: p.Namespace, WorkspaceName: p.WorkspaceName, WorkspaceUID: target.WorkspaceUID,
		OsIdentity: target.OSIdentity(), Reason: "Guest does not advertise compatible script support.",
	}
	checker, ok := s.qga.(scriptSupportChecker)
	if !target.Linux || !ok {
		return result, nil
	}
	if err := checker.CheckScriptSupport(ctx, target); err != nil {
		if errors.Is(err, qga.ErrUnsupportedScripts) {
			return result, nil
		}
		if errors.Is(err, qga.ErrDenied) {
			return nil, executions.NotFound("workspace changed during capability discovery")
		}
		return nil, executions.Unavailable("script capability discovery unavailable")
	}
	result.ScriptSupported = true
	result.ScriptRequestVersion = 2
	result.InterpreterPolicy = qga.LinuxScriptPolicy
	result.MaxScriptBytes = qga.MaxScriptBytes
	result.Reason = ""
	return result, nil
}
