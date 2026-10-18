package kubeworkspaces

import (
	"context"
	"errors"
	"time"

	executions "github.com/kube-workspaces/api/gen/executions"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/platform"
	"goa.design/clue/log"
)

// managementError maps internal failures to the explicitly designed HTTP errors.
func managementError(name, message string) error {
	switch name {
	case "unauthorized":
		return executions.Unauthorized(message)
	case "forbidden":
		return executions.Forbidden(message)
	case "not_found":
		return executions.NotFound(message)
	case "invalid":
		return executions.Invalid(message)
	default:
		return executions.Unavailable(message)
	}
}

// executions service implementation.
type executionssrvc struct {
	execSvc     *execution.Service
	plat        *platform.ConfigProvider
	issuerReady func(context.Context) error
}

// NewExecutions returns the executions service implementation.
func NewExecutions(execSvc *execution.Service, plat *platform.ConfigProvider, issuerReadiness ...func(context.Context) error) executions.Service {
	execSvc.WithReplayAuthorizer(managementReplayAuthorizer{})
	s := &executionssrvc{execSvc: execSvc, plat: plat}
	if len(issuerReadiness) > 0 {
		s.issuerReady = issuerReadiness[0]
	}
	return s
}

type managementReplayAuthorizer struct{}

func (managementReplayAuthorizer) AuthorizeReplay(ctx context.Context, actor string, rec storage.ExecutionRecord) error {
	u := auth.ExecutionPrincipal(ctx)
	if u == nil || u.UID != actor || !auth.HasExecutionPermission(u, rec.Namespace, rec.WorkspaceName, auth.PermissionReadRecordings, time.Now()) {
		return execution.ErrAdmissionDenied
	}
	return nil
}

func (s *executionssrvc) replay(ctx context.Context, id string) (storage.Reader, error) {
	u := auth.ExecutionPrincipal(ctx)
	if u == nil {
		return nil, managementError("unauthorized", "sign in with a user-bound credential")
	}
	r, _, err := s.execSvc.Replay(ctx, u.UID, id)
	if errors.Is(err, execution.ErrAdmissionDenied) && !errors.Is(err, storage.ErrDisabled) && !errors.Is(err, storage.ErrNotReady) {
		return nil, managementError("forbidden", "recording access denied")
	}
	if err != nil {
		return nil, managementReadError(err)
	}
	return r, nil
}

func (s *executionssrvc) Manifest(ctx context.Context, p *executions.ManifestPayload) (*executions.ExecutionRecordingManifest, error) {
	if p == nil || p.ExecutionID == "" {
		return nil, executions.Invalid("execution id required")
	}
	r, err := s.replay(ctx, p.ExecutionID)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	m := r.Manifest()
	return &executions.ExecutionRecordingManifest{RecordingID: m.RecordingID, Chunks: m.Chunks, PlaintextBytes: m.PlaintextBytes, Verified: true}, nil
}

func (s *executionssrvc) Chunk(ctx context.Context, p *executions.ChunkPayload) (*executions.ExecutionRecordingChunk, error) {
	if p == nil || p.ExecutionID == "" {
		return nil, executions.Invalid("execution id required")
	}
	r, err := s.replay(ctx, p.ExecutionID)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := r.ReadChunk(ctx, p.Index)
	if err != nil {
		return nil, managementReadError(err)
	}
	return &executions.ExecutionRecordingChunk{Index: p.Index, Data: data}, nil
}

// Status returns execution management status.
func (s *executionssrvc) Status(ctx context.Context) (*executions.ExecutionStatus, error) {
	if auth.ExecutionPrincipal(ctx) == nil {
		return nil, managementError("unauthorized", "sign in with a user-bound credential")
	}
	log.Printf(ctx, "executions.status")
	mode, durable, available := s.execSvc.RecordingStatus(ctx)
	if s.plat == nil {
		return nil, executions.Unavailable("execution policy unavailable")
	}
	policy, err := s.plat.GetVMExecutionPolicy(ctx)
	if err != nil {
		return nil, managementError("unavailable", "execution policy unavailable")
	}
	return &executions.ExecutionStatus{
		Enabled:          policy.Enabled,
		AllowElevated:    policy.AllowElevated,
		StorageMode:      mode,
		Durable:          durable,
		StorageAvailable: available,
		IssuerReady:      policy.Enabled && available && s.issuerReady != nil && s.issuerReady(ctx) == nil,
	}, nil
}

// List returns execution records visible to the actor.
func (s *executionssrvc) List(ctx context.Context, p *executions.ListPayload) ([]*executions.ExecutionRecord, error) {
	user := auth.ExecutionPrincipal(ctx)
	if user == nil {
		return nil, managementError("unauthorized", "sign in with a user-bound credential")
	}
	log.Printf(ctx, "executions.list")
	f := storage.Filter{}
	if p != nil {
		if p.Namespace != nil {
			f.Namespace = *p.Namespace
		}
		if p.WorkspaceName != nil {
			f.WorkspaceName = *p.WorkspaceName
		}
		if p.ActorID != nil {
			f.ActorID = *p.ActorID
		}
		if p.Since != nil {
			t, err := time.Parse(time.RFC3339, *p.Since)
			if err != nil {
				return nil, managementError("invalid", "invalid since timestamp")
			}
			f.Since = t
		}
		f.Limit = p.Limit
	}
	// Require an exact workspace before querying: filtering only after a global
	// limit would both leak scope and hide authorized results behind other rows.
	if !auth.HasExecutionPermission(user, f.Namespace, f.WorkspaceName, auth.PermissionManage, time.Now()) {
		return nil, managementError("forbidden", "scoped execution management permission required")
	}
	if f.Limit == 0 {
		f.Limit = 100
	}
	if f.Limit < 1 || f.Limit > 1000 {
		return nil, managementError("invalid", "limit must be between 1 and 1000")
	}
	recs, err := s.execSvc.List(ctx, f)
	if err != nil {
		return nil, managementReadError(err)
	}
	out := make([]*executions.ExecutionRecord, 0, len(recs))
	for _, rec := range recs {
		_, outcome, err := s.execSvc.Get(ctx, rec.ExecutionID)
		if err != nil {
			return nil, managementReadError(err)
		}
		out = append(out, recordToResult(rec, outcome))
	}
	return out, nil
}

// Get returns a single execution record.
func (s *executionssrvc) Get(ctx context.Context, p *executions.GetPayload) (*executions.ExecutionRecord, error) {
	user := auth.ExecutionPrincipal(ctx)
	if user == nil {
		return nil, managementError("unauthorized", "sign in with a user-bound credential")
	}
	if p == nil || p.ExecutionID == "" {
		return nil, managementError("invalid", "execution id required")
	}
	log.Printf(ctx, "executions.get")
	rec, outcome, err := s.execSvc.Get(ctx, p.ExecutionID)
	if err != nil {
		return nil, managementReadError(err)
	}
	if !auth.HasExecutionPermission(user, rec.Namespace, rec.WorkspaceName, auth.PermissionManage, time.Now()) {
		return nil, managementError("not_found", "execution not found")
	}
	return recordToResult(rec, outcome), nil
}

func managementReadError(err error) error {
	if errors.Is(err, storage.ErrNotFound) {
		return managementError("not_found", "execution not found")
	}
	return managementError("unavailable", "execution storage unavailable")
}

func recordToResult(rec storage.ExecutionRecord, outcome storage.ExecutionOutcome) *executions.ExecutionRecord {
	at := rec.AdmissionTime.UTC().Format(time.RFC3339)
	out := &executions.ExecutionRecord{
		ExecutionID:         rec.ExecutionID,
		Operation:           string(rec.Operation),
		Namespace:           rec.Namespace,
		WorkspaceName:       rec.WorkspaceName,
		RecordingID:         rec.RecordingID,
		Mode:                rec.Mode,
		Durability:          string(rec.Durability),
		Admitted:            rec.Admitted,
		AdmissionTime:       at,
		ActorID:             &rec.ActorID,
		WorkspaceUID:        &rec.WorkspaceUID,
		WorkspaceGeneration: &rec.WorkspaceGeneration,
		GrantVersion:        &rec.GrantVersion,
		OsIdentity:          &rec.OSIdentity,
		Elevated:            &rec.Elevated,
	}
	if rec.DenyReason != "" {
		out.DenyReason = &rec.DenyReason
	}
	state := string(outcome.State)
	if state == "" {
		state = string(storage.StateAdmitted)
	}
	out.State = &state
	if !outcome.StartTime.IsZero() {
		s := outcome.StartTime.UTC().Format(time.RFC3339)
		out.StartTime = &s
	}
	if !outcome.EndTime.IsZero() {
		e := outcome.EndTime.UTC().Format(time.RFC3339)
		out.EndTime = &e
	}
	if outcome.ExitCode != nil {
		c := *outcome.ExitCode
		out.ExitCode = &c
	}
	if outcome.Termination != "" {
		t := outcome.Termination
		out.Termination = &t
	}
	lost := outcome.RecordingLost
	out.RecordingLost = &lost
	return out
}
