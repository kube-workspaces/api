package kubeworkspaces

import (
	"context"
	"time"

	executions "github.com/kube-workspaces/api/gen/executions"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/platform"
	"goa.design/clue/log"
)

// executions service implementation.
type executionssrvc struct {
	execSvc *execution.Service
	plat    *platform.ConfigProvider
}

// NewExecutions returns the executions service implementation.
func NewExecutions(execSvc *execution.Service, plat *platform.ConfigProvider) executions.Service {
	return &executionssrvc{execSvc: execSvc, plat: plat}
}

// Status returns execution management status.
func (s *executionssrvc) Status(ctx context.Context) (*executions.ExecutionStatus, error) {
	log.Printf(ctx, "executions.status")
	mode, durable, available := s.execSvc.RecordingStatus(ctx)
	policy, err := s.plat.GetVMExecutionPolicy(ctx)
	if err != nil {
		policy = platform.VMExecutionPolicy{}
	}
	return &executions.ExecutionStatus{
		Enabled:          policy.Enabled,
		AllowElevated:    policy.AllowElevated,
		StorageMode:      mode,
		Durable:          durable,
		StorageAvailable: available,
	}, nil
}

// List returns execution records visible to the actor.
func (s *executionssrvc) List(ctx context.Context, p *executions.ListPayload) ([]*executions.ExecutionRecord, error) {
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
			if t, err := time.Parse(time.RFC3339, *p.Since); err == nil {
				f.Since = t
			}
		}
		if p.Limit > 0 {
			f.Limit = p.Limit
		}
	}
	recs, err := s.execSvc.List(ctx, f)
	if err != nil {
		return nil, err
	}
	out := make([]*executions.ExecutionRecord, 0, len(recs))
	for _, rec := range recs {
		out = append(out, recordToResult(rec, storage.ExecutionOutcome{}))
	}
	return out, nil
}

// Get returns a single execution record.
func (s *executionssrvc) Get(ctx context.Context, p *executions.GetPayload) (*executions.ExecutionRecord, error) {
	log.Printf(ctx, "executions.get")
	rec, outcome, err := s.execSvc.Get(ctx, p.ExecutionID)
	if err != nil {
		return nil, err
	}
	return recordToResult(rec, outcome), nil
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
