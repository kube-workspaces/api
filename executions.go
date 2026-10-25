package kubeworkspaces

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	executions "github.com/kube-workspaces/api/gen/executions"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/qga"
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
	qga         qgaExecutor
	lifecycle   context.Context
}

// qgaExecutor is the opt-in pilot transport surface the start method needs.
type qgaExecutor interface {
	Resolve(ctx context.Context, namespace, name string) (qga.Target, error)
	Execute(ctx context.Context, target qga.Target, command qga.Command) (*qga.GuestResult, error)
}

// ExecutionsOption configures optional executions-service dependencies.
type ExecutionsOption func(*executionssrvc)

// WithIssuerReadiness supplies the management issuer readiness probe reported
// by the status endpoint.
func WithIssuerReadiness(probe func(context.Context) error) ExecutionsOption {
	return func(s *executionssrvc) { s.issuerReady = probe }
}

// WithQGA installs the opt-in QGA pilot transport behind the start method. A
// nil executor leaves start unavailable; the transport is never a fallback.
func WithQGA(executor qgaExecutor) ExecutionsOption {
	return func(s *executionssrvc) { s.qga = executor }
}

// WithLifecycleContext fences a dispatched guest run against process
// shutdown. The caller's request context deliberately does not do that: a
// disconnected client would otherwise fabricate a transport-loss unknown and
// a recording gap for a command that is still running.
func WithLifecycleContext(lifecycle context.Context) ExecutionsOption {
	return func(s *executionssrvc) { s.lifecycle = lifecycle }
}

// NewExecutions returns the executions service implementation.
func NewExecutions(execSvc *execution.Service, plat *platform.ConfigProvider, options ...ExecutionsOption) executions.Service {
	execSvc.WithReplayAuthorizer(managementReplayAuthorizer{})
	s := &executionssrvc{execSvc: execSvc, plat: plat}
	for _, option := range options {
		option(s)
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

// newExecutionID mints the server-owned execution/recording identifiers.
func newExecutionID(prefix string) (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}

// validateStartCommand mirrors the guest's structural pilot bounds so an
// out-of-bounds command is rejected before anything is admitted or staged.
func validateStartCommand(p *executions.StartPayload) error {
	if p.Namespace == "" || p.WorkspaceName == "" || p.Executable == "" {
		return errors.New("namespace, workspace name and executable are required")
	}
	if strings.TrimSpace(p.Executable) != p.Executable || strings.IndexFunc(p.Executable, unicode.IsControl) >= 0 {
		return errors.New("executable is missing or out of bounds")
	}
	if len(p.Args) > qga.MaxArgs {
		return errors.New("too many arguments")
	}
	for _, arg := range p.Args {
		if len(arg) > qga.MaxArgBytes || strings.IndexFunc(arg, unicode.IsControl) >= 0 {
			return errors.New("arguments are out of bounds")
		}
	}
	if p.Cwd != nil {
		cwd := *p.Cwd
		if cwd == "" || len(cwd) > qga.MaxCwdBytes || strings.TrimSpace(cwd) != cwd || strings.IndexFunc(cwd, unicode.IsControl) >= 0 {
			return errors.New("cwd is out of bounds")
		}
	}
	if p.DeadlineSeconds < 1 || p.DeadlineSeconds > qga.MaxDeadlineSeconds {
		return errors.New("deadline_seconds must be between 1 and 20")
	}
	return nil
}

// recordingStart is the committed first recording chunk: the durable record of
// exactly what was requested, before any guest process exists.
type recordingStart struct {
	ProvisioningGeneration string   `json:"provisioning_generation"`
	RevocationEpoch        uint64   `json:"revocation_epoch"`
	Type                   string   `json:"type"`
	Time                   string   `json:"time"`
	Executable             string   `json:"executable"`
	Args                   []string `json:"args"`
	Cwd                    *string  `json:"cwd"`
	DeadlineSeconds        int      `json:"deadline_seconds"`
}

// recordingResult is the committed second recording chunk: the authoritative
// runner outcome, recorded verbatim as guest evidence.
type recordingResult struct {
	Type       string `json:"type"`
	Time       string `json:"time"`
	Outcome    string `json:"outcome"`
	ExitCode   *int   `json:"exit_code"`
	StdoutB64  string `json:"stdout_b64"`
	StderrB64  string `json:"stderr_b64"`
	Truncated  bool   `json:"truncated"`
	DurationMS uint64 `json:"duration_ms"`
	Denial     string `json:"denial"`
}

// mapGuestResult turns the authoritative runner result into the terminal
// storage outcome plus the API outcome/denial. Loss of the runner result — or
// an unrecognized outcome string — is a permanently uncertain outcome, never
// success. Failures that provably happened before any guest process existed
// are recorded as failures instead: recording them as a transport loss would
// invent uncertainty about a command that never ran.
func mapGuestResult(result *qga.GuestResult, execErr error) (storage.ExecutionOutcome, string, string) {
	if errors.Is(execErr, qga.ErrDenied) {
		const revoked = "execution authority changed before dispatch"
		return storage.ExecutionOutcome{State: storage.StateRevoked, Termination: revoked}, "failed", revoked
	}
	if errors.Is(execErr, qga.ErrUnavailable) {
		const notDispatched = "workspace unavailable before dispatch; the command did not run"
		return storage.ExecutionOutcome{State: storage.StateFailed, Termination: "not-dispatched"}, "failed", notDispatched
	}
	if errors.Is(execErr, qga.ErrNotStarted) {
		return storage.ExecutionOutcome{State: storage.StateFailed, Termination: "runner-error"}, "failed", execErr.Error()
	}
	if errors.Is(execErr, qga.ErrRequestTooLarge) {
		return storage.ExecutionOutcome{State: storage.StateFailed, Termination: "request-too-large"}, "failed", execErr.Error()
	}
	if execErr != nil || result == nil {
		const lost = "transport lost; do not rerun"
		return storage.ExecutionOutcome{State: storage.StateUnknown, Termination: lost}, "unknown", lost
	}
	switch result.Outcome {
	case "completed":
		if result.ExitCode != nil && *result.ExitCode != 0 {
			return storage.ExecutionOutcome{State: storage.StateFailed, ExitCode: result.ExitCode}, "failed", result.Denial
		}
		return storage.ExecutionOutcome{State: storage.StateSucceeded, ExitCode: result.ExitCode}, "succeeded", result.Denial
	case "deadline":
		return storage.ExecutionOutcome{State: storage.StateTimedOut, ExitCode: result.ExitCode}, "timed_out", result.Denial
	case "denied":
		denial := result.Denial
		if denial == "" {
			denial = "denied"
		} else {
			denial = "denied:" + denial
		}
		return storage.ExecutionOutcome{State: storage.StateFailed, ExitCode: result.ExitCode, Termination: denial}, "failed", denial
	case "output-limit":
		return storage.ExecutionOutcome{State: storage.StateFailed, ExitCode: result.ExitCode, Termination: "output-limit"}, "failed", result.Denial
	case "runner-error", "spawn-failed":
		denial := result.Denial
		if denial == "" {
			denial = result.Outcome
		}
		return storage.ExecutionOutcome{State: storage.StateFailed, ExitCode: result.ExitCode, Termination: result.Outcome}, "failed", denial
	default:
		const unrecognized = "unrecognized runner outcome"
		return storage.ExecutionOutcome{State: storage.StateUnknown, Termination: unrecognized}, "unknown", unrecognized
	}
}

// Start executes one bounded root/SYSTEM command through the opt-in transport
// and returns its recorded outcome synchronously. Any guest transport loss is
// a terminal unknown outcome; success is only ever reported from a parsed
// runner result. After dispatch the run is bounded by the pilot budget rather
// than the caller's socket, so a disconnect cannot fabricate a transport loss
// or a recording gap.
func (s *executionssrvc) Start(ctx context.Context, p *executions.StartPayload) (*executions.ExecutionCommand, error) {
	user := auth.ExecutionPrincipal(ctx)
	if user == nil {
		return nil, managementError("unauthorized", "sign in with a user-bound credential")
	}
	if p == nil {
		return nil, managementError("invalid", "namespace, workspace name and executable are required")
	}
	if err := validateStartCommand(p); err != nil {
		return nil, managementError("invalid", err.Error())
	}
	// Elevated execution needs both the execution grant and the separately
	// granted elevation, checked against the exact requested scope.
	if !auth.HasExecutionPermission(user, p.Namespace, p.WorkspaceName, auth.PermissionExec, time.Now()) ||
		!auth.HasExecutionPermission(user, p.Namespace, p.WorkspaceName, auth.PermissionElevated, time.Now()) {
		return nil, managementError("forbidden", "scoped execution and elevation permissions are required")
	}
	if s.plat == nil {
		return nil, managementError("unavailable", "execution policy unavailable")
	}
	policy, err := s.plat.GetVMExecutionPolicy(ctx)
	if err != nil {
		return nil, managementError("unavailable", "execution policy unavailable")
	}
	if !policy.Enabled || !policy.AllowElevated {
		return nil, managementError("forbidden", "elevated execution is disabled by policy")
	}
	if s.qga == nil {
		return nil, managementError("unavailable", "the pilot execution transport is not enabled")
	}
	target, err := s.qga.Resolve(ctx, p.Namespace, p.WorkspaceName)
	if err != nil {
		if errors.Is(err, qga.ErrDenied) {
			return nil, managementError("not_found", "not an eligible running agent-equipped VM")
		}
		return nil, managementError("unavailable", "workspace is temporarily unavailable")
	}
	executionID, err := newExecutionID("exec")
	if err != nil {
		return nil, managementError("unavailable", "cannot mint execution identifiers")
	}
	recordingID, err := newExecutionID("rec")
	if err != nil {
		return nil, managementError("unavailable", "cannot mint execution identifiers")
	}
	session, err := s.execSvc.Admit(ctx, execution.AdmissionRequest{
		ExecutionID:   executionID,
		RecordingID:   recordingID,
		ActorID:       user.UID,
		Operation:     storage.OperationCommand,
		Namespace:     p.Namespace,
		WorkspaceName: p.WorkspaceName,
		WorkspaceUID:  target.WorkspaceUID,
		// The QGA transport binds the controller-owned VM UID as the
		// management provisioning generation; grant version 1 is the only
		// version the pilot runner accepts.
		GrantVersion: "1",
		OSIdentity:   target.OSIdentity(),
		Elevated:     true,
	})
	if err != nil {
		return nil, managementError("unavailable", "execution admission unavailable")
	}
	rec := session.Record()
	chunk, err := json.Marshal(recordingStart{
		ProvisioningGeneration: target.VMUID,
		RevocationEpoch:        target.RevocationEpoch,
		Type:                   "start",
		Time:                   time.Now().UTC().Format(time.RFC3339),
		Executable:             p.Executable,
		Args:                   p.Args,
		Cwd:                    p.Cwd,
		DeadlineSeconds:        p.DeadlineSeconds,
	})
	if err == nil {
		err = session.AppendChunk(ctx, chunk)
	}
	if err != nil {
		abortSession(ctx, session, "recording unavailable")
		return nil, managementError("unavailable", "execution recording unavailable")
	}
	if err := session.Start(ctx); err != nil {
		abortSession(ctx, session, "lifecycle transition unavailable")
		return nil, managementError("unavailable", "execution state unavailable")
	}
	// Admission, validation and the committed start chunk stay on the caller's
	// context: a client that disappears before dispatch simply never runs a
	// command. Once the execution has started the caller can no longer abandon
	// it — the run is bounded by the pilot budget instead of the socket, and
	// process shutdown still fences it through the lifecycle context.
	runCtx, cancelRun := s.runContext(ctx, p.DeadlineSeconds)
	defer cancelRun()
	log.Printf(runCtx, "executions.start execution=%s namespace=%s workspace=%s", executionID, p.Namespace, p.WorkspaceName)
	result, execErr := s.qga.Execute(runCtx, target, qga.Command{
		ActorUID:        user.UID,
		ExecutionID:     executionID,
		RecordingID:     recordingID,
		Executable:      p.Executable,
		Args:            p.Args,
		Cwd:             p.Cwd,
		DeadlineSeconds: p.DeadlineSeconds,
	})
	// Finalization gets its own caller-independent budget: even an expired run
	// budget must not turn a known outcome into a recording gap.
	finishCtx, cancelFinish := finalizeContext(ctx)
	defer cancelFinish()
	outcome, apiOutcome, denial := mapGuestResult(result, execErr)
	recorded := recordingResult{
		Type:    "result",
		Time:    time.Now().UTC().Format(time.RFC3339),
		Outcome: apiOutcome,
	}
	if result != nil {
		recorded.Outcome = result.Outcome
		recorded.ExitCode = result.ExitCode
		recorded.StdoutB64 = base64.StdEncoding.EncodeToString(result.Stdout)
		recorded.StderrB64 = base64.StdEncoding.EncodeToString(result.Stderr)
		recorded.Truncated = result.Truncated
		recorded.DurationMS = result.DurationMS
		recorded.Denial = result.Denial
	} else {
		recorded.Denial = denial
	}
	chunk, err = json.Marshal(recorded)
	if err == nil {
		err = session.AppendChunk(finishCtx, chunk)
	}
	if err != nil {
		// Finish marks the execution recording_lost; the guest may have run
		// without durable evidence, so the request fails closed.
		_ = session.Finish(finishCtx, storage.ExecutionOutcome{State: storage.StateRecordingLost, RecordingLost: true})
		return nil, managementError("unavailable", "execution recording lost")
	}
	if err := session.Finish(finishCtx, outcome); err != nil {
		return nil, managementError("unavailable", "execution state unavailable")
	}
	return commandResult(rec, outcome, apiOutcome, denial, result), nil
}

// finalizeBudget bounds the terminal recording/metadata writes of one
// execution independently of the caller and of the guest run budget.
const finalizeBudget = 30 * time.Second

// runContext bounds one guest run independently of the caller's socket while
// preserving the request values (logging, tracing).
func (s *executionssrvc) runContext(req context.Context, deadlineSeconds int) (context.Context, context.CancelFunc) {
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(req), qga.RunBudget(deadlineSeconds))
	if s.lifecycle == nil {
		return runCtx, cancel
	}
	stop := context.AfterFunc(s.lifecycle, cancel)
	return runCtx, func() {
		stop()
		cancel()
	}
}

// finalizeContext gives the terminal recording writes their own bounded,
// caller-independent context.
func finalizeContext(req context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(req), finalizeBudget)
}

// abortSession closes an admitted record whose request context has already
// failed: an execution stuck open forever is worse than a bounded cleanup
// write, and nothing was dispatched on these paths.
func abortSession(ctx context.Context, session *execution.Session, reason string) {
	abortCtx, cancel := finalizeContext(ctx)
	defer cancel()
	_ = session.Abort(abortCtx, reason)
}

func commandResult(rec storage.ExecutionRecord, outcome storage.ExecutionOutcome, apiOutcome, denial string, result *qga.GuestResult) *executions.ExecutionCommand {
	at := rec.AdmissionTime.UTC().Format(time.RFC3339)
	mode := rec.Mode
	durability := string(rec.Durability)
	workspaceUID := rec.WorkspaceUID
	response := &executions.ExecutionCommand{
		ExecutionID:   rec.ExecutionID,
		RecordingID:   rec.RecordingID,
		Namespace:     rec.Namespace,
		WorkspaceName: rec.WorkspaceName,
		WorkspaceUID:  &workspaceUID,
		AdmissionTime: &at,
		Mode:          &mode,
		Durability:    &durability,
		Outcome:       apiOutcome,
		State:         string(outcome.State),
	}
	if outcome.ExitCode != nil {
		code := *outcome.ExitCode
		response.ExitCode = &code
	}
	if result != nil {
		response.Stdout = result.Stdout
		response.Stderr = result.Stderr
		truncated := result.Truncated
		response.Truncated = &truncated
		duration := result.DurationMS
		response.DurationMs = &duration
	}
	if denial != "" {
		response.Denial = &denial
	}
	return response
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
