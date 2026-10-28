package updates

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
)

const (
	MaxJournalBytes          = 16 * 1024
	MaxJournalSequence       = 1_000_000
	AttemptSeconds     int64 = 15 * 60
	RebootWaitSeconds  int64 = 24 * 60 * 60
)

var (
	ErrJournal     = errors.New("invalid update journal")
	ErrFence       = errors.New("update journal binding or owner fence changed")
	ErrTransition  = errors.New("update journal transition denied")
	ErrClock       = errors.New("update journal clock is stale or out of bounds")
	ErrRecording   = errors.New("update journal recording acknowledgment required")
	ErrPersistence = errors.New("update journal persistence outcome unavailable; reload before continuing")
	ErrConflict    = errors.New("update journal compare-and-swap conflict")
)

// JournalBinding must be supplied by authenticated admission/current identity,
// never reconstructed as authority from a guest journal or client annotation.
type JournalBinding struct {
	AttemptID       string `json:"attempt_id"`
	Namespace       string `json:"namespace"`
	WorkspaceName   string `json:"workspace_name"`
	WorkspaceUID    string `json:"workspace_uid"`
	VMUID           string `json:"vm_uid"`
	RevocationEpoch uint64 `json:"revocation_epoch"`
	ActorUID        string `json:"actor_uid"`
	RecordingID     string `json:"recording_id"`
	TargetSHA256    string `json:"target_sha256"`
	PreviousSHA256  string `json:"previous_sha256"`
	InventorySHA256 string `json:"inventory_sha256"`
}

// JournalPlan is a projection of verified manifests and authenticated inventory.
// Its validation is structural, not publisher trust or installation permission.
type JournalPlan struct {
	Binding              JournalBinding `json:"binding"`
	TargetProductCode    string         `json:"target_product_code"`
	PreviousProductCode  string         `json:"previous_product_code"`
	TargetDriverSHA256   string         `json:"target_driver_sha256"`
	PreviousDriverSHA256 string         `json:"previous_driver_sha256"`
	AllowReboot          bool           `json:"allow_reboot"`
}

type JournalAction struct {
	Sequence uint64 `json:"sequence"`
	Kind     string `json:"kind"`
	BootID   string `json:"boot_id"`
}

type ActionReceipt struct {
	Sequence         uint64 `json:"sequence"`
	Kind             string `json:"kind"`
	Outcome          string `json:"outcome"`
	MSICode          *int64 `json:"msi_code"`
	ServiceState     string `json:"service_state"`
	ProductCode      string `json:"product_code"`
	TargetAbsent     bool   `json:"target_absent"`
	DriverSHA256     string `json:"driver_sha256"`
	IdentityVerified bool   `json:"identity_verified"`
	HealthVerified   bool   `json:"health_verified"`
}

type JournalSnapshot struct {
	Version             uint32         `json:"version"`
	Plan                JournalPlan    `json:"plan"`
	Sequence            uint64         `json:"sequence"`
	OwnerFence          uint64         `json:"owner_fence"`
	Phase               string         `json:"phase"`
	Flow                string         `json:"flow"`
	Step                uint32         `json:"step"`
	Active              *JournalAction `json:"active"`
	LastReceipt         *ActionReceipt `json:"last_receipt"`
	Mutated             bool           `json:"mutated"`
	ServiceNeedsRestore bool           `json:"service_needs_restore"`
	CancelRequested     bool           `json:"cancel_requested"`
	RebootCount         uint32         `json:"reboot_count"`
	WaitBootID          string         `json:"wait_boot_id"`
	WaitingSince        int64          `json:"waiting_since"`
	StartedAt           int64          `json:"started_at"`
	UpdatedAt           int64          `json:"updated_at"`
	ExpiresAt           int64          `json:"expires_at"`
	CleanupResult       string         `json:"cleanup_result"`
	Result              string         `json:"result"`
}

// Journal is immutable between successfully persisted transitions.
type Journal struct{ snapshot JournalSnapshot }

type JournalContext struct {
	Binding            JournalBinding
	OwnerFence         uint64
	Now                int64
	BootID             string
	Authorized         bool
	RecordingAvailable bool
	InstallerBusy      bool
}

type JournalEvent struct {
	Kind    string // begin, complete, cancel, rollback, observe_boot, claim, manual, recording_lost, finalize
	Receipt *ActionReceipt
}

// JournalStore must durably and atomically replace the checkpoint only if its
// current digest matches expected. Uncertain writes return an error, even if
// they might have committed. A native ACL/flush/lock adapter is still required.
type JournalStore interface {
	CompareAndSwap(expected string, next []byte) error
}

type JournalAck struct {
	Sequence uint64
	SHA256   string
	Kind     string
}

type JournalTransition struct {
	previous string
	bootID   string
	next     *Journal
	effect   *JournalAction
	ackKind  string
}

func (p JournalPlan) SHA256() string {
	raw, _ := json.Marshal(p)
	return Digest(append([]byte("kw-agent-upgrade-plan/v1\x00"), raw...))
}

// Validate checks only structural journal-plan bounds, not trust or permission.
func (p JournalPlan) Validate() error {
	if !p.valid() {
		return ErrJournal
	}
	return nil
}

func (p JournalPlan) valid() bool {
	b := p.Binding
	for _, s := range []string{b.AttemptID, b.Namespace, b.WorkspaceName, b.WorkspaceUID, b.VMUID, b.ActorUID, b.RecordingID} {
		if !identifier.MatchString(s) {
			return false
		}
	}
	if b.RevocationEpoch > math.MaxInt64 || !validDigest(b.TargetSHA256) || !validDigest(b.PreviousSHA256) || b.TargetSHA256 == b.PreviousSHA256 || !validDigest(b.InventorySHA256) {
		return false
	}
	if !guid.MatchString(p.TargetProductCode) || !guid.MatchString(p.PreviousProductCode) || p.TargetProductCode == p.PreviousProductCode || p.TargetProductCode == AgentUpgradeCode || p.PreviousProductCode == AgentUpgradeCode || p.TargetProductCode == "00000000-0000-0000-0000-000000000000" || p.PreviousProductCode == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	return (p.TargetDriverSHA256 == "" && p.PreviousDriverSHA256 == "") || (validDigest(p.TargetDriverSHA256) && validDigest(p.PreviousDriverSHA256))
}

func NewJournal(plan JournalPlan, owner uint64, now int64) (*Journal, error) {
	if !plan.valid() || owner == 0 || owner > math.MaxInt64 || !validJournalTime(now) {
		return nil, ErrJournal
	}
	return &Journal{snapshot: JournalSnapshot{Version: 1, Plan: plan, OwnerFence: owner, Phase: "ready", Flow: "forward", StartedAt: now, UpdatedAt: now, ExpiresAt: now + AttemptSeconds}}, nil
}

func validJournalTime(now int64) bool {
	return now > 0 && now <= math.MaxInt64-2*RebootWaitSeconds-AttemptSeconds
}

func (j *Journal) Snapshot() JournalSnapshot {
	s := j.snapshot
	if s.Active != nil {
		a := *s.Active
		s.Active = &a
	}
	if s.LastReceipt != nil {
		r := *s.LastReceipt
		if r.MSICode != nil {
			code := *r.MSICode
			r.MSICode = &code
		}
		s.LastReceipt = &r
	}
	return s
}

func (j *Journal) Encode() []byte { raw, _ := json.Marshal(j.snapshot); return raw }
func (j *Journal) SHA256() string {
	return Digest(append([]byte("kw-agent-upgrade-journal/v1\x00"), j.Encode()...))
}

// DecodeJournal needs the admitted plan digest and a trusted checkpoint digest/
// sequence floor. A self-reported hash is corruption detection, not authority.
func DecodeJournal(raw []byte, planDigest, checkpointDigest string, minimumSequence uint64) (*Journal, error) {
	if len(raw) == 0 || len(raw) > MaxJournalBytes || uniqueJSON(raw) != nil || exactFields(raw, reflect.TypeOf(JournalSnapshot{})) != nil {
		return nil, ErrJournal
	}
	var s JournalSnapshot
	if json.Unmarshal(raw, &s) != nil {
		return nil, ErrJournal
	}
	j := &Journal{snapshot: s}
	if !j.valid() || s.Sequence < minimumSequence || s.Plan.SHA256() != planDigest || j.SHA256() != checkpointDigest || !bytes.Equal(j.Encode(), raw) {
		return nil, ErrJournal
	}
	return j, nil
}

func (j *Journal) actions() []string {
	var actions []string
	switch j.snapshot.Flow {
	case "forward":
		actions = []string{"stop_agent", "install_target_msi"}
		if j.snapshot.Plan.TargetDriverSHA256 != "" {
			actions = append(actions, "install_target_driver")
		}
		actions = append(actions, "start_agent", "verify_target")
	case "rollback":
		actions = []string{"stop_agent", "uninstall_target_msi", "install_previous_msi"}
		if j.snapshot.Plan.TargetDriverSHA256 != "" {
			actions = append(actions, "restore_previous_driver")
		}
		actions = append(actions, "start_agent", "verify_previous")
	case "cleanup":
		actions = []string{"start_agent"}
	}
	return actions
}

func (j *Journal) valid() bool {
	s := j.snapshot
	if s.Version != 1 || !s.Plan.valid() || s.Sequence > MaxJournalSequence || s.OwnerFence == 0 || s.OwnerFence > math.MaxInt64 || !validJournalTime(s.StartedAt) || !validJournalTime(s.UpdatedAt) || s.UpdatedAt < s.StartedAt || s.ExpiresAt < s.StartedAt+AttemptSeconds || s.ExpiresAt > s.StartedAt+AttemptSeconds+RebootWaitSeconds || s.RebootCount > 1 {
		return false
	}
	actions := j.actions()
	if len(actions) == 0 || int(s.Step) > len(actions) {
		return false
	}
	if s.Sequence < uint64(s.Step)*2 || (s.Step > 0 && s.LastReceipt == nil) || (s.Flow == "rollback" && !s.Mutated) || (s.Flow == "cleanup" && s.Mutated) || (s.Flow == "forward" && s.Step > 1 && !s.Mutated) {
		return false
	}
	if s.Flow == "cleanup" && s.CleanupResult != "cancelled" && s.CleanupResult != "failed" {
		return false
	}
	if s.Flow != "cleanup" && s.CleanupResult != "" {
		return false
	}
	switch s.Phase {
	case "ready":
		if s.Active != nil || int(s.Step) >= len(actions) || s.Result != "" {
			return false
		}
	case "active":
		if s.Active == nil || int(s.Step) >= len(actions) || s.Active.Kind != actions[s.Step] || s.Result != "" {
			return false
		}
	case "rollback_pending":
		if s.Active != nil || !s.Mutated || s.Flow != "forward" || s.Result != "" {
			return false
		}
	case "awaiting_reboot":
		if s.WaitingSince == 0 || s.WaitBootID == "" || !identifier.MatchString(s.WaitBootID) || s.Result != "" || (s.RebootCount == 1 && s.Active == nil) || (s.Active != nil && (s.Active.Kind != "reboot" || s.RebootCount != 1 || s.Active.BootID != s.WaitBootID)) {
			return false
		}
	case "result_pending", "terminal":
		if !validJournalResult(s.Result) || (s.Active != nil && s.Result != "manual_recovery_required" && s.Result != "recording_lost") {
			return false
		}
		if s.Result == "succeeded" && (s.ServiceNeedsRestore || s.Flow != "forward" || int(s.Step) != len(actions) || !j.healthReceipt(s.LastReceipt, "verify_target")) {
			return false
		}
		if s.Result == "rolled_back" && (s.ServiceNeedsRestore || s.Flow != "rollback" || int(s.Step) != len(actions) || !j.healthReceipt(s.LastReceipt, "verify_previous")) {
			return false
		}
		if s.Result == "cancelled" && (s.Mutated || s.ServiceNeedsRestore) {
			return false
		}
	default:
		return false
	}
	if s.Phase != "awaiting_reboot" && (s.WaitingSince != 0 || s.WaitBootID != "") {
		return false
	}
	if s.WaitingSince < 0 || s.WaitingSince > s.UpdatedAt {
		return false
	}
	if s.Active != nil && (s.Active.Sequence == 0 || s.Active.Sequence > s.Sequence || !identifier.MatchString(s.Active.BootID)) {
		return false
	}
	if s.Active != nil {
		if s.Active.Kind == "reboot" && s.RebootCount != 1 {
			return false
		}
		if s.Active.Kind != "reboot" && (int(s.Step) >= len(actions) || s.Active.Kind != actions[s.Step]) {
			return false
		}
		if mutatingAction(s.Active.Kind) && !s.Mutated {
			return false
		}
		if (s.Active.Kind == "stop_agent" || s.Active.Kind == "start_agent") && !s.ServiceNeedsRestore {
			return false
		}
	}
	if s.LastReceipt != nil && (s.LastReceipt.Sequence == 0 || s.LastReceipt.Sequence > s.Sequence || !j.receiptValid(*s.LastReceipt)) {
		return false
	}
	return true
}

func validJournalResult(s string) bool {
	switch s {
	case "succeeded", "rolled_back", "cancelled", "failed", "manual_recovery_required", "recording_lost":
		return true
	}
	return false
}

func (j *Journal) check(c JournalContext, claim bool) error {
	if !j.valid() {
		return ErrJournal
	}
	if c.Binding != j.snapshot.Plan.Binding || (!claim && c.OwnerFence != j.snapshot.OwnerFence) || (claim && (c.OwnerFence <= j.snapshot.OwnerFence || c.OwnerFence > math.MaxInt64)) {
		return ErrFence
	}
	if !validJournalTime(c.Now) || c.Now < j.snapshot.UpdatedAt || !identifier.MatchString(c.BootID) {
		return ErrClock
	}
	return nil
}

func (j *Journal) Prepare(event JournalEvent, c JournalContext) (*JournalTransition, error) {
	if err := j.check(c, event.Kind == "claim"); err != nil {
		return nil, err
	}
	if j.snapshot.Phase == "terminal" || j.snapshot.Sequence >= MaxJournalSequence {
		return nil, ErrTransition
	}
	n := &Journal{snapshot: j.Snapshot()}
	s := &n.snapshot
	s.Sequence++
	s.UpdatedAt = c.Now
	t := &JournalTransition{previous: j.SHA256(), bootID: c.BootID, next: n}
	switch event.Kind {
	case "begin":
		if !c.Authorized || !c.RecordingAvailable || c.InstallerBusy {
			return nil, ErrTransition
		}
		kind := ""
		switch s.Phase {
		case "ready":
			if c.Now > s.ExpiresAt {
				return nil, ErrClock
			}
			kind = n.actions()[s.Step]
			s.Phase = "active"
		case "awaiting_reboot":
			if s.Active != nil || c.BootID != s.WaitBootID || c.Now-s.WaitingSince > RebootWaitSeconds || !s.Plan.AllowReboot || s.RebootCount != 0 {
				return nil, ErrTransition
			}
			kind = "reboot"
			s.RebootCount = 1
		default:
			return nil, ErrTransition
		}
		s.Active = &JournalAction{Sequence: s.Sequence, Kind: kind, BootID: c.BootID}
		if kind == "stop_agent" || kind == "start_agent" {
			s.ServiceNeedsRestore = true
		}
		if mutatingAction(kind) {
			s.Mutated = true
		}
		a := *s.Active
		t.effect = &a
		t.ackKind = "intent"
	case "complete":
		if s.Phase != "active" || s.Active == nil || event.Receipt == nil || event.Receipt.Sequence != s.Active.Sequence || event.Receipt.Kind != s.Active.Kind || !n.receiptValid(*event.Receipt) {
			return nil, ErrTransition
		}
		r := *event.Receipt
		if r.MSICode != nil {
			code := *r.MSICode
			r.MSICode = &code
		}
		s.LastReceipt = &r
		s.Active = nil
		if r.Outcome == "failed" {
			n.failedAction()
		} else {
			if r.Kind == "start_agent" {
				s.ServiceNeedsRestore = false
			}
			s.Step++
			if r.Outcome == "reboot_required" {
				if s.RebootCount != 0 {
					n.result("manual_recovery_required")
				} else {
					s.Phase = "awaiting_reboot"
					s.WaitingSince = c.Now
					s.WaitBootID = c.BootID
				}
			} else {
				n.afterAction()
			}
		}
	case "cancel":
		if !c.Authorized || s.CancelRequested || s.Phase == "result_pending" || s.Flow != "forward" {
			return nil, ErrTransition
		}
		s.CancelRequested = true
		if s.Phase == "ready" {
			n.afterAction()
		}
	case "rollback":
		if !c.Authorized || !c.RecordingAvailable || s.Phase != "rollback_pending" || c.Now > s.ExpiresAt {
			return nil, ErrTransition
		}
		s.Flow = "rollback"
		s.Step = 0
		s.Phase = "ready"
	case "observe_boot":
		if s.Phase != "awaiting_reboot" || c.BootID == s.WaitBootID {
			return nil, ErrTransition
		}
		if c.Now-s.WaitingSince > RebootWaitSeconds {
			n.result("manual_recovery_required")
		} else {
			s.ExpiresAt += c.Now - s.WaitingSince
			s.Active = nil
			s.RebootCount = 1
			s.WaitingSince = 0
			s.WaitBootID = ""
			n.afterAction()
		}
	case "claim":
		if !c.Authorized {
			return nil, ErrFence
		}
		s.OwnerFence = c.OwnerFence
	case "manual":
		n.result("manual_recovery_required")
	case "recording_lost":
		n.result("recording_lost")
	case "finalize":
		if s.Phase != "result_pending" || !c.RecordingAvailable {
			return nil, ErrTransition
		}
		s.Phase = "terminal"
		t.ackKind = "result"
	default:
		return nil, ErrTransition
	}
	if !n.valid() {
		return nil, ErrJournal
	}
	return t, nil
}

func mutatingAction(s string) bool {
	switch s {
	case "install_target_msi", "install_target_driver", "uninstall_target_msi", "install_previous_msi", "restore_previous_driver":
		return true
	}
	return false
}

func (j *Journal) result(result string) {
	j.snapshot.Phase = "result_pending"
	j.snapshot.Result = result
	j.snapshot.WaitingSince = 0
	j.snapshot.WaitBootID = ""
}

func (j *Journal) failedAction() {
	s := &j.snapshot
	if s.Flow != "forward" {
		j.result("manual_recovery_required")
	} else if s.Mutated {
		s.Phase = "rollback_pending"
	} else if s.ServiceNeedsRestore {
		s.Flow = "cleanup"
		s.Step = 0
		s.Phase = "ready"
		s.CleanupResult = "failed"
	} else {
		j.result("failed")
	}
}

func (j *Journal) afterAction() {
	s := &j.snapshot
	if s.Flow == "forward" && s.CancelRequested {
		if s.Mutated {
			s.Phase = "rollback_pending"
		} else if s.ServiceNeedsRestore {
			s.Flow = "cleanup"
			s.Step = 0
			s.Phase = "ready"
			s.CleanupResult = "cancelled"
		} else {
			j.result("cancelled")
		}
	} else if int(s.Step) == len(j.actions()) {
		switch s.Flow {
		case "forward":
			j.result("succeeded")
		case "rollback":
			j.result("rolled_back")
		case "cleanup":
			j.result(s.CleanupResult)
		}
	} else {
		s.Phase = "ready"
	}
}

func (j *Journal) healthReceipt(r *ActionReceipt, kind string) bool {
	if r == nil || r.Kind != kind || r.Outcome != "ok" || !r.IdentityVerified || !r.HealthVerified {
		return false
	}
	p := j.snapshot.Plan
	product, driver := p.TargetProductCode, p.TargetDriverSHA256
	if kind == "verify_previous" {
		product, driver = p.PreviousProductCode, p.PreviousDriverSHA256
	}
	return r.ProductCode == product && (driver == "" || r.DriverSHA256 == driver)
}

func (j *Journal) receiptValid(r ActionReceipt) bool {
	if r.ServiceState != "" && r.ServiceState != "unknown" && r.ServiceState != "stopped" && r.ServiceState != "running" {
		return false
	}
	if r.ProductCode != "" && (!guid.MatchString(r.ProductCode) || r.ProductCode == "00000000-0000-0000-0000-000000000000") {
		return false
	}
	if r.DriverSHA256 != "" && !validDigest(r.DriverSHA256) {
		return false
	}
	if r.Outcome != "ok" && r.Outcome != "failed" && r.Outcome != "reboot_required" {
		return false
	}
	msi := r.Kind == "install_target_msi" || r.Kind == "uninstall_target_msi" || r.Kind == "install_previous_msi"
	if msi {
		if r.MSICode == nil || *r.MSICode < 0 || *r.MSICode > math.MaxUint32 {
			return false
		}
		expected := "failed"
		switch *r.MSICode {
		case 0:
			expected = "ok"
		case 3010, 1641:
			expected = "reboot_required"
		}
		if r.Outcome != expected {
			return false
		}
	} else if r.MSICode != nil {
		return false
	}
	if r.Outcome == "failed" {
		switch r.Kind {
		case "stop_agent", "start_agent", "install_target_msi", "uninstall_target_msi", "install_previous_msi", "install_target_driver", "restore_previous_driver", "verify_target", "verify_previous":
			return true
		}
		return false
	}
	if r.Outcome == "reboot_required" {
		return msi || r.Kind == "install_target_driver" || r.Kind == "restore_previous_driver"
	}
	p := j.snapshot.Plan
	switch r.Kind {
	case "stop_agent":
		return r.ServiceState == "stopped"
	case "start_agent":
		return r.ServiceState == "running"
	case "install_target_msi":
		return r.ProductCode == p.TargetProductCode
	case "uninstall_target_msi":
		return r.TargetAbsent
	case "install_previous_msi":
		return r.ProductCode == p.PreviousProductCode
	case "install_target_driver":
		return p.TargetDriverSHA256 != "" && r.DriverSHA256 == p.TargetDriverSHA256
	case "restore_previous_driver":
		return p.PreviousDriverSHA256 != "" && r.DriverSHA256 == p.PreviousDriverSHA256
	case "verify_target", "verify_previous":
		return j.healthReceipt(&r, r.Kind)
	}
	return false
}

func (t *JournalTransition) Bytes() []byte    { return t.next.Encode() }
func (t *JournalTransition) SHA256() string   { return t.next.SHA256() }
func (t *JournalTransition) Sequence() uint64 { return t.next.snapshot.Sequence }

// Commit returns an action descriptor only after durable CAS and matching
// off-guest intent acknowledgment. Descriptors are not signed execution grants.
// Any lost/uncertain persistence reply returns no action: reload/reconcile.
func (t *JournalTransition) Commit(store JournalStore, c JournalContext, ack *JournalAck) (*Journal, *JournalAction, error) {
	if store == nil {
		return nil, nil, ErrPersistence
	}
	if err := t.next.check(c, false); err != nil {
		return nil, nil, err
	}
	if c.BootID != t.bootID {
		return nil, nil, ErrFence
	}
	if t.effect != nil && (!c.Authorized || c.InstallerBusy || (t.effect.Kind != "reboot" && c.Now > t.next.snapshot.ExpiresAt)) {
		return nil, nil, ErrFence
	}
	if t.effect != nil && t.effect.Kind == "reboot" && c.Now-t.next.snapshot.WaitingSince > RebootWaitSeconds {
		return nil, nil, ErrClock
	}
	if t.ackKind != "" && (!c.RecordingAvailable || ack == nil || ack.Sequence != t.Sequence() || ack.SHA256 != t.SHA256() || ack.Kind != t.ackKind) {
		return nil, nil, ErrRecording
	}
	if err := store.CompareAndSwap(t.previous, t.Bytes()); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, nil, ErrConflict
		}
		return nil, nil, ErrPersistence
	}
	j := &Journal{snapshot: t.next.Snapshot()}
	if t.effect == nil {
		return j, nil, nil
	}
	a := *t.effect
	return j, &a, nil
}

// Recovery is advisory only. Active actions are observed/reconciled, never
// replayed; callers still need fresh native inventory and authenticated permits.
func (j *Journal) Recovery(c JournalContext) string {
	if j.check(c, false) != nil {
		return "fenced"
	}
	s := j.snapshot
	if s.Phase == "result_pending" {
		if s.Active != nil && c.InstallerBusy {
			return "wait_transaction"
		}
		return "commit_result"
	}
	if s.Phase == "terminal" && s.Active != nil {
		if c.InstallerBusy {
			return "wait_transaction"
		}
		return "manual_recovery"
	}
	if s.Active != nil && s.Active.Kind != "reboot" {
		if c.InstallerBusy {
			return "wait_transaction"
		}
		return "reconcile_action"
	}
	if s.Phase == "awaiting_reboot" {
		if c.Now-s.WaitingSince > RebootWaitSeconds {
			return "manual_recovery"
		}
		if c.BootID != s.WaitBootID {
			return "observe_boot"
		}
		if s.Active != nil || !s.Plan.AllowReboot || s.RebootCount != 0 {
			return "wait_reboot"
		}
	}
	if s.Phase == "terminal" {
		return "report_result"
	}
	if s.Sequence >= MaxJournalSequence {
		return "manual_recovery"
	}
	if !c.Authorized {
		return "fenced"
	}
	if s.Phase != "awaiting_reboot" && c.Now > s.ExpiresAt {
		return "manual_recovery"
	}
	if !c.RecordingAvailable {
		return "wait_recording"
	}
	if c.InstallerBusy {
		return "wait_transaction"
	}
	if s.Phase == "rollback_pending" {
		return "admit_rollback"
	}
	return "request_phase_permit"
}
