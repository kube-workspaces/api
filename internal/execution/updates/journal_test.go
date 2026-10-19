package updates

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

const journalStart int64 = 1700000000

func journalPlan() JournalPlan {
	return JournalPlan{Binding: JournalBinding{AttemptID: "upd-1", Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "workspace-uid", VMUID: "vm-uid", RevocationEpoch: 7, ActorUID: "actor-uid", RecordingID: "rec-1", TargetSHA256: strings.Repeat("1", 64), PreviousSHA256: strings.Repeat("2", 64), InventorySHA256: strings.Repeat("3", 64)}, TargetProductCode: "12345678-1234-1234-1234-123456789abc", PreviousProductCode: "87654321-4321-4321-4321-cba987654321"}
}

type journalStore struct {
	raw             []byte
	writes          int
	fail, loseReply bool
}

func headDigest(raw []byte) string {
	return Digest(append([]byte("kw-agent-upgrade-journal/v1\x00"), raw...))
}
func (s *journalStore) CompareAndSwap(expected string, next []byte) error {
	if expected != headDigest(s.raw) {
		return ErrConflict
	}
	if s.fail {
		return errors.New("synthetic storage outage")
	}
	s.raw = append([]byte{}, next...)
	s.writes++
	if s.loseReply {
		return errors.New("lost durable write reply")
	}
	return nil
}

func journalRig(t *testing.T, plan JournalPlan) (*Journal, *journalStore, JournalContext) {
	t.Helper()
	j, err := NewJournal(plan, 1, journalStart)
	if err != nil {
		t.Fatal(err)
	}
	return j, &journalStore{raw: j.Encode()}, JournalContext{Binding: plan.Binding, OwnerFence: 1, Now: journalStart, BootID: "boot-1", Authorized: true, RecordingAvailable: true}
}

func journalApply(t *testing.T, j *Journal, store *journalStore, c *JournalContext, event JournalEvent) (*Journal, *JournalAction) {
	t.Helper()
	c.Now++
	transition, err := j.Prepare(event, *c)
	if err != nil {
		t.Fatalf("prepare %s: %v", event.Kind, err)
	}
	ack := &JournalAck{Sequence: transition.Sequence(), SHA256: transition.SHA256(), Kind: transition.ackKind}
	next, action, err := transition.Commit(store, *c, ack)
	if err != nil {
		t.Fatalf("commit %s: %v", event.Kind, err)
	}
	return next, action
}

func okReceipt(j *Journal) *ActionReceipt {
	a := j.snapshot.Active
	r := &ActionReceipt{Sequence: a.Sequence, Kind: a.Kind, Outcome: "ok"}
	p := j.snapshot.Plan
	switch a.Kind {
	case "stop_agent":
		r.ServiceState = "stopped"
	case "start_agent":
		r.ServiceState = "running"
	case "install_target_msi":
		code := int64(0)
		r.MSICode = &code
		r.ProductCode = p.TargetProductCode
	case "uninstall_target_msi":
		code := int64(0)
		r.MSICode = &code
		r.TargetAbsent = true
	case "install_previous_msi":
		code := int64(0)
		r.MSICode = &code
		r.ProductCode = p.PreviousProductCode
	case "install_target_driver":
		r.DriverSHA256 = p.TargetDriverSHA256
	case "restore_previous_driver":
		r.DriverSHA256 = p.PreviousDriverSHA256
	case "verify_target":
		r.ProductCode = p.TargetProductCode
		r.DriverSHA256 = p.TargetDriverSHA256
		r.IdentityVerified = true
		r.HealthVerified = true
	case "verify_previous":
		r.ProductCode = p.PreviousProductCode
		r.DriverSHA256 = p.PreviousDriverSHA256
		r.IdentityVerified = true
		r.HealthVerified = true
	}
	return r
}

func journalRound(t *testing.T, j *Journal, s *journalStore, c *JournalContext) *Journal {
	t.Helper()
	j, _ = journalApply(t, j, s, c, JournalEvent{Kind: "begin"})
	j, _ = journalApply(t, j, s, c, JournalEvent{Kind: "complete", Receipt: okReceipt(j)})
	return j
}

func TestJournalSharedWriteAheadFixtureAndRestart(t *testing.T) {
	j, s, c := journalRig(t, journalPlan())
	j = journalRound(t, j, s, &c) // stop service
	j, a := journalApply(t, j, s, &c, JournalEvent{Kind: "begin"})
	if a.Kind != "install_target_msi" || a.Sequence != 3 {
		t.Fatal("wrong write-ahead action", a)
	}
	raw, err := os.ReadFile("testdata/journal-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), j.Encode()) {
		t.Fatalf("Go/Rust checkpoint fixture differs:\n%s", j.Encode())
	}
	reloaded, err := DecodeJournal(s.raw, j.snapshot.Plan.SHA256(), headDigest(s.raw), 3)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Recovery(c) != "reconcile_action" {
		t.Fatal("idle interrupted MSI was replayable")
	}
	c.InstallerBusy = true
	if reloaded.Recovery(c) != "wait_transaction" {
		t.Fatal("active MSI was not left at its safe boundary")
	}
	c.InstallerBusy = false
	if _, err := reloaded.Prepare(JournalEvent{Kind: "begin"}, c); !errors.Is(err, ErrTransition) {
		t.Fatal("interrupted MSI was restarted", err)
	}
	// A trusted, action-specific completion receipt can reconcile the same ID.
	reloaded, _ = journalApply(t, reloaded, s, &c, JournalEvent{Kind: "complete", Receipt: okReceipt(reloaded)})
	if reloaded.snapshot.Step != 2 {
		t.Fatal("reconciled receipt did not advance")
	}
}

func TestJournalNeedsIntentAckAndDurableCASBeforeAction(t *testing.T) {
	for _, failure := range []string{"no-ack", "wrong-digest", "wrong-sequence", "wrong-kind", "before-write", "lost-reply", "changed-boot", "changed-epoch"} {
		t.Run(failure, func(t *testing.T) {
			j, s, c := journalRig(t, journalPlan())
			c.Now++
			transition, err := j.Prepare(JournalEvent{Kind: "begin"}, c)
			if err != nil {
				t.Fatal(err)
			}
			ack := &JournalAck{Sequence: transition.Sequence(), SHA256: transition.SHA256(), Kind: "intent"}
			want := ErrRecording
			switch failure {
			case "no-ack":
				ack = nil
			case "wrong-digest":
				ack.SHA256 = strings.Repeat("0", 64)
			case "wrong-sequence":
				ack.Sequence++
			case "wrong-kind":
				ack.Kind = "result"
			case "before-write":
				s.fail = true
				want = ErrPersistence
			case "lost-reply":
				s.loseReply = true
				want = ErrPersistence
			case "changed-boot":
				c.BootID = "boot-2"
				want = ErrFence
			case "changed-epoch":
				c.Binding.RevocationEpoch++
				want = ErrFence
			}
			next, action, err := transition.Commit(s, c, ack)
			if !errors.Is(err, want) || next != nil || action != nil {
				t.Fatalf("unsafe descriptor after %s: action=%v err=%v", failure, action, err)
			}
			if failure == "lost-reply" {
				reloaded, err := DecodeJournal(s.raw, j.snapshot.Plan.SHA256(), headDigest(s.raw), 1)
				if err != nil {
					t.Fatal(err)
				}
				if reloaded.Recovery(c) != "reconcile_action" {
					t.Fatal("lost commit reply permitted replay")
				}
				if _, _, err := transition.Commit(s, c, ack); !errors.Is(err, ErrConflict) {
					t.Fatal("same transition committed twice", err)
				}
			} else if s.writes != 0 {
				t.Fatal("denied transition changed durable state")
			}
		})
	}
}

func TestJournalOwnerTakeoverAndConcurrentWriterFencing(t *testing.T) {
	j, s, c := journalRig(t, journalPlan())
	c.Now++
	first, _ := j.Prepare(JournalEvent{Kind: "begin"}, c)
	second, _ := j.Prepare(JournalEvent{Kind: "begin"}, c)
	ack := &JournalAck{Sequence: first.Sequence(), SHA256: first.SHA256(), Kind: "intent"}
	j, action, err := first.Commit(s, c, ack)
	if err != nil || action == nil {
		t.Fatal(err)
	}
	if _, a, err := second.Commit(s, c, ack); !errors.Is(err, ErrConflict) || a != nil {
		t.Fatal("two writers dispatched one sequence", err)
	}
	old := c
	c.OwnerFence = 2
	j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "claim"})
	if j.Recovery(old) != "fenced" || j.Recovery(c) != "reconcile_action" {
		t.Fatal("ownership transfer replayed or trusted the old owner")
	}
	if _, err := j.Prepare(JournalEvent{Kind: "claim"}, c); !errors.Is(err, ErrFence) {
		t.Fatal("owner fence did not increase", err)
	}
}

func TestJournalSuccessRequiresHealthAndCommittedResult(t *testing.T) {
	j, s, c := journalRig(t, journalPlan())
	for j.snapshot.Phase == "ready" {
		j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "begin"})
		r := okReceipt(j)
		if r.Kind == "verify_target" {
			r.HealthVerified = false
			if _, err := j.Prepare(JournalEvent{Kind: "complete", Receipt: r}, c); !errors.Is(err, ErrTransition) {
				t.Fatal("MSI success substituted for health evidence")
			}
			r.HealthVerified = true
			r.IdentityVerified = false
			if _, err := j.Prepare(JournalEvent{Kind: "complete", Receipt: r}, c); !errors.Is(err, ErrTransition) {
				t.Fatal("missing identity proof accepted")
			}
			r.IdentityVerified = true
		}
		j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "complete", Receipt: r})
	}
	if j.snapshot.Phase != "result_pending" || j.snapshot.Result != "succeeded" || j.Recovery(c) != "commit_result" {
		t.Fatal("completion skipped result recording")
	}
	c.Now++
	transition, _ := j.Prepare(JournalEvent{Kind: "finalize"}, c)
	if _, _, err := transition.Commit(s, c, nil); !errors.Is(err, ErrRecording) {
		t.Fatal("unrecorded success published")
	}
	j, action, err := transition.Commit(s, c, &JournalAck{Sequence: transition.Sequence(), SHA256: transition.SHA256(), Kind: "result"})
	if err != nil || action != nil || j.Recovery(c) != "report_result" {
		t.Fatal("recorded completion failed", err)
	}
	if _, err := j.Prepare(JournalEvent{Kind: "begin"}, c); !errors.Is(err, ErrTransition) {
		t.Fatal("terminal attempt restarted")
	}
}

func TestJournalCancellationRestoresServiceOrRequiresRollback(t *testing.T) {
	j, s, c := journalRig(t, journalPlan())
	j = journalRound(t, j, s, &c)
	j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "cancel"})
	if j.snapshot.Flow != "cleanup" || j.snapshot.Result != "" {
		t.Fatal("cancel left the old agent service stopped")
	}
	j = journalRound(t, j, s, &c)
	if j.snapshot.Result != "cancelled" || j.snapshot.ServiceNeedsRestore || j.snapshot.Mutated {
		t.Fatal("pre-install cancellation was not safe")
	}

	j, s, c = journalRig(t, journalPlan())
	j = journalRound(t, j, s, &c)
	j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "begin"})
	j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "cancel"})
	if j.snapshot.Active == nil {
		t.Fatal("cancel killed an in-flight installer")
	}
	j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "complete", Receipt: okReceipt(j)})
	if j.snapshot.Phase != "rollback_pending" || j.Recovery(c) != "admit_rollback" {
		t.Fatal("mutated cancellation claimed success")
	}
	if _, err := j.Prepare(JournalEvent{Kind: "begin"}, c); !errors.Is(err, ErrTransition) {
		t.Fatal("rollback lacked separate admission")
	}
	j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "rollback"})
	for j.snapshot.Phase == "ready" {
		j = journalRound(t, j, s, &c)
	}
	if j.snapshot.Result != "rolled_back" || j.snapshot.ServiceNeedsRestore {
		t.Fatal("qualified predecessor was not restored")
	}
}

func TestJournalMSIRebootIsNotSuccessOrRepeatedReboot(t *testing.T) {
	for _, allow := range []bool{false, true} {
		plan := journalPlan()
		plan.AllowReboot = allow
		j, s, c := journalRig(t, plan)
		j = journalRound(t, j, s, &c)
		j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "begin"})
		r := okReceipt(j)
		code := int64(3010)
		r.MSICode = &code
		if _, err := j.Prepare(JournalEvent{Kind: "complete", Receipt: r}, c); !errors.Is(err, ErrTransition) {
			t.Fatal("3010 reported success")
		}
		r.Outcome = "reboot_required"
		j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "complete", Receipt: r})
		if j.snapshot.Phase != "awaiting_reboot" || j.snapshot.Result != "" {
			t.Fatal("reboot requirement became success")
		}
		if _, err := j.Prepare(JournalEvent{Kind: "observe_boot"}, c); !errors.Is(err, ErrTransition) {
			t.Fatal("same boot cleared reboot requirement")
		}
		if allow {
			j, a := journalApply(t, j, s, &c, JournalEvent{Kind: "begin"})
			if a.Kind != "reboot" || j.Recovery(c) != "wait_reboot" {
				t.Fatal("automatic reboot was not write-ahead")
			}
			if _, err := j.Prepare(JournalEvent{Kind: "begin"}, c); !errors.Is(err, ErrTransition) {
				t.Fatal("reboot repeated after restart")
			}
			c.Now += 3600
			c.BootID = "boot-2"
			j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "observe_boot"})
			if j.snapshot.Phase != "ready" || j.snapshot.RebootCount != 1 || j.snapshot.ExpiresAt <= journalStart+AttemptSeconds {
				t.Fatal("reboot recovery lost deadline accounting")
			}
		} else if j.Recovery(c) != "wait_reboot" {
			t.Fatal("reboot without explicit consent")
		}
	}
}

func TestJournalFailureAndClockFencing(t *testing.T) {
	j, s, c := journalRig(t, journalPlan())
	for _, mode := range []string{"revoked", "recording", "foreign-vm", "clock", "deadline"} {
		bad := c
		switch mode {
		case "revoked":
			bad.Authorized = false
		case "recording":
			bad.RecordingAvailable = false
		case "foreign-vm":
			bad.Binding.VMUID = "another-vm"
		case "clock":
			bad.Now--
		case "deadline":
			bad.Now += AttemptSeconds + 1
		}
		if _, err := j.Prepare(JournalEvent{Kind: "begin"}, bad); err == nil {
			t.Fatal("unsafe phase admitted", mode)
		}
	}
	j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "begin"})
	j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "recording_lost"})
	if j.snapshot.Active == nil || j.snapshot.Result != "recording_lost" {
		t.Fatal("recording loss erased uncertain action")
	}
	j, _ = journalApply(t, j, s, &c, JournalEvent{Kind: "finalize"})
	if j.Recovery(c) != "manual_recovery" {
		t.Fatal("unresolved action released as ordinary completion")
	}
}

func TestJournalCodecRejectsRollbackAndMalformedState(t *testing.T) {
	j, s, c := journalRig(t, journalPlan())
	j = journalRound(t, j, s, &c)
	if _, err := DecodeJournal(j.Encode(), j.snapshot.Plan.SHA256(), j.SHA256(), j.snapshot.Sequence+1); !errors.Is(err, ErrJournal) {
		t.Fatal("sequence rollback accepted")
	}
	if _, err := DecodeJournal(j.Encode(), strings.Repeat("4", 64), j.SHA256(), 0); !errors.Is(err, ErrJournal) {
		t.Fatal("wrong admitted plan accepted")
	}
	for _, mutate := range []func(*JournalSnapshot){
		func(s *JournalSnapshot) { s.Phase = "active"; s.Active = nil },
		func(s *JournalSnapshot) { s.Plan.Binding.VMUID = "other-vm" },
		func(s *JournalSnapshot) { s.Sequence = MaxJournalSequence + 1 },
		func(s *JournalSnapshot) { s.Result = "succeeded"; s.Phase = "terminal" },
		func(s *JournalSnapshot) { s.RebootCount = 2 },
		func(s *JournalSnapshot) { s.UpdatedAt = s.StartedAt - 1 },
		func(s *JournalSnapshot) { s.LastReceipt.ServiceState = "arbitrary-log-text" },
	} {
		state := j.Snapshot()
		mutate(&state)
		raw, _ := json.Marshal(state)
		if _, err := DecodeJournal(raw, j.snapshot.Plan.SHA256(), headDigest(raw), 0); !errors.Is(err, ErrJournal) {
			t.Fatal("malformed checkpoint accepted", string(raw))
		}
	}
	for _, raw := range [][]byte{append(j.Encode(), ' '), bytes.Replace(j.Encode(), []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1), bytes.Replace(j.Encode(), []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)} {
		if _, err := DecodeJournal(raw, j.snapshot.Plan.SHA256(), headDigest(raw), 0); !errors.Is(err, ErrJournal) {
			t.Fatal("noncanonical/ambiguous journal accepted")
		}
	}
}
