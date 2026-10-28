package upgrades

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
)

func activeArtifactJournal(t *testing.T, set *VerifiedPhaseArtifacts, f *artifactFixture) *updates.Journal {
	t.Helper()
	plan, err := set.Plan(context.Background(), f.attempt, f.approval)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	j, err := updates.NewJournal(plan, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	transition, err := j.Prepare(updates.JournalEvent{Kind: "begin"}, updates.JournalContext{
		Binding: plan.Binding, OwnerFence: 1, Now: now, BootID: "boot-1", Authorized: true, RecordingAvailable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	j, err = updates.DecodeJournal(transition.Bytes(), plan.SHA256(), transition.SHA256(), transition.Sequence())
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestArtifactAuthorityRequiresBaseAndCurrentApprovalAtBothBoundaries(t *testing.T) {
	for _, mode := range []string{"enabled", "revoked-before", "revoked-during-exchange", "policy-outage", "base-denied", "base-outage"} {
		t.Run(mode, func(t *testing.T) {
			f := newArtifactFixture(t)
			set, err := f.verify()
			if err != nil {
				t.Fatal(err)
			}
			j := activeArtifactJournal(t, set, f)
			base := &phaseSourceProbe{current: PhaseContext{BootID: "boot-1", Challenge: "synthetic-challenge", PeerSHA256: "synthetic-peer"}}
			reads, exchanges := 0, 0
			base.onCurrent = func() { exchanges++ }
			var policyErr error
			authority, err := NewArtifactPhaseAuthority(base, set, func(context.Context) (ArtifactApproval, error) { reads++; return f.approval, policyErr })
			if err != nil {
				t.Fatal(err)
			}
			if err := authority.CheckIntent(context.Background(), f.attempt, j); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "revoked-before":
				delete(f.approval.Targets, f.target.TargetID)
			case "revoked-during-exchange":
				base.onCurrent = func() { exchanges++; delete(f.approval.Targets, f.previous.TargetID) }
			case "policy-outage":
				policyErr = errors.New("approval unavailable")
			case "base-denied":
				base.currentErr = ErrDenied
			case "base-outage":
				base.currentErr = ErrUnavailable
			}
			result, err := authority.CurrentPhase(context.Background(), f.attempt, j)
			if mode == "enabled" {
				if err != nil || result != base.current || reads != 3 || exchanges != 1 {
					t.Fatalf("missing approval/base checks: %+v %v reads=%d exchanges=%d", result, err, reads, exchanges)
				}
			} else if err == nil || result != (PhaseContext{}) {
				t.Fatal("revoked/unavailable composition returned authority context")
			}
			if (mode == "revoked-before" || mode == "policy-outage") && exchanges != 0 {
				t.Fatal("unapproved artifact reached guest exchange")
			}
		})
	}
}

func TestArtifactAuthorityNoPermissiveOrZeroValueFallback(t *testing.T) {
	f := newArtifactFixture(t)
	set, err := f.verify()
	if err != nil {
		t.Fatal(err)
	}
	j := activeArtifactJournal(t, set, f)
	base := &phaseSourceProbe{}
	reader := func(context.Context) (ArtifactApproval, error) { return f.approval, nil }
	for _, test := range []struct {
		base   PhaseAuthoritySource
		set    *VerifiedPhaseArtifacts
		reader ArtifactApprovalReader
	}{
		{nil, set, reader}, {base, nil, reader}, {base, set, nil},
	} {
		if _, err := NewArtifactPhaseAuthority(test.base, test.set, test.reader); err == nil {
			t.Fatal("missing required dependency accepted")
		}
	}
	for _, authority := range []*ArtifactPhaseAuthority{nil, {}} {
		if err := authority.CheckIntent(context.Background(), storage.AgentUpgradeAttempt{}, j); err == nil {
			t.Fatal("zero-value source authorized intent")
		}
		if result, err := authority.CurrentPhase(context.Background(), storage.AgentUpgradeAttempt{}, j); err == nil || result != (PhaseContext{}) {
			t.Fatal("zero-value source returned authority")
		}
	}
	base.intentErr = ErrDenied
	authority, err := NewArtifactPhaseAuthority(base, set, reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.CheckIntent(context.Background(), f.attempt, j); !errors.Is(err, ErrDenied) {
		t.Fatal("artifact approval bypassed base intent denial", err)
	}
}
