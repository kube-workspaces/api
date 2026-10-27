package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sampleTerminalIntent(recordingID string) TerminalIntent {
	rec := sampleRecord("terminal-execution")
	rec.RecordingID, rec.ActorID, rec.OSIdentity = recordingID, "protected-actor", "root"
	rec.GrantVersion, rec.Elevated = "policy-1", true
	rec.AdmissionTime = time.Date(2026, 10, 27, 0, 0, 0, 123456000, time.UTC)
	code := 7
	return TerminalIntent{Version: 1, Admission: rec, Outcome: ExecutionOutcome{
		State: StateFailed, StartTime: rec.AdmissionTime.Add(time.Second), EndTime: rec.AdmissionTime.Add(2 * time.Second), ExitCode: &code, Termination: "protected-termination",
	}}
}

func TestTerminalIntentEncryptionAndBindings(t *testing.T) {
	intent := sampleTerminalIntent("recording")
	for _, state := range []State{StateSucceeded, StateFailed, StateTimedOut, StateCancelled, StateRevoked, StateUnknown, StateRecordingLost} {
		terminal := intent
		terminal.Outcome.State, terminal.Outcome.RecordingLost = state, state == StateRecordingLost
		sealed, err := sealTerminalIntent(testKey(), "key", "recording", terminal)
		if err != nil {
			t.Fatal(err)
		}
		got, err := openTerminalIntent(testKey(), "key", "recording", sealed)
		if err != nil || got.Outcome.State != state || got.Outcome.RecordingLost != terminal.Outcome.RecordingLost {
			t.Fatalf("terminal outcome changed: %+v %v", got, err)
		}
	}
	sealed, err := sealTerminalIntent(testKey(), "key", "recording", intent)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{intent.Admission.ActorID, intent.Admission.WorkspaceUID, intent.Outcome.Termination} {
		if bytes.Contains(sealed, []byte(secret)) {
			t.Fatal("terminal intent leaked plaintext")
		}
	}
	got, err := openTerminalIntent(testKey(), "key", "recording", sealed)
	if err != nil || !reflect.DeepEqual(got, &intent) || !got.MatchesAdmission(intent.Admission) {
		t.Fatalf("terminal intent round trip: %+v %v", got, err)
	}
	for _, change := range []struct {
		name   string
		mutate func(*ExecutionRecord)
	}{
		{"execution", func(r *ExecutionRecord) { r.ExecutionID += "-other" }},
		{"recording", func(r *ExecutionRecord) { r.RecordingID += "-other" }},
		{"actor", func(r *ExecutionRecord) { r.ActorID += "-other" }},
		{"namespace", func(r *ExecutionRecord) { r.Namespace += "-other" }},
		{"workspace", func(r *ExecutionRecord) { r.WorkspaceName += "-other" }},
		{"workspace-uid", func(r *ExecutionRecord) { r.WorkspaceUID += "-other" }},
		{"generation", func(r *ExecutionRecord) { r.WorkspaceGeneration++ }},
		{"operation", func(r *ExecutionRecord) { r.Operation = OperationShell }},
		{"grant", func(r *ExecutionRecord) { r.GrantVersion += "-other" }},
		{"identity", func(r *ExecutionRecord) { r.OSIdentity = "SYSTEM" }},
		{"elevation", func(r *ExecutionRecord) { r.Elevated = false }},
		{"mode", func(r *ExecutionRecord) { r.Mode = "external" }},
		{"durability", func(r *ExecutionRecord) { r.Durability = DurabilityDurable }},
		{"admission-time", func(r *ExecutionRecord) { r.AdmissionTime = r.AdmissionTime.Add(time.Microsecond) }},
		{"admitted", func(r *ExecutionRecord) { r.Admitted = false }},
	} {
		t.Run(change.name, func(t *testing.T) {
			rec := intent.Admission
			change.mutate(&rec)
			if got.MatchesAdmission(rec) {
				t.Fatal("substituted admission matched terminal intent")
			}
		})
	}
	for _, tc := range []struct {
		name, keyID, recordingID string
		key, payload             []byte
	}{
		{"other-key", "key", "recording", bytes.Repeat([]byte{9}, 32), sealed},
		{"other-key-id", "other-key", "recording", testKey(), sealed},
		{"other-recording", "key", "other", testKey(), sealed},
		{"truncated", "key", "recording", testKey(), sealed[:len(sealed)-1]},
		{"missing", "key", "recording", testKey(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := openTerminalIntent(tc.key, tc.keyID, tc.recordingID, tc.payload); !errors.Is(err, ErrTampered) {
				t.Fatalf("substitution accepted: %v", err)
			}
		})
	}
	for _, index := range []int{0, len(sealed) - 1} {
		corrupt := append([]byte(nil), sealed...)
		corrupt[index] ^= 1
		if _, err := openTerminalIntent(testKey(), "key", "recording", corrupt); !errors.Is(err, ErrTampered) {
			t.Fatal("modified terminal intent accepted")
		}
	}
	gcm, _ := newGCM(testKey())
	raw, _ := json.Marshal(intent)
	if _, err := openTerminalIntent(testKey(), "key", "recording", sealChunk(gcm, "recording", "key", 0, raw)); !errors.Is(err, ErrTampered) {
		t.Fatal("recording chunk accepted as terminal intent")
	}
}

func TestTerminalIntentValidationAndManifestVersions(t *testing.T) {
	// Fixed pre-extension v1 serialization/signature. A zero/omitted new field
	// must not alter the existing authentication contract.
	const legacy = `{"authentication":"5157256518c82eabe3fffaaa37069c6dcec980b911dc852adc4b8d68f78f4f29","version":1,"recordingID":"legacy","keyID":"key","chunks":0,"plaintextBytes":0,"chain":"legacy-chain","createdAt":"2026-10-27T00:00:00Z","finalizedAt":"2026-10-27T00:00:01Z"}`
	var old Manifest
	if json.Unmarshal([]byte(legacy), &old) != nil || verifyManifest(testKey(), "key", "legacy", old) != nil {
		t.Fatal("legacy v1 authentication changed")
	}
	intent := sampleTerminalIntent("recording")
	for _, mutate := range []func(*TerminalIntent){
		func(i *TerminalIntent) { i.Version = 2 },
		func(i *TerminalIntent) { i.Admission.RecordingID = "other" },
		func(i *TerminalIntent) { i.Admission.ActorID = "" },
		func(i *TerminalIntent) { i.Admission.WorkspaceUID = "" },
		func(i *TerminalIntent) { i.Admission.Admitted = false },
		func(i *TerminalIntent) { i.Admission.Operation = "other" },
		func(i *TerminalIntent) { i.Admission.Mode = "disabled" },
		func(i *TerminalIntent) { i.Admission.Durability = DurabilityDurable },
		func(i *TerminalIntent) { i.Outcome.State = StateRunning },
		func(i *TerminalIntent) { i.Outcome.EndTime = time.Time{} },
		func(i *TerminalIntent) { i.Outcome.EndTime = i.Admission.AdmissionTime.Add(-time.Second) },
		func(i *TerminalIntent) { i.Outcome.RecordingLost = true },
	} {
		bad := intent
		mutate(&bad)
		if _, err := sealTerminalIntent(testKey(), "key", "recording", bad); !errors.Is(err, ErrConflict) {
			t.Fatalf("invalid terminal intent accepted: %v", err)
		}
	}
	oversized := intent
	oversized.Outcome.Termination = strings.Repeat("x", maxTerminalIntentBytes)
	if _, err := sealTerminalIntent(testKey(), "key", "recording", oversized); !errors.Is(err, ErrChunkTooLarge) {
		t.Fatalf("oversized intent accepted: %v", err)
	}
	m := Manifest{Version: 1, KeyID: "key", RecordingID: "recording"}
	meta := FinalizeMeta{ActorID: intent.Admission.ActorID, EndTime: intent.Outcome.EndTime, Terminal: &intent}
	bad := meta
	bad.ActorID = "other"
	if err := protectTerminalIntent(&m, testKey(), bad); !errors.Is(err, ErrConflict) {
		t.Fatal("finalizer actor substitution accepted")
	}
	bad = meta
	bad.EndTime = bad.EndTime.Add(time.Second)
	if err := protectTerminalIntent(&m, testKey(), bad); !errors.Is(err, ErrConflict) {
		t.Fatal("finalizer time substitution accepted")
	}
	if err := protectTerminalIntent(&m, testKey(), meta); err != nil {
		t.Fatal(err)
	}
	m.Authentication = manifestAuthentication(testKey(), m)
	if m.Version != 2 || verifyManifest(testKey(), "key", "recording", m) != nil {
		t.Fatal("version 2 manifest rejected")
	}
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.Version = 1 },
		func(m *Manifest) { m.Version = 3 },
		func(m *Manifest) { m.Terminal = nil },
	} {
		bad := m
		mutate(&bad)
		bad.Authentication = manifestAuthentication(testKey(), bad)
		if err := verifyManifest(testKey(), "key", "recording", bad); !errors.Is(err, ErrTampered) {
			t.Fatal("malformed/downgraded manifest accepted")
		}
	}
}

func TestEphemeralTerminalIntentAndLegacyPlayback(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{true: "legacy-v1", false: "terminal-v2"}[legacy], func(t *testing.T) {
			ctx := context.Background()
			s, dir := newTestRecording(t, 1<<20)
			w, err := s.Begin(ctx, "recording")
			if err != nil {
				t.Fatal(err)
			}
			if err := w.PutChunk(ctx, 0, []byte("protected output")); err != nil {
				t.Fatal(err)
			}
			intent := sampleTerminalIntent("recording")
			meta := FinalizeMeta{}
			if !legacy {
				meta = FinalizeMeta{ActorID: intent.Admission.ActorID, EndTime: intent.Outcome.EndTime, Terminal: &intent}
			}
			if err := w.Finalize(ctx, meta); err != nil {
				t.Fatal(err)
			}
			r, err := s.Open(ctx, "recording")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := r.TerminalIntent(ctx)
			if legacy {
				if !errors.Is(err, ErrNoTerminalIntent) || r.Manifest().Version != 1 {
					t.Fatalf("legacy evidence was invented: %v", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, &intent) {
				t.Fatalf("terminal intent not retained: %+v %v", got, err)
			}
			copy := r.Manifest()
			copy.Terminal[0] ^= 1
			if _, err := r.TerminalIntent(ctx); err != nil {
				t.Fatal("Manifest exposed mutable reader ciphertext")
			}
			// A verified manifest alone is insufficient; missing output must
			// also fence retrieval of the intended terminal metadata.
			if err := os.Remove(filepath.Join(dir, "recordings", "recording", "chunk-0000000000000000.bin")); err != nil {
				t.Fatal(err)
			}
			if _, err := r.TerminalIntent(ctx); !errors.Is(err, ErrTruncated) {
				t.Fatalf("terminal evidence returned from incomplete recording: %v", err)
			}
		})
	}
}

func TestEphemeralTerminalIntentUsesRecordingBudget(t *testing.T) {
	ctx := context.Background()
	s, dir := newTestRecording(t, 64)
	w, err := s.Begin(ctx, "recording")
	if err != nil {
		t.Fatal(err)
	}
	intent := sampleTerminalIntent("recording")
	if err := w.Finalize(ctx, FinalizeMeta{ActorID: intent.Admission.ActorID, EndTime: intent.Outcome.EndTime, Terminal: &intent}); !errors.Is(err, ErrOverCapacity) {
		t.Fatalf("terminal intent bypassed recording cap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "recordings", "recording", "manifest.json")); !os.IsNotExist(err) {
		t.Fatal("over-budget terminal manifest was written")
	}
}
