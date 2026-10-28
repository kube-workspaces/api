package upgrades

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestPhaseRecorderDeniesEphemeralOrDisabled(t *testing.T) {
	s, _, _ := newUpgradeTestService(t)
	a, _, err := s.Admit(context.Background(), admitRequest("ephemeral-recorder"))
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []*Service{s, NewService(nil, nil)} {
		r, err := service.RecordPhaseIntent(context.Background(), a, []byte("checkpoint"))
		if err == nil || r != (storage.PhaseRecordingReceipt{}) {
			t.Fatalf("non-durable recorder returned receipt: %+v %v", r, err)
		}
	}
}

type phaseObjectFault struct {
	deny, loseACK bool
	afterPut      func()
}

// This executes the REAL admission session, encrypted recorder, PostgreSQL phase
// ledger and signer. Only live identity/artifact/policy/guest exchange is a double.
// Use explicitly supplied disposable services, never deployment storage.
func TestPhaseRecorderPersistentIntegration(t *testing.T) {
	dsn, endpoint := os.Getenv("KW_EXECUTION_TEST_DATABASE_URL"), os.Getenv("KW_EXECUTION_TEST_S3_ENDPOINT")
	if dsn == "" || endpoint == "" {
		t.Skip("set KW_EXECUTION_TEST_DATABASE_URL and KW_EXECUTION_TEST_S3_ENDPOINT for disposable storage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	upstream, err := url.Parse(endpoint)
	if err != nil || upstream.Host == "" {
		t.Fatal("invalid disposable S3 endpoint")
	}
	var rule atomic.Pointer[phaseObjectFault]
	var puts atomic.Int64
	const phaseSuffix = "/chunks/0000000000000001.chunk"
	const denied = "<Error><Code>AccessDenied</Code><Message>disposable phase recorder fault</Message></Error>"
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ModifyResponse = func(response *http.Response) error {
		fault := rule.Load()
		if fault == nil || response.Request.Method != http.MethodPut || !strings.HasSuffix(response.Request.URL.Path, phaseSuffix) || response.StatusCode/100 != 2 {
			return nil
		}
		if fault.afterPut != nil {
			fault.afterPut()
		}
		if fault.loseACK {
			// The upstream object is REAL and committed. Replace only the ACK
			// with a nonretryable S3 error, without replacing recorder code.
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			response.StatusCode, response.Status = http.StatusForbidden, "403 Forbidden"
			response.Body = io.NopCloser(strings.NewReader(denied))
			response.ContentLength = int64(len(denied))
			response.Header.Set("Content-Type", "application/xml")
			response.Header.Set("Content-Length", strconv.Itoa(len(denied)))
		}
		return nil
	}
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
			fault := rule.Load()
			if fault != nil && fault.deny && strings.HasSuffix(r.URL.Path, phaseSuffix) {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, denied)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	defer gate.Close()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	opts := storage.Options{Mode: "external", DatabaseURL: dsn, RecordingKey: key, KeyID: storage.DeriveKeyID(key), S3: storage.S3Options{
		Endpoint: gate.URL, Region: "us-east-1", Bucket: "upgrade-phase-recorder-integration", CreateBucket: true, ForcePathStyle: true,
		AccessKey: os.Getenv("KW_EXECUTION_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("KW_EXECUTION_TEST_S3_SECRET_KEY"),
	}}
	store, err := storage.Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	attempts, err := storage.NewPostgresAgentUpgrades(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer attempts.Close()
	ledger, err := storage.NewPostgresUpgradePhases(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	rawS3, err := minio.New(upstream.Host, &minio.Options{Secure: upstream.Scheme == "https", Region: opts.S3.Region,
		BucketLookup: minio.BucketLookupPath, Creds: credentials.NewStaticV4(opts.S3.AccessKey, opts.S3.SecretKey, "")})
	if err != nil {
		t.Fatal(err)
	}
	readCiphertext := func(t *testing.T, a storage.AgentUpgradeAttempt) []byte {
		t.Helper()
		object, err := rawS3.GetObject(ctx, opts.S3.Bucket, fmt.Sprintf("executions/%s/chunks/%016d.chunk", a.RecordingID, 1), minio.GetObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer object.Close()
		raw, err := io.ReadAll(object)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	setup := func(t *testing.T) (*Service, *PhaseIssuer, storage.AgentUpgradeAttempt, []byte, string, string) {
		t.Helper()
		rule.Store(nil)
		service := NewService(store, attempts)
		id := fmt.Sprintf("phase-%d", time.Now().UnixNano())
		req := admitRequest(id)
		req.VMUID = id
		a, _, err := service.Admit(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		fence, err := attempts.ClaimLease(ctx, a.AttemptID, "worker", now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile("../updates/testdata/journal-v1.json")
		if err != nil {
			t.Fatal(err)
		}
		var snapshot updates.JournalSnapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			t.Fatal(err)
		}
		predecessor := storage.AttemptPredecessor{TargetID: "previous", ManifestSHA256: snapshot.Plan.Binding.PreviousSHA256}
		if err := attempts.Transition(ctx, a.AttemptID, storage.AttemptAdmitted, storage.AttemptTransition{
			To: storage.AttemptStaging, Now: now, Fence: &fence, Predecessor: &predecessor,
		}); err != nil {
			t.Fatal(err)
		}
		a, err = attempts.Get(ctx, a.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Plan.Binding = updates.JournalBinding{AttemptID: a.AttemptID, Namespace: a.Namespace, WorkspaceName: a.WorkspaceName,
			WorkspaceUID: a.WorkspaceUID, VMUID: a.VMUID, RevocationEpoch: a.ExpectedRevocationEpoch, ActorUID: a.ActorUID,
			RecordingID: a.RecordingID, TargetSHA256: a.TargetManifestSHA256, PreviousSHA256: predecessor.ManifestSHA256,
			InventorySHA256: a.ExpectedInstalledInventorySHA256}
		snapshot.OwnerFence = fence
		snapshot.StartedAt, snapshot.UpdatedAt, snapshot.ExpiresAt = now.Unix(), now.Unix(), now.Unix()+900
		raw, _ = json.Marshal(snapshot)
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		source := &phaseSourceProbe{current: PhaseContext{Challenge: base64.RawURLEncoding.EncodeToString(nonce[:]),
			PeerSHA256: updates.Digest([]byte("synthetic authenticated peer")), BootID: snapshot.Active.BootID}}
		issuer, err := NewPhaseIssuer(attempts, ledger, source, service, ed25519.NewKeyFromSeed(make([]byte, 32)))
		if err != nil {
			t.Fatal(err)
		}
		return service, issuer, a, raw, snapshot.Plan.SHA256(), updates.Digest(append([]byte("kw-agent-upgrade-journal/v1\x00"), raw...))
	}
	t.Run("encrypted-ack-ledger-signature-and-playback", func(t *testing.T) {
		service, issuer, a, checkpoint, plan, digest := setup(t)
		if err := issuer.RecordIntent(ctx, a.AttemptID, a.LeaseOwner, checkpoint, plan, digest); err != nil {
			t.Fatal(err)
		}
		i, err := ledger.GetIntent(ctx, a.AttemptID, 3)
		if err != nil || i.Receipt.RecordingID != a.RecordingID || i.Receipt.ChunkIndex != 1 || i.Receipt.ChunkSHA256 != updates.Digest(checkpoint) {
			t.Fatalf("incorrect real recorder ACK: %+v %v", i.Receipt, err)
		}
		before := puts.Load()
		if err := issuer.RecordIntent(ctx, a.AttemptID, a.LeaseOwner, checkpoint, plan, digest); !errors.Is(err, ErrConflict) || puts.Load() != before {
			t.Fatal("known intent was appended again instead of requiring reconciliation")
		}
		ciphertext := readCiphertext(t, a)
		if len(ciphertext) == 0 || bytes.Contains(ciphertext, checkpoint) {
			t.Fatal("plaintext intent was not independently committed encrypted before signing")
		}
		signed, err := issuer.Issue(ctx, a.AttemptID, a.LeaseOwner, 3)
		if err != nil {
			t.Fatal(err)
		}
		var permit updates.PhasePermit
		if err := json.Unmarshal(signed.Permit, &permit); err != nil {
			t.Fatal(err)
		}
		public := issuer.key.Public().(ed25519.PublicKey)
		if err := updates.VerifyPhase(signed.Permit, signed.Signature, signed.KeyID,
			map[string]ed25519.PublicKey{updates.KeyID(public): public}, permit, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Cancel(ctx, a.AttemptID); err != nil {
			t.Fatal(err)
		}
		observer, err := storage.Open(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		defer observer.Close()
		reader, err := observer.Recording().Open(ctx, a.RecordingID)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		if err := reader.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := reader.ReadChunk(ctx, i.Receipt.ChunkIndex)
		if err != nil || !bytes.Equal(got, checkpoint) || reader.Manifest().Chunks != 2 {
			t.Fatalf("protected playback did not match receipt: %v", err)
		}
	})
	for _, mode := range []string{"restart-after-record", "poisoned-writer-after-record"} {
		t.Run(mode, func(t *testing.T) {
			service, issuer, a, checkpoint, plan, digest := setup(t)
			if err := issuer.RecordIntent(ctx, a.AttemptID, a.LeaseOwner, checkpoint, plan, digest); err != nil {
				t.Fatal(err)
			}
			if mode == "restart-after-record" {
				issuer.recorder = NewService(store, attempts)
			} else {
				service.mu.Lock()
				session := service.sessions[a.AttemptID]
				service.mu.Unlock()
				if _, err := session.AppendChunkReceipt(ctx, make([]byte, storage.MaxChunkBytes+1)); !errors.Is(err, storage.ErrChunkTooLarge) {
					t.Fatal(err)
				}
			}
			_, outcome, err := store.Metadata().Get(ctx, a.ExecutionID)
			if err != nil || outcome.State != storage.StateAdmitted || outcome.RecordingLost {
				t.Fatalf("fixture must retain healthy metadata despite lost/poisoned writer: %+v %v", outcome, err)
			}
			before := puts.Load()
			if result, err := issuer.Issue(ctx, a.AttemptID, a.LeaseOwner, 3); err == nil || len(result.Signature) != 0 || puts.Load() != before {
				t.Fatal("prior intent/healthy metadata bypassed missing or poisoned live writer")
			}
			if _, err := service.Cancel(ctx, a.AttemptID); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, mode := range []string{"denied-put", "lost-put-ack", "restart", "finalized", "metadata-terminal", "wrong-binding", "lease-expired", "cancel-before-put", "cancel-during-put", "fence-during-put"} {
		t.Run(mode, func(t *testing.T) {
			service, issuer, a, checkpoint, plan, digest := setup(t)
			callback := make(chan error, 1)
			direct := false
			switch mode {
			case "denied-put":
				rule.Store(&phaseObjectFault{deny: true})
			case "lost-put-ack":
				rule.Store(&phaseObjectFault{loseACK: true})
			case "restart":
				issuer.recorder = NewService(store, attempts) // no live writer; never Begin again
			case "finalized":
				if _, err := service.Cancel(ctx, a.AttemptID); err != nil {
					t.Fatal(err)
				}
				direct = true
			case "metadata-terminal":
				if err := store.Metadata().Transition(ctx, a.ExecutionID, storage.ExecutionOutcome{State: storage.StateRecordingLost, RecordingLost: true, EndTime: time.Now()}); err != nil {
					t.Fatal(err)
				}
			case "wrong-binding":
				a.ActorUID = "forged-actor"
				direct = true
			case "lease-expired":
				service.now = func() time.Time { return a.LeaseExpiresAt }
			case "cancel-before-put":
				if err := attempts.RequestCancel(ctx, a.AttemptID, time.Now()); err != nil {
					t.Fatal(err)
				}
			case "cancel-during-put":
				rule.Store(&phaseObjectFault{afterPut: func() { callback <- attempts.RequestCancel(ctx, a.AttemptID, time.Now()) }})
			case "fence-during-put":
				rule.Store(&phaseObjectFault{afterPut: func() {
					_, err := attempts.ClaimLease(ctx, a.AttemptID, a.LeaseOwner, time.Now(), time.Minute)
					callback <- err
				}})
			}
			before := puts.Load()
			if direct {
				if receipt, err := service.RecordPhaseIntent(ctx, a, checkpoint); err == nil || receipt != (storage.PhaseRecordingReceipt{}) {
					t.Fatal("invalid/finalized recording returned receipt")
				}
			} else if err := issuer.RecordIntent(ctx, a.AttemptID, a.LeaseOwner, checkpoint, plan, digest); err == nil {
				t.Fatal("failed or stale recording admitted an intent")
			}
			if mode == "cancel-during-put" || mode == "fence-during-put" {
				select {
				case err := <-callback:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(15 * time.Second):
					t.Fatal("PUT never reached the authority-change callback")
				}
			}
			if _, err := ledger.GetIntent(ctx, a.AttemptID, 3); !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("recording failure created intent: %v", err)
			}
			if result, err := issuer.Issue(ctx, a.AttemptID, a.LeaseOwner, 3); err == nil || len(result.Signature) != 0 {
				t.Fatal("recording failure returned signature")
			}
			if mode == "restart" || mode == "finalized" || mode == "metadata-terminal" || mode == "wrong-binding" || mode == "lease-expired" || mode == "cancel-before-put" {
				if puts.Load() != before {
					t.Fatal("unowned or unhealthy recording was written/reopened")
				}
			}
			if mode == "denied-put" || mode == "lost-put-ack" {
				var committed []byte
				if mode == "lost-put-ack" {
					committed = readCiphertext(t, a)
				}
				rule.Store(nil)
				before = puts.Load()
				if err := issuer.RecordIntent(ctx, a.AttemptID, a.LeaseOwner, checkpoint, plan, digest); err == nil || puts.Load() != before {
					t.Fatal("uncertain/failed protected PUT was retried")
				}
				if mode == "lost-put-ack" && !bytes.Equal(committed, readCiphertext(t, a)) {
					t.Fatal("uncertain committed chunk was overwritten")
				}
				if _, err := service.Cancel(ctx, a.AttemptID); err != nil {
					t.Fatal(err)
				}
				_, outcome, err := store.Metadata().Get(ctx, a.ExecutionID)
				if err != nil || outcome.State != storage.StateRecordingLost || !outcome.RecordingLost {
					t.Fatalf("failed recording was not truthfully marked lost: %+v %v", outcome, err)
				}
				reader, err := store.Recording().Open(ctx, a.RecordingID)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				if err := reader.Verify(ctx); err != nil || reader.Manifest().Chunks != 1 {
					t.Fatalf("uncertain chunk entered acknowledged recording history: %v", err)
				}
			}
		})
	}
}

func TestPhaseRecordingBindingPinsEveryAuthorityField(t *testing.T) {
	a := storage.AgentUpgradeAttempt{}
	mutations := map[string]func(*storage.AgentUpgradeAttempt){
		"attempt":            func(a *storage.AgentUpgradeAttempt) { a.AttemptID = "changed" },
		"execution":          func(a *storage.AgentUpgradeAttempt) { a.ExecutionID = "changed" },
		"recording":          func(a *storage.AgentUpgradeAttempt) { a.RecordingID = "changed" },
		"actor":              func(a *storage.AgentUpgradeAttempt) { a.ActorUID = "changed" },
		"namespace":          func(a *storage.AgentUpgradeAttempt) { a.Namespace = "changed" },
		"workspace-name":     func(a *storage.AgentUpgradeAttempt) { a.WorkspaceName = "changed" },
		"workspace-uid":      func(a *storage.AgentUpgradeAttempt) { a.WorkspaceUID = "changed" },
		"vm":                 func(a *storage.AgentUpgradeAttempt) { a.VMUID = "changed" },
		"epoch":              func(a *storage.AgentUpgradeAttempt) { a.ExpectedRevocationEpoch++ },
		"target-id":          func(a *storage.AgentUpgradeAttempt) { a.TargetID = "changed" },
		"manifest":           func(a *storage.AgentUpgradeAttempt) { a.TargetManifestSHA256 = "changed" },
		"inventory":          func(a *storage.AgentUpgradeAttempt) { a.ExpectedInstalledInventorySHA256 = "changed" },
		"reboot":             func(a *storage.AgentUpgradeAttempt) { a.AllowReboot = true },
		"predecessor-id":     func(a *storage.AgentUpgradeAttempt) { a.Predecessor.TargetID = "changed" },
		"predecessor-digest": func(a *storage.AgentUpgradeAttempt) { a.Predecessor.ManifestSHA256 = "changed" },
		"owner":              func(a *storage.AgentUpgradeAttempt) { a.LeaseOwner = "changed" },
		"fence":              func(a *storage.AgentUpgradeAttempt) { a.LeaseFence++ },
	}
	for name, mutate := range mutations {
		b := a
		mutate(&b)
		if samePhaseRecordingBinding(a, b) {
			t.Fatalf("changed %s did not invalidate recording authority", name)
		}
	}
	b := a
	b.LeaseExpiresAt = time.Now().Add(time.Minute)
	if !samePhaseRecordingBinding(a, b) {
		t.Fatal("same-fence renewal incorrectly changed immutable recording binding")
	}
}
