package grants

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Signer, *Verifier, Binding, time.Time) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	s, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	v, err := NewVerifier(map[string]ed25519.PublicKey{KeyID(pub): pub}, 16)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{ActorUID: "actor-uid", Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "workspace-uid", ProvisioningGeneration: "generation-2", ExecutionID: "exec-1", RecordingID: "rec-1", Operation: "command", OSIdentity: "workspace-user", PolicyVersion: "policy-1", RevocationEpoch: 4, Challenge: challenge, PeerCertificateSHA256: Digest([]byte("peer certificate DER")), RequestSHA256: Digest([]byte("framed request bytes"))}
	return s, v, b, time.Unix(1800000000, 0)
}

func issue(t *testing.T, s *Signer, b Binding, now time.Time) string {
	t.Helper()
	token, err := s.Issue(b, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestSignatureBindingAndSingleUse(t *testing.T) {
	s, v, b, now := fixture(t)
	token := issue(t, s, b, now)
	claims, err := v.Consume(token, b, now)
	if err != nil || claims.Binding != b || claims.Audience != Audience {
		t.Fatalf("consume: %+v, %v", claims, err)
	}
	if _, err := v.Consume(token, b, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
}

func TestEveryBindingIsEnforced(t *testing.T) {
	mutations := map[string]func(*Binding){
		"actor":      func(b *Binding) { b.ActorUID += "-other" },
		"namespace":  func(b *Binding) { b.Namespace += "-other" },
		"workspace":  func(b *Binding) { b.WorkspaceName += "-other" },
		"uid":        func(b *Binding) { b.WorkspaceUID += "-other" },
		"generation": func(b *Binding) { b.ProvisioningGeneration += "-reset" },
		"execution":  func(b *Binding) { b.ExecutionID += "-other" },
		"recording":  func(b *Binding) { b.RecordingID += "-other" },
		"operation":  func(b *Binding) { b.Operation = "shell" },
		"identity":   func(b *Binding) { b.OSIdentity = "another-user" },
		"elevation":  func(b *Binding) { b.Elevated = true },
		"policy":     func(b *Binding) { b.PolicyVersion += "-new" },
		"revocation": func(b *Binding) { b.RevocationEpoch++ },
		"challenge":  func(b *Binding) { b.Challenge = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
		"peer":       func(b *Binding) { b.PeerCertificateSHA256 = Digest([]byte("other certificate")) },
		"command":    func(b *Binding) { b.RequestSHA256 = Digest([]byte("different command")) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s, v, b, now := fixture(t)
			token := issue(t, s, b, now)
			other := b
			mutate(&other)
			if _, err := v.Consume(token, other, now); !errors.Is(err, ErrBinding) {
				t.Fatalf("scope mismatch accepted: %v", err)
			}
			if _, err := v.Consume(token, b, now); err != nil {
				t.Fatalf("failed check consumed grant: %v", err)
			}
		})
	}
}

func TestTimeAndElevationDenials(t *testing.T) {
	s, v, b, now := fixture(t)
	token := issue(t, s, b, now)
	for _, at := range []time.Time{now.Add(-time.Second), now.Add(30 * time.Second), now.Add(time.Hour)} {
		if _, err := v.Consume(token, b, at); !errors.Is(err, ErrExpired) {
			t.Fatalf("time %v: %v", at, err)
		}
	}
	for _, ttl := range []time.Duration{0, time.Millisecond, MaxLifetime + time.Second} {
		if _, err := s.Issue(b, now, ttl); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ttl %s: %v", ttl, err)
		}
	}
	for _, identity := range []string{"root", "SYSTEM", "0"} {
		b.OSIdentity = identity
		if _, err := s.Issue(b, now, time.Second); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ordinary elevated identity %s: %v", identity, err)
		}
	}
}

func TestRotationAndForgedTokens(t *testing.T) {
	s, v, b, now := fixture(t)
	token := issue(t, s, b, now)
	parts := strings.Split(token, ".")
	for _, bad := range []string{"", "a.b", strings.Repeat("x", maxTokenBytes+1), parts[0] + "." + parts[1] + ".AA", parts[0] + ".AA." + parts[2]} {
		if _, err := v.Consume(bad, b, now); err == nil {
			t.Fatal("forgery accepted")
		}
	}
	seed := make([]byte, 32)
	seed[0] = 1
	newPrivate := ed25519.NewKeyFromSeed(seed)
	newPublic := newPrivate.Public().(ed25519.PublicKey)
	newSigner, _ := NewSigner(newPrivate)
	oldPublic := s.private.Public().(ed25519.PublicKey)
	rotating, _ := NewVerifier(map[string]ed25519.PublicKey{KeyID(oldPublic): oldPublic, KeyID(newPublic): newPublic}, 16)
	if _, err := rotating.Consume(token, b, now); err != nil {
		t.Fatal(err)
	}
	if _, err := rotating.Consume(issue(t, newSigner, b, now), b, now); err != nil {
		t.Fatal(err)
	}
	revoked, _ := NewVerifier(map[string]ed25519.PublicKey{KeyID(newPublic): newPublic}, 16)
	if _, err := revoked.Consume(token, b, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("retired key accepted", err)
	}
}

func TestReplayCacheConcurrencyAndCapacity(t *testing.T) {
	s, v, b, now := fixture(t)
	v.capacity = 1
	token := issue(t, s, b, now)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Consume(token, b, now); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrReplay) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("got %d consumers", winners.Load())
	}
	if _, err := v.Consume(issue(t, s, b, now), b, now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("unexpired entry evicted: %v", err)
	}
	later := now.Add(time.Minute)
	if _, err := v.Consume(issue(t, s, b, later), b, later); err != nil {
		t.Fatal("expired entries not reclaimed", err)
	}
	if _, err := v.Consume(token, b, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("clock rollback reopened replay window: %v", err)
	}
}

func TestSignedAlgorithmAudienceAndUnknownFieldDenials(t *testing.T) {
	s, v, b, now := fixture(t)
	token := issue(t, s, b, now)
	parts := strings.Split(token, ".")
	var c map[string]interface{}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(raw, &c)
	for _, mutate := range []func(map[string]interface{}){
		func(c map[string]interface{}) { c["aud"] = "desktop" },
		func(c map[string]interface{}) { c["iss"] = "other" },
		func(c map[string]interface{}) { c["version"] = float64(2) },
		func(c map[string]interface{}) { c["unexpected"] = true },
	} {
		json.Unmarshal(raw, &c)
		mutate(c)
		payload, _ := json.Marshal(c)
		input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
		forged := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, []byte(input)))
		if _, err := v.Consume(forged, b, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid signed claims accepted: %v", err)
		}
	}
	h, _ := json.Marshal(header{Algorithm: "none", Type: grantType, KeyID: s.keyID})
	input := base64.RawURLEncoding.EncodeToString(h) + "." + parts[1]
	if _, err := v.Consume(input+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, []byte(input))), b, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("algorithm substitution accepted", err)
	}
}

func FuzzConsume(f *testing.F) {
	f.Add("")
	f.Add("e30.e30.AA")
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	public := key.Public().(ed25519.PublicKey)
	b := Binding{ActorUID: "actor", Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "uid", ProvisioningGeneration: "1", ExecutionID: "exec", RecordingID: "rec", Operation: "shell", OSIdentity: "workspace", PolicyVersion: "1", Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), PeerCertificateSHA256: Digest(nil), RequestSHA256: Digest(nil)}
	now := time.Unix(1800000000, 0)
	s, _ := NewSigner(key)
	token, _ := s.Issue(b, now, time.Second)
	f.Add(token)
	f.Fuzz(func(t *testing.T, input string) {
		v, err := NewVerifier(map[string]ed25519.PublicKey{KeyID(public): public}, 1)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = v.Consume(input, b, now)
	})
}
