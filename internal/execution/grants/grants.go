// Package grants defines the independently verifiable management-v1 grant
// envelope. It is separate from display tickets and session authentication.
// It does not establish enrollment, mTLS, policy, recording or process admission.
package grants

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	Audience      = "kube-workspaces/management/v1"
	Issuer        = "kube-workspaces-api/management/v1"
	MaxLifetime   = 60 * time.Second
	maxTokenBytes = 16 * 1024
	grantType     = "kw-management-grant+jwt"
)

var (
	ErrInvalid  = errors.New("invalid management grant")
	ErrExpired  = errors.New("management grant expired or not yet valid")
	ErrBinding  = errors.New("management grant binding mismatch")
	ErrReplay   = errors.New("management grant already consumed")
	ErrCapacity = errors.New("management grant replay cache at capacity")
)

// Binding describes one authorized operation on one authenticated connection.
// Expected values must come from guest identity, the mTLS peer, the connection's
// fresh challenge and the actual request, never from the grant being verified.
type Binding struct {
	ActorUID               string `json:"actor_uid"`
	Namespace              string `json:"namespace"`
	WorkspaceName          string `json:"workspace_name"`
	WorkspaceUID           string `json:"workspace_uid"`
	ProvisioningGeneration string `json:"provisioning_generation"`
	ExecutionID            string `json:"execution_id"`
	RecordingID            string `json:"recording_id"`
	Operation              string `json:"operation"`
	OSIdentity             string `json:"os_identity"`
	Elevated               bool   `json:"elevated"`
	PolicyVersion          string `json:"policy_version"`
	RevocationEpoch        uint64 `json:"revocation_epoch"`
	Challenge              string `json:"challenge"`
	PeerCertificateSHA256  string `json:"peer_certificate_sha256"`
	RequestSHA256          string `json:"request_sha256"`
}

type Claims struct {
	Version   int     `json:"version"`
	Issuer    string  `json:"iss"`
	Audience  string  `json:"aud"`
	ID        string  `json:"jti"`
	IssuedAt  int64   `json:"iat"`
	ExpiresAt int64   `json:"exp"`
	Binding   Binding `json:"binding"`
}

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// KeyID is the public verification-key fingerprint, never a session signing key.
func KeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:16])
}

// Digest binds exact request bytes (or a certificate DER encoding). The protocol
// caller must define the request framing before issuance and guest verification.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NewChallenge produces a 256-bit, connection-specific challenge.
func NewChallenge() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

func (b Binding) validate() error {
	for _, v := range []string{b.ActorUID, b.Namespace, b.WorkspaceName, b.WorkspaceUID, b.ProvisioningGeneration, b.ExecutionID, b.RecordingID, b.OSIdentity, b.PolicyVersion} {
		if v == "" || len(v) > 256 || strings.TrimSpace(v) != v || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return ErrInvalid
		}
	}
	if b.Operation != "command" && b.Operation != "script" && b.Operation != "shell" {
		return ErrInvalid
	}
	challenge, err := base64.RawURLEncoding.DecodeString(b.Challenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != b.Challenge {
		return ErrInvalid
	}
	if !validDigest(b.PeerCertificateSHA256) || !validDigest(b.RequestSHA256) {
		return ErrInvalid
	}
	// Elevated OS identities must not be smuggled through an ordinary grant.
	if (strings.EqualFold(b.OSIdentity, "root") || strings.EqualFold(b.OSIdentity, "SYSTEM") || b.OSIdentity == "0") && !b.Elevated {
		return ErrInvalid
	}
	return nil
}

// Signer owns only the management signing key. Callers must independently check
// current user grants, platform policy, guest capability and recording admission.
type Signer struct {
	private ed25519.PrivateKey
	keyID   string
}

func NewSigner(private ed25519.PrivateKey) (*Signer, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	if !bytes.Equal(private, ed25519.NewKeyFromSeed(private.Seed())) {
		return nil, ErrInvalid
	}
	copyKey := append(ed25519.PrivateKey(nil), private...)
	return &Signer{private: copyKey, keyID: KeyID(copyKey.Public().(ed25519.PublicKey))}, nil
}

// Issue creates one compact EdDSA JWS; there is no symmetric or unsigned mode.
func (s *Signer) Issue(binding Binding, now time.Time, lifetime time.Duration) (string, error) {
	if err := binding.validate(); err != nil {
		return "", err
	}
	if lifetime < time.Second || lifetime > MaxLifetime {
		return "", ErrInvalid
	}
	if now.Unix() <= 0 {
		return "", ErrInvalid
	}
	id, err := NewChallenge()
	if err != nil {
		return "", err
	}
	c := Claims{Version: 1, Issuer: Issuer, Audience: Audience, ID: id, IssuedAt: now.Unix(), ExpiresAt: now.Add(lifetime).Unix(), Binding: binding}
	h, err := json.Marshal(header{Algorithm: "EdDSA", Type: grantType, KeyID: s.keyID})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	signature := ed25519.Sign(s.private, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Verifier is a bounded one-time-consumption reference verifier for one guest
// connection. Guests get only public keys. A disconnect must discard its random
// challenge; recreating a verifier for the same challenge would permit replay.
type Verifier struct {
	keys     map[string]ed25519.PublicKey
	mu       sync.Mutex
	used     map[string]int64
	capacity int
	lastTime int64
}

func NewVerifier(keys map[string]ed25519.PublicKey, capacity int) (*Verifier, error) {
	if len(keys) == 0 || len(keys) > 16 || capacity < 1 || capacity > 65536 {
		return nil, ErrInvalid
	}
	v := &Verifier{keys: make(map[string]ed25519.PublicKey), used: make(map[string]int64), capacity: capacity}
	for id, key := range keys {
		if len(key) != ed25519.PublicKeySize || id != KeyID(key) {
			return nil, ErrInvalid
		}
		v.keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	return v, nil
}

func decode(segment string, into interface{}) error {
	b, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(into); err != nil {
		return ErrInvalid
	}
	if err := d.Decode(new(interface{})); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

// Consume verifies signature, time, full request/connection binding, and single
// use before returning claims. A full replay cache denies rather than evicting
// unexpired entries. Failed verification never consumes a valid grant.
func (v *Verifier) Consume(token string, expected Binding, now time.Time) (Claims, error) {
	var c Claims
	if len(token) > maxTokenBytes || expected.validate() != nil {
		return c, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrInvalid
	}
	var h header
	if err := decode(parts[0], &h); err != nil || h.Algorithm != "EdDSA" || h.Type != grantType {
		return c, ErrInvalid
	}
	key := v.keys[h.KeyID]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return c, ErrInvalid
	}
	if err := decode(parts[1], &c); err != nil {
		return Claims{}, err
	}
	if c.Version != 1 || c.Issuer != Issuer || c.Audience != Audience || c.Binding.validate() != nil {
		return Claims{}, ErrInvalid
	}
	jti, err := base64.RawURLEncoding.DecodeString(c.ID)
	if err != nil || len(jti) != 32 {
		return Claims{}, ErrInvalid
	}
	if c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(MaxLifetime/time.Second) || now.Unix() < c.IssuedAt || now.Unix() >= c.ExpiresAt {
		return Claims{}, ErrExpired
	}
	if c.Binding != expected {
		return Claims{}, ErrBinding
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	// Never reopen an expired replay window after a guest wall-clock rollback.
	if now.Unix() < v.lastTime {
		return Claims{}, ErrExpired
	}
	v.lastTime = now.Unix()
	for id, expiry := range v.used {
		if now.Unix() >= expiry {
			delete(v.used, id)
		}
	}
	if _, exists := v.used[c.ID]; exists {
		return Claims{}, ErrReplay
	}
	if len(v.used) >= v.capacity {
		return Claims{}, ErrCapacity
	}
	v.used[c.ID] = c.ExpiresAt
	return c, nil
}

func (s *Signer) String() string { return fmt.Sprintf("management grant signer key_id=%s", s.keyID) }
