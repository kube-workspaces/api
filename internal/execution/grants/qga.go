package grants

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
	"unicode"
)

const (
	// QGAAudience/QGAIssuer identify the QGA pilot transport separately from
	// the mTLS management endpoint so one transport can never accept the
	// other's grants.
	QGAAudience = "kube-workspaces/management-qga/v1"
	QGAIssuer   = "kube-workspaces-api/management-qga/v1"
	// TransportQGAPodExec names the approved pilot transport: Kubernetes-
	// authenticated pod exec into the current virt-launcher, invoking the
	// fixed installed runner via the QEMU guest agent.
	TransportQGAPodExec = "qga-pod-exec/v1"
	// QGAMaxLifetime bounds one pilot grant. The confirmed pilot deadline is
	// 20 seconds; the grant lifetime covers staging, exec and polling.
	QGAMaxLifetime = 60 * time.Second
	qgaGrantType   = "kw-management-grant+qga"
)

// BindingQGA is the QGA pilot transport binding. It replaces the mTLS peer
// certificate digest with the fixed transport name plus a digest of the
// server-resolved target identity (namespace/VM UID/launcher pod UID). The
// guest cannot independently know the launcher pod UID; the trust anchors for
// the pilot are the API signature, the authenticated Kubernetes exec path and
// single-use consumption. The guest does independently check workspace_uid
// against its enrolled identity.
type BindingQGA struct {
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
	Transport              string `json:"transport"`
	TransportTargetSHA256  string `json:"transport_target_sha256"`
	RequestSHA256          string `json:"request_sha256"`
}

// ClaimsQGA is the signed QGA grant payload.
type ClaimsQGA struct {
	Version   int        `json:"version"`
	Issuer    string     `json:"iss"`
	Audience  string     `json:"aud"`
	ID        string     `json:"jti"`
	IssuedAt  int64      `json:"iat"`
	ExpiresAt int64      `json:"exp"`
	Binding   BindingQGA `json:"binding"`
}

func (b BindingQGA) validate() error {
	for _, v := range []string{b.ActorUID, b.Namespace, b.WorkspaceName, b.WorkspaceUID, b.ProvisioningGeneration, b.ExecutionID, b.RecordingID, b.OSIdentity, b.PolicyVersion} {
		if v == "" || len(v) > 256 || strings.TrimSpace(v) != v || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return ErrInvalid
		}
	}
	// The pilot transport admits bounded commands only; scripts and shells
	// arrive with later transports.
	if b.Operation != "command" {
		return ErrInvalid
	}
	if b.Transport != TransportQGAPodExec {
		return ErrInvalid
	}
	challenge, err := base64.RawURLEncoding.DecodeString(b.Challenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != b.Challenge {
		return ErrInvalid
	}
	if !validDigest(b.TransportTargetSHA256) || !validDigest(b.RequestSHA256) {
		return ErrInvalid
	}
	if (strings.EqualFold(b.OSIdentity, "root") || strings.EqualFold(b.OSIdentity, "SYSTEM") || b.OSIdentity == "0") && !b.Elevated {
		return ErrInvalid
	}
	// SYSTEM is the only elevated OS identity the pilot runner accepts; do
	// not mint grants that the runner must reject.
	if !strings.EqualFold(b.OSIdentity, "SYSTEM") {
		return ErrInvalid
	}
	return nil
}

// IssueQGA creates one compact EdDSA JWS bound to the QGA pilot transport.
func (s *Signer) IssueQGA(binding BindingQGA, now time.Time, lifetime time.Duration) (string, error) {
	if err := binding.validate(); err != nil {
		return "", err
	}
	if lifetime < time.Second || lifetime > QGAMaxLifetime {
		return "", ErrInvalid
	}
	if now.Unix() <= 0 {
		return "", ErrInvalid
	}
	id, err := NewChallenge()
	if err != nil {
		return "", err
	}
	c := ClaimsQGA{Version: 1, Issuer: QGAIssuer, Audience: QGAAudience, ID: id, IssuedAt: now.Unix(), ExpiresAt: now.Add(lifetime).Unix(), Binding: binding}
	h, err := json.Marshal(header{Algorithm: "EdDSA", Type: qgaGrantType, KeyID: s.keyID})
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

// ConsumeQGA verifies a QGA pilot grant against the expected binding and
// enforces single use on the same bounded replay state as the mTLS verifier.
func (v *Verifier) ConsumeQGA(token string, expected BindingQGA, now time.Time) (ClaimsQGA, error) {
	var c ClaimsQGA
	if len(token) > maxTokenBytes || expected.validate() != nil {
		return c, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrInvalid
	}
	var h header
	if err := decode(parts[0], &h); err != nil || h.Algorithm != "EdDSA" || h.Type != qgaGrantType {
		return c, ErrInvalid
	}
	key := v.keys[h.KeyID]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return c, ErrInvalid
	}
	if err := decode(parts[1], &c); err != nil {
		return ClaimsQGA{}, err
	}
	if c.Version != 1 || c.Issuer != QGAIssuer || c.Audience != QGAAudience || c.Binding.validate() != nil {
		return ClaimsQGA{}, ErrInvalid
	}
	jti, err := base64.RawURLEncoding.DecodeString(c.ID)
	if err != nil || len(jti) != 32 {
		return ClaimsQGA{}, ErrInvalid
	}
	if c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(QGAMaxLifetime/time.Second) || now.Unix() < c.IssuedAt || now.Unix() >= c.ExpiresAt {
		return ClaimsQGA{}, ErrExpired
	}
	if c.Binding != expected {
		return ClaimsQGA{}, ErrBinding
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if now.Unix() < v.lastTime {
		return ClaimsQGA{}, ErrExpired
	}
	v.lastTime = now.Unix()
	for id, expiry := range v.used {
		if now.Unix() >= expiry {
			delete(v.used, id)
		}
	}
	if _, exists := v.used[c.ID]; exists {
		return ClaimsQGA{}, ErrReplay
	}
	if len(v.used) >= v.capacity {
		return ClaimsQGA{}, ErrCapacity
	}
	v.used[c.ID] = c.ExpiresAt
	return c, nil
}
