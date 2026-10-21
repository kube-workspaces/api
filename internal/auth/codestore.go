package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"goa.design/clue/log"
)

// CodeStore is the seam behind OIDCHandler.codes: single-use, TTL-bounded
// authorization codes shared by the RFC 8252 native login (native.go) and the
// browser-session grant (browsersession.go).
//
// The in-memory nativeCodeStore implements this for single-replica use and for
// tests. The K8s-backed store below implements the same contract across
// replicas so a code issued on one pod redeems on any other.
type CodeStore interface {
	Issue(code string, entry nativeAuthCode) error
	Redeem(code string) (nativeAuthCode, bool)
	Close()
}

var _ CodeStore = (*nativeCodeStore)(nil)

var authCodeGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "secrets",
}

// authCodeNamespace is where short-lived code Secrets live. It matches the
// local-auth convention (LocalAuthSystemNamespace): the API already has RBAC
// there and no user workload ever lists it.
const authCodeNamespace = LocalAuthSystemNamespace

const (
	authCodeLabelKey   = "kubeworkspaces.io/kind"
	authCodeLabelValue = "authcode"
	authCodeExpiryAnno = "kubeworkspaces.io/expires-at"
)

// codeSecretName derives a deterministic, non-revealing Secret name from the
// code itself: the code is 256 bits of randomness, so its SHA-256 hex is both
// collision-free and safe to list. Callers never learn another client's code
// from the name because the name is the hash, not the code.
func codeSecretName(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "kw-code-" + hex.EncodeToString(sum[:20])
}

// k8sCodeStore persists authorization codes as Secrets so any replica can
// redeem them. Redemption uses Get then a conditional Delete so only the winner
// may redeem. Strict stores fail closed instead of falling back to memory.
//
// When dyn is nil the store degrades to a pure in-memory store so unit tests
// and local runs without cluster access keep working.
type k8sCodeStore struct {
	dyn    dynamic.Interface
	mem    *nativeCodeStore
	ttl    time.Duration
	max    int
	strict bool // security-sensitive flows must not fall back on storage failures
}

// NewK8sCodeStore returns a CodeStore backed by K8s Secrets when dyn is
// non-nil, or a pure in-memory store otherwise. TTL/max match the native flow
// defaults so callers do not repeat them.
func NewK8sCodeStore(dyn dynamic.Interface) CodeStore {
	return newK8sCodeStore(dyn, nativeCodeTTL, nativeCodeMaxEntries)
}

func newK8sCodeStore(dyn dynamic.Interface, ttl time.Duration, max int) CodeStore {
	mem := newNativeCodeStore(ttl, max)
	if dyn == nil {
		return mem
	}
	s := &k8sCodeStore{dyn: dyn, mem: mem, ttl: ttl, max: max}
	go s.sweep()
	return s
}

func (s *k8sCodeStore) Close() { s.mem.Close() }

func (s *k8sCodeStore) Issue(code string, entry nativeAuthCode) error {
	entry.expiresAt = time.Now().Add(s.ttl)

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name":      codeSecretName(code),
				"namespace": authCodeNamespace,
				"labels": map[string]interface{}{
					authCodeLabelKey: authCodeLabelValue,
				},
				"annotations": map[string]interface{}{
					authCodeExpiryAnno: strconv.FormatInt(entry.expiresAt.Unix(), 10),
				},
			},
			"type": "Opaque",
			"stringData": map[string]interface{}{
				"token":          entry.token,
				"codeChallenge":  entry.codeChallenge,
				"email":          entry.email,
				"role":           entry.role,
				"tokenExpiresAt": strconv.FormatInt(entry.tokenExpiresAt, 10),
				"redirect":       entry.redirect,
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.dyn.Resource(authCodeGVR).Namespace(authCodeNamespace).Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			return fmt.Errorf("authorization code already issued")
		}
		if s.strict {
			return err
		}
		// K8s outage: fall back to the issuing replica's memory so logins
		// keep working single-replica (the pre-K8s behavior) instead of
		// failing every login. Cross-replica redeem degrades until K8s
		// recovers.
		log.Printf(context.Background(), "auth: code persist failed, using memory fallback: %v", err)
		return s.mem.Issue(code, entry)
	}
	return nil
}

func (s *k8sCodeStore) Redeem(code string) (nativeAuthCode, bool) {
	// K8s is authoritative when available: a remote replica's delete must be
	// visible here, so a memory hit alone is never enough.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	obj, err := s.dyn.Resource(authCodeGVR).Namespace(authCodeNamespace).Get(ctx, codeSecretName(code), metav1.GetOptions{})
	if err == nil {
		entry, ok := codeEntryFromSecret(obj)
		if !ok {
			s.deleteSecret(code)
			return nativeAuthCode{}, false
		}
		if time.Now().After(entry.expiresAt) {
			s.deleteSecret(code)
			return nativeAuthCode{}, false
		}
		// Only the successful conditional deleter may use this value. A competing
		// replica or a replacement object must not produce a second redemption.
		uid, rv := obj.GetUID(), obj.GetResourceVersion()
		if err := s.dyn.Resource(authCodeGVR).Namespace(authCodeNamespace).Delete(ctx, obj.GetName(), metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv},
		}); err != nil {
			return nativeAuthCode{}, false
		}
		return entry, true
	}
	if !k8serrors.IsNotFound(err) {
		log.Printf(context.Background(), "auth: code fetch failed: %v", err)
	}
	if s.strict {
		return nativeAuthCode{}, false
	}
	// Miss (or K8s outage): fall back to memory for codes issued during an
	// outage on this replica.
	return s.mem.Redeem(code)
}

func (s *k8sCodeStore) deleteSecret(code string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.dyn.Resource(authCodeGVR).Namespace(authCodeNamespace).Delete(ctx, codeSecretName(code), metav1.DeleteOptions{})
}

func codeEntryFromSecret(obj *unstructured.Unstructured) (nativeAuthCode, bool) {
	data, found, _ := unstructured.NestedMap(obj.Object, "data")
	if !found {
		// stringData is already merged into data by the API server; a fake
		// dynamic client may still carry stringData only.
		data, found, _ = unstructured.NestedMap(obj.Object, "stringData")
		if !found {
			return nativeAuthCode{}, false
		}
	}
	get := func(key string) string {
		v, _ := data[key].(string)
		if v == "" {
			return ""
		}
		// Real API server returns base64 in .data; fake clients return plain.
		if decoded, err := decodeSecretValue(v); err == nil {
			return decoded
		}
		return v
	}
	tokenExpiresAt, _ := strconv.ParseInt(get("tokenExpiresAt"), 10, 64)
	var expiresAt time.Time
	if anno, _, _ := unstructured.NestedString(obj.Object, "metadata", "annotations", authCodeExpiryAnno); anno != "" {
		if unix, err := strconv.ParseInt(anno, 10, 64); err == nil {
			expiresAt = time.Unix(unix, 0)
		}
	}
	if expiresAt.IsZero() {
		return nativeAuthCode{}, false
	}
	return nativeAuthCode{
		token:          get("token"),
		codeChallenge:  get("codeChallenge"),
		email:          get("email"),
		role:           get("role"),
		tokenExpiresAt: tokenExpiresAt,
		redirect:       get("redirect"),
		expiresAt:      expiresAt,
	}, true
}

// decodeSecretValue base64-decodes a Secret .data value, tolerating plaintext
// (fake clients and stringData round-trips).
func decodeSecretValue(v string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return v, fmt.Errorf("not base64")
	}
	return string(decoded), nil
}

// sweep periodically deletes expired code Secrets so abandoned logins (closed
// browser tabs) do not accumulate. Failures are logged and retried next tick;
// the store stays correct without the sweeper because Redeem checks expiry.
func (s *k8sCodeStore) sweep() {
	interval := s.ttl
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		list, err := s.dyn.Resource(authCodeGVR).Namespace(authCodeNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: authCodeLabelKey + "=" + authCodeLabelValue,
		})
		cancel()
		if err != nil {
			log.Printf(context.Background(), "auth: code sweep list failed: %v", err)
			continue
		}
		now := time.Now()
		for _, item := range list.Items {
			anno, _, _ := unstructured.NestedString(item.Object, "metadata", "annotations", authCodeExpiryAnno)
			unix, err := strconv.ParseInt(anno, 10, 64)
			if err != nil || now.After(time.Unix(unix, 0)) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = s.dyn.Resource(authCodeGVR).Namespace(authCodeNamespace).Delete(ctx, item.GetName(), metav1.DeleteOptions{})
				cancel()
			}
		}
	}
}
