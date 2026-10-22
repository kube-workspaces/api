package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// revalidateContext binds a session token to a context the way the request
// middleware does, so revalidation sees the same credential.
func revalidateContext(t *testing.T, provider *ConfigProvider, raw string) context.Context {
	t.Helper()
	token, err := ValidateSessionTokenWithKeys(raw, provider.config.SessionSigningKeys())
	if err != nil {
		t.Fatal(err)
	}
	return ContextWithSession(context.Background(), token)
}

func TestRevalidateCredentialKeepsLiveCredentialValid(t *testing.T) {
	f := newLifecycleFixture(t, false)
	ctx := revalidateContext(t, f.h.provider, f.localToken)

	if err := RevalidateCredential(ctx, f.h.provider); err != nil {
		t.Fatalf("live credential reported as revoked: %v", err)
	}
}

func TestRevalidateCredentialRevokesExpiredSession(t *testing.T) {
	f := newLifecycleFixture(t, false)
	ctx := revalidateContext(t, f.h.provider, f.localToken)
	SessionFromContext(ctx).ExpiresAt = time.Now().Add(-time.Second).Unix()
	if err := RevalidateCredential(ctx, f.h.provider); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expired session still valid: %v", err)
	}
}

func TestRevalidateCredentialRevokesReplacedPassword(t *testing.T) {
	f := newLifecycleFixture(t, false)
	provider := f.h.provider
	ctx := revalidateContext(t, provider, f.localToken)

	hash, err := bcrypt.GenerateFromPassword([]byte("Rotated-password-456!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.UpdatePasswordHash(context.Background(), "lifecycle-password", string(hash)); err != nil {
		t.Fatal(err)
	}

	err = RevalidateCredential(ctx, provider)
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expected revocation after password change, got %v", err)
	}
}

func TestRevalidateCredentialRevokesDisabledAccount(t *testing.T) {
	f := newLifecycleFixture(t, false)
	provider := f.h.provider
	ctx := revalidateContext(t, provider, f.localToken)

	user, err := provider.GetUserByEmail(context.Background(), "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(user.Object, true, "spec", "disabled")
	if _, err := provider.UpdateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	err = RevalidateCredential(ctx, provider)
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expected revocation for a disabled account, got %v", err)
	}
}

func TestRevalidateCredentialRevokesRemovedAccount(t *testing.T) {
	f := newLifecycleFixture(t, false)
	provider := f.h.provider
	ctx := revalidateContext(t, provider, f.localToken)

	user, err := provider.GetUserByEmail(context.Background(), "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.DeleteUser(context.Background(), user.GetName()); err != nil {
		t.Fatal(err)
	}

	err = RevalidateCredential(ctx, provider)
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expected revocation for a removed account, got %v", err)
	}
}

func TestRevalidateCredentialRevokesRestrictedCredential(t *testing.T) {
	f := newLifecycleFixture(t, true)
	provider := f.h.provider
	ctx := revalidateContext(t, provider, f.localToken)

	// A restricted (temporary password) credential may not hold a stream open.
	err := RevalidateCredential(ctx, provider)
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expected revocation for a restricted credential, got %v", err)
	}

	// The OIDC session of the same account stays usable: the restriction is
	// method specific.
	oidcCtx := revalidateContext(t, provider, f.oidcToken)
	if err := RevalidateCredential(oidcCtx, provider); err != nil {
		t.Fatalf("OIDC credential reported as revoked: %v", err)
	}
}

func TestRevalidateCredentialRevokesRotatedIdentityReservation(t *testing.T) {
	f := newLifecycleFixture(t, false)
	provider := f.h.provider
	ctx := revalidateContext(t, provider, f.oidcToken)

	if err := RevalidateCredential(ctx, provider); err != nil {
		t.Fatalf("live OIDC credential reported as revoked: %v", err)
	}

	// Rotating the reservation revision (as an unlink does) revokes the
	// credential derived from it.
	user, err := provider.GetUserByEmail(context.Background(), "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := identityBindings(user)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) == 0 {
		t.Fatal("fixture has no identity binding")
	}
	claim, err := provider.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Get(context.Background(), bindings[0].claimName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := claim.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[identityVersionAnnotation] = "rotated-revision"
	claim.SetAnnotations(annotations)
	if _, err := provider.dynamicClient.Resource(secretGVR).Namespace(LocalAuthSystemNamespace).Update(context.Background(), claim, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	err = RevalidateCredential(ctx, provider)
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expected revocation after the reservation rotated, got %v", err)
	}
}

func TestRevalidateCredentialRevokesRevokedDevice(t *testing.T) {
	f := newLifecycleFixture(t, false)
	provider := f.h.provider
	device := f.deviceToken(t, f.localToken)
	ctx := revalidateContext(t, provider, device)

	if err := RevalidateCredential(ctx, provider); err != nil {
		t.Fatalf("live device credential reported as revoked: %v", err)
	}

	store := NewDeviceStore(provider.DynamicClient())
	devices, err := store.List(context.Background(), "user@example.com", false)
	if err != nil || len(devices) != 1 {
		t.Fatalf("device list: %v %+v", err, devices)
	}
	if err := store.Revoke(context.Background(), devices[0].DeviceID); err != nil {
		t.Fatal(err)
	}

	err = RevalidateCredential(ctx, provider)
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("expected revocation for a revoked device, got %v", err)
	}
}

func TestRevalidateCredentialWithoutSessionIsNoop(t *testing.T) {
	f := newLifecycleFixture(t, false)
	if err := RevalidateCredential(context.Background(), f.h.provider); err != nil {
		t.Fatalf("unexpected error without a session: %v", err)
	}
}

func TestWatchCredentialRevocationEndsStreamOnRevocation(t *testing.T) {
	revoked := make(chan string, 1)
	stop := WatchCredentialRevocation(context.Background(), func(context.Context) error {
		return ErrCredentialRevoked
	}, 10*time.Millisecond, func(reason string) { revoked <- reason })
	defer stop()

	select {
	case reason := <-revoked:
		if reason == "" {
			t.Fatal("expected a revocation reason")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not report the revocation")
	}
}

func TestWatchCredentialRevocationToleratesTransientFailures(t *testing.T) {
	var attempts int
	revoked := make(chan string, 1)
	stop := WatchCredentialRevocation(context.Background(), func(context.Context) error {
		attempts++
		if attempts < 3 {
			return errors.New("temporarily unavailable")
		}
		return ErrCredentialRevoked
	}, 10*time.Millisecond, func(reason string) { revoked <- reason })
	defer stop()

	select {
	case <-revoked:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not report the revocation")
	}
	if attempts != 3 {
		t.Fatalf("expected the transient failures to be retried, got %d attempts", attempts)
	}
}

func TestWatchCredentialRevocationStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	revoked := make(chan string, 1)
	stop := WatchCredentialRevocation(ctx, func(context.Context) error {
		return ErrCredentialRevoked
	}, 10*time.Millisecond, func(reason string) { revoked <- reason })
	defer stop()
	cancel()

	select {
	case <-revoked:
		t.Fatal("watcher reported a revocation after cancellation")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestLocalCredentialVersionIgnoresSecretEncoding(t *testing.T) {
	// The revision is derived from the decoded hash, never the stored
	// base64 text, so a re-encoded Secret does not look like a new credential.
	hash := base64.StdEncoding.EncodeToString([]byte("material"))
	decoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Fatal(err)
	}
	if LocalCredentialVersion("uid", "secret", "passwordHash", string(decoded)) != LocalCredentialVersion("uid", "secret", "passwordHash", "material") {
		t.Fatal("credential version depends on the secret encoding")
	}
}
