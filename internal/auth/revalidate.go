package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ErrCredentialRevoked marks a credential that must no longer authorise work.
// Long-lived streams end as soon as revalidation reports it.
var ErrCredentialRevoked = errors.New("credential revoked")

// RevalidateCredential re-checks the credential bound to the current request
// against live account state.
//
// It returns nil while the credential is still usable, ErrCredentialRevoked once
// the account or credential is revoked, disabled, replaced or restricted, and a
// plain error when the state could not be verified. Callers must distinguish
// the two failure kinds: a revoked credential ends the stream immediately,
// while an unverifiable state is retried.
//
// The check reads live cluster state rather than any per-replica cache, so a
// revocation performed against one API replica is observed by every replica
// that holds a stream for the same account.
func RevalidateCredential(ctx context.Context, provider *ConfigProvider) error {
	if provider == nil {
		return nil
	}
	token := SessionFromContext(ctx)
	if token == nil {
		// No credential is bound to this request (authentication disabled).
		return nil
	}
	cfg, err := provider.GetConfig(ctx)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	if time.Now().Unix() >= token.ExpiresAt {
		return fmt.Errorf("%w: credential expired", ErrCredentialRevoked)
	}
	if token.UserUID == "" {
		return fmt.Errorf("%w: credential is not bound to an account", ErrCredentialRevoked)
	}
	if token.Type == DeviceTokenType {
		revoked, err := NewDeviceStore(provider.DynamicClient()).revocationState(ctx, token.JTI, token.Email)
		if err != nil {
			return err
		}
		if revoked {
			return fmt.Errorf("%w: device credential revoked", ErrCredentialRevoked)
		}
	}
	userCR, err := provider.GetUserByEmail(ctx, token.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return fmt.Errorf("%w: account no longer exists", ErrCredentialRevoked)
		}
		return err
	}
	if token.UserUID != string(userCR.GetUID()) {
		return fmt.Errorf("%w: session user identity no longer matches", ErrCredentialRevoked)
	}
	if userCR.GetDeletionTimestamp() != nil {
		return fmt.Errorf("%w: account is being deleted", ErrCredentialRevoked)
	}
	disabled, _, err := unstructured.NestedBool(userCR.Object, "spec", "disabled")
	if err != nil {
		return err
	}
	if disabled {
		return fmt.Errorf("%w: account is disabled", ErrCredentialRevoked)
	}
	restricted, err := provider.validateProvenance(ctx, token, userCR)
	if err != nil {
		var status apierrors.APIStatus
		var transport net.Error
		if (errors.As(err, &status) && !apierrors.IsNotFound(err)) || errors.As(err, &transport) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrCredentialRevoked, err)
	}
	if restricted {
		return fmt.Errorf("%w: credential is restricted to identity operations", ErrCredentialRevoked)
	}
	return nil
}

const (
	// DefaultRevalidateInterval is how often an open stream revalidates the
	// credential that authorised it.
	DefaultRevalidateInterval = 5 * time.Second
	// maxRevalidateFailures is how many consecutive verification failures are
	// tolerated before a stream is ended. A verification failure is not a
	// revocation: the account state may simply be momentarily unavailable.
	maxRevalidateFailures = 3
)

// WatchCredentialRevocation revalidates a credential on an interval and calls
// onRevoked once the credential is no longer usable. The returned function
// stops the watcher.
//
// A revoked credential ends the stream immediately. A verification failure is
// retried, because the account state may only be momentarily unavailable; after
// repeated failures the stream is ended rather than left open on unverified
// state.
func WatchCredentialRevocation(ctx context.Context, revalidate func(context.Context) error, interval time.Duration, onRevoked func(reason string)) func() {
	if revalidate == nil || onRevoked == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = DefaultRevalidateInterval
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := make(chan struct{})
	go func() {
		defer cancel()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		failures := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
			}
			checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
			err := revalidate(checkCtx)
			checkCancel()
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				failures = 0
				continue
			}
			if errors.Is(err, ErrCredentialRevoked) {
				onRevoked("credential revoked")
				return
			}
			failures++
			if failures >= maxRevalidateFailures {
				onRevoked("credential could not be verified")
				return
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); close(stop) }) }
}
