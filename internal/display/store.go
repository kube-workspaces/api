// Package display coordinates the single interactive VM display across API
// replicas. Media never enters this package.
package display

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	coordination "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// ClientTTL is how long a claim stays valid without a renewal, measured on
	// each participant's own monotonic clock from when it sent the request.
	ClientTTL = 4 * time.Second
	// FenceInterval is how long a contender must observe an unchanged
	// resourceVersion before it may take over a held lease. It exceeds the
	// worst case in which a partitioned owner could still be writing input:
	// its renewals fail, and its local input deadline passes, within ClientTTL
	// of losing API contact — long before FenceInterval elapses.
	FenceInterval = 12 * time.Second
	revokedKey    = "kubeworkspaces.io/display-revoked"
	tierKey       = "kubeworkspaces.io/display-tier"
)

var ErrBusy = errors.New("interactive display in use")
var ErrRevoked = errors.New("interactive display ownership revoked")

type observation struct {
	version string
	since   time.Time
}

type Store struct {
	client   kubernetes.Interface
	mu       sync.Mutex
	observed map[string]observation
	now      func() time.Time
}

func NewStore(client kubernetes.Interface) *Store {
	return &Store{client: client, observed: make(map[string]observation), now: time.Now}
}

func leaseName(name string) string {
	h := sha256.Sum256([]byte(name))
	return "kw-display-" + hex.EncodeToString(h[:20])
}

// expired requires this replica to have observed the SAME resourceVersion for
// the fencing interval. We never compare clocks across pods or trust a remote
// wall-clock timestamp for expiry. A CAS update fences renewals racing acquire.
func (s *Store) expired(ns string, lease *coordination.Lease) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ns + "/" + lease.Name
	old, ok := s.observed[key]
	if !ok || old.version != lease.ResourceVersion {
		s.observed[key] = observation{lease.ResourceVersion, s.now()}
		return false
	}
	return s.now().Sub(old.since) >= FenceInterval
}

func held(l *coordination.Lease) bool {
	return l.Spec.HolderIdentity != nil && *l.Spec.HolderIdentity != ""
}

func (s *Store) Claim(ctx context.Context, ns, name, tier string) (string, error) {
	if tier != "vnc" && tier != "tier1" {
		return "", errors.New("invalid display tier")
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(secret[:])
	leases := s.client.CoordinationV1().Leases(ns)
	l, err := leases.Get(ctx, leaseName(name), metav1.GetOptions{})
	create := apierrors.IsNotFound(err)
	if err != nil && !create {
		return "", err
	}
	if create {
		l = &coordination.Lease{ObjectMeta: metav1.ObjectMeta{Name: leaseName(name), Namespace: ns,
			Labels: map[string]string{"app.kubernetes.io/component": "display-ownership"}}}
	} else if held(l) && !s.expired(ns, l) {
		return "", ErrBusy
	}
	l.Spec.HolderIdentity = &id
	seconds := int32(FenceInterval / time.Second)
	l.Spec.LeaseDurationSeconds = &seconds
	now := metav1.NewMicroTime(s.now())
	l.Spec.RenewTime = &now
	l.Annotations = map[string]string{tierKey: tier, revokedKey: "false"}
	if create {
		_, err = leases.Create(ctx, l, metav1.CreateOptions{})
	} else {
		_, err = leases.Update(ctx, l, metav1.UpdateOptions{})
	}
	if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
		return "", ErrBusy
	}
	if err != nil {
		return "", err
	}
	// A fresh claim restarts fencing observation: the next contender must
	// watch this holder's lease go quiet for the full interval.
	s.mu.Lock()
	delete(s.observed, ns+"/"+leaseName(name))
	s.mu.Unlock()
	return id, nil
}

func (s *Store) Renew(ctx context.Context, ns, name, id string) error {
	return s.modify(ctx, ns, name, func(l *coordination.Lease) error {
		if !held(l) || id == "" || *l.Spec.HolderIdentity != id || l.Annotations[revokedKey] == "true" {
			return ErrRevoked
		}
		// Every update bumps resourceVersion, so a contender observing an
		// unchanged version knows no renewal got through. RenewTime itself is
		// informational only — expiry never compares wall clocks across pods.
		now := metav1.NewMicroTime(s.now())
		l.Spec.RenewTime = &now
		return nil
	})
}

// Release is called only after media sockets/workers have stopped. A stale
// token can never release a successor. Tokens must not be logged or sent to guests.
func (s *Store) Release(ctx context.Context, ns, name, id string) error {
	return s.modify(ctx, ns, name, func(l *coordination.Lease) error {
		if !held(l) || id == "" || *l.Spec.HolderIdentity != id {
			return ErrRevoked
		}
		l.Spec.HolderIdentity = nil
		return nil
	})
}

// Revoke marks the current owner revoked without freeing its slot. The old
// proxy/API must stop input before Release, or the full fence interval elapses.
func (s *Store) Revoke(ctx context.Context, ns, name string) (bool, error) {
	wasHeld := false
	err := s.modify(ctx, ns, name, func(l *coordination.Lease) error {
		wasHeld = held(l)
		if l.Annotations == nil {
			l.Annotations = make(map[string]string)
		}
		l.Annotations[revokedKey] = "true"
		return nil
	})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return wasHeld, err
}

func (s *Store) InUse(ctx context.Context, ns, name string) (bool, error) {
	l, err := s.client.CoordinationV1().Leases(ns).Get(ctx, leaseName(name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return held(l) && !s.expired(ns, l), nil
}

func (s *Store) modify(ctx context.Context, ns, name string, change func(*coordination.Lease) error) error {
	leases := s.client.CoordinationV1().Leases(ns)
	l, err := leases.Get(ctx, leaseName(name), metav1.GetOptions{})
	if err != nil {
		return err
	}
	if err = change(l); err != nil {
		return err
	}
	_, err = leases.Update(ctx, l, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return fmt.Errorf("%w: ownership changed", ErrRevoked)
	}
	return err
}
