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
	// controlKey records which session participant holds the control lease.
	// It is written only by the local claimer; readers treat it as advisory to
	// the registry, never as an authorization boundary on its own.
	controlKey = "kubeworkspaces.io/control-participant"
	// ownerKey records which API replica claimed a lease, so other replicas can
	// route participants to the pod generating a workspace's display instead of
	// dialing a second VNC console.
	ownerKey = "kubeworkspaces.io/display-owner"
)

var ErrBusy = errors.New("interactive display in use")
var ErrRevoked = errors.New("interactive display ownership revoked")

// OwnershipError reports that another API replica owns a workspace display or
// its control slot. Owner is the replica identity recorded on the lease at
// claim time (see ownerKey); Kind is which lease held it
// ("display-ownership" or "display-control"). It unwraps to ErrBusy so callers
// keep working with a plain busy check while learning where to route.
type OwnershipError struct {
	Owner string
	Kind  string
}

func (e *OwnershipError) Error() string {
	return fmt.Sprintf("interactive display owned by replica %q (%s)", e.Owner, e.Kind)
}

func (e *OwnershipError) Unwrap() error { return ErrBusy }

type observation struct {
	version string
	since   time.Time
}

type Store struct {
	client   kubernetes.Interface
	owner    string
	mu       sync.Mutex
	observed map[string]observation
	now      func() time.Time
}

func NewStore(client kubernetes.Interface) *Store {
	return NewStoreWithOwner(client, "")
}

// NewStoreWithOwner attaches this API replica's identity to every lease it
// claims. Other replicas read it to route clients to the pod that actually
// generates a workspace's display (see Owner, SeatOwner, ControlOwner).
func NewStoreWithOwner(client kubernetes.Interface, owner string) *Store {
	return &Store{client: client, owner: owner, observed: make(map[string]observation), now: time.Now}
}

// Owner reports the replica identity this store writes onto claims.
func (s *Store) Owner() string { return s.owner }

// SetNow overrides the store's clock. It exists for tests that drive fencing
// observations through time.
func (s *Store) SetNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

func leaseName(name string) string {
	h := sha256.Sum256([]byte(name))
	return "kw-display-" + hex.EncodeToString(h[:20])
}

// controlLeaseName derives the control-role lease for a workspace. It is a
// separate coordination object from the capture/seat lease so a controller's
// input claim can die independently of the broker's framebuffer ownership.
func controlLeaseName(name string) string {
	h := sha256.Sum256([]byte(name))
	return "kw-display-control-" + hex.EncodeToString(h[:20])
}

// captureLeaseName derives the VNC-console capture lease for a workspace. It
// coordinates the one resource the seat lease does not model on its own: the
// single KubeVirt VNC console connection. Every console dialer holds it —
// the legacy bridge and a full shared-display generation via their seat
// claim, and an observer-only broker generation on its own, which is how
// observers can watch a desktop while a Tier 1 session holds the seat.
func captureLeaseName(name string) string {
	h := sha256.Sum256([]byte(name))
	return "kw-display-capture-" + hex.EncodeToString(h[:20])
}

// membershipLeaseName derives the membership-owner lease for a workspace. The
// session registry is in-memory per replica, so before any generation exists
// the first join must record WHICH replica holds the membership: sibling
// replicas then forward stream attaches and REST calls there instead of
// answering 404 from an empty registry. The lease gates nothing media-side —
// it is a routing marker with the same fencing/expiry semantics as the other
// display leases, claimed on first join, renewed while members exist, and
// released when the last member leaves.
func membershipLeaseName(name string) string {
	h := sha256.Sum256([]byte(name))
	return "kw-display-membership-" + hex.EncodeToString(h[:20])
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
	return s.claimLease(ctx, leaseName(name), ns, map[string]string{tierKey: tier, revokedKey: "false"}, "display-ownership")
}

// claimLease creates or takes over a coordination lease after the fencing
// interval when its holder went quiet. A fresh claim restarts fencing
// observation so the next contender must watch this holder go quiet again.
func (s *Store) claimLease(ctx context.Context, lease string, ns string, annotations map[string]string, component string) (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(secret[:])
	leases := s.client.CoordinationV1().Leases(ns)
	l, err := leases.Get(ctx, lease, metav1.GetOptions{})
	create := apierrors.IsNotFound(err)
	if err != nil && !create {
		return "", err
	}
	if create {
		l = &coordination.Lease{ObjectMeta: metav1.ObjectMeta{Name: lease, Namespace: ns,
			Labels: map[string]string{"app.kubernetes.io/component": component}}}
	} else if held(l) && !s.expired(ns, l) {
		if owner := l.Annotations[ownerKey]; owner != "" && owner != s.owner {
			return "", &OwnershipError{Owner: owner, Kind: component}
		}
		return "", ErrBusy
	}
	l.Spec.HolderIdentity = &id
	seconds := int32(FenceInterval / time.Second)
	l.Spec.LeaseDurationSeconds = &seconds
	now := metav1.NewMicroTime(s.now())
	l.Spec.RenewTime = &now
	l.Annotations = annotations
	if s.owner != "" {
		// Never mutate the caller's map; add the replica identity on top.
		l.Annotations = make(map[string]string, len(annotations)+1)
		for k, v := range annotations {
			l.Annotations[k] = v
		}
		l.Annotations[ownerKey] = s.owner
	}
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
	delete(s.observed, ns+"/"+lease)
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
		if l.Annotations != nil {
			delete(l.Annotations, ownerKey)
		}
		return nil
	})
}

// Revoke marks the current owner revoked without freeing its slot. The old
// proxy/API must stop input before Release, or the full fence interval elapses.
func (s *Store) Revoke(ctx context.Context, ns, name string) (bool, error) {
	wasHeld := false
	err := s.modifyNamed(ctx, leaseName(name), ns, func(l *coordination.Lease) error {
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

// ClaimControl takes the control-role lease for a workspace, associated with a
// session participant id. It lives in a separate coordination object from the
// capture/seat lease so input ownership can be split from framebuffer capture
// (and revoked/transferred independently).
func (s *Store) ClaimControl(ctx context.Context, ns, name, participant string) (string, error) {
	if participant == "" {
		return "", errors.New("control participant required")
	}
	return s.claimLease(ctx, controlLeaseName(name), ns, map[string]string{controlKey: participant, revokedKey: "false"}, "display-control")
}

// RenewControl keeps the control lease alive. Once revoked it only fails; a
// stripped controller loses the lease at the developer-controlled fence bound.
func (s *Store) RenewControl(ctx context.Context, ns, name, token string) error {
	return s.modifyNamed(ctx, controlLeaseName(name), ns, func(l *coordination.Lease) error {
		if !held(l) || token == "" || *l.Spec.HolderIdentity != token || l.Annotations[revokedKey] == "true" {
			return ErrRevoked
		}
		now := metav1.NewMicroTime(s.now())
		l.Spec.RenewTime = &now
		return nil
	})
}

// ReleaseControl frees the control lease held by token. A stale token can never
// release a successor.
func (s *Store) ReleaseControl(ctx context.Context, ns, name, token string) error {
	return s.modifyNamed(ctx, controlLeaseName(name), ns, func(l *coordination.Lease) error {
		if !held(l) || token == "" || *l.Spec.HolderIdentity != token {
			return ErrRevoked
		}
		l.Spec.HolderIdentity = nil
		if l.Annotations == nil {
			l.Annotations = make(map[string]string)
		}
		delete(l.Annotations, controlKey)
		delete(l.Annotations, ownerKey)
		return nil
	})
}

// RevokeControl strips the current control holder without freeing the slot,
// mirroring Revoke for the capture seat. Renewal fails immediately; input stops
// within ClientTTL of the holder observing the revoke.
func (s *Store) RevokeControl(ctx context.Context, ns, name string) (bool, error) {
	wasHeld := false
	err := s.modifyNamed(ctx, controlLeaseName(name), ns, func(l *coordination.Lease) error {
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

// ControlInUse reports whether the control lease is currently held (not fenced).
func (s *Store) ControlInUse(ctx context.Context, ns, name string) (bool, error) {
	l, err := s.client.CoordinationV1().Leases(ns).Get(ctx, controlLeaseName(name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return held(l) && !s.expired(ns, l), nil
}

// ControlHolder reports the control lease's recorded participant, whether the
// lease is held, and the holder token. The participant id is advisory to the
// registry and is not an authorization boundary on its own.
func (s *Store) ControlHolder(ctx context.Context, ns, name string) (string, bool, error) {
	l, err := s.client.CoordinationV1().Leases(ns).Get(ctx, controlLeaseName(name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return l.Annotations[controlKey], held(l) && !s.expired(ns, l), nil
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

// SeatTier reports the transport tier recorded on a held seat lease: "vnc",
// "tier1", or "" when the seat is free (or held by a build that records no
// tier). A shared-display broker uses it to tell "a Tier 1 controller owns
// this desktop — observers may watch but nobody here may drive" from every
// other hold state.
func (s *Store) SeatTier(ctx context.Context, ns, name string) (string, bool, error) {
	l, err := s.client.CoordinationV1().Leases(ns).Get(ctx, leaseName(name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !held(l) || s.expired(ns, l) {
		return "", false, nil
	}
	return l.Annotations[tierKey], true, nil
}

// ClaimCapture takes the VNC-console capture lease for a workspace. See
// captureLeaseName for who claims it and why.
func (s *Store) ClaimCapture(ctx context.Context, ns, name string) (string, error) {
	return s.claimLease(ctx, captureLeaseName(name), ns, map[string]string{revokedKey: "false"}, "display-capture")
}

// RenewCapture keeps the capture lease alive, with the same fencing semantics
// as Renew.
func (s *Store) RenewCapture(ctx context.Context, ns, name, id string) error {
	return s.modifyNamed(ctx, captureLeaseName(name), ns, func(l *coordination.Lease) error {
		if !held(l) || id == "" || *l.Spec.HolderIdentity != id || l.Annotations[revokedKey] == "true" {
			return ErrRevoked
		}
		now := metav1.NewMicroTime(s.now())
		l.Spec.RenewTime = &now
		return nil
	})
}

// ReleaseCapture frees the capture lease held by id, called only after the
// console connection it guarded is closed. A stale id can never release a
// successor.
func (s *Store) ReleaseCapture(ctx context.Context, ns, name, id string) error {
	return s.modifyNamed(ctx, captureLeaseName(name), ns, func(l *coordination.Lease) error {
		if !held(l) || id == "" || *l.Spec.HolderIdentity != id {
			return ErrRevoked
		}
		l.Spec.HolderIdentity = nil
		if l.Annotations != nil {
			delete(l.Annotations, ownerKey)
		}
		return nil
	})
}

// CaptureOwner reports the replica that currently holds the capture lease for
// ns/name, or "" when it is free or absent. It is the cross-replica routing
// key for shared-display traffic: a replica that cannot claim the capture
// must send observers to the owner instead of dialing a second console.
func (s *Store) CaptureOwner(ctx context.Context, ns, name string) (string, error) {
	return s.leaseOwner(ctx, captureLeaseName(name), ns)
}

// ClaimMembership takes the membership-owner lease for a workspace. Unlike
// the media leases, a claim by the SAME replica that already holds it adopts
// the slot with a fresh id: after a process restart the registry is empty
// while the old claim may still be fresh, and the replica must be able to
// re-attach its own routing marker without waiting out the fencing interval.
// Another replica's live claim still yields an OwnershipError naming it.
func (s *Store) ClaimMembership(ctx context.Context, ns, name string) (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(secret[:])
	leases := s.client.CoordinationV1().Leases(ns)
	lease := membershipLeaseName(name)
	l, err := leases.Get(ctx, lease, metav1.GetOptions{})
	create := apierrors.IsNotFound(err)
	if err != nil && !create {
		return "", err
	}
	if create {
		l = &coordination.Lease{ObjectMeta: metav1.ObjectMeta{Name: lease, Namespace: ns,
			Labels: map[string]string{"app.kubernetes.io/component": "display-membership"}}}
	} else if held(l) {
		owner := l.Annotations[ownerKey]
		switch {
		case owner == s.owner:
			// Same-owner adopt (including two owner-less stores in tests):
			// fall through and overwrite with the fresh id.
		case !s.expired(ns, l):
			if owner != "" {
				return "", &OwnershipError{Owner: owner, Kind: "display-membership"}
			}
			return "", ErrBusy
		}
	}
	l.Spec.HolderIdentity = &id
	seconds := int32(FenceInterval / time.Second)
	l.Spec.LeaseDurationSeconds = &seconds
	now := metav1.NewMicroTime(s.now())
	l.Spec.RenewTime = &now
	l.Annotations = map[string]string{revokedKey: "false"}
	if s.owner != "" {
		l.Annotations[ownerKey] = s.owner
	}
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
	delete(s.observed, ns+"/"+lease)
	s.mu.Unlock()
	return id, nil
}

// RenewMembership keeps the membership lease alive, with the same fencing
// semantics as Renew.
func (s *Store) RenewMembership(ctx context.Context, ns, name, id string) error {
	return s.modifyNamed(ctx, membershipLeaseName(name), ns, func(l *coordination.Lease) error {
		if !held(l) || id == "" || *l.Spec.HolderIdentity != id || l.Annotations[revokedKey] == "true" {
			return ErrRevoked
		}
		now := metav1.NewMicroTime(s.now())
		l.Spec.RenewTime = &now
		return nil
	})
}

// ReleaseMembership frees the membership lease held by id. A stale id can
// never release a successor.
func (s *Store) ReleaseMembership(ctx context.Context, ns, name, id string) error {
	return s.modifyNamed(ctx, membershipLeaseName(name), ns, func(l *coordination.Lease) error {
		if !held(l) || id == "" || *l.Spec.HolderIdentity != id {
			return ErrRevoked
		}
		l.Spec.HolderIdentity = nil
		if l.Annotations != nil {
			delete(l.Annotations, ownerKey)
		}
		return nil
	})
}

// MembershipOwner reports the replica that currently holds the membership
// lease for ns/name, or "" when it is free or absent. It is the cross-replica
// routing key for the in-memory session registry: a replica that cannot find
// a participant locally forwards to the membership owner.
func (s *Store) MembershipOwner(ctx context.Context, ns, name string) (string, error) {
	return s.leaseOwner(ctx, membershipLeaseName(name), ns)
}

// SeatOwner reports the replica that currently holds the capture/seat lease for
// ns/name, or "" when the lease is free or absent.
func (s *Store) SeatOwner(ctx context.Context, ns, name string) (string, error) {
	return s.leaseOwner(ctx, leaseName(name), ns)
}

// LiveSeatOwner is SeatOwner with a liveness check: it returns "" once the
// recorded holder has gone quiet past this replica's fencing observation, so
// routing toward a dead owner's pod stops and a local takeover can proceed.
// The repeated reads that drive routing traffic ARE the fencing observation.
func (s *Store) LiveSeatOwner(ctx context.Context, ns, name string) (string, error) {
	return s.liveOwner(ctx, leaseName(name), ns)
}

// LiveCaptureOwner is CaptureOwner with the same liveness check as
// LiveSeatOwner.
func (s *Store) LiveCaptureOwner(ctx context.Context, ns, name string) (string, error) {
	return s.liveOwner(ctx, captureLeaseName(name), ns)
}

// LiveMembershipOwner is MembershipOwner with the same liveness check as
// LiveSeatOwner.
func (s *Store) LiveMembershipOwner(ctx context.Context, ns, name string) (string, error) {
	return s.liveOwner(ctx, membershipLeaseName(name), ns)
}

func (s *Store) liveOwner(ctx context.Context, lease, ns string) (string, error) {
	l, err := s.client.CoordinationV1().Leases(ns).Get(ctx, lease, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !held(l) {
		return "", nil
	}
	if s.expired(ns, l) {
		return "", nil
	}
	return l.Annotations[ownerKey], nil
}

// ControlOwner reports the replica that currently holds the control-role lease
// for ns/name, or "" when it is free or absent. The control claim is written by
// the seat holder, so this normally equals SeatOwner.
func (s *Store) ControlOwner(ctx context.Context, ns, name string) (string, error) {
	return s.leaseOwner(ctx, controlLeaseName(name), ns)
}

func (s *Store) leaseOwner(ctx context.Context, lease, ns string) (string, error) {
	l, err := s.client.CoordinationV1().Leases(ns).Get(ctx, lease, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return l.Annotations[ownerKey], nil
}

func (s *Store) modify(ctx context.Context, ns, name string, change func(*coordination.Lease) error) error {
	return s.modifyNamed(ctx, leaseName(name), ns, change)
}

func (s *Store) modifyNamed(ctx context.Context, lease string, ns string, change func(*coordination.Lease) error) error {
	leases := s.client.CoordinationV1().Leases(ns)
	l, err := leases.Get(ctx, lease, metav1.GetOptions{})
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
