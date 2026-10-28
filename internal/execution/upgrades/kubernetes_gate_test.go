package upgrades

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/updates"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

var (
	gateUserResource   = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "users"}
	gateAuthResource   = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "authconfigs"}
	gatePolicyResource = schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "platformconfigs"}
	gateVMResource     = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachines"}
	gateSecretResource = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
)

const gateSigningKey = "synthetic-phase-gate-signing-key-not-for-production"

type gateFixture struct {
	gate       *KubernetesPhaseGate
	client     *fake.FakeDynamicClient
	objects    map[string]*unstructured.Unstructured
	attempt    storage.AgentUpgradeAttempt
	journal    *updates.Journal
	credential string
	issuer     *PhaseIssuer
	intent     storage.UpgradePhaseIntent
	ledger     *phaseLedgerProbe
	phase      PhaseContext
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	t.Setenv("POD_NAMESPACE", auth.LocalAuthSystemNamespace)
	ctx := context.Background()
	issuer, ledger, source, _, intent, _ := phaseIssuerFixture(t)
	j, err := updates.DecodeJournal(intent.Checkpoint, intent.PlanSHA256, intent.CheckpointSHA256, 1)
	if err != nil {
		t.Fatal(err)
	}
	a, err := issuer.attempts.Get(ctx, intent.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	predecessor := storage.AttemptPredecessor{TargetID: "previous", ManifestSHA256: j.Snapshot().Plan.Binding.PreviousSHA256}
	if err := issuer.attempts.Transition(ctx, a.AttemptID, a.State, storage.AttemptTransition{
		To: storage.AttemptStaging, Now: issuer.now(), Fence: &a.LeaseFence, Predecessor: &predecessor,
	}); err != nil {
		t.Fatal(err)
	}
	a, err = issuer.attempts.Get(ctx, a.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	object := func(apiVersion, kind, name, uid, namespace string, spec map[string]interface{}) *unstructured.Unstructured {
		metadata := map[string]interface{}{"name": name, "uid": uid, "resourceVersion": "1"}
		if namespace != "" {
			metadata["namespace"] = namespace
		}
		return &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": apiVersion, "kind": kind, "metadata": metadata, "spec": spec}}
	}
	objects := map[string]*unstructured.Unstructured{
		"auth": object("kubeworkspaces.io/v1alpha1", "AuthConfig", "default", "auth-config-uid", "", map[string]interface{}{
			"enabled": true, "localAuth": map[string]interface{}{"enabled": true},
			"session": map[string]interface{}{"signingKey": map[string]interface{}{"name": "phase-signing", "key": "key"}},
		}),
		"policy": object("kubeworkspaces.io/v1alpha1", "PlatformConfig", "default", "platform-config-uid", "", map[string]interface{}{
			"agentUpgrades": map[string]interface{}{"enabled": true}, "vmExecution": map[string]interface{}{"enabled": true, "allowElevated": true},
		}),
		"user": object("kubeworkspaces.io/v1alpha1", "User", "operator", a.ActorUID, "", map[string]interface{}{
			"email": "operator@example.com", "role": "admin", "executionGrants": []interface{}{},
			"namespaceAccess": []interface{}{map[string]interface{}{"namespace": a.Namespace, "role": "editor"}},
			"localAuth":       map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": "phase-password", "key": "passwordHash"}},
		}),
		"workspace": object("kubeworkspaces.io/v1alpha1", "Workspace", a.WorkspaceName, a.WorkspaceUID, a.Namespace, map[string]interface{}{
			"type": "vm", "vmProfile": map[string]interface{}{"id": "windows11-amd64-v1", "generation": "generation-1"},
		}),
		"vm":       object("kubevirt.io/v1", "VirtualMachine", a.WorkspaceName, a.VMUID, a.Namespace, map[string]interface{}{"running": true}),
		"signer":   object("v1", "Secret", "phase-signing", "signing-secret-uid", auth.LocalAuthSystemNamespace, nil),
		"password": object("v1", "Secret", "phase-password", "password-secret-uid", auth.LocalAuthSystemNamespace, nil),
	}
	objects["signer"].Object["data"] = map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte(gateSigningKey))}
	objects["password"].Object["data"] = map[string]interface{}{"passwordHash": base64.StdEncoding.EncodeToString([]byte("synthetic-password-hash")),
		"mustChangePassword": base64.StdEncoding.EncodeToString([]byte("false"))}
	objects["password"].SetAnnotations(map[string]string{"kubeworkspaces.io/user-uid": a.ActorUID})
	objects["password"].SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "kubeworkspaces.io/v1alpha1", Kind: "User", Name: "operator", UID: objects["user"].GetUID()}})
	objects["workspace"].SetAnnotations(map[string]string{"kubeworkspaces.io/windows-provisioned-generation": "generation-1"})
	objects["workspace"].Object["status"] = map[string]interface{}{"managementExecution": map[string]interface{}{"vmUID": a.VMUID, "revocationEpoch": int64(a.ExpectedRevocationEpoch)}}
	objects["vm"].SetAnnotations(map[string]string{"kubeworkspaces.io/windows-generation": "generation-1"})
	controller := true
	objects["vm"].SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "kubeworkspaces.io/v1alpha1", Kind: "Workspace", Name: a.WorkspaceName,
		UID: objects["workspace"].GetUID(), Controller: &controller}})
	list := make([]runtime.Object, 0, len(objects))
	for _, obj := range objects {
		list = append(list, obj)
	}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gateUserResource: "UserList"}, list...)
	gate, err := NewKubernetesPhaseGate(client)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := auth.CreateSessionTokenWithProvenance("operator@example.com", "Operator", "admin", nil, []byte(gateSigningKey), time.Hour, a.ActorUID,
		auth.SessionProvenance{AuthMethod: "local", CredentialVersion: auth.LocalCredentialVersion(a.ActorUID, "phase-password", "passwordHash", "synthetic-password-hash")})
	if err != nil {
		t.Fatal(err)
	}
	return &gateFixture{gate: gate, client: client, objects: objects, attempt: a, journal: j, credential: credential, issuer: issuer, intent: intent, ledger: ledger, phase: source.current}
}

func (f *gateFixture) update(t *testing.T, name string, mutate func(*unstructured.Unstructured)) {
	t.Helper()
	obj := f.objects[name].DeepCopy()
	mutate(obj)
	if obj.GetResourceVersion() != "" {
		obj.SetResourceVersion(obj.GetResourceVersion() + "x")
	}
	var resource schema.GroupVersionResource
	switch name {
	case "auth":
		resource = gateAuthResource
	case "policy":
		resource = gatePolicyResource
	case "user":
		resource = gateUserResource
	case "workspace":
		resource = phaseWorkspaceResource
	case "vm":
		resource = gateVMResource
	default:
		resource = gateSecretResource
	}
	if err := f.client.Tracker().Update(resource, obj, obj.GetNamespace()); err != nil {
		t.Fatal(err)
	}
	f.objects[name] = obj
}

func (f *gateFixture) check() (pki.Identity, error) {
	return f.gate.Check(context.Background(), f.attempt, f.journal, f.credential)
}

func TestKubernetesPhaseGateFreshCredentialAndIncarnation(t *testing.T) {
	f := newGateFixture(t)
	i, err := f.check()
	if err != nil || i.Role != pki.RoleGuest || i.WorkspaceUID != f.attempt.WorkspaceUID || i.Generation != f.attempt.VMUID || i.RevocationEpoch != f.attempt.ExpectedRevocationEpoch {
		t.Fatalf("valid control-plane gate denied: %+v %v", i, err)
	}
	for _, action := range f.client.Actions() {
		if action.GetResource().Resource == "pods" || action.GetResource().Resource == "virtualmachineinstances" {
			t.Fatal("management authority acquired a QGA/launcher dependency")
		}
	}
	f.update(t, "vm", func(o *unstructured.Unstructured) { o.SetGeneration(99) })
	if current, err := f.check(); err != nil || current != i {
		t.Fatalf("ordinary VM metadata generation change rotated root identity: %+v %v", current, err)
	}
	f.update(t, "user", func(obj *unstructured.Unstructured) {
		_ = unstructured.SetNestedField(obj.Object, true, "spec", "disabled")
	})
	if i, err := f.check(); err == nil || i != (pki.Identity{}) {
		t.Fatal("last good administrator authorization was cached")
	}
}

func TestKubernetesPhaseGateRevocationAndLifecycleDenials(t *testing.T) {
	mutations := map[string]struct {
		object string
		mutate func(*unstructured.Unstructured)
	}{
		"auth-off": {"auth", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, false, "spec", "enabled")
		}},
		"upgrade-off": {"policy", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, false, "spec", "agentUpgrades", "enabled")
		}},
		"execution-off": {"policy", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, false, "spec", "vmExecution", "enabled")
		}},
		"elevation-off": {"policy", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, false, "spec", "vmExecution", "allowElevated")
		}},
		"malformed-policy": {"policy", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "true", "spec", "vmExecution", "enabled")
		}},
		"unknown-policy": {"policy", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, true, "spec", "agentUpgrades", "force")
		}},
		"user-disabled": {"user", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, true, "spec", "disabled")
		}},
		"user-deleted":  {"user", func(o *unstructured.Unstructured) { now := metav1.Now(); o.SetDeletionTimestamp(&now) }},
		"user-replaced": {"user", func(o *unstructured.Unstructured) { o.SetUID("replacement-uid") }},
		"local-method-revoked": {"user", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, false, "spec", "localAuth", "enabled")
		}},
		"password-revoked": {"password", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, base64.StdEncoding.EncodeToString([]byte("replacement-hash")), "data", "passwordHash")
		}},
		"temporary-password": {"password", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, base64.StdEncoding.EncodeToString([]byte("true")), "data", "mustChangePassword")
		}},
		"missing-profile": {"workspace", func(o *unstructured.Unstructured) { unstructured.RemoveNestedField(o.Object, "spec", "vmProfile") }},
		"unsupported-profile": {"workspace", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "windows11-amd64-v99", "spec", "vmProfile", "id")
		}},
		"workspace-replaced": {"workspace", func(o *unstructured.Unstructured) { o.SetUID("replacement-workspace") }},
		"workspace-deleting": {"workspace", func(o *unstructured.Unstructured) { now := metav1.Now(); o.SetDeletionTimestamp(&now) }},
		"epoch-revoked": {"workspace", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, int64(999), "status", "managementExecution", "revocationEpoch")
		}},
		"epoch-pending": {"workspace", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, int64(999), "spec", "executionRevocationEpoch")
		}},
		"missing-epoch": {"workspace", func(o *unstructured.Unstructured) {
			unstructured.RemoveNestedField(o.Object, "status", "managementExecution")
		}},
		"vm-stopped": {"vm", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, false, "spec", "running")
		}},
		"vm-reset": {"vm", func(o *unstructured.Unstructured) { o.SetUID("reset-vm") }},
		"vm-owner": {"vm", func(o *unstructured.Unstructured) { o.SetOwnerReferences(nil) }},
		"vm-generation": {"vm", func(o *unstructured.Unstructured) {
			o.SetAnnotations(map[string]string{"kubeworkspaces.io/windows-generation": "other"})
		}},
	}
	for _, marker := range []string{"kubeworkspaces.io/reset", "kubeworkspaces.io/stopped", "kubeworkspaces.io/reboot", "kubeworkspaces.io/windows-detaching-generation"} {
		mutations[marker] = struct {
			object string
			mutate func(*unstructured.Unstructured)
		}{"workspace", func(o *unstructured.Unstructured) { o.SetAnnotations(map[string]string{marker: ""}) }}
	}
	for name, test := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newGateFixture(t)
			f.update(t, test.object, test.mutate)
			if i, err := f.check(); err == nil || i != (pki.Identity{}) {
				t.Fatalf("changed %s authorized: %+v %v", name, i, err)
			}
		})
	}
}

func TestKubernetesPhaseGateRejectsDelegationAndUnboundCredentials(t *testing.T) {
	for _, mode := range []string{"delegated-system", "wrong-actor", "other-admin", "unsigned", "legacy", "expired", "missing", "caller-userinfo"} {
		t.Run(mode, func(t *testing.T) {
			f := newGateFixture(t)
			ctx := context.Background()
			switch mode {
			case "delegated-system":
				f.update(t, "user", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, "editor", "spec", "role")
					_ = unstructured.SetNestedSlice(o.Object, []interface{}{map[string]interface{}{"namespace": f.attempt.Namespace,
						"permissions": []interface{}{string(auth.PermissionExec), string(auth.PermissionElevated), string(auth.PermissionManage)}}}, "spec", "executionGrants")
				})
			case "wrong-actor":
				f.attempt.ActorUID = "another-actor"
			case "other-admin":
				f.update(t, "user", func(o *unstructured.Unstructured) { o.SetUID("other-actor") })
				f.update(t, "password", func(o *unstructured.Unstructured) {
					o.SetAnnotations(map[string]string{"kubeworkspaces.io/user-uid": "other-actor"})
					owners := o.GetOwnerReferences()
					owners[0].UID = "other-actor"
					o.SetOwnerReferences(owners)
				})
				f.credential, _ = auth.CreateSessionTokenWithProvenance("operator@example.com", "Operator", "admin", nil, []byte(gateSigningKey), time.Hour, "other-actor",
					auth.SessionProvenance{AuthMethod: "local", CredentialVersion: auth.LocalCredentialVersion("other-actor", "phase-password", "passwordHash", "synthetic-password-hash")})
				if user, err := auth.NewConfigProvider(f.client).AuthorizeExecution(ctx, f.credential, f.attempt.Namespace, f.attempt.WorkspaceName, auth.PermissionExec, true, time.Now()); err != nil || user.UID != "other-actor" {
					t.Fatal("fixture must be a valid different administrator", err)
				}
			case "unsigned":
				f.credential += "forged"
			case "legacy":
				f.credential, _ = auth.CreateSessionToken("operator@example.com", "Operator", "admin", nil, []byte(gateSigningKey), time.Hour)
			case "expired":
				f.credential, _ = auth.CreateSessionToken("operator@example.com", "Operator", "admin", nil, []byte(gateSigningKey), -time.Second, f.attempt.ActorUID)
			case "missing":
				f.credential = ""
			case "caller-userinfo":
				ctx = auth.ContextWithUser(ctx, &auth.UserInfo{UID: f.attempt.ActorUID, Role: "admin"})
				f.credential = ""
			}
			if i, err := f.gate.Check(ctx, f.attempt, f.journal, f.credential); err == nil || i != (pki.Identity{}) {
				t.Fatalf("credential bypass authorized: %+v %v", i, err)
			}
		})
	}
}

func TestKubernetesPhaseGateSnapshotChangesAndOutagesDeny(t *testing.T) {
	for _, mode := range []string{"auth-version", "policy-version", "user-version", "signing-key", "password", "workspace-version", "workspace-read-outage", "user-read-outage", "policy-read-outage"} {
		t.Run(mode, func(t *testing.T) {
			f := newGateFixture(t)
			changed := false
			f.client.PrependReactor("get", "virtualmachines", func(ktesting.Action) (bool, runtime.Object, error) {
				if changed {
					return false, nil, nil
				}
				changed = true
				switch mode {
				case "auth-version":
					f.update(t, "auth", func(*unstructured.Unstructured) {})
				case "policy-version":
					f.update(t, "policy", func(*unstructured.Unstructured) {})
				case "user-version":
					f.update(t, "user", func(*unstructured.Unstructured) {})
				case "workspace-version":
					f.update(t, "workspace", func(*unstructured.Unstructured) {})
				case "signing-key":
					f.update(t, "signer", func(o *unstructured.Unstructured) {
						_ = unstructured.SetNestedField(o.Object, base64.StdEncoding.EncodeToString([]byte("rotated-key")), "data", "key")
					})
				case "password":
					f.update(t, "password", func(o *unstructured.Unstructured) {
						_ = unstructured.SetNestedField(o.Object, base64.StdEncoding.EncodeToString([]byte("rotated-hash")), "data", "passwordHash")
					})
				}
				return false, nil, nil
			})
			if strings.HasSuffix(mode, "outage") {
				resource, verb := "workspaces", "get"
				if mode == "user-read-outage" {
					resource, verb = "users", "list"
				}
				if mode == "policy-read-outage" {
					resource = "platformconfigs"
				}
				f.client.PrependReactor(verb, resource, func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("synthetic cluster outage")
				})
			}
			if i, err := f.check(); err == nil || i != (pki.Identity{}) {
				t.Fatalf("mixed/unavailable authority authorized: %+v %v", i, err)
			}
		})
	}
}

func TestKubernetesPhaseGateAttemptAndDeadlineFencing(t *testing.T) {
	for _, mode := range []string{"cancel", "terminal", "owner", "fence", "expired-lease", "journal-ahead", "previous-manifest", "inventory", "reboot-consent", "expired-journal", "nil-journal", "canceled-context"} {
		t.Run(mode, func(t *testing.T) {
			f := newGateFixture(t)
			ctx := context.Background()
			switch mode {
			case "cancel":
				f.attempt.CancelRequested = true
			case "terminal":
				f.attempt.State = storage.AttemptCancelled
			case "owner":
				f.attempt.LeaseOwner = ""
			case "fence":
				f.attempt.LeaseFence++
			case "expired-lease":
				f.gate.now = func() time.Time { return f.attempt.LeaseExpiresAt }
			case "journal-ahead":
				f.attempt.JournalSequence = f.journal.Snapshot().Sequence + 1
			case "previous-manifest":
				f.attempt.Predecessor.ManifestSHA256 = updates.Digest([]byte("other"))
			case "inventory":
				f.attempt.ExpectedInstalledInventorySHA256 = updates.Digest([]byte("other"))
			case "reboot-consent":
				f.attempt.AllowReboot = true
			case "expired-journal":
				f.attempt.LeaseExpiresAt = time.Now().Add(time.Hour)
				f.gate.now = func() time.Time { return time.Unix(f.journal.Snapshot().ExpiresAt, 0) }
			case "nil-journal":
				f.journal = nil
			case "canceled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if i, err := f.gate.Check(ctx, f.attempt, f.journal, f.credential); err == nil || i != (pki.Identity{}) {
				t.Fatalf("stale attempt authority authorized: %+v %v", i, err)
			}
		})
	}
}

// Test-only composition: artifact/lineage and guest exchange are still doubles.
// This is NOT a production PhaseAuthoritySource implementation.
type gateTestSource struct{ fixture *gateFixture }

func (s gateTestSource) CheckIntent(ctx context.Context, a storage.AgentUpgradeAttempt, j *updates.Journal) error {
	_, err := s.fixture.gate.Check(ctx, a, j, s.fixture.credential)
	return err
}
func (s gateTestSource) CurrentPhase(ctx context.Context, a storage.AgentUpgradeAttempt, j *updates.Journal) (PhaseContext, error) {
	_, err := s.fixture.gate.Check(ctx, a, j, s.fixture.credential)
	return s.fixture.phase, err
}

func TestKubernetesPhaseGateRevocationFencesPhaseSigning(t *testing.T) {
	for _, mode := range []string{"enabled", "policy-revoked", "actor-revoked", "epoch-revoked", "signer-rotated"} {
		t.Run(mode, func(t *testing.T) {
			f := newGateFixture(t)
			f.issuer.source = gateTestSource{f}
			i := f.intent
			if err := f.issuer.RecordIntent(context.Background(), i.AttemptID, i.Owner, i.Checkpoint, i.PlanSHA256, i.CheckpointSHA256); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "policy-revoked":
				f.update(t, "policy", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, false, "spec", "agentUpgrades", "enabled")
				})
			case "actor-revoked":
				f.update(t, "user", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, true, "spec", "disabled")
				})
			case "epoch-revoked":
				f.update(t, "workspace", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, int64(999), "status", "managementExecution", "revocationEpoch")
				})
			case "signer-rotated":
				f.update(t, "signer", func(o *unstructured.Unstructured) {
					_ = unstructured.SetNestedField(o.Object, base64.StdEncoding.EncodeToString([]byte("rotated-key")), "data", "key")
				})
			}
			result, err := f.issuer.Issue(context.Background(), i.AttemptID, i.Owner, f.journal.Snapshot().Sequence)
			if mode == "enabled" {
				if err != nil || len(result.Signature) != 64 || !f.ledger.spent {
					t.Fatal("valid gate composition did not sign the exact phase", err)
				}
			} else if err == nil || len(result.Signature) != 0 || f.ledger.spent {
				t.Fatal("recorded intent bypassed current revocation")
			}
		})
	}
}

func TestKubernetesPhaseGateMissingSnapshotMetadataDenies(t *testing.T) {
	for _, object := range []string{"auth", "policy", "user", "workspace", "vm"} {
		for _, field := range []string{"uid", "resourceVersion"} {
			t.Run(object+"-"+field, func(t *testing.T) {
				f := newGateFixture(t)
				f.update(t, object, func(o *unstructured.Unstructured) { unstructured.RemoveNestedField(o.Object, "metadata", field) })
				if i, err := f.check(); err == nil || i != (pki.Identity{}) {
					t.Fatal("unversioned/unbound snapshot authorized")
				}
			})
		}
	}
	if _, err := NewKubernetesPhaseGate(nil); err == nil {
		t.Fatal("nil cluster client accepted")
	}
	var gate *KubernetesPhaseGate
	if i, err := gate.Check(context.Background(), storage.AgentUpgradeAttempt{}, nil, "credential"); err == nil || i != (pki.Identity{}) {
		t.Fatal("nil gate authorized")
	}
}

func TestKubernetesPhaseGateUsesCurrentExplicitAdminOverride(t *testing.T) {
	f := newGateFixture(t)
	f.update(t, "user", func(o *unstructured.Unstructured) {
		_ = unstructured.SetNestedField(o.Object, "editor", "spec", "role")
	})
	if _, err := f.check(); err == nil {
		t.Fatal("stale token administrator claim authorized")
	}
	f.update(t, "auth", func(o *unstructured.Unstructured) {
		_ = unstructured.SetNestedStringSlice(o.Object, []string{"operator@example.com"}, "spec", "adminEmails")
	})
	if _, err := f.check(); err != nil {
		t.Fatal("current explicit platform administrator override denied", err)
	}
	f.update(t, "auth", func(o *unstructured.Unstructured) { unstructured.RemoveNestedField(o.Object, "spec", "adminEmails") })
	if _, err := f.check(); err == nil {
		t.Fatal("removed administrator override was cached")
	}
}

func TestKubernetesPhaseGateRechecksDeadlinesAfterClusterReads(t *testing.T) {
	for _, mode := range []string{"credential", "lease", "journal"} {
		t.Run(mode, func(t *testing.T) {
			f := newGateFixture(t)
			now := time.Now()
			late := f.attempt.LeaseExpiresAt
			if mode == "credential" {
				f.credential, _ = auth.CreateSessionTokenWithProvenance("operator@example.com", "Operator", "admin", nil, []byte(gateSigningKey), 5*time.Minute, f.attempt.ActorUID,
					auth.SessionProvenance{AuthMethod: "local", CredentialVersion: auth.LocalCredentialVersion(f.attempt.ActorUID, "phase-password", "passwordHash", "synthetic-password-hash")})
				token, err := auth.ValidateSessionToken(f.credential, []byte(gateSigningKey))
				if err != nil {
					t.Fatal(err)
				}
				late = time.Unix(token.ExpiresAt, 0)
				f.attempt.LeaseExpiresAt = now.Add(10 * time.Minute)
			} else if mode == "journal" {
				late = time.Unix(f.journal.Snapshot().ExpiresAt, 0)
				f.attempt.LeaseExpiresAt = now.Add(time.Hour)
			}
			f.gate.now = func() time.Time { return now }
			f.client.PrependReactor("get", "virtualmachines", func(ktesting.Action) (bool, runtime.Object, error) {
				now = late // model slow reads, without a real clock wait
				return false, nil, nil
			})
			if i, err := f.check(); err == nil || i != (pki.Identity{}) {
				t.Fatalf("%s expiry during reads authorized: %+v %v", mode, i, err)
			}
		})
	}
}
