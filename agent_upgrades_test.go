package kubeworkspaces

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	genagentupgrades "github.com/kube-workspaces/api/gen/agentupgrades"
	svrau "github.com/kube-workspaces/api/gen/http/agentupgrades/server"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/upgrades"
	"github.com/kube-workspaces/api/internal/platform"
	goahttp "goa.design/goa/v3/http"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

// stubUpgradeEligibility scripts the fail-closed workspace resolver behind the
// upgrade admission surface.
type stubUpgradeEligibility struct {
	target     qga.Target
	resolveErr error
}

func (s *stubUpgradeEligibility) Resolve(_ context.Context, _, _ string) (qga.Target, error) {
	if s.resolveErr != nil {
		return qga.Target{}, s.resolveErr
	}
	return s.target, nil
}

type upgradeStack struct {
	attempts storage.AgentUpgradeStore
	do       func(method, path, body string) *httptest.ResponseRecorder
	anon     func(method, path, body string) *httptest.ResponseRecorder
}

func newUpgradeStack(t *testing.T, role string, policy map[string]interface{}, eligibility *stubUpgradeEligibility) *upgradeStack {
	t.Helper()
	ctx := context.Background()
	key := "upgrade-test-signing-key-32b"
	user := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "User",
		"metadata": map[string]interface{}{"name": "operator", "uid": "operator-uid"},
		"spec": map[string]interface{}{
			"email": "operator@example.com", "role": role,
		},
	}}
	cfg := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "AuthConfig",
		"metadata": map[string]interface{}{"name": "default"},
		"spec": map[string]interface{}{"enabled": true, "session": map[string]interface{}{
			"signingKey": map[string]interface{}{"name": "session-key", "key": "key"},
		}},
	}}
	secret := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]interface{}{"name": "session-key", "namespace": auth.LocalAuthSystemNamespace},
		"data":     map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte(key))},
	}}
	platformConfig := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "PlatformConfig",
		"metadata": map[string]interface{}{"name": "default"},
		"spec":     map[string]interface{}{"agentUpgrades": policy},
	}}
	users := schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "users"}
	passwordSecret, provenance := methodCredentialFixture(user)
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{users: "UserList"}, user, cfg, secret, platformConfig, passwordSecret)
	provider := auth.NewConfigProvider(client)
	store, err := storage.Open(ctx, storage.Options{Mode: "ephemeral", EphemeralDir: t.TempDir(), EphemeralMaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	attempts, err := storage.NewMemoryAgentUpgrades(100)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewAgentUpgrades(upgrades.NewService(store, attempts), platform.NewConfigProvider(client), eligibility)
	mux := goahttp.NewMuxer()
	server := svrau.New(genagentupgrades.NewEndpoints(svc), mux, goahttp.RequestDecoder, goahttp.ResponseEncoder, nil, nil)
	svrau.Mount(mux, server)
	handler := auth.Middleware(provider)(mux)
	token, err := auth.CreateSessionTokenWithProvenance("operator@example.com", "Operator", role, nil, []byte(key), time.Hour, "operator-uid", provenance)
	if err != nil {
		t.Fatal(err)
	}
	return &upgradeStack{
		attempts: attempts,
		do: func(method, path, body string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+token)
			if body != "" {
				r.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			return w
		},
		anon: func(method, path, body string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, path, strings.NewReader(body))
			if body != "" {
				r.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			return w
		},
	}
}

// digest64 is a valid lowercase sha256-shaped digest for request validation.
const digest64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digest64B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func upgradeStartJSON(idempotencyKey string) string {
	return `{"namespace":"team","name":"vm","target_id":"windows11-amd64-v2",` +
		`"target_manifest_sha256":"` + digest64 + `","expected_vm_uid":"vm-uid","expected_revocation_epoch":4,` +
		`"expected_installed_inventory_sha256":"` + digest64B + `","idempotency_key":"` + idempotencyKey + `","allow_reboot":false}`
}

func eligibleUpgradeTarget() qga.Target {
	return qga.Target{
		Namespace: "team", WorkspaceName: "vm", WorkspaceUID: "ws-uid",
		VMUID: "vm-uid", PodName: "virt-launcher-vm", PodUID: "pod-uid", Domain: "team_vm",
	}
}

func enabledUpgradePolicy() map[string]interface{} {
	return map[string]interface{}{"enabled": true}
}

// wireAttempt mirrors the JSON wire shape of the attempt result: the
// generated Go types carry no encoding/json tags, so tests decode the
// snake_case attributes directly.
type wireAttempt struct {
	AttemptID     string `json:"attempt_id"`
	Namespace     string `json:"namespace"`
	WorkspaceName string `json:"workspace_name"`
	WorkspaceUID  string `json:"workspace_uid"`
	VMUID         string `json:"vm_uid"`
	ActorID       string `json:"actor_id"`
	State         string `json:"state"`
	TargetID      string `json:"target_id"`
	ExecutionID   string `json:"execution_id"`
	RecordingID   string `json:"recording_id"`
	RecordingURL  string `json:"recording_url"`
	StatusURL     string `json:"status_url"`
}

func decodeUpgradeAttempt(t *testing.T, w *httptest.ResponseRecorder) *wireAttempt {
	t.Helper()
	var response wireAttempt
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return &response
}

func TestAgentUpgradesRequireAdminPrincipal(t *testing.T) {
	eligibility := &stubUpgradeEligibility{target: eligibleUpgradeTarget()}
	// Unauthenticated callers never see the surface.
	anonymous := newUpgradeStack(t, "admin", enabledUpgradePolicy(), eligibility)
	if w := anonymous.anon(http.MethodGet, "/v1/workspaces/vm/agent-upgrades/availability?namespace=team", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous must be unauthorized: %d %s", w.Code, w.Body.String())
	}
	if w := anonymous.anon(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", upgradeStartJSON("run-1")); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous start must be unauthorized: %d %s", w.Code, w.Body.String())
	}
	// Authenticated non-administrators are forbidden.
	viewer := newUpgradeStack(t, "viewer", enabledUpgradePolicy(), eligibility)
	if w := viewer.do(http.MethodGet, "/v1/workspaces/vm/agent-upgrades/availability?namespace=team", ""); w.Code != http.StatusForbidden {
		t.Fatalf("viewer must be forbidden: %d %s", w.Code, w.Body.String())
	}
	if w := viewer.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", upgradeStartJSON("run-1")); w.Code != http.StatusForbidden {
		t.Fatalf("viewer start must be forbidden: %d %s", w.Code, w.Body.String())
	}
}

func TestAgentUpgradesAvailability(t *testing.T) {
	t.Run("policy-disabled", func(t *testing.T) {
		stack := newUpgradeStack(t, "admin", map[string]interface{}{"enabled": false}, &stubUpgradeEligibility{target: eligibleUpgradeTarget()})
		w := stack.do(http.MethodGet, "/v1/workspaces/vm/agent-upgrades/availability?namespace=team", "")
		if w.Code != http.StatusOK {
			t.Fatalf("availability: %d %s", w.Code, w.Body.String())
		}
		var response struct {
			PolicyEnabled    bool   `json:"policy_enabled"`
			StorageAvailable bool   `json:"storage_available"`
			Admissible       bool   `json:"admissible"`
			DenyReason       string `json:"deny_reason"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.PolicyEnabled || response.Admissible || response.DenyReason != "policy_disabled" {
			t.Fatalf("unexpected availability: %s", w.Body.String())
		}
	})
	t.Run("admissible", func(t *testing.T) {
		stack := newUpgradeStack(t, "admin", enabledUpgradePolicy(), &stubUpgradeEligibility{target: eligibleUpgradeTarget()})
		w := stack.do(http.MethodGet, "/v1/workspaces/vm/agent-upgrades/availability?namespace=team", "")
		if w.Code != http.StatusOK {
			t.Fatalf("availability: %d %s", w.Code, w.Body.String())
		}
		var response struct {
			PolicyEnabled      bool    `json:"policy_enabled"`
			StorageAvailable   bool    `json:"storage_available"`
			WorkspaceEligible  bool    `json:"workspace_eligible"`
			InventoryAvailable bool    `json:"inventory_available"`
			Admissible         bool    `json:"admissible"`
			DenyReason         string  `json:"deny_reason"`
			VMUID              *string `json:"vm_uid"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if !response.PolicyEnabled || !response.StorageAvailable || !response.WorkspaceEligible ||
			!response.Admissible || response.DenyReason != "" || response.VMUID == nil || *response.VMUID != "vm-uid" {
			t.Fatalf("unexpected availability: %s", w.Body.String())
		}
		// Guest inventory is a mandatory but not-yet-integrated prerequisite:
		// the flag stays false without ever blocking start admission here.
		if response.InventoryAvailable {
			t.Fatal("inventory must stay false until guest integration")
		}
	})
	t.Run("eligibility-unavailable", func(t *testing.T) {
		stack := newUpgradeStack(t, "admin", enabledUpgradePolicy(), &stubUpgradeEligibility{resolveErr: qga.ErrUnavailable})
		w := stack.do(http.MethodGet, "/v1/workspaces/vm/agent-upgrades/availability?namespace=team", "")
		if w.Code != http.StatusOK {
			t.Fatalf("availability: %d %s", w.Code, w.Body.String())
		}
		var response struct {
			Admissible bool   `json:"admissible"`
			DenyReason string `json:"deny_reason"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Admissible || response.DenyReason != "eligibility_unavailable" {
			t.Fatalf("unexpected availability: %s", w.Body.String())
		}
	})
}

func TestAgentUpgradesStartAdmitsDurably(t *testing.T) {
	stack := newUpgradeStack(t, "admin", enabledUpgradePolicy(), &stubUpgradeEligibility{target: eligibleUpgradeTarget()})
	w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", upgradeStartJSON("run-1"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	attempt := decodeUpgradeAttempt(t, w)
	if !strings.HasPrefix(attempt.AttemptID, "upg_") || attempt.State != "admitted" || attempt.VMUID != "vm-uid" {
		t.Fatalf("unexpected attempt: %+v", attempt)
	}
	if attempt.RecordingURL != "/v1/executions/"+attempt.ExecutionID+"/recording" {
		t.Fatalf("recording url: %s", attempt.RecordingURL)
	}
	if !strings.HasPrefix(attempt.StatusURL, "/v1/workspaces/vm/agent-upgrades/"+attempt.AttemptID) {
		t.Fatalf("status url: %s", attempt.StatusURL)
	}
	// The durable attempt record exists in the admitted state.
	rec, err := stack.attempts.Get(context.Background(), attempt.AttemptID)
	if err != nil || rec.State != storage.AttemptAdmitted || rec.ActorUID != "operator-uid" {
		t.Fatalf("stored attempt: %+v %v", rec, err)
	}
	// Identical replay returns the original attempt.
	replay := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", upgradeStartJSON("run-1"))
	if replay.Code != http.StatusAccepted {
		t.Fatalf("replay: %d %s", replay.Code, replay.Body.String())
	}
	if replayed := decodeUpgradeAttempt(t, replay); replayed.AttemptID != attempt.AttemptID {
		t.Fatalf("replay minted a new attempt: %s", replayed.AttemptID)
	}
	// The same key with a different request is a conflict.
	conflictBody := upgradeStartJSON("run-1")
	conflictBody = strings.Replace(conflictBody, "windows11-amd64-v2", "windows11-amd64-v3", 1)
	if w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", conflictBody); w.Code != http.StatusConflict {
		t.Fatalf("idempotency conflict: %d %s", w.Code, w.Body.String())
	}
	// A fresh key still cannot take the reserved VM.
	if w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", upgradeStartJSON("run-2")); w.Code != http.StatusConflict {
		t.Fatalf("reservation conflict: %d %s", w.Code, w.Body.String())
	}
	// Status is available under the exact admitting scope.
	w = stack.do(http.MethodGet, "/v1/workspaces/vm/agent-upgrades/"+attempt.AttemptID+"?namespace=team", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	// A different workspace name never sees the attempt.
	if w := stack.do(http.MethodGet, "/v1/workspaces/other/agent-upgrades/"+attempt.AttemptID+"?namespace=team", ""); w.Code != http.StatusNotFound {
		t.Fatalf("scope mismatch: %d %s", w.Code, w.Body.String())
	}
}

func TestAgentUpgradesStartFailsClosed(t *testing.T) {
	body := upgradeStartJSON("run-1")
	t.Run("policy-disabled", func(t *testing.T) {
		stack := newUpgradeStack(t, "admin", map[string]interface{}{"enabled": false}, &stubUpgradeEligibility{target: eligibleUpgradeTarget()})
		if w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", body); w.Code != http.StatusForbidden {
			t.Fatalf("expected forbidden, got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("ineligible-workspace", func(t *testing.T) {
		stack := newUpgradeStack(t, "admin", enabledUpgradePolicy(), &stubUpgradeEligibility{resolveErr: qga.ErrDenied})
		if w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", body); w.Code != http.StatusBadRequest {
			t.Fatalf("expected invalid, got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("vm-uid-mismatch", func(t *testing.T) {
		stack := newUpgradeStack(t, "admin", enabledUpgradePolicy(), &stubUpgradeEligibility{target: eligibleUpgradeTarget()})
		stale := strings.Replace(body, `"expected_vm_uid":"vm-uid"`, `"expected_vm_uid":"old-vm-uid"`, 1)
		if w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", stale); w.Code != http.StatusConflict {
			t.Fatalf("expected conflict, got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("invalid-payload", func(t *testing.T) {
		stack := newUpgradeStack(t, "admin", enabledUpgradePolicy(), &stubUpgradeEligibility{target: eligibleUpgradeTarget()})
		bad := strings.Replace(body, digest64, "not-a-digest", 1)
		if w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", bad); w.Code != http.StatusBadRequest {
			t.Fatalf("expected invalid, got %d %s", w.Code, w.Body.String())
		}
	})
}

func TestAgentUpgradesCancelAndRollback(t *testing.T) {
	stack := newUpgradeStack(t, "admin", enabledUpgradePolicy(), &stubUpgradeEligibility{target: eligibleUpgradeTarget()})
	w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", upgradeStartJSON("run-1"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	attempt := decodeUpgradeAttempt(t, w)
	// Rollback of a non-failed attempt is a conflict; admission itself never
	// performs a guest effect.
	if w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades/"+attempt.AttemptID+"/rollback?namespace=team", ""); w.Code != http.StatusConflict {
		t.Fatalf("rollback: %d %s", w.Code, w.Body.String())
	}
	// Cancel before any install phase closes the attempt out.
	w = stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades/"+attempt.AttemptID+"/cancel?namespace=team", "")
	if w.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}
	if cancelled := decodeUpgradeAttempt(t, w); cancelled.State != "cancelled" {
		t.Fatalf("state after cancel: %s", cancelled.State)
	}
	// Cancelling a finished attempt is a conflict.
	if w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades/"+attempt.AttemptID+"/cancel?namespace=team", ""); w.Code != http.StatusConflict {
		t.Fatalf("double cancel: %d %s", w.Code, w.Body.String())
	}
	// The reservation is released: a fresh start admits.
	if w := stack.do(http.MethodPost, "/v1/workspaces/vm/agent-upgrades?namespace=team", upgradeStartJSON("run-2")); w.Code != http.StatusAccepted {
		t.Fatalf("restart after cancel: %d %s", w.Code, w.Body.String())
	}
}
