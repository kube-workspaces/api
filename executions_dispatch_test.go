package kubeworkspaces

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktesting "k8s.io/client-go/testing"
)

// Mutate live authority after the recorded input and running transition have
// committed. The admitted input must be finalized without ever
// entering the guest transport, including on an unavailable identity backend.
func TestStartRechecksAuthorityBeforeDispatch(t *testing.T) {
	users := schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "users"}
	platforms := schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "platformconfigs"}
	for _, kind := range []string{"command", "linux-script", "windows-script"} {
		for _, name := range []string{"grant-revoked", "elevation-revoked", "wrong-namespace", "wrong-workspace", "malformed-grants", "namespace-removed", "account-disabled", "account-replaced", "account-missing", "account-backend-unavailable", "grant-expired", "policy-disabled", "elevation-disabled", "policy-missing", "client-disconnected", "server-stopped", "unchanged"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				ctx := context.Background()
				requestCtx, disconnect := context.WithCancel(ctx)
				defer disconnect()
				lifecycle, stop := context.WithCancel(ctx)
				defer stop()
				target := eligibleTarget()
				target.Linux = kind == "linux-script"
				code := 0
				stub := &stubQGA{target: target, result: &qga.GuestResult{Outcome: "completed", ExitCode: &code}}
				store, err := storage.Open(ctx, storage.Options{Mode: "ephemeral", EphemeralDir: t.TempDir(), EphemeralMaxBytes: 1 << 20})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = store.Close() })
				boundary := &dispatchBoundaryStore{Store: store}
				stack := newStoredStartStack(t, "team", "vm", []string{string(auth.PermissionExec), string(auth.PermissionElevated), string(auth.PermissionReadRecordings)}, enabledElevatedPolicy(), stub, boundary, WithLifecycleContext(lifecycle))
				boundary.afterStart = func() error {
					if name == "client-disconnected" {
						disconnect()
						return nil
					}
					if name == "server-stopped" {
						stop()
						return nil
					}
					resource := stack.client.Resource(users)
					user, err := resource.Get(ctx, "operator", metav1.GetOptions{})
					if err != nil {
						t.Fatal(err)
					}
					switch name {
					case "grant-revoked":
						_ = unstructured.SetNestedSlice(user.Object, []interface{}{}, "spec", "executionGrants")
					case "wrong-namespace", "wrong-workspace", "malformed-grants":
						grants, _, _ := unstructured.NestedSlice(user.Object, "spec", "executionGrants")
						grant := grants[0].(map[string]interface{})
						if name == "wrong-namespace" {
							grant["namespace"] = "other-team"
						} else if name == "wrong-workspace" {
							grant["workspaces"] = []interface{}{"other-vm"}
						} else {
							grant["unknown-scope"] = "invalid"
						}
						_ = unstructured.SetNestedSlice(user.Object, grants, "spec", "executionGrants")
					case "account-backend-unavailable":
						stack.client.PrependReactor("list", "users", func(ktesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("disposable account backend unavailable")
						})
						return nil
					case "elevation-revoked":
						_ = unstructured.SetNestedSlice(user.Object, []interface{}{map[string]interface{}{"namespace": "team", "permissions": []interface{}{string(auth.PermissionExec)}}}, "spec", "executionGrants")
					case "namespace-removed":
						_ = unstructured.SetNestedSlice(user.Object, []interface{}{}, "spec", "namespaceAccess")
					case "account-disabled":
						_ = unstructured.SetNestedField(user.Object, true, "spec", "disabled")
					case "account-replaced":
						user.SetUID("replacement-uid")
					case "account-missing":
						if err := resource.Delete(ctx, "operator", metav1.DeleteOptions{}); err != nil {
							t.Fatal(err)
						}
						return nil
					case "grant-expired":
						grants, _, _ := unstructured.NestedSlice(user.Object, "spec", "executionGrants")
						grants[0].(map[string]interface{})["expiresAt"] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
						_ = unstructured.SetNestedSlice(user.Object, grants, "spec", "executionGrants")
					case "policy-disabled", "elevation-disabled", "policy-missing":
						p := stack.client.Resource(platforms)
						if name == "policy-missing" {
							if err := p.Delete(ctx, "default", metav1.DeleteOptions{}); err != nil {
								t.Fatal(err)
							}
							return nil
						}
						policy, err := p.Get(ctx, "default", metav1.GetOptions{})
						if err != nil {
							t.Fatal(err)
						}
						field := "enabled"
						if name == "elevation-disabled" {
							field = "allowElevated"
						}
						_ = unstructured.SetNestedField(policy.Object, false, "spec", "vmExecution", field)
						if _, err := p.Update(ctx, policy, metav1.UpdateOptions{}); err != nil {
							t.Fatal(err)
						}
						return nil
					}
					if _, err := resource.Update(ctx, user, metav1.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
					return nil
				}
				body := `{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[]}`
				if kind == "linux-script" {
					body = `{"namespace":"team","workspace_name":"vm","script":{"body":"#!/bin/sh\nprintf sensitive-input"}}`
				} else if kind == "windows-script" {
					body = `{"namespace":"team","workspace_name":"vm","script":{"body":"#!powershell\nWrite-Output sensitive-input"}}`
				}
				w := stack.postCtx(requestCtx, body)
				if len(stub.commands) != 0 && name != "unchanged" {
					t.Fatal("revoked/unverifiable authority reached guest dispatch")
				}
				// A canceled request may prevent admission itself. No guest ran and
				// no success is claimed; remaining cases reach recorded finalization.
				if name == "client-disconnected" && w.Code == http.StatusServiceUnavailable {
					return
				}
				if w.Code != http.StatusOK {
					t.Fatalf("expected recorded terminal outcome: %d %s", w.Code, w.Body.String())
				}
				var response struct {
					ExecutionID string `json:"execution_id"`
					State       string `json:"state"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				rec, outcome, err := stack.store.Metadata().Get(ctx, response.ExecutionID)
				if err != nil || !outcome.State.Terminal() {
					t.Fatalf("missing terminal state: %+v %v", outcome, err)
				}
				if name == "unchanged" {
					if len(stub.commands) != 1 || response.State != "succeeded" {
						t.Fatalf("unchanged authority did not run once: %s", w.Body.String())
					}
				} else if response.State != "revoked" && response.State != "failed" {
					t.Fatalf("pre-dispatch refusal was misclassified: %s", w.Body.String())
				}
				reader, err := stack.store.Recording().Open(ctx, rec.RecordingID)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				if err := reader.Verify(ctx); err != nil || reader.Manifest().Chunks != 2 {
					t.Fatal("refusal did not retain protected input and result")
				}
			})
		}
	}
}

// Intercept only the real running transition; all admission, encryption,
// recording and terminal completion continue through the actual store.
type dispatchBoundaryStore struct {
	storage.Store
	afterStart func() error
}

func (s *dispatchBoundaryStore) Metadata() storage.MetadataStore {
	return &dispatchBoundaryMetadata{MetadataStore: s.Store.Metadata(), store: s}
}

type dispatchBoundaryMetadata struct {
	storage.MetadataStore
	store *dispatchBoundaryStore
}

func (m *dispatchBoundaryMetadata) Transition(ctx context.Context, id string, outcome storage.ExecutionOutcome) error {
	if err := m.MetadataStore.Transition(ctx, id, outcome); err != nil {
		return err
	}
	if outcome.State == storage.StateRunning && m.store.afterStart != nil {
		return m.store.afterStart()
	}
	return nil
}
