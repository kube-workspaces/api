package kubeworkspaces

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gen "github.com/kube-workspaces/api/gen/executions"
	svr "github.com/kube-workspaces/api/gen/http/executions/server"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/platform"
	goahttp "goa.design/goa/v3/http"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

// Exercise generated HTTP transports with real authentication, including a live
// User update between requests using the same signed credential.
func TestExecutionHTTPAuthorizationAndReplay(t *testing.T) {
	ctx := context.Background()
	key := "execution-test-signing-key-32-bytes"
	user := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "User",
		"metadata": map[string]interface{}{"name": "reader", "uid": "reader-uid"},
		"spec": map[string]interface{}{
			"email": "reader@example.com", "role": "viewer",
			"namespaceAccess": []interface{}{map[string]interface{}{"namespace": "team", "role": "viewer"}},
			"executionGrants": []interface{}{map[string]interface{}{
				"namespace": "team", "workspaces": []interface{}{"vm"},
				"permissions": []interface{}{string(auth.PermissionManage), string(auth.PermissionReadRecordings)},
			}},
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
	users := schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "users"}
	policy := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "PlatformConfig", "metadata": map[string]interface{}{"name": "default"}, "spec": map[string]interface{}{"vmExecution": map[string]interface{}{"enabled": true, "allowElevated": false}}}}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{users: "UserList"}, user, cfg, secret, policy)
	provider := auth.NewConfigProvider(client)
	store, err := storage.Open(ctx, storage.Options{Mode: "ephemeral", EphemeralDir: t.TempDir(), EphemeralMaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	for _, name := range []string{"vm", "other"} {
		rec := storage.ExecutionRecord{ExecutionID: name, RecordingID: "rec-" + name, ActorID: "owner", Operation: storage.OperationShell, Namespace: "team", WorkspaceName: name, Mode: "ephemeral", Durability: storage.DurabilityNone, Admitted: true, AdmissionTime: time.Now()}
		if err := store.Metadata().Create(ctx, rec); err != nil {
			t.Fatal(err)
		}
		w, err := store.Recording().Begin(ctx, rec.RecordingID)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.PutChunk(ctx, 0, []byte("protected output")); err != nil {
			t.Fatal(err)
		}
		if err := w.Finalize(ctx, storage.FinalizeMeta{}); err != nil {
			t.Fatal(err)
		}
	}
	issuerErr := errors.New("issuer unavailable")
	svc := NewExecutions(execution.NewService(store), platform.NewConfigProvider(client), WithIssuerReadiness(func(context.Context) error { return issuerErr }))
	mux := goahttp.NewMuxer()
	server := svr.New(gen.NewEndpoints(svc), mux, goahttp.RequestDecoder, goahttp.ResponseEncoder, nil, nil)
	svr.Mount(mux, server)
	handler := auth.Middleware(provider)(mux)
	token, err := auth.CreateSessionToken("reader@example.com", "Reader", "admin", nil, []byte(key), time.Hour, "reader-uid")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := auth.CreateSessionToken("reader@example.com", "Reader", "admin", nil, []byte(key), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, credential string, want int) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: got %d %s, want %d", path, w.Code, w.Body.String(), want)
		}
	}
	request("/v1/executions/vm", token, 200)
	checkStatus := func(wantIssuer bool) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/executions/status", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || body["issuer_ready"] != wantIssuer {
			t.Fatalf("issuer readiness response: %d %s", w.Code, w.Body.String())
		}
	}
	checkStatus(false)
	issuerErr = nil
	checkStatus(true)
	issuerErr = errors.New("issuer unavailable again")
	checkStatus(false)
	request("/v1/executions/status", legacy, 401)
	request("/v1/executions?namespace=team&workspace_name=vm", token, 200)
	request("/v1/executions", token, 403)
	request("/v1/executions/other", token, 404)
	request("/v1/executions/vm", legacy, 401)
	request("/v1/executions/vm/recording", token, 200)
	request("/v1/executions/vm/recording/chunks/0", token, 200)
	request("/v1/executions/other/recording", token, 403)
	request("/v1/executions/vm/recording/chunks/1", token, 404)
	// Management and recording-read are independent: metadata administration
	// alone must never disclose terminal content.
	unstructured.SetNestedSlice(user.Object, []interface{}{map[string]interface{}{
		"namespace": "team", "workspaces": []interface{}{"vm"},
		"permissions": []interface{}{string(auth.PermissionManage)},
	}}, "spec", "executionGrants")
	if _, err := client.Resource(users).Update(ctx, user, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	request("/v1/executions/vm", token, 200)
	request("/v1/executions/vm/recording", token, 403)
	unstructured.SetNestedSlice(user.Object, []interface{}{}, "spec", "executionGrants")
	if _, err := client.Resource(users).Update(ctx, user, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	request("/v1/executions/vm", token, 404)
	request("/v1/executions/vm/recording", token, 403)
}
