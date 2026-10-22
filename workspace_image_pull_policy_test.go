package kubeworkspaces

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	server "github.com/kube-workspaces/api/gen/http/workspaces/server"
	"github.com/kube-workspaces/api/internal/k8s"
	goahttp "goa.design/goa/v3/http"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

// Exercise the real HTTP decoder: the pull policy used to be defaulted to
// IfNotPresent by Goa before buildWorkspaceCR ever saw the payload, which made
// an omitted value indistinguishable from an explicit choice and broke
// :latest updates on restarted workspaces.
func TestWorkspaceImagePullPolicyResolution(t *testing.T) {
	for _, tt := range []struct {
		name       string
		imageSpec  map[string]interface{}
		payload    string
		want       string
		wantAbsent bool
	}{
		{
			name:       "unset everywhere leaves the field unset",
			imageSpec:  map[string]interface{}{"image": "test/signal", "defaultPort": int64(6080)},
			payload:    "",
			wantAbsent: true,
		},
		{
			name:      "image default applies",
			imageSpec: map[string]interface{}{"image": "test/signal", "defaultPort": int64(6080), "defaultImagePullPolicy": "Always"},
			payload:   "",
			want:      "Always",
		},
		{
			name:      "workspace overrides the image default",
			imageSpec: map[string]interface{}{"image": "test/signal", "defaultPort": int64(6080), "defaultImagePullPolicy": "Always"},
			payload:   `,"image_pull_policy":"Never"`,
			want:      "Never",
		},
		{
			name:      "explicit workspace choice without an image default",
			imageSpec: map[string]interface{}{"image": "test/signal", "defaultPort": int64(6080)},
			payload:   `,"image_pull_policy":"IfNotPresent"`,
			want:      "IfNotPresent",
		},
		{
			name:      "image default is overridden by an explicit workspace choice",
			imageSpec: map[string]interface{}{"image": "test/signal", "defaultPort": int64(6080), "defaultImagePullPolicy": "Never"},
			payload:   `,"image_pull_policy":"Always"`,
			want:      "Always",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			image := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Image",
				"metadata": map[string]interface{}{"name": "signal"},
				"spec":     tt.imageSpec,
			}}
			client := k8s.NewImageClientFor(fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
				map[schema.GroupVersionResource]string{{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "images"}: "ImageList"}, image))

			body := fmt.Sprintf(`{"name":"signal","namespace":"test","type":"container","container":{"name":"signal","image":"test/signal","port":6080,"cpu_request":"500m","memory_request":"512Mi","cpu_limit":"2","memory_limit":"2Gi"}%s}`, tt.payload)
			req := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(body))
			payload, err := server.DecodeCreateRequest(nil, func(r *http.Request) goahttp.Decoder { return json.NewDecoder(r.Body) })(req)
			if err != nil {
				t.Fatal(err)
			}
			ws := buildWorkspaceCR(payload, client)
			pod, _, _ := unstructured.NestedMap(ws.Object, "spec", "template", "spec")
			main := pod["containers"].([]interface{})[0].(map[string]interface{})

			got, ok := main["imagePullPolicy"]
			if tt.wantAbsent {
				if ok {
					t.Fatalf("imagePullPolicy should be unset, got %v", got)
				}
				return
			}
			if !ok {
				t.Fatalf("imagePullPolicy missing, want %q", tt.want)
			}
			if got != tt.want {
				t.Fatalf("imagePullPolicy = %v, want %q", got, tt.want)
			}
		})
	}
}
