package kubeworkspaces

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	server "github.com/kube-workspaces/api/gen/http/images/server"
	images "github.com/kube-workspaces/api/gen/images"
	"github.com/kube-workspaces/api/internal/k8s"
	goahttp "goa.design/goa/v3/http"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

// Exercise CR parsing through the generated HTTP transport so provenance cannot
// silently disappear from a result view or response encoder.
func TestImagesRepositoryProvenanceHTTP(t *testing.T) {
	for _, recorded := range []bool{true, false} {
		t.Run(map[bool]string{true: "imported", false: "unrecorded"}[recorded], func(t *testing.T) {
			image := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Image",
				"metadata": map[string]interface{}{"name": "code"},
				"spec":     map[string]interface{}{"displayName": "Code", "image": "ghcr.io/example/code", "defaultPort": int64(8080), "sourceURL": "https://example.com/upstream"},
			}}
			if recorded {
				image.SetLabels(map[string]string{"kubeworkspaces.io/image-repository": "official"})
				image.SetAnnotations(map[string]string{
					"kubeworkspaces.io/source-url": "https://example.com/catalog.git",
					"kubeworkspaces.io/source-ref": "main", "kubeworkspaces.io/source-commit": "abc123",
					"kubeworkspaces.io/source-path": "images/code.yaml",
				})
			}
			client := k8s.NewImageClientFor(fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
				map[schema.GroupVersionResource]string{{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "images"}: "ImageList"}, image))
			mux := goahttp.NewMuxer()
			handler := server.New(images.NewEndpoints(NewImages(client)), mux, goahttp.RequestDecoder, goahttp.ResponseEncoder, nil, nil)
			handler.Mount(mux)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/images", nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status %d: %s", response.Code, response.Body.String())
			}
			var body []map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 1 {
				t.Fatalf("expected one image, got %v", body)
			}
			if body[0]["source_url"] != "https://example.com/upstream" {
				t.Fatal("application source URL must remain distinct from catalog origin")
			}
			for field, want := range map[string]string{
				"source_repository": "official", "source_repository_url": "https://example.com/catalog.git",
				"source_repository_ref": "main", "source_repository_commit": "abc123", "source_repository_path": "images/code.yaml",
			} {
				got, present := body[0][field]
				if recorded && got != want {
					t.Errorf("%s = %v, want %q", field, got, want)
				} else if !recorded && present {
					t.Errorf("unrecorded provenance should omit %s, got %v", field, got)
				}
			}
		})
	}
}
