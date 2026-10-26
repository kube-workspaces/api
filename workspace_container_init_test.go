package kubeworkspaces

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	server "github.com/kube-workspaces/api/gen/http/workspaces/server"
	"github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/k8s"
	goahttp "goa.design/goa/v3/http"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func TestContainerInitImageSnapshotAndOverrides(t *testing.T) {
	for _, kind := range []string{"container", "scratch"} {
		for _, scenario := range []string{"defaults", "disabled", "private-secret", "explicit-data", "empty-data", "both-data", "override-command", "no-command", "no-opt-in"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				image := &unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Image", "metadata": map[string]interface{}{"name": "demo"},
					"spec": map[string]interface{}{"image": "alpine:3.22", "defaultPort": int64(80), "defaultCommand": []interface{}{"sleep"}, "defaultArgs": []interface{}{"infinity"},
						"defaultContainerInit": map[string]interface{}{"mode": "injected"}, "defaultUserData": "#cloud-config\nruncmd: []\n"},
				}}
				dynamic := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "images"}: "ImageList"}, image)
				images := k8s.NewImageClientFor(dynamic)
				extra := ""
				switch scenario {
				case "disabled":
					extra = `,"container_init":{"mode":"disabled"}`
				case "private-secret":
					extra = `,"container_init":{"mode":"injected","user_data_secret":"private"}`
				case "explicit-data":
					extra = `,"container_init":{"mode":"injected","user_data":"#cloud-config\npackages: [curl]\n"}`
				case "empty-data":
					extra = `,"container_init":{"mode":"injected","user_data":""}`
				case "both-data":
					extra = `,"container_init":{"mode":"injected","user_data":"#cloud-config\n","user_data_secret":"private"}`
				case "no-command":
					unstructured.RemoveNestedField(image.Object, "spec", "defaultCommand")
				case "no-opt-in":
					unstructured.RemoveNestedField(image.Object, "spec", "defaultContainerInit")
				}
				if scenario == "no-command" || scenario == "no-opt-in" {
					if _, err := dynamic.Resource(schema.GroupVersionResource{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "images"}).Update(context.Background(), image, metav1.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				body := `{"name":"demo","namespace":"test","type":"` + kind + `","container":{"name":"main","image":"alpine:3.22"}` + extra + `}`
				request := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(body))
				payload, err := server.DecodeCreateRequest(nil, func(r *http.Request) goahttp.Decoder { return json.NewDecoder(r.Body) })(request)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "override-command" {
					payload.Container.Command = []string{"app", "arg with spaces", ""}
				}
				ws := buildWorkspaceCR(payload, images)
				err = validateContainerInitWorkspace(ws)
				if scenario == "empty-data" || scenario == "both-data" || scenario == "no-command" {
					if err == nil {
						t.Fatal("invalid initialization accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				cfg, found, _ := unstructured.NestedMap(ws.Object, "spec", "containerInit")
				if scenario == "no-opt-in" {
					if found {
						t.Fatal("user-data alone enabled initialization")
					}
					return
				}
				if scenario == "disabled" && len(cfg) != 1 {
					t.Fatal("disabled mode retained data")
				}
				if scenario == "private-secret" && (cfg["userData"] != nil || cfg["userDataSecretRef"] == nil) {
					t.Fatal("secret override retained catalog data")
				}
				if scenario == "explicit-data" && !strings.Contains(cfg["userData"].(string), "packages") {
					t.Fatal("explicit data did not override catalog")
				}
				containers, _, _ := unstructured.NestedSlice(ws.Object, "spec", "template", "spec", "containers")
				main := containers[0].(map[string]interface{})
				if scenario == "override-command" {
					command, _, _ := unstructured.NestedStringSlice(main, "command")
					if !reflect.DeepEqual(command, payload.Container.Command) || main["args"] != nil {
						t.Fatal("explicit command did not replace catalog startup verbatim")
					}
				}
				// Changing the Image object after creation cannot change the stored snapshot.
				unstructured.SetNestedField(image.Object, "changed", "spec", "defaultUserData") //nolint:errcheck
				if scenario == "defaults" && cfg["userData"] != "#cloud-config\nruncmd: []\n" {
					t.Fatal("default document was not snapshotted")
				}
			})
		}
	}
}

func TestContainerInitVMRejectsExplicitConfiguration(t *testing.T) {
	p := &workspaces.CreateWorkspacePayload{Name: "vm", Type: "vm", Container: &workspaces.WorkspaceContainer{Name: "main", Image: "vm"}, ContainerInit: &workspaces.WorkspaceContainerInit{Mode: "disabled"}}
	if err := validateContainerInitWorkspace(buildWorkspaceCR(p, nil)); err == nil {
		t.Fatal("VM accepted container initialization configuration")
	}
}

func TestContainerInitIdentitySnapshotAndClear(t *testing.T) {
	defaults := defaultContainerInitSnapshot(&k8s.Image{DefaultContainerInit: &k8s.ImageContainerInit{Mode: "injected", DefaultUser: "developer", RunAsUser: "app"}, DefaultUserData: "#cloud-config\nruncmd: []\n"})
	if defaults["defaultUser"] != "developer" || defaults["runAsUser"] != "app" {
		t.Fatal("identity defaults not snapshotted")
	}
	empty := ""
	cleared := resolveContainerInitOverride(defaults, &workspaces.WorkspaceContainerInit{Mode: "injected", RunAsUser: &empty})
	if cleared["runAsUser"] != nil || cleared["defaultUser"] != "developer" || defaults["runAsUser"] != "app" {
		t.Fatal("explicit clear mutated defaults or retained privilege drop")
	}
	for _, cfg := range []map[string]interface{}{
		{"mode": "injected", "userData": "#cloud-config\n", "runAsUser": "root"},
		{"mode": "injected", "userData": "#cloud-config\n", "defaultUser": "--option"},
		{"mode": "baked-in", "userData": "#cloud-config\n", "runAsUser": "app"},
	} {
		ws := &unstructured.Unstructured{Object: map[string]interface{}{"spec": map[string]interface{}{"type": "container", "containerInit": cfg}}}
		if err := validateContainerInitWorkspace(ws); err == nil {
			t.Fatal("invalid identity request accepted")
		}
	}
}
