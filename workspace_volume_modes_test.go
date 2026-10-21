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

// Exercise the real HTTP decoder: a service-only test would miss Goa applying
// the old readonly=true default before buildWorkspaceCR sees the payload.
func TestWorkspaceVolumeModes(t *testing.T) {
	image := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "Image",
		"metadata": map[string]interface{}{"name": "signal"},
		"spec": map[string]interface{}{
			"image": "test/signal", "defaultPort": int64(6080), "defaultUID": int64(1000),
			"defaultInitContainers": []interface{}{map[string]interface{}{
				"name": "permfix", "image": "busybox:1.37", "command": []interface{}{"sh", "-c", "chown -R {{uid}}:{{uid}} /home/signal"},
			}},
		},
	}}
	client := k8s.NewImageClientFor(fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{{Group: "kubeworkspaces.io", Version: "v1alpha1", Resource: "images"}: "ImageList"}, image))
	for _, tt := range []struct {
		name, wsType, extra string
		want                bool
	}{
		{"container omitted", "container", "", false},
		{"container false", "container", `,"readonly":false`, false},
		{"container true", "container", `,"readonly":true`, true},
		{"VM disk omitted", "vm", `,"type":"disk"`, false},
		{"VM CD-ROM omitted", "vm", `,"type":"cdrom"`, true},
		{"VM CD-ROM false", "vm", `,"type":"cdrom","readonly":false`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"name":"signal","namespace":"test","type":%q,"container":{"name":"signal","image":"test/signal","port":6080,"cpu_request":"500m","memory_request":"512Mi","cpu_limit":"2","memory_limit":"2Gi"},"shared_memory":true,"volume_mounts":[{"name":"home","mount_path":"/home/signal"%s}]}`, tt.wsType, tt.extra)
			req := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(body))
			payload, err := server.DecodeCreateRequest(nil, func(r *http.Request) goahttp.Decoder { return json.NewDecoder(r.Body) })(req)
			if err != nil {
				t.Fatal(err)
			}
			ws := buildWorkspaceCR(payload, client)
			pod, _, _ := unstructured.NestedMap(ws.Object, "spec", "template", "spec")
			main := pod["containers"].([]interface{})[0].(map[string]interface{})
			init := pod["initContainers"].([]interface{})[0].(map[string]interface{})
			for name, container := range map[string]map[string]interface{}{"app": main, "permfix": init} {
				mount := container["volumeMounts"].([]interface{})[0].(map[string]interface{})
				if mount["readOnly"] != tt.want {
					t.Fatalf("%s mount: %#v", name, mount)
				}
			}
			result := unstructuredToWorkspace(ws, nil)
			if tt.wsType == "container" && len(result.VolumeMounts) != 1 {
				t.Fatalf("auxiliary shm leaked into editable PVCs: %+v", result.VolumeMounts)
			}
			if result.VolumeMounts[0].Readonly == nil || *result.VolumeMounts[0].Readonly != tt.want {
				t.Fatal("mount mode lost in response")
			}
		})
	}
}
