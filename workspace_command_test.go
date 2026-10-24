package kubeworkspaces

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	server "github.com/kube-workspaces/api/gen/http/workspaces/server"
	goahttp "goa.design/goa/v3/http"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Exercise the HTTP boundary that previously silently discarded command.
func TestScratchCommandSurvivesHTTPDecoder(t *testing.T) {
	for _, command := range []string{`["sleep","infinity"]`, `["sh","-c","echo 'hello world'; exec sleep infinity"]`} {
		body := `{"name":"scratch","namespace":"test","type":"scratch","container":{"name":"main","image":"alpine","command":` + command + `,"args":["argument with spaces"]}}`
		req := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(body))
		payload, err := server.DecodeCreateRequest(nil, func(r *http.Request) goahttp.Decoder { return json.NewDecoder(r.Body) })(req)
		if err != nil {
			t.Fatal(err)
		}
		ws := buildWorkspaceCR(payload, nil)
		// DeepCopy also verifies the generated CR contains JSON-compatible slices.
		containers, _, err := unstructured.NestedSlice(ws.DeepCopy().Object, "spec", "template", "spec", "containers")
		if err != nil {
			t.Fatal(err)
		}
		main := containers[0].(map[string]interface{})
		var want []interface{}
		if err := json.Unmarshal([]byte(command), &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(main["command"], want) {
			t.Fatalf("command = %#v, want %#v", main["command"], want)
		}
		if !reflect.DeepEqual(main["args"], []interface{}{"argument with spaces"}) {
			t.Fatalf("args = %#v", main["args"])
		}
	}
}
