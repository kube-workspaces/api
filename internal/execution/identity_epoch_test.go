package execution

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCurrentEpochRequiresControllerStatusAndAcknowledgedRevocation(t *testing.T) {
	for _, test := range []struct {
		name    string
		state   map[string]interface{}
		request interface{}
		allowed bool
	}{
		{name: "missing"},
		{name: "current", state: map[string]interface{}{"vmUID": "vm", "revocationEpoch": int64(4)}, allowed: true},
		{name: "foreign", state: map[string]interface{}{"vmUID": "other", "revocationEpoch": int64(4)}},
		{name: "negative", state: map[string]interface{}{"vmUID": "vm", "revocationEpoch": int64(-1)}},
		{name: "string", state: map[string]interface{}{"vmUID": "vm", "revocationEpoch": "4"}},
		{name: "pending", state: map[string]interface{}{"vmUID": "vm", "revocationEpoch": int64(4)}, request: int64(5)},
		{name: "acked", state: map[string]interface{}{"vmUID": "vm", "revocationEpoch": int64(4)}, request: int64(4), allowed: true},
		{name: "lower-request", state: map[string]interface{}{"vmUID": "vm", "revocationEpoch": int64(4)}, request: int64(1), allowed: true},
		{name: "invalid-request", state: map[string]interface{}{"vmUID": "vm", "revocationEpoch": int64(4)}, request: "4"},
		{name: "negative-request", state: map[string]interface{}{"vmUID": "vm", "revocationEpoch": int64(4)}, request: int64(-1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ws := &unstructured.Unstructured{Object: map[string]interface{}{}}
			if test.state != nil {
				_ = unstructured.SetNestedMap(ws.Object, test.state, "status", "managementExecution")
			}
			if test.request != nil {
				_ = unstructured.SetNestedField(ws.Object, test.request, "spec", "executionRevocationEpoch")
			}
			epoch, err := CurrentEpoch(ws, "vm")
			if (err == nil) != test.allowed || (test.allowed && epoch != 4) {
				t.Fatalf("epoch=%d err=%v allowed=%v", epoch, err, test.allowed)
			}
		})
	}
}
