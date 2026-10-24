package k8s

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestVMConsoleAvailability(t *testing.T) {
	for _, tc := range []struct {
		name, phase                                      string
		missing, deleting, disableSerial, disableDisplay bool
		want                                             VMConsoleAvailability
	}{
		{name: "import has no VMI", missing: true},
		{name: "scheduling", phase: "Scheduling"},
		{name: "scheduled before launch", phase: "Scheduled"},
		{name: "booting guest without workspace readiness", phase: "Running", want: VMConsoleAvailability{true, true}},
		{name: "terminating", phase: "Running", deleting: true},
		{name: "serial disabled", phase: "Running", disableSerial: true, want: VMConsoleAvailability{false, true}},
		{name: "graphics disabled", phase: "Running", disableDisplay: true, want: VMConsoleAvailability{true, false}},
		{name: "failed guest", phase: "Failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vmi := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance",
				"metadata": map[string]interface{}{"name": "booting", "namespace": "team"},
				"status":   map[string]interface{}{"phase": tc.phase},
			}}
			if tc.deleting {
				now := metav1.Now()
				vmi.SetDeletionTimestamp(&now)
			}
			if tc.disableSerial {
				_ = unstructured.SetNestedField(vmi.Object, false, "spec", "domain", "devices", "autoattachSerialConsole")
			}
			if tc.disableDisplay {
				_ = unstructured.SetNestedField(vmi.Object, false, "spec", "domain", "devices", "autoattachGraphicsDevice")
			}
			objects := []runtime.Object{}
			if !tc.missing {
				objects = append(objects, vmi)
			}
			client := NewWorkspaceClientFor(dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), objects...))
			got, err := client.VMConsoleAvailability(context.Background(), "team", "booting")
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

func TestVMConsoleAvailabilityDoesNotMaskLookupFailure(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	dyn.PrependReactor("get", "virtualmachineinstances", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("API unavailable")
	})
	if _, err := NewWorkspaceClientFor(dyn).VMConsoleAvailability(context.Background(), "team", "booting"); err == nil {
		t.Fatal("lookup failure was reported as unavailable instead of an error")
	}
}
