package k8s

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// VMConsoleAvailability describes launched console devices, independently of
// Workspace readiness or guest provisioning. It does not reserve either seat.
type VMConsoleAvailability struct {
	Available        bool `json:"available"`
	DisplayAvailable bool `json:"displayAvailable"`
}

func (c *WorkspaceClient) VMConsoleAvailability(ctx context.Context, namespace, name string) (VMConsoleAvailability, error) {
	result := VMConsoleAvailability{}
	vmi, err := c.dynamic.Resource(schema.GroupVersionResource{
		Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances",
	}).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	phase, _, _ := unstructured.NestedString(vmi.Object, "status", "phase")
	if phase != "Running" || vmi.GetDeletionTimestamp() != nil {
		return result, nil
	}
	serial, hasSerial, _ := unstructured.NestedBool(vmi.Object, "spec", "domain", "devices", "autoattachSerialConsole")
	graphics, hasGraphics, _ := unstructured.NestedBool(vmi.Object, "spec", "domain", "devices", "autoattachGraphicsDevice")
	result.Available = !hasSerial || serial
	result.DisplayAvailable = !hasGraphics || graphics
	return result, nil
}
