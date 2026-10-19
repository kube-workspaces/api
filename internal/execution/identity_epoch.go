package execution

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// CurrentEpoch reads controller-owned status, bound to the current VM UID.
// A monotonic spec minimum may request revocation but never supplies authority.
// Missing status (including an old CRD pruning it), malformed state, and a
// request not yet acknowledged by the controller all deny admission.
func CurrentEpoch(ws *unstructured.Unstructured, vmUID string) (uint64, error) {
	uid, _, err := unstructured.NestedString(ws.Object, "status", "managementExecution", "vmUID")
	if err != nil || uid == "" || uid != vmUID {
		return 0, fmt.Errorf("execution identity is not current")
	}
	epoch, found, err := unstructured.NestedInt64(ws.Object, "status", "managementExecution", "revocationEpoch")
	if err != nil || !found || epoch < 0 {
		return 0, fmt.Errorf("execution epoch is unavailable")
	}
	requested, _, err := unstructured.NestedInt64(ws.Object, "spec", "executionRevocationEpoch")
	if err != nil || requested < 0 || requested > epoch {
		return 0, fmt.Errorf("execution revocation is pending or malformed")
	}
	return uint64(epoch), nil
}
