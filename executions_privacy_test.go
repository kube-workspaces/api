package kubeworkspaces

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution/qga"
	"github.com/kube-workspaces/api/internal/execution/storage"
)

const privateGuestDenial = "private-guest-denial-marker /sensitive/guest/path"

// The submitter may receive immediate command output/denials. A metadata-only
// manager must not inherit access to that guest content through termination.
func assertGuestDenialMetadataPrivate(t *testing.T, stack *startStack, executionID string) {
	t.Helper()
	rec, outcome, err := stack.store.Metadata().Get(context.Background(), executionID)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(struct {
		Record  storage.ExecutionRecord
		Outcome storage.ExecutionOutcome
	}{rec, outcome})
	if err != nil || bytes.Contains(metadata, []byte(privateGuestDenial)) {
		t.Fatal("guest denial leaked into searchable metadata")
	}
	for _, path := range []string{"/v1/executions/" + executionID, "/v1/executions?namespace=team&workspace_name=vm"} {
		w := stack.get(path, true)
		if w.Code != http.StatusOK || bytes.Contains(w.Body.Bytes(), []byte(privateGuestDenial)) {
			t.Fatalf("metadata reader saw guest content or lost access: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestGuestDenialContentIsNotExecutionMetadata(t *testing.T) {
	for _, outcome := range []string{"completed", "deadline", "output-limit", "denied", "runner-error", "spawn-failed"} {
		t.Run(outcome, func(t *testing.T) {
			stub := &stubQGA{target: eligibleTarget(), result: &qga.GuestResult{Outcome: outcome, ExitCode: intPtr(0), Denial: privateGuestDenial, Truncated: outcome == "output-limit"}}
			permissions := []string{string(auth.PermissionExec), string(auth.PermissionElevated), string(auth.PermissionManage)}
			stack := newStartStack(t, permissions, enabledElevatedPolicy(), stub)
			w := stack.post(`{"namespace":"team","workspace_name":"vm","executable":"whoami","args":[]}`, "")
			var result struct {
				ExecutionID string `json:"execution_id"`
				RecordingID string `json:"recording_id"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.ExecutionID == "" {
				t.Fatalf("start failed: %d %s", w.Code, w.Body.String())
			}
			assertGuestDenialMetadataPrivate(t, stack, result.ExecutionID)
			if outcome == "denied" {
				_, stored, err := stack.store.Metadata().Get(context.Background(), result.ExecutionID)
				if err != nil || stored.State != storage.StateFailed || stored.Termination != "denied" {
					t.Fatalf("denial classification drifted: %+v %v", stored, err)
				}
			}
			path := "/v1/executions/" + result.ExecutionID + "/recording/chunks/1"
			if w := stack.get(path, true); w.Code != http.StatusForbidden || bytes.Contains(w.Body.Bytes(), []byte(privateGuestDenial)) {
				t.Fatal("metadata-only manager obtained protected denial")
			}
			reader := newStoredStartStack(t, "team", "vm", []string{string(auth.PermissionReadRecordings)}, enabledElevatedPolicy(), nil, stack.store)
			w = reader.get(path, true)
			var chunk struct {
				Data []byte `json:"data"`
			}
			var recorded recordingResult
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &chunk) != nil || json.Unmarshal(chunk.Data, &recorded) != nil || recorded.Denial != privateGuestDenial {
				t.Fatalf("protected denial was lost: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHistoricalGuestDenialIsRedactedFromMetadataResponse(t *testing.T) {
	outcome := storage.ExecutionOutcome{State: storage.StateFailed, Termination: "denied:" + privateGuestDenial}
	response := recordToResult(storage.ExecutionRecord{ExecutionID: "exec_legacy"}, outcome)
	if response.Termination == nil || *response.Termination != "denied" || outcome.Termination != "denied:"+privateGuestDenial {
		t.Fatal("legacy metadata response leaked denial or rewrote historical evidence")
	}
}
