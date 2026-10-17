package exec

import (
	"net/http/httptest"
	"testing"
)

func TestExecTargetCannotBeSelectedByClientPodQuery(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/workspaces/mine/exec?pod=other-workspace-0", nil)
	if got := execPodName(r, "mine"); got != "mine-0" {
		t.Fatalf("client-selected pod escaped workspace: %s", got)
	}
	r = r.WithContext(ContextWithPod(r.Context(), "scratch-server-resolved"))
	if got := execPodName(r, "mine"); got != "scratch-server-resolved" {
		t.Fatalf("trusted scratch resolution lost: %s", got)
	}
}
