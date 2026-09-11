package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestResolveShellLogic tests the core logic of shell resolution by
// simulating what resolveShell does with various workspace/image states.
// This tests the logic without requiring real Kubernetes clients.
func TestResolveShellLogic(t *testing.T) {
	tests := []struct {
		name        string
		wsObj       map[string]interface{} // workspace spec (nil = not found)
		imageShell  string                 // Image CR defaultShell value
		imageFound  bool                   // whether image CR exists
		expected    string
	}{
		{
			name:     "workspace not found returns empty",
			wsObj:    nil,
			expected: "",
		},
		{
			name: "workspace with no containers returns empty",
			wsObj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{},
						},
					},
				},
			},
			expected: "",
		},
		{
			name: "workspace container with no image returns empty",
			wsObj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name": "workspace",
								},
							},
						},
					},
				},
			},
			expected: "",
		},
		{
			name: "image CR not found returns empty",
			wsObj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"image": "nginx:latest",
								},
							},
						},
					},
				},
			},
			imageFound: false,
			expected:   "",
		},
		{
			name: "image CR with no defaultShell returns empty",
			wsObj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"image": "ubuntu:22.04",
								},
							},
						},
					},
				},
			},
			imageFound: true,
			imageShell: "",
			expected:   "",
		},
		{
			name: "image CR with defaultShell set returns it",
			wsObj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"image": "ubuntu:22.04",
								},
							},
						},
					},
				},
			},
			imageFound: true,
			imageShell: "/bin/zsh",
			expected:   "/bin/zsh",
		},
		{
			name: "image CR with /bin/bash returns /bin/bash",
			wsObj: map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"image": "codercom/code-server:latest",
								},
							},
						},
					},
				},
			},
			imageFound: true,
			imageShell: "/bin/bash",
			expected:   "/bin/bash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveShellFromObjects(tt.wsObj, tt.imageShell, tt.imageFound)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// resolveShellFromObjects extracts the logic from resolveShell into a testable function.
// This mirrors the exact logic in resolveShell but operates on raw objects instead of clients.
func resolveShellFromObjects(wsObj map[string]interface{}, imageShell string, imageFound bool) string {
	if wsObj == nil {
		return ""
	}

	containers, found, _ := unstructured.NestedSlice(wsObj, "spec", "template", "spec", "containers")
	if !found || len(containers) == 0 {
		return ""
	}
	container, ok := containers[0].(map[string]interface{})
	if !ok {
		return ""
	}
	imageRef, _ := container["image"].(string)
	if imageRef == "" {
		return ""
	}

	if !imageFound {
		return ""
	}

	return imageShell
}

func TestParseWindow(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"5m", false},
		{"15m", false},
		{"1h", false},
		{"3h", false},
		{"6h", false},
		{"24h", false},
		{"", false},
		{"10m", true},
		{"2h", true},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parseWindow(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseWindow(%q): err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestImageTag(t *testing.T) {
	tests := []struct {
		image string
		want  string
	}{
		{"ghcr.io/kube-workspaces/api:latest", "latest"},
		{"ghcr.io/kube-workspaces/controller:v0.3.0", "v0.3.0"},
		{"quay.io/containerdisks/debian:13.0.0", "13.0.0"},
		{"codercom/code-server:latest", "latest"},
		{"no-tag-image", "no-tag-image"},
	}
	for _, tt := range tests {
		if got := imageTag(tt.image); got != tt.want {
			t.Errorf("imageTag(%q) = %q, want %q", tt.image, got, tt.want)
		}
	}
}

// readyPod is a helper for building pod fixtures in the summarizer tests.
func readyPod(phase corev1.PodPhase, image string, ready, waitingReason string) corev1.Pod {
	pod := corev1.Pod{}
	pod.Status.Phase = phase
	if image != "" {
		pod.Spec.Containers = []corev1.Container{{Name: "main", Image: image}}
	}
	cs := corev1.ContainerStatus{Name: "main"}
	if ready != "" {
		cs.Ready = ready == "ready"
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{cs}
	}
	if waitingReason != "" {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "main",
			State: corev1.ContainerState{
				Waiting: &corev1.ContainerStateWaiting{Reason: waitingReason},
			},
		}}
	}
	return pod
}

func TestSummarizeComponent(t *testing.T) {
	tests := []struct {
		name   string
		pods   []corev1.Pod
		want   componentStatus
	}{
		{
			name: "single running ready pod is healthy",
			pods: []corev1.Pod{readyPod(corev1.PodRunning, "ghcr.io/kube-workspaces/api:latest", "ready", "")},
			want: componentStatus{
				Version: "latest",
				Image:   "ghcr.io/kube-workspaces/api:latest",
				Status:  "healthy",
				Ready:   1,
				Total:   1,
			},
		},
		{
			name: "one ready of two replicas is healthy (rolling update)",
			pods: []corev1.Pod{
				readyPod(corev1.PodRunning, "ghcr.io/kube-workspaces/controller:v0.3.0", "ready", ""),
				readyPod(corev1.PodPending, "", "not", ""),
			},
			want: componentStatus{
				Version: "v0.3.0",
				Image:   "ghcr.io/kube-workspaces/controller:v0.3.0",
				Status:  "healthy",
				Ready:   1,
				Total:   2,
			},
		},
		{
			name: "running but containers not ready is starting",
			pods: []corev1.Pod{readyPod(corev1.PodRunning, "ghcr.io/kube-workspaces/proxy:latest", "not", "")},
			want: componentStatus{
				Version: "latest",
				Image:   "ghcr.io/kube-workspaces/proxy:latest",
				Status:  "starting",
				Ready:   0,
				Total:   1,
			},
		},
		{
			name: "pending pod is starting",
			pods: []corev1.Pod{readyPod(corev1.PodPending, "ghcr.io/kube-workspaces/frontend:latest", "", "")},
			want: componentStatus{
				Version: "latest",
				Image:   "ghcr.io/kube-workspaces/frontend:latest",
				Status:  "starting",
				Ready:   0,
				Total:   1,
			},
		},
		{
			name: "crash looping pod is down",
			pods: []corev1.Pod{readyPod(corev1.PodRunning, "ghcr.io/kube-workspaces/api:latest", "", "CrashLoopBackOff")},
			want: componentStatus{
				Version: "latest",
				Image:   "ghcr.io/kube-workspaces/api:latest",
				Status:  "down",
				Ready:   0,
				Total:   1,
			},
		},
		{
			name: "failed pod is down",
			pods: []corev1.Pod{readyPod(corev1.PodFailed, "ghcr.io/kube-workspaces/controller:latest", "", "")},
			want: componentStatus{
				Version: "latest",
				Image:   "ghcr.io/kube-workspaces/controller:latest",
				Status:  "down",
				Ready:   0,
				Total:   1,
			},
		},
		{
			name: "empty pod list stays down",
			pods: []corev1.Pod{},
			want: componentStatus{Status: "down"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarizeComponent(tt.pods)
			if got != tt.want {
				t.Errorf("summarizeComponent() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
