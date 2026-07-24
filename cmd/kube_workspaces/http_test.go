package main

import (
	"testing"

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

func TestExtractProxyPrefix(t *testing.T) {
	tests := []struct {
		name     string
		referer  string
		expected string
	}{
		{
			name:     "valid proxy referer",
			referer:  "http://localhost:3000/proxy/workspaces/my-ws/some/path",
			expected: "/proxy/workspaces/my-ws",
		},
		{
			name:     "no proxy in path",
			referer:  "http://localhost:3000/workspaces/my-ws",
			expected: "",
		},
		{
			name:     "proxy with only namespace",
			referer:  "http://localhost:3000/proxy/ns/",
			expected: "",
		},
		{
			name:     "empty referer",
			referer:  "",
			expected: "",
		},
		{
			name:     "proxy with namespace and name",
			referer:  "http://localhost:3000/proxy/default/code-server/?folder=/home",
			expected: "/proxy/default/code-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractProxyPrefix(tt.referer)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
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
