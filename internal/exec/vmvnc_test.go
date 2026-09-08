package exec

import (
	"testing"

	"k8s.io/client-go/rest"
)

func TestVMVNCURLHTTPS(t *testing.T) {
	cfg := &rest.Config{Host: "https://api.k8s.local:6443"}
	got, err := vmVNCURL(cfg, "workspaces", "my-vm")
	if err != nil {
		t.Fatal(err)
	}
	want := "wss://api.k8s.local:6443/apis/subresources.kubevirt.io/v1/namespaces/workspaces/virtualmachineinstances/my-vm/vnc"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestVMVNCURLHTTP(t *testing.T) {
	cfg := &rest.Config{Host: "http://127.0.0.1:8080"}
	got, err := vmVNCURL(cfg, "ns-a", "vm k")
	if err != nil {
		t.Fatal(err)
	}
	want := "ws://127.0.0.1:8080/apis/subresources.kubevirt.io/v1/namespaces/ns-a/virtualmachineinstances/vm%20k/vnc"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestVMVNCURLEscapesNameAndNamespace(t *testing.T) {
	cfg := &rest.Config{Host: "https://cluster"}
	got, err := vmVNCURL(cfg, "chris space/ns", "vm/1")
	if err != nil {
		t.Fatal(err)
	}
	// PathEscape encodes / but keeps some characters; verify no unescaped
	// slash from the names leaks into the path.
	if got != "wss://cluster/apis/subresources.kubevirt.io/v1/namespaces/chris%20space%2Fns/virtualmachineinstances/vm%2F1/vnc" {
		t.Errorf("unexpected URL: %q", got)
	}
}

func TestVMVNCURLTrailingSlashHost(t *testing.T) {
	cfg := &rest.Config{Host: "https://cluster/"}
	got, err := vmVNCURL(cfg, "workspaces", "vm")
	if err != nil {
		t.Fatal(err)
	}
	want := "wss://cluster/apis/subresources.kubevirt.io/v1/namespaces/workspaces/virtualmachineinstances/vm/vnc"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}
