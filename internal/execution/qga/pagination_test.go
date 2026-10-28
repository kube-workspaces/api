package qga

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func paginatedResolver(t *testing.T, linux bool, page func(int, *unstructured.UnstructuredList)) *Resolver {
	t.Helper()
	ws, vm, vmi, pod := windowsFixtures()
	if linux {
		unstructured.RemoveNestedField(ws.Object, "spec", "vmProfile")
		ws.SetAnnotations(map[string]string{"kubeworkspaces.io/agent-generation": "root-one"})
		vm.SetAnnotations(nil)
	}
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, vm, vmi, pod)
	reads := 0
	client.PrependReactor("list", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		reads++
		list := &unstructured.UnstructuredList{Object: map[string]interface{}{"apiVersion": "v1", "kind": "PodList"}, Items: []unstructured.Unstructured{*pod.DeepCopy()}}
		page(reads, list)
		return true, list, nil
	})
	resolver, err := NewResolver(client, policyStub{enabled: true, elevated: true})
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func TestResolveRejectsIncompleteLauncherListings(t *testing.T) {
	for _, linux := range []bool{false, true} {
		for _, snapshot := range []int{1, 2} {
			for _, metadata := range []string{"continue", "remaining", "negative-remaining", "empty-page"} {
				t.Run(fmt.Sprintf("linux=%t/snapshot=%d/%s", linux, snapshot, metadata), func(t *testing.T) {
					reads := 0
					r := paginatedResolver(t, linux, func(n int, list *unstructured.UnstructuredList) {
						reads = n
						if n != snapshot {
							return
						}
						switch metadata {
						case "continue":
							list.SetContinue("private-continuation-marker")
						case "remaining", "negative-remaining":
							remaining := int64(1)
							if metadata == "negative-remaining" {
								remaining = -1
							}
							list.SetRemainingItemCount(&remaining)
						case "empty-page":
							list.Items = nil
							list.SetContinue("private-continuation-marker")
						}
					})
					target, err := r.Resolve(context.Background(), "team", "vm")
					if target != (Target{}) || !errors.Is(err, ErrUnavailable) || reads != snapshot {
						t.Fatalf("incomplete page selected a target or followed pagination: %+v %v reads=%d", target, err, reads)
					}
				})
			}
		}
	}
}

func TestResolveAllowsCompleteLauncherListings(t *testing.T) {
	for _, remainingZero := range []bool{false, true} {
		r := paginatedResolver(t, false, func(_ int, list *unstructured.UnstructuredList) {
			if remainingZero {
				zero := int64(0)
				list.SetRemainingItemCount(&zero)
			}
			// A full two-item page without a continuation is complete. An
			// unrelated/inactive lookalike does not create a second target.
			inactive := list.Items[0].DeepCopy()
			inactive.SetName("inactive-lookalike")
			inactive.SetUID("inactive-uid")
			list.Items = append(list.Items, *inactive)
		})
		if target, err := r.Resolve(context.Background(), "team", "vm"); err != nil || target.PodUID != testPodUID {
			t.Fatalf("complete listing rejected: %+v %v", target, err)
		}
	}
}

func TestRuntimeFencesNewlyIncompleteLauncherListing(t *testing.T) {
	for _, afterDispatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("after-dispatch=%t", afterDispatch), func(t *testing.T) {
			incomplete := false
			resolver := paginatedResolver(t, false, func(_ int, list *unstructured.UnstructuredList) {
				if incomplete {
					list.SetContinue("private-continuation-marker")
				}
			})
			target, err := resolver.Resolve(context.Background(), "team", "vm")
			if err != nil {
				t.Fatal(err)
			}
			guest := newFakeExec(successRunnerResult())
			_, _, signer := testRuntime(t, guest)
			callsAtFence := 0
			r, err := NewRuntimeWithExec(signer, resolver, func(ctx context.Context, namespace, pod, container string, args []string, stdin []byte) ([]byte, []byte, error) {
				stdout, stderr, err := guest.run(ctx, namespace, pod, container, args, stdin)
				operations := executes(guest.calls)
				if !afterDispatch || operations[len(operations)-1] == "guest-exec" {
					incomplete = true
					callsAtFence = len(guest.calls)
				}
				return stdout, stderr, err
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := r.Execute(context.Background(), target, Command{ActorUID: "user-1", ExecutionID: "exec_page", RecordingID: "rec_page", Executable: "whoami", DeadlineSeconds: 20})
			if result != nil || !errors.Is(err, ErrTransport) || callsAtFence == 0 || len(guest.calls) != callsAtFence {
				t.Fatalf("incomplete listing did not fence next RPC/cleanup: %+v %v calls=%d boundary=%d", result, err, len(guest.calls), callsAtFence)
			}
		})
	}
}
