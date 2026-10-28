package qga

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestResolveRequiresCompleteControllerLineage(t *testing.T) {
	for _, linux := range []bool{false, true} {
		for _, edge := range []string{"workspace-vm", "vm-vmi", "vmi-pod"} {
			for _, mutation := range []string{"missing", "uid", "name", "kind", "api-version", "no-controller", "false-controller", "extra-controller"} {
				t.Run(ScriptPolicy(Target{Linux: linux})+"/"+edge+"/"+mutation, func(t *testing.T) {
					r := newTestResolver(t, func(ws, vm, vmi, pod *unstructured.Unstructured) {
						if linux {
							unstructured.RemoveNestedField(ws.Object, "spec", "vmProfile")
							ws.SetAnnotations(map[string]string{"kubeworkspaces.io/agent-generation": "root-one"})
							vm.SetAnnotations(nil)
						}
						child := vm
						if edge == "vm-vmi" {
							child = vmi
						}
						if edge == "vmi-pod" {
							child = pod
						}
						refs := child.GetOwnerReferences()
						switch mutation {
						case "missing":
							refs = nil
						case "uid":
							refs[0].UID = "other-incarnation"
						case "name":
							refs[0].Name = "other-workspace"
						case "kind":
							refs[0].Kind = "Pod"
						case "api-version":
							refs[0].APIVersion = "other.example/v1"
						case "no-controller":
							refs[0].Controller = nil
						case "false-controller":
							no := false
							refs[0].Controller = &no
						case "extra-controller":
							extra := refs[0]
							extra.UID = "second-controller"
							refs = append(refs, extra)
						}
						child.SetOwnerReferences(refs)
					}, policyStub{enabled: true, elevated: true})
					if target, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrDenied) || target != (Target{}) {
						t.Fatalf("foreign/uncontrolled lineage resolved: %+v %v", target, err)
					}
				})
			}
		}
	}
}

func TestResolveAllowsUnrelatedNonControllerOwnerReferences(t *testing.T) {
	r := newTestResolver(t, func(_, vm, vmi, pod *unstructured.Unstructured) {
		for _, child := range []*unstructured.Unstructured{vm, vmi, pod} {
			refs := append([]metav1.OwnerReference{{APIVersion: "other.example/v1", Kind: "Other", Name: "observer", UID: "unrelated"}}, child.GetOwnerReferences()...)
			child.SetOwnerReferences(refs)
		}
	}, policyStub{enabled: true, elevated: true})
	if target, err := r.Resolve(context.Background(), "team", "vm"); err != nil || target.VMIUID != "vmi-uid" {
		t.Fatalf("valid controller lineage denied: %+v %v", target, err)
	}
}

func TestResolveFencesVMIRotationAcrossFreshSnapshots(t *testing.T) {
	ws, vm, vmi, pod := windowsFixtures()
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), ws, vm, vmi, pod)
	reads := 0
	client.PrependReactor("get", "virtualmachineinstances", func(ktesting.Action) (bool, runtime.Object, error) {
		reads++
		if reads == 2 {
			// Keep VM/Pod UIDs and digest unchanged while replacing the VMI and
			// its pod owner binding: only explicit VMI identity catches this.
			next := vmi.DeepCopy()
			next.SetUID("vmi-replaced")
			if err := client.Tracker().Update(vmiResource, next, "team"); err != nil {
				t.Fatal(err)
			}
			nextPod := pod.DeepCopy()
			refs := nextPod.GetOwnerReferences()
			refs[0].UID = next.GetUID()
			nextPod.SetOwnerReferences(refs)
			if err := client.Tracker().Update(podResource, nextPod, "team"); err != nil {
				t.Fatal(err)
			}
		}
		return false, nil, nil
	})
	r, err := NewResolver(client, policyStub{enabled: true, elevated: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(context.Background(), "team", "vm"); !errors.Is(err, ErrDenied) {
		t.Fatalf("VMI replacement escaped snapshot fencing: %v", err)
	}
}

func TestRuntimeFencesVMIRotationBeforeProbeOrDispatch(t *testing.T) {
	for _, linux := range []bool{false, true} {
		for _, operation := range []string{"command", "script", "script-dispatch", "probe"} {
			t.Run(ScriptPolicy(Target{Linux: linux})+"/"+operation, func(t *testing.T) {
				guest := newFakeExec(successRunnerResult())
				r, resolver, _ := testRuntime(t, guest)
				target := testTarget()
				target.Linux, target.VMIUID = linux, "original-vmi"
				resolver.target = target
				resolver.target.VMIUID = "replacement-vmi"
				if target.identity() != resolver.target.identity() {
					t.Fatal("legacy signed digest unexpectedly changed")
				}
				command := Command{ActorUID: "user-1", ExecutionID: "exec_1", RecordingID: "rec_1", Executable: "whoami", Args: []string{}, DeadlineSeconds: 20}
				var err error
				switch operation {
				case "probe":
					err = r.CheckScriptSupport(context.Background(), target)
				case "script", "script-dispatch":
					body := "#!powershell\nWrite-Output proof"
					if linux {
						body = "#!/bin/sh\nprintf proof"
					}
					command.Executable = ""
					command.Script = &Script{Body: body, InterpreterPolicy: ScriptPolicy(target)}
					if operation == "script-dispatch" {
						_, err = r.Execute(context.Background(), target, command)
					} else {
						err = r.PreflightScript(context.Background(), target, command)
					}
				default:
					_, err = r.Execute(context.Background(), target, command)
				}
				if !errors.Is(err, ErrDenied) || len(guest.calls) != 0 || len(guest.files) != 0 {
					t.Fatalf("replacement VMI was probed/staged/executed: %v", err)
				}
			})
		}
	}
}
