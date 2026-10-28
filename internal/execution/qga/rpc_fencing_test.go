package qga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRuntimeRevalidatesBetweenEveryQGARPC(t *testing.T) {
	for _, linux := range []bool{false, true} {
		t.Run(fmt.Sprintf("linux=%t", linux), func(t *testing.T) {
			target := testTarget()
			target.Linux = linux
			command := Command{ActorUID: "user-1", ExecutionID: "exec_fenced", RecordingID: "rec_fenced", Executable: "whoami", DeadlineSeconds: 20}
			baseline := newFakeExec(successRunnerResult())
			runtime, resolver, _ := testRuntime(t, baseline)
			resolver.target = target
			if _, err := runtime.Execute(context.Background(), target, command); err != nil {
				t.Fatal(err)
			}
			// Fence after every successful staging RPC, dispatch and first
			// nonterminal status poll. Terminal result cleanup is best effort.
			for i, call := range baseline.calls {
				var request struct {
					Execute string `json:"execute"`
				}
				if err := json.Unmarshal(call.stdin, &request); err != nil {
					t.Fatal(err)
				}
				boundary := i + 1
				for _, change := range []string{"vmi", "pod", "revocation", "unavailable"} {
					t.Run(fmt.Sprintf("after-%02d-%s/%s", boundary, request.Execute, change), func(t *testing.T) {
						guest := newFakeExec(successRunnerResult())
						r, current, _ := testRuntime(t, guest)
						current.target = target
						r.bridge.exec = func(ctx context.Context, namespace, pod, container string, args []string, stdin []byte) ([]byte, []byte, error) {
							stdout, stderr, err := guest.run(ctx, namespace, pod, container, args, stdin)
							if len(guest.calls) == boundary {
								switch change {
								case "vmi":
									current.target.VMIUID = "replacement-vmi"
								case "pod":
									current.target.PodUID = "replacement-pod"
								case "revocation":
									current.target.RevocationEpoch++
								case "unavailable":
									current.err = errors.New("private-resolver-marker")
								}
							}
							return stdout, stderr, err
						}
						result, err := r.Execute(context.Background(), target, command)
						if result != nil || !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "private-resolver-marker") {
							t.Fatalf("mid-flight target loss escaped unknown outcome: %+v %v", result, err)
						}
						if len(guest.calls) != boundary {
							t.Fatalf("RPC or cleanup reached changed target: got %d calls, want %d", len(guest.calls), boundary)
						}
					})
				}
				if request.Execute == "guest-exec-status" {
					break
				}
			}
		})
	}
}

func TestRuntimeRevalidatesEachScriptCapabilityRPC(t *testing.T) {
	guest := newFakeExec(nil)
	runtime, resolver, _ := testRuntime(t, guest)
	target := resolver.target
	runtime.bridge.exec = func(ctx context.Context, namespace, pod, container string, args []string, stdin []byte) ([]byte, []byte, error) {
		stdout, stderr, err := guest.run(ctx, namespace, pod, container, args, stdin)
		resolver.target.VMIUID = "replacement-vmi"
		return stdout, stderr, err
	}
	if err := runtime.CheckScriptSupport(context.Background(), target); !errors.Is(err, ErrUnsupportedScripts) {
		t.Fatalf("changed capability target was accepted: %v", err)
	}
	if len(guest.calls) != 1 || len(guest.files) != 0 {
		t.Fatal("probe polled changed target or staged guest content")
	}
}

func TestRuntimeFencesPartialScriptEnvelopeWrites(t *testing.T) {
	for _, linux := range []bool{false, true} {
		t.Run(fmt.Sprintf("linux=%t", linux), func(t *testing.T) {
			guest := newFakeExec(successRunnerResult())
			runtime, resolver, _ := testRuntime(t, guest)
			resolver.target.Linux = linux
			target := resolver.target
			path := dataDirPath + `\qga-request-exec_chunks.json`
			marker := "#!powershell\n"
			if linux {
				path = "/var/lib/workspace-agent/qga-request-exec_chunks.json"
				marker = "#!/bin/sh\n"
			}
			boundary := 0
			runtime.bridge.exec = func(ctx context.Context, namespace, pod, container string, args []string, stdin []byte) ([]byte, []byte, error) {
				stdout, stderr, err := guest.run(ctx, namespace, pod, container, args, stdin)
				if len(guest.files[path]) > 0 {
					boundary = len(guest.calls)
					resolver.target.PodUID = "replacement-pod"
				}
				return stdout, stderr, err
			}
			result, err := runtime.Execute(context.Background(), target, Command{
				ActorUID: "user-1", ExecutionID: "exec_chunks", RecordingID: "rec_chunks", DeadlineSeconds: 20,
				Script: &Script{Body: marker + strings.Repeat("# filler\n", fileWriteChunkBytes/2), InterpreterPolicy: ScriptPolicy(target)},
			})
			if result != nil || !errors.Is(err, ErrTransport) || boundary == 0 || len(guest.calls) != boundary || len(guest.files[path]) != fileWriteChunkBytes {
				t.Fatalf("partial envelope continued on changed target: calls=%d boundary=%d bytes=%d err=%v", len(guest.calls), boundary, len(guest.files[path]), err)
			}
		})
	}
}

func TestRuntimeDoesNotFollowChangedTargetForTerminalCleanup(t *testing.T) {
	guest := newFakeExec(successRunnerResult())
	runtime, resolver, _ := testRuntime(t, guest)
	target := resolver.target
	terminalBoundary := 0
	runtime.bridge.exec = func(ctx context.Context, namespace, pod, container string, args []string, stdin []byte) ([]byte, []byte, error) {
		stdout, stderr, err := guest.run(ctx, namespace, pod, container, args, stdin)
		if guest.statusCalls == 2 {
			terminalBoundary = len(guest.calls)
			resolver.target.PodUID = "replacement-pod"
		}
		return stdout, stderr, err
	}
	result, err := runtime.Execute(context.Background(), target, Command{
		ActorUID: "user-1", ExecutionID: "exec_terminal", RecordingID: "rec_terminal", Executable: "whoami", DeadlineSeconds: 20,
	})
	if err != nil || result == nil || result.Outcome != "completed" || terminalBoundary == 0 || len(guest.calls) != terminalBoundary {
		t.Fatalf("cleanup followed changed target or invalidated terminal result: %+v %v", result, err)
	}
}
