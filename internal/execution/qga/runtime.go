package qga

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/kube-workspaces/api/internal/execution/grants"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ErrRequestTooLarge reports a framed request plus grant beyond the staged
// envelope bound; the caller records an invalid error, never an outcome.
var ErrRequestTooLarge = errors.New("QGA pilot request is too large")

// policyVersion is the signed pilot policy marker shared with the guest.
const policyVersion = "vm-execution-pilot/v1"

// qgaRequest mirrors kw-management's Rust QgaCommandRequest field-for-field;
// the grant binds the digest of its exact compact serialized bytes, so field
// order and the explicit "cwd":null must never change.
type qgaRequest struct {
	Version                uint32   `json:"version"`
	Challenge              string   `json:"challenge"`
	TransportTargetSHA256  string   `json:"transport_target_sha256"`
	ActorUID               string   `json:"actor_uid"`
	Namespace              string   `json:"namespace"`
	WorkspaceName          string   `json:"workspace_name"`
	WorkspaceUID           string   `json:"workspace_uid"`
	ProvisioningGeneration string   `json:"provisioning_generation"`
	ExecutionID            string   `json:"execution_id"`
	RecordingID            string   `json:"recording_id"`
	Operation              string   `json:"operation"`
	OSIdentity             string   `json:"os_identity"`
	Elevated               bool     `json:"elevated"`
	PolicyVersion          string   `json:"policy_version"`
	RevocationEpoch        uint64   `json:"revocation_epoch"`
	Executable             string   `json:"executable"`
	Args                   []string `json:"args"`
	Cwd                    *string  `json:"cwd"`
	DeadlineSeconds        int      `json:"deadline_seconds"`
}

// Command is one bounded SYSTEM command. ExecutionID/RecordingID/ActorUID are
// server-minted or authenticated values, never raw client input.
type Command struct {
	ActorUID        string
	ExecutionID     string
	RecordingID     string
	Executable      string
	Args            []string
	Cwd             *string
	DeadlineSeconds int
}

// TargetResolver resolves the fresh launcher target for one workspace.
type TargetResolver interface {
	Resolve(ctx context.Context, namespace, name string) (Target, error)
}

// Runtime is the opt-in QGA pilot executor behind the API's start endpoint.
type Runtime struct {
	signer   *grants.Signer
	keysJSON []byte
	resolver TargetResolver
	bridge   *Bridge
	now      func() time.Time
}

// NewRuntime wires the production pilot stack: the configured signing key, an
// uncached dynamic-client resolver and the SPDY pod-exec bridge. Every
// dependency must be present; enabling the pilot never degrades silently.
func NewRuntime(cfg Config, dyn dynamic.Interface, policy PolicyReader, restConfig *rest.Config, client kubernetes.Interface) (*Runtime, error) {
	if !cfg.Enabled {
		return nil, ErrConfiguration
	}
	signer, err := LoadSigner(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	resolver, err := NewResolver(dyn, policy)
	if err != nil {
		return nil, err
	}
	exec, err := KubernetesExecFunc(restConfig, client)
	if err != nil {
		return nil, err
	}
	bridge, err := NewBridge(exec)
	if err != nil {
		return nil, err
	}
	return newRuntime(signer, resolver, bridge, time.Now)
}

// NewRuntimeWithExec wires a runtime over an injected exec transport for
// tests; the guest-side contract is exercised end to end through fakes.
func NewRuntimeWithExec(signer *grants.Signer, resolver TargetResolver, exec ExecFunc) (*Runtime, error) {
	if signer == nil || resolver == nil {
		return nil, ErrConfiguration
	}
	bridge, err := NewBridge(exec)
	if err != nil {
		return nil, err
	}
	return newRuntime(signer, resolver, bridge, time.Now)
}

func newRuntime(signer *grants.Signer, resolver TargetResolver, bridge *Bridge, now func() time.Time) (*Runtime, error) {
	if signer == nil || resolver == nil || bridge == nil || now == nil {
		return nil, ErrConfiguration
	}
	keys, err := publicKeyFileJSON(signer.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("%w: cannot frame the guest keys file", ErrConfiguration)
	}
	return &Runtime{signer: signer, keysJSON: keys, resolver: resolver, bridge: bridge, now: now}, nil
}

// Resolve delegates to the fail-closed launcher resolver.
func (r *Runtime) Resolve(ctx context.Context, namespace, name string) (Target, error) {
	return r.resolver.Resolve(ctx, namespace, name)
}

// Execute issues one single-use QGA grant bound to the resolved target and the
// exact request bytes, stages both through the bridge and returns the runner's
// authoritative result. Resolver errors pass through; framing failures are
// ErrTransport (unknown outcome); oversized framing is ErrRequestTooLarge.
// A GuestResult is returned only from a parsed runner reply, never invented.
func (r *Runtime) Execute(ctx context.Context, target Target, command Command) (*GuestResult, error) {
	if err := validateCommand(command); err != nil {
		return nil, err
	}
	// Recording admission can take time. Re-resolve before staging any guest
	// bytes so revocation/reset since the initial admission fences this command.
	current, err := r.resolver.Resolve(ctx, target.Namespace, target.WorkspaceName)
	if err != nil {
		return nil, err
	}
	if current != target {
		return nil, ErrDenied
	}
	challenge, err := grants.NewChallenge()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot mint a challenge", ErrTransport)
	}
	args := command.Args
	if args == nil {
		// The guest deserializes a JSON array, never null.
		args = []string{}
	}
	request := qgaRequest{
		Version:                1,
		Challenge:              challenge,
		TransportTargetSHA256:  grants.Digest([]byte(target.identity())),
		ActorUID:               command.ActorUID,
		Namespace:              target.Namespace,
		WorkspaceName:          target.WorkspaceName,
		WorkspaceUID:           target.WorkspaceUID,
		ProvisioningGeneration: target.VMUID,
		ExecutionID:            command.ExecutionID,
		RecordingID:            command.RecordingID,
		Operation:              "command",
		OSIdentity:             "SYSTEM",
		Elevated:               true,
		PolicyVersion:          policyVersion,
		RevocationEpoch:        target.RevocationEpoch,
		Executable:             command.Executable,
		Args:                   args,
		Cwd:                    command.Cwd,
		DeadlineSeconds:        command.DeadlineSeconds,
	}
	raw, err := json.Marshal(&request)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot frame the request", ErrTransport)
	}
	binding := grants.BindingQGA{
		ActorUID:               command.ActorUID,
		Namespace:              target.Namespace,
		WorkspaceName:          target.WorkspaceName,
		WorkspaceUID:           target.WorkspaceUID,
		ProvisioningGeneration: target.VMUID,
		ExecutionID:            command.ExecutionID,
		RecordingID:            command.RecordingID,
		Operation:              "command",
		OSIdentity:             "SYSTEM",
		Elevated:               true,
		PolicyVersion:          policyVersion,
		RevocationEpoch:        target.RevocationEpoch,
		Challenge:              challenge,
		Transport:              grants.TransportQGAPodExec,
		TransportTargetSHA256:  grants.Digest([]byte(target.identity())),
		RequestSHA256:          grants.Digest(raw),
	}
	token, err := r.signer.IssueQGA(binding, r.now(), grants.QGAMaxLifetime)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot issue the grant", ErrTransport)
	}
	envelope, err := json.Marshal(map[string]any{"grant": token, "request": json.RawMessage(raw)})
	if err != nil {
		return nil, fmt.Errorf("%w: cannot frame the envelope", ErrTransport)
	}
	if len(envelope) > MaxEnvelopeBytes {
		return nil, ErrRequestTooLarge
	}
	return r.bridge.Run(ctx, target, command.ExecutionID, envelope, r.keysJSON, command.DeadlineSeconds)
}

// validateCommand mirrors the guest's structural pilot bounds so an
// out-of-bounds command is rejected before anything is staged.
func validateCommand(command Command) error {
	if !validExecutionID(command.ExecutionID) || command.ActorUID == "" || command.RecordingID == "" {
		return fmt.Errorf("%w: command identity fields are missing or malformed", ErrTransport)
	}
	for _, field := range []string{command.ActorUID, command.RecordingID} {
		if len(field) > 256 || strings.TrimSpace(field) != field || strings.IndexFunc(field, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: command identity fields are missing or malformed", ErrTransport)
		}
	}
	if command.Executable == "" || len(command.Executable) > MaxExecutableBytes ||
		strings.TrimSpace(command.Executable) != command.Executable || strings.IndexFunc(command.Executable, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: executable is missing or out of bounds", ErrTransport)
	}
	if len(command.Args) > MaxArgs {
		return fmt.Errorf("%w: arguments are out of bounds", ErrTransport)
	}
	for _, arg := range command.Args {
		if len(arg) > MaxArgBytes || strings.IndexFunc(arg, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: arguments are out of bounds", ErrTransport)
		}
	}
	if command.Cwd != nil {
		cwd := *command.Cwd
		if cwd == "" || len(cwd) > MaxCwdBytes || strings.TrimSpace(cwd) != cwd || strings.IndexFunc(cwd, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: cwd is out of bounds", ErrTransport)
		}
	}
	if command.DeadlineSeconds < 1 || command.DeadlineSeconds > MaxDeadlineSeconds {
		return fmt.Errorf("%w: deadline is out of bounds", ErrTransport)
	}
	return nil
}

// publicKeyFileJSON renders the pinned-keys file for the guest (exported for
// contract tests alongside the committed Rust fixture).
func publicKeyFileJSON(public ed25519.PublicKey) ([]byte, error) {
	return json.Marshal(map[string]any{
		"version": 1,
		"keys":    []string{base64.RawURLEncoding.EncodeToString(public)},
	})
}
