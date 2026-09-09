package kubeworkspaces

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	sshkeys "github.com/kube-workspaces/api/gen/sshkeys"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"goa.design/clue/log"
)

// sshkeys service implementation.
type sshkeyssrvc struct {
	client       *k8s.SSHKeyClient
	authProvider *auth.ConfigProvider
}

// NewSSHKeys returns the sshkeys service implementation.
func NewSSHKeys(authProvider *auth.ConfigProvider) sshkeys.Service {
	client, err := k8s.NewSSHKeyClient()
	if err != nil {
		panic(fmt.Sprintf("failed to create ssh key client: %v", err))
	}
	return &sshkeyssrvc{client: client, authProvider: authProvider}
}

func (s *sshkeyssrvc) isNamespaceRestricted(ctx context.Context) bool {
	if s.authProvider == nil {
		return false
	}
	cfg, err := s.authProvider.GetConfig(ctx)
	if err != nil || cfg == nil {
		return false
	}
	return cfg.Enabled && cfg.RestrictNamespaceAccess
}

// resolveNamespace maps the (optional) requested namespace to an actual one.
// When not explicitly requested, keys live in the caller's personal namespace
// so the "SSH keys" preference UI needs no namespace plumbing. Falls back to
// "workspaces" when auth is disabled (no user context).
func (s *sshkeyssrvc) resolveNamespace(ctx context.Context, requested *string) string {
	if requested != nil && *requested != "" {
		return *requested
	}
	if user := auth.UserFromContext(ctx); user != nil && user.PersonalNamespace != "" {
		return user.PersonalNamespace
	}
	return "workspaces"
}

// hasAccess reports whether the caller may read/write SshKeys in ns.
func (s *sshkeyssrvc) hasAccess(ctx context.Context, ns string) bool {
	if !s.isNamespaceRestricted(ctx) {
		return true
	}
	user := auth.UserFromContext(ctx)
	return user != nil && auth.UserHasNamespaceAccess(user, ns)
}

// List the user's SSH public keys
func (s *sshkeyssrvc) List(ctx context.Context, p *sshkeys.ListPayload) (res []*sshkeys.Sshkey, err error) {
	ns := s.resolveNamespace(ctx, p.Namespace)
	log.Printf(ctx, "sshkeys.list namespace=%s", ns)

	if !s.hasAccess(ctx, ns) {
		return []*sshkeys.Sshkey{}, nil
	}

	list, err := s.client.ListSSHKeys(ctx, ns)
	if err != nil {
		return nil, fmt.Errorf("failed to list ssh keys: %w", err)
	}

	res = make([]*sshkeys.Sshkey, 0, len(list.Items))
	for i := range list.Items {
		res = append(res, sshKeyToResult(&list.Items[i]))
	}
	return res, nil
}

// Get an SSH public key by name
func (s *sshkeyssrvc) Get(ctx context.Context, p *sshkeys.GetPayload) (res *sshkeys.Sshkey, err error) {
	ns := s.resolveNamespace(ctx, p.Namespace)
	log.Printf(ctx, "sshkeys.get name=%s namespace=%s", p.Name, ns)

	if !s.hasAccess(ctx, ns) {
		return nil, sshkeys.NotFound(fmt.Sprintf("ssh key %s/%s not found", ns, p.Name))
	}

	obj, err := s.client.GetSSHKey(ctx, ns, p.Name)
	if err != nil {
		return nil, sshkeys.NotFound(fmt.Sprintf("ssh key %s/%s not found", ns, p.Name))
	}
	return sshKeyToResult(obj), nil
}

// Create stores a new SSH public key
func (s *sshkeyssrvc) Create(ctx context.Context, p *sshkeys.CreateSSHKeyPayload) (res *sshkeys.Sshkey, err error) {
	ns := s.resolveNamespace(ctx, p.Namespace)
	log.Printf(ctx, "sshkeys.create name=%s namespace=%s", p.Name, ns)

	if !s.hasAccess(ctx, ns) {
		return nil, sshkeys.Invalid("no access to namespace")
	}

	// Validate the public key parses (covers type, base64 body, comment).
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.PublicKey)); err != nil {
		return nil, sshkeys.Invalid("invalid SSH public key: " + err.Error())
	}

	if _, getErr := s.client.GetSSHKey(ctx, ns, p.Name); getErr == nil {
		return nil, sshkeys.AlreadyExists(fmt.Sprintf("ssh key %s already exists", p.Name))
	}

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "kubeworkspaces.io",
		Version: "v1alpha1",
		Kind:    "SshKey",
	})
	obj.SetNamespace(ns)
	obj.SetName(p.Name)
	obj.SetLabels(map[string]string{managedLabel: "true"})
	keyName := ""
	if p.KeyName != nil {
		keyName = *p.KeyName
	}
	obj.Object["spec"] = map[string]interface{}{
		"name":      keyName,
		"publicKey": p.PublicKey,
	}

	created, err := s.client.CreateSSHKey(ctx, obj)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, sshkeys.AlreadyExists(fmt.Sprintf("ssh key %s already exists", p.Name))
		}
		return nil, fmt.Errorf("failed to create ssh key: %w", err)
	}
	return sshKeyToResult(created), nil
}

// Delete an SSH public key
func (s *sshkeyssrvc) Delete(ctx context.Context, p *sshkeys.DeletePayload) (err error) {
	ns := s.resolveNamespace(ctx, p.Namespace)
	log.Printf(ctx, "sshkeys.delete name=%s namespace=%s", p.Name, ns)

	if !s.hasAccess(ctx, ns) {
		return sshkeys.NotFound(fmt.Sprintf("ssh key %s/%s not found", ns, p.Name))
	}

	err = s.client.DeleteSSHKey(ctx, ns, p.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete ssh key: %w", err)
	}
	return nil
}

func sshKeyToResult(obj *unstructured.Unstructured) *sshkeys.Sshkey {
	res := &sshkeys.Sshkey{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	if v, ok := spec["name"].(string); ok {
		res.KeyName = &v
	}
	if pk, ok := spec["publicKey"].(string); ok {
		res.PublicKey = pk
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk)); err == nil {
			fp := ssh.FingerprintSHA256(pub)
			res.Fingerprint = &fp
		}
	}
	createdAt := obj.GetCreationTimestamp().Format("2006-01-02T15:04:05Z")
	res.CreatedAt = &createdAt
	return res
}
