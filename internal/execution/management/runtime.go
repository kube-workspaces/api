package management

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/enrollment"
	"github.com/kube-workspaces/api/internal/execution/pki"
	"github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/platform"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

var secretResource = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

// Runtime owns the issuer's shared ledger and bootstrap worker. Recording
// storage, the Kubernetes client and auth provider remain caller-owned.
type Runtime struct {
	config      Config
	credentials *credentials
	ledger      storage.EnrollmentStore
	recording   storage.Store
	client      dynamic.Interface
	auth        *auth.ConfigProvider
	policy      *platform.ConfigProvider
	resolver    *enrollment.KubernetesResolver
	importer    *enrollment.BootstrapImporter
	service     *enrollment.Service
	now         func() time.Time
	syncTimeout time.Duration
	synced      atomic.Bool
	mu          sync.Mutex
	closed      bool
	runDone     chan struct{}
	cancel      context.CancelFunc
	closeOnce   sync.Once
	closeErr    error
}

type ledgerOpener func(context.Context, string) (storage.EnrollmentStore, error)

func Open(ctx context.Context, c Config, storageConfig execution.StorageConfig, recording storage.Store, client dynamic.Interface, authProvider *auth.ConfigProvider) (*Runtime, error) {
	return openRuntime(ctx, c, storageConfig, recording, client, authProvider, storage.NewPostgresEnrollment)
}

func openRuntime(ctx context.Context, c Config, storageConfig execution.StorageConfig, recording storage.Store, client dynamic.Interface, authProvider *auth.ConfigProvider, openLedger ledgerOpener) (*Runtime, error) {
	if !c.Enabled {
		return nil, nil
	}
	if !storageConfig.Persistent() || storageConfig.DatabaseURL == "" || recording == nil || recording.Mode() != string(storageConfig.Mode) || recording.Durability() != storage.DurabilityDurable || client == nil || authProvider == nil {
		return nil, ErrConfiguration
	}
	if c.LeafLifetime < time.Minute || c.LeafLifetime > pki.MaxLeafLifetime || len(validation.IsDNS1123Label(c.BootstrapNamespace)) != 0 {
		return nil, ErrConfiguration
	}
	if ctx.Err() != nil || recording.Ready(ctx) != nil {
		return nil, ErrUnavailable
	}
	authConfig, err := authProvider.GetConfig(ctx)
	if err != nil || authConfig == nil || !authConfig.Enabled {
		return nil, ErrUnavailable
	}
	credentials, err := loadCredentials(c, time.Now())
	if err != nil {
		return nil, err
	}
	ledger, err := openLedger(ctx, storageConfig.DatabaseURL)
	if err != nil {
		return nil, ErrUnavailable
	}
	keep := false
	defer func() {
		if !keep {
			_ = ledger.Close()
		}
	}()
	if ledger.Ready(ctx) != nil {
		return nil, ErrUnavailable
	}
	policy := platform.NewConfigProvider(client)
	resolver, err := enrollment.NewKubernetesResolver(client, policy)
	if err != nil {
		return nil, ErrUnavailable
	}
	r := &Runtime{config: c, credentials: credentials, ledger: ledger, recording: recording, client: client, auth: authProvider, policy: policy, resolver: resolver, now: time.Now, syncTimeout: 30 * time.Second}
	current := func(ctx context.Context, i pki.Identity) error {
		if err := r.prerequisites(ctx); err != nil {
			if errors.Is(err, ErrDenied) {
				return enrollment.ErrDenied
			}
			return enrollment.ErrUnavailable
		}
		return resolver.Authorize(ctx, i)
	}
	r.service, err = enrollment.New(ledger, credentials.authority, current, c.LeafLifetime)
	if err != nil {
		return nil, ErrUnavailable
	}
	r.importer, err = enrollment.NewBootstrapImporter(client, c.BootstrapNamespace, resolver, r.service)
	if err != nil {
		return nil, ErrUnavailable
	}
	keep = true
	return r, nil
}

func (r *Runtime) prerequisites(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return ErrUnavailable
	}
	if r.credentials.validAt(r.now(), r.config.LeafLifetime) != nil {
		return ErrUnavailable
	}
	authConfig, err := r.auth.GetConfig(ctx)
	if err != nil || authConfig == nil {
		return ErrUnavailable
	}
	if !authConfig.Enabled {
		return ErrDenied
	}
	if r.recording.Ready(ctx) != nil || r.ledger.Ready(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}

// Ready describes issuer prerequisites and completed initial bootstrap cache
// synchronization. It does not advertise a public route or guest capability.
func (r *Runtime) Ready(ctx context.Context) error {
	if r == nil || !r.synced.Load() {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.prerequisites(ctx); err != nil {
		return err
	}
	policy, err := r.policy.GetVMExecutionPolicy(ctx)
	if err != nil {
		return ErrUnavailable
	}
	if !policy.Enabled {
		return ErrDenied
	}
	return nil
}

// Result contains only public certificate/trust material. A future authenticated
// bootstrap transport must deliver it over an independently verified channel.
type Result struct {
	CertificateDER []byte
	IssuerChainPEM []byte
	TrustRootsPEM  []byte
}

// Enroll is an internal transport boundary, not an HTTP handler. It imports only
// current protected material, binds the request to the resolved scope, and
// withholds results if readiness is lost while issuance commits.
func (r *Runtime) Enroll(ctx context.Context, namespace, name, token string, csrDER []byte) (Result, error) {
	if len(token) != 43 || len(csrDER) == 0 || len(csrDER) > 16*1024 {
		return Result{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := r.Ready(ctx); err != nil {
		return Result{}, err
	}
	expected, err := r.resolver.Resolve(ctx, namespace, name)
	if err != nil {
		return Result{}, enrollmentError(err)
	}
	if err := r.importer.Import(ctx, namespace, name); err != nil {
		return Result{}, enrollmentError(err)
	}
	certificate, err := r.service.EnrollBound(ctx, expected, token, csrDER)
	if err != nil {
		return Result{}, enrollmentError(err)
	}
	if err := r.Ready(ctx); err != nil {
		return Result{}, err
	}
	if err := r.credentials.verifyIssued(certificate, csrDER, expected, r.now()); err != nil {
		return Result{}, err
	}
	return Result{CertificateDER: certificate, IssuerChainPEM: append([]byte(nil), r.credentials.chainPEM...), TrustRootsPEM: append([]byte(nil), r.credentials.rootsPEM...)}, nil
}

func enrollmentError(err error) error {
	if errors.Is(err, enrollment.ErrDenied) {
		return ErrDenied
	}
	return ErrUnavailable
}

// metadataOnly prevents raw bootstrap payloads from remaining in the informer
// store. Import always re-reads and validates the actual protected Secret.
func metadataOnly(obj interface{}) (interface{}, error) {
	source, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, ErrUnavailable
	}
	result := &unstructured.Unstructured{}
	result.SetAPIVersion("v1")
	result.SetKind("Secret")
	result.SetName(source.GetName())
	result.SetNamespace(source.GetNamespace())
	result.SetUID(source.GetUID())
	result.SetResourceVersion(source.GetResourceVersion())
	labels := source.GetLabels()
	annotations := source.GetAnnotations()
	result.SetLabels(map[string]string{"kubeworkspaces.io/management-bootstrap": labels["kubeworkspaces.io/management-bootstrap"]})
	result.SetAnnotations(map[string]string{"kubeworkspaces.io/workspace-namespace": annotations["kubeworkspaces.io/workspace-namespace"], "kubeworkspaces.io/workspace-name": annotations["kubeworkspaces.io/workspace-name"]})
	return result, nil
}

func (r *Runtime) bootstrapKey(obj interface{}) (types.NamespacedName, bool) {
	meta, ok := obj.(*unstructured.Unstructured)
	if !ok || meta.GetNamespace() != r.config.BootstrapNamespace || meta.GetLabels()["kubeworkspaces.io/management-bootstrap"] != "v1" {
		return types.NamespacedName{}, false
	}
	annotations := meta.GetAnnotations()
	key := types.NamespacedName{Namespace: annotations["kubeworkspaces.io/workspace-namespace"], Name: annotations["kubeworkspaces.io/workspace-name"]}
	if key.Namespace == r.config.BootstrapNamespace || len(validation.IsDNS1123Label(key.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(key.Name)) != 0 {
		return types.NamespacedName{}, false
	}
	return key, true
}

func (r *Runtime) Run(parent context.Context) error {
	if r == nil {
		return ErrUnavailable
	}
	r.mu.Lock()
	if r.closed || r.runDone != nil {
		r.mu.Unlock()
		return ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	r.cancel = cancel
	r.runDone = done
	r.mu.Unlock()
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[types.NamespacedName]())
	var wg sync.WaitGroup
	defer func() { r.synced.Store(false); cancel(); queue.ShutDown(); wg.Wait(); close(done) }()
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(r.client, time.Minute, r.config.BootstrapNamespace, func(options *metav1.ListOptions) { options.LabelSelector = "kubeworkspaces.io/management-bootstrap=v1" })
	informer := factory.ForResource(secretResource).Informer()
	if informer.SetTransform(metadataOnly) != nil {
		return ErrUnavailable
	}
	enqueue := func(obj interface{}) {
		if key, ok := r.bootstrapKey(obj); ok {
			queue.Add(key)
		}
	}
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{AddFunc: enqueue, UpdateFunc: func(_, current interface{}) { enqueue(current) }}); err != nil {
		return ErrUnavailable
	}
	wg.Add(1)
	go func() { defer wg.Done(); informer.Run(ctx.Done()) }()
	syncCtx, syncCancel := context.WithTimeout(ctx, r.syncTimeout)
	synced := cache.WaitForCacheSync(syncCtx.Done(), informer.HasSynced)
	syncCancel()
	if !synced {
		if ctx.Err() != nil {
			return nil
		}
		return ErrUnavailable
	}
	r.synced.Store(true)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r.process(ctx, queue) {
		}
	}()
	<-ctx.Done()
	return nil
}

func (r *Runtime) process(ctx context.Context, queue workqueue.TypedRateLimitingInterface[types.NamespacedName]) bool {
	key, shutdown := queue.Get()
	if shutdown {
		return false
	}
	defer queue.Done(key)
	err := r.importer.Import(ctx, key.Namespace, key.Name)
	if err != nil && !errors.Is(err, enrollment.ErrDenied) && ctx.Err() == nil && queue.NumRequeues(key) < 5 {
		queue.AddRateLimited(key)
	} else {
		queue.Forget(key)
	}
	return true
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.synced.Store(false)
		cancel, done := r.cancel, r.runDone
		r.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}
		r.closeErr = r.ledger.Close()
	})
	return r.closeErr
}

func (r *Runtime) String() string   { return "management issuer runtime (private material redacted)" }
func (r *Runtime) GoString() string { return r.String() }
