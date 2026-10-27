package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	kubeworkspaces "github.com/kube-workspaces/api"
	agent "github.com/kube-workspaces/api/gen/agent"
	agentupgrades "github.com/kube-workspaces/api/gen/agentupgrades"
	display "github.com/kube-workspaces/api/gen/display"
	executions "github.com/kube-workspaces/api/gen/executions"
	health "github.com/kube-workspaces/api/gen/health"
	images "github.com/kube-workspaces/api/gen/images"
	namespaces "github.com/kube-workspaces/api/gen/namespaces"
	sshkeys "github.com/kube-workspaces/api/gen/sshkeys"
	volumes "github.com/kube-workspaces/api/gen/volumes"
	workspaces "github.com/kube-workspaces/api/gen/workspaces"
	agentstore "github.com/kube-workspaces/api/internal/agent"
	"github.com/kube-workspaces/api/internal/auth"
	dispstore "github.com/kube-workspaces/api/internal/display"
	"github.com/kube-workspaces/api/internal/execution"
	"github.com/kube-workspaces/api/internal/execution/management"
	"github.com/kube-workspaces/api/internal/execution/qga"
	executionstorage "github.com/kube-workspaces/api/internal/execution/storage"
	"github.com/kube-workspaces/api/internal/execution/upgrades"
	"github.com/kube-workspaces/api/internal/k8s"
	"github.com/kube-workspaces/api/internal/platform"
	"goa.design/clue/debug"
	"goa.design/clue/log"
)

// Build information, injected at link time:
//
//	go build -ldflags "-X main.version=v1.2.3 -X main.commit=abc1234 -X main.buildDate=..."
//
// runtime/debug.ReadBuildInfo cannot substitute for this: it reports "(devel)"
// for a build that is not driven by `go install module@version`, which is the
// case for the container build.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// Version returns the build version. Exported so the HTTP layer can serve it.
func Version() (v, c, d string) { return version, commit, buildDate }

// versionString renders the build information for logs and the -version flag.
func versionString() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s/%s, %s)",
		version, commit, buildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func main() {
	// Define command line flags, add any other flag required to configure the
	// service.
	var (
		hostF     = flag.String("host", "localhost", "Server host (valid values: localhost)")
		domainF   = flag.String("domain", "", "Host domain name (overrides host domain specified in service design)")
		httpPortF = flag.String("http-port", "", "HTTP port (overrides host HTTP port specified in service design)")
		secureF   = flag.Bool("secure", false, "Use secure scheme (https or grpcs)")
		dbgF      = flag.Bool("debug", false, "Log request and response bodies")
		versionF  = flag.Bool("version", false, "Print version information and exit")
	)
	flag.Parse()

	if *versionF {
		fmt.Println(versionString())
		return
	}

	// Setup logger. Replace logger with your own log package of choice.
	format := log.FormatJSON
	if log.IsTerminal() {
		format = log.FormatTerminal
	}
	ctx := log.Context(context.Background(), log.WithFormat(format))
	if *dbgF {
		ctx = log.Context(ctx, log.WithDebug())
		log.Debugf(ctx, "debug logs enabled")
	}
	// Log the build up front, so a pod can be identified from its logs alone
	// without inspecting the image digest.
	log.Print(ctx,
		log.KV{K: "msg", V: "starting kube-workspaces-api"},
		log.KV{K: "version", V: version},
		log.KV{K: "commit", V: commit},
		log.KV{K: "buildDate", V: buildDate},
		log.KV{K: "go", V: runtime.Version()},
		log.KV{K: "platform", V: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)})
	log.Print(ctx, log.KV{K: "http-port", V: *httpPortF})
	// Server-scoped context: SIGINT/SIGTERM cancels in-flight work such as a
	// dispatched guest execution, while individual request contexts are only
	// bounded by their own clients.
	ctx, cancel := context.WithCancel(ctx)
	// Configuration is fail-closed and does not establish storage readiness or
	// enable guest execution. The management service must additionally open and
	// verify its stores before issuing any process-creation grant.
	executionStorage, err := execution.StorageConfigFromEnv()
	if err != nil {
		log.Fatal(ctx, err)
	}
	log.Print(ctx, log.KV{K: "execution-storage-mode", V: string(executionStorage.Mode)})
	managementConfig, err := management.ConfigFromEnv()
	if err != nil {
		log.Fatal(ctx, err)
	}
	log.Print(ctx, log.KV{K: "management-issuer-enabled", V: managementConfig.Enabled})

	// Initialize the services.
	wsClient, err := k8s.NewWorkspaceClient()
	if err != nil {
		log.Fatal(ctx, fmt.Errorf("failed to create workspace client: %w", err))
	}

	coreClient, err := k8s.NewCoreClient()
	if err != nil {
		log.Fatal(ctx, fmt.Errorf("failed to create core k8s client: %w", err))
	}

	crdClient, err := k8s.NewCRDClient()
	if err != nil {
		log.Fatal(ctx, fmt.Errorf("failed to create CRD client: %w", err))
	}

	imageClient, err := k8s.NewImageClient()
	if err != nil {
		log.Fatal(ctx, fmt.Errorf("failed to create image client: %w", err))
	}

	imageRepoClient, err := k8s.NewImageRepositoryClient()
	if err != nil {
		log.Fatal(ctx, fmt.Errorf("failed to create image repository client: %w", err))
	}

	var metricsBuffer *k8s.MetricsBuffer
	metricsClient, err := k8s.NewMetricsClient()
	if err != nil {
		log.Printf(ctx, "metrics client not available: %v (pod metrics will be unavailable)", err)
	} else {
		metricsBuffer = k8s.NewMetricsBuffer(metricsClient, 15*time.Second, 24*time.Hour)
		go metricsBuffer.Run(ctx)
	}

	// Create dynamic client for auth (User CRs, AuthConfig CRs)
	dynClient, err := k8s.NewDynamicClient()
	if err != nil {
		log.Fatal(ctx, fmt.Errorf("failed to create dynamic client for auth: %w", err))
	}

	// Create auth provider for namespace access control
	authProvider := auth.NewConfigProvider(dynClient)

	podDefaultClient, err := k8s.NewPodDefaultClient()
	if err != nil {
		log.Printf(ctx, "warning: PodDefault client not available: %v (PodDefaults will not be applied)", err)
	}

	var (
		workspacesSvc    workspaces.Service
		volumesSvc       volumes.Service
		imagesSvc        images.Service
		namespacesSvc    namespaces.Service
		sshkeysSvc       sshkeys.Service
		healthSvc        health.Service
		displaySvc       display.Service
		agentSvc         agent.Service
		executionsSvc    executions.Service
		agentUpgradesSvc agentupgrades.Service
	)
	// The sessions registry is shared by the Goa display service (REST
	// membership/control) and the shared-display WebSocket route so both see
	// the same one-controller-plus-observers state per workspace.
	displaySessions := dispstore.NewSessions()
	var managementIssuer *management.Runtime
	{
		workspacesSvc = kubeworkspaces.NewWorkspaces(wsClient, imageClient, coreClient, authProvider, podDefaultClient)
		volumesSvc = kubeworkspaces.NewVolumes(authProvider)
		imagesSvc = kubeworkspaces.NewImages(imageClient)
		namespacesSvc = kubeworkspaces.NewNamespaces(authProvider)
		sshkeysSvc = kubeworkspaces.NewSSHKeys(authProvider)
		healthSvc = kubeworkspaces.NewHealth()
		displaySvc = kubeworkspaces.NewDisplay(wsClient, displaySessions, kubeworkspaces.SharedDisplayEnabledFromEnv())
		issuer, _ := os.Hostname()
		agentSvc = kubeworkspaces.NewAgent(wsClient, agentstore.NewOwnedStore(issuer), func(ctx context.Context) ([][]byte, error) {
			cfg, err := authProvider.GetConfig(ctx)
			if err != nil {
				return nil, err
			}
			return cfg.SessionSigningKeys(), nil
		})
		// execution storage/service
		execStore, execErr := executionstorage.Open(ctx, executionStorage.StorageOptions())
		if execErr != nil {
			if executionStorage.Mode != execution.StorageDisabled {
				log.Fatal(ctx, fmt.Errorf("configured execution storage could not be initialized"))
			}
			execStore = nil
		}
		log.Print(ctx, log.KV{K: "execution-storage-ready-at-start", V: execStore != nil})
		if execStore != nil {
			defer execStore.Close()
			probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
			readyErr := execStore.Ready(probeCtx)
			probeCancel()
			if readyErr != nil {
				log.Fatal(ctx, fmt.Errorf("configured execution storage is not ready"))
			}
		}
		execSvc := execution.NewService(execStore)
		stopTerminalRecovery := execSvc.StartTerminalRecovery(ctx)
		defer stopTerminalRecovery()
		startupCtx, startupCancel := context.WithTimeout(ctx, 30*time.Second)
		managementIssuer, err = management.Open(startupCtx, managementConfig, executionStorage, execStore, dynClient, authProvider)
		startupCancel()
		if err != nil {
			log.Fatal(ctx, fmt.Errorf("configured management issuer could not be initialized"))
		}
		if managementIssuer != nil {
			defer managementIssuer.Close()
		}
		var issuerReady func(context.Context) error
		if managementIssuer != nil {
			issuerReady = managementIssuer.Ready
		}
		platProvider := platform.NewConfigProvider(dynClient)
		var options []kubeworkspaces.ExecutionsOption
		// A dispatched guest run follows the server lifecycle, never the
		// caller's socket: shutdown must still fence it.
		options = append(options, kubeworkspaces.WithLifecycleContext(ctx))
		if issuerReady != nil {
			options = append(options, kubeworkspaces.WithIssuerReadiness(issuerReady))
		}
		// The QGA pilot transport is an explicit opt-in: enabling it without a
		// usable signing key or client configuration is a startup error, never
		// a silent downgrade to a narrower transport.
		qgaConfig, err := qga.ConfigFromEnv()
		if err != nil {
			log.Fatal(ctx, err)
		}
		var qgaEligibility kubeworkspaces.UpgradeEligibility
		if qgaConfig.Enabled {
			restConfig, err := k8s.GetRESTConfig()
			if err != nil {
				log.Fatal(ctx, fmt.Errorf("QGA pilot transport requires a usable rest configuration: %w", err))
			}
			clientset, err := k8s.GetClientset()
			if err != nil {
				log.Fatal(ctx, fmt.Errorf("QGA pilot transport requires a usable clientset: %w", err))
			}
			runtime, err := qga.NewRuntime(qgaConfig, dynClient, platProvider, restConfig, clientset)
			if err != nil {
				log.Fatal(ctx, fmt.Errorf("QGA pilot transport could not be initialized: %w", err))
			}
			options = append(options, kubeworkspaces.WithQGA(runtime))
			qgaEligibility = runtime
		}
		executionsSvc = kubeworkspaces.NewExecutions(execSvc, platProvider, options...)

		// Durable agent-upgrade attempt store. Persistent modes open the
		// postgres store on the same execution database and never fall back
		// to RAM; ephemeral mode gets a bounded process-local store; disabled
		// execution storage leaves agent upgrades unavailable.
		var upgradeAttempts executionstorage.AgentUpgradeStore
		switch {
		case executionStorage.Persistent() && executionStorage.DatabaseURL != "":
			attempts, err := executionstorage.NewPostgresAgentUpgrades(ctx, executionStorage.DatabaseURL)
			if err != nil {
				log.Fatal(ctx, fmt.Errorf("configured agent-upgrade attempt store could not be initialized"))
			}
			upgradeAttempts = attempts
			defer upgradeAttempts.Close()
		case executionStorage.Mode == execution.StorageEphemeral:
			attempts, err := executionstorage.NewMemoryAgentUpgrades(executionstorage.DefaultMemoryUpgradeAttempts)
			if err != nil {
				log.Fatal(ctx, fmt.Errorf("agent-upgrade attempt store could not be initialized: %w", err))
			}
			upgradeAttempts = attempts
		}
		log.Print(ctx, log.KV{K: "agent-upgrade-attempts-ready-at-start", V: upgradeAttempts != nil})
		upgradeSvc := upgrades.NewService(execStore, upgradeAttempts)
		agentUpgradesSvc = kubeworkspaces.NewAgentUpgrades(upgradeSvc, platProvider, qgaEligibility)
	}

	// Wrap the services in endpoints that can be invoked from other services
	// potentially running in different processes.
	var (
		workspacesEndpoints    *workspaces.Endpoints
		volumesEndpoints       *volumes.Endpoints
		imagesEndpoints        *images.Endpoints
		namespacesEndpoints    *namespaces.Endpoints
		sshkeysEndpoints       *sshkeys.Endpoints
		healthEndpoints        *health.Endpoints
		displayEndpoints       *display.Endpoints
		agentEndpoints         *agent.Endpoints
		executionsEndpoints    *executions.Endpoints
		agentUpgradesEndpoints *agentupgrades.Endpoints
	)
	{
		workspacesEndpoints = workspaces.NewEndpoints(workspacesSvc)
		workspacesEndpoints.Use(debug.LogPayloads())
		workspacesEndpoints.Use(log.Endpoint)
		volumesEndpoints = volumes.NewEndpoints(volumesSvc)
		volumesEndpoints.Use(debug.LogPayloads())
		volumesEndpoints.Use(log.Endpoint)
		imagesEndpoints = images.NewEndpoints(imagesSvc)
		imagesEndpoints.Use(debug.LogPayloads())
		imagesEndpoints.Use(log.Endpoint)
		namespacesEndpoints = namespaces.NewEndpoints(namespacesSvc)
		namespacesEndpoints.Use(debug.LogPayloads())
		namespacesEndpoints.Use(log.Endpoint)
		sshkeysEndpoints = sshkeys.NewEndpoints(sshkeysSvc)
		sshkeysEndpoints.Use(debug.LogPayloads())
		sshkeysEndpoints.Use(log.Endpoint)
		healthEndpoints = health.NewEndpoints(healthSvc)
		healthEndpoints.Use(debug.LogPayloads())
		healthEndpoints.Use(log.Endpoint)
		displayEndpoints = display.NewEndpoints(displaySvc)
		displayEndpoints.Use(debug.LogPayloads())
		displayEndpoints.Use(log.Endpoint)
		agentEndpoints = agent.NewEndpoints(agentSvc)
		agentEndpoints.Use(debug.LogPayloads())
		agentEndpoints.Use(log.Endpoint)
		executionsEndpoints = executions.NewEndpoints(executionsSvc)
		executionsEndpoints.Use(log.Endpoint)
		agentUpgradesEndpoints = agentupgrades.NewEndpoints(agentUpgradesSvc)
		agentUpgradesEndpoints.Use(log.Endpoint)
	}

	// Create channel used by both the signal handler and server goroutines
	// to notify the main goroutine when to stop the server.
	errc := make(chan error)

	// Setup interrupt handler. This optional step configures the process so
	// that SIGINT and SIGTERM signals cause the services to stop gracefully.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	var wg sync.WaitGroup
	if managementIssuer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := managementIssuer.Run(ctx); err != nil && ctx.Err() == nil {
				select {
				case errc <- fmt.Errorf("management bootstrap worker stopped"):
				case <-ctx.Done():
				}
			}
		}()
	}

	// Start the servers and send errors (if any) to the error channel.
	switch *hostF {
	case "localhost":
		{
			addr := "http://localhost:8080"
			u, err := url.Parse(addr)
			if err != nil {
				log.Fatalf(ctx, err, "invalid URL %#v\n", addr)
			}
			if *secureF {
				u.Scheme = "https"
			}
			if *domainF != "" {
				u.Host = *domainF
			}
			if *httpPortF != "" {
				h, _, err := net.SplitHostPort(u.Host)
				if err != nil {
					log.Fatalf(ctx, err, "invalid URL %#v\n", u.Host)
				}
				u.Host = net.JoinHostPort(h, *httpPortF)
			} else if u.Port() == "" {
				u.Host = net.JoinHostPort(u.Host, "80")
			}
			handleHTTPServer(ctx, u, workspacesEndpoints, volumesEndpoints, imagesEndpoints, namespacesEndpoints, sshkeysEndpoints, healthEndpoints, displayEndpoints, agentEndpoints, executionsEndpoints, agentUpgradesEndpoints, wsClient, coreClient, crdClient, imageClient, imageRepoClient, metricsBuffer, dynClient, podDefaultClient, displaySessions, &wg, errc, *dbgF)
		}

	default:
		log.Fatal(ctx, fmt.Errorf("invalid host argument: %q (valid hosts: localhost)", *hostF))
	}

	// Wait for signal.
	log.Printf(ctx, "exiting (%v)", <-errc)

	// Send cancellation signal to the goroutines.
	cancel()

	wg.Wait()
	log.Printf(ctx, "exited")
}
