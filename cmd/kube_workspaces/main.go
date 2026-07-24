package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	kubeworkspaces "github.com/kube-workspaces/api"
	health "github.com/kube-workspaces/api/gen/health"
	images "github.com/kube-workspaces/api/gen/images"
	namespaces "github.com/kube-workspaces/api/gen/namespaces"
	volumes "github.com/kube-workspaces/api/gen/volumes"
	workspaces "github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/k8s"
	"goa.design/clue/debug"
	"goa.design/clue/log"
)

func main() {
	// Define command line flags, add any other flag required to configure the
	// service.
	var (
		hostF     = flag.String("host", "localhost", "Server host (valid values: localhost)")
		domainF   = flag.String("domain", "", "Host domain name (overrides host domain specified in service design)")
		httpPortF = flag.String("http-port", "", "HTTP port (overrides host HTTP port specified in service design)")
		secureF   = flag.Bool("secure", false, "Use secure scheme (https or grpcs)")
		dbgF      = flag.Bool("debug", false, "Log request and response bodies")
	)
	flag.Parse()

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
	log.Print(ctx, log.KV{K: "http-port", V: *httpPortF})

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
		workspacesSvc workspaces.Service
		volumesSvc    volumes.Service
		imagesSvc     images.Service
		namespacesSvc namespaces.Service
		healthSvc     health.Service
	)
	{
		workspacesSvc = kubeworkspaces.NewWorkspaces(wsClient, imageClient, coreClient, authProvider, podDefaultClient)
		volumesSvc = kubeworkspaces.NewVolumes(authProvider)
		imagesSvc = kubeworkspaces.NewImages(imageClient)
		namespacesSvc = kubeworkspaces.NewNamespaces(authProvider)
		healthSvc = kubeworkspaces.NewHealth()
	}

	// Wrap the services in endpoints that can be invoked from other services
	// potentially running in different processes.
	var (
		workspacesEndpoints *workspaces.Endpoints
		volumesEndpoints    *volumes.Endpoints
		imagesEndpoints     *images.Endpoints
		namespacesEndpoints *namespaces.Endpoints
		healthEndpoints     *health.Endpoints
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
		healthEndpoints = health.NewEndpoints(healthSvc)
		healthEndpoints.Use(debug.LogPayloads())
		healthEndpoints.Use(log.Endpoint)
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
	ctx, cancel := context.WithCancel(ctx)

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
			handleHTTPServer(ctx, u, workspacesEndpoints, volumesEndpoints, imagesEndpoints, namespacesEndpoints, healthEndpoints, wsClient, coreClient, crdClient, imageClient, metricsBuffer, dynClient, podDefaultClient, &wg, errc, *dbgF)
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
