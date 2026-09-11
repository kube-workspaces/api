package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	health "github.com/kube-workspaces/api/gen/health"
	healthsvr "github.com/kube-workspaces/api/gen/http/health/server"
	imagessvr "github.com/kube-workspaces/api/gen/http/images/server"
	namespacessvr "github.com/kube-workspaces/api/gen/http/namespaces/server"
	sshkeyssvr "github.com/kube-workspaces/api/gen/http/sshkeys/server"
	volumessvr "github.com/kube-workspaces/api/gen/http/volumes/server"
	workspacessvr "github.com/kube-workspaces/api/gen/http/workspaces/server"
	images "github.com/kube-workspaces/api/gen/images"
	namespaces "github.com/kube-workspaces/api/gen/namespaces"
	sshkeys "github.com/kube-workspaces/api/gen/sshkeys"
	volumes "github.com/kube-workspaces/api/gen/volumes"
	workspaces "github.com/kube-workspaces/api/gen/workspaces"
	"github.com/kube-workspaces/api/internal/auth"
	"github.com/kube-workspaces/api/internal/exec"
	"github.com/kube-workspaces/api/internal/k8s"
	"github.com/kube-workspaces/api/internal/platform"
	"goa.design/clue/debug"
	"goa.design/clue/log"
	goahttp "goa.design/goa/v3/http"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

//go:embed openapi3.json
var openapi3JSON []byte

//go:embed openapi3.yaml
var openapi3YAML []byte

//go:embed godoc
var godocFS embed.FS

// handleHTTPServer starts configures and starts a HTTP server on the given
// URL. It shuts down the server if any error is received in the error channel.
func handleHTTPServer(ctx context.Context, u *url.URL, workspacesEndpoints *workspaces.Endpoints, volumesEndpoints *volumes.Endpoints, imagesEndpoints *images.Endpoints, namespacesEndpoints *namespaces.Endpoints, sshkeysEndpoints *sshkeys.Endpoints, healthEndpoints *health.Endpoints, wsClient *k8s.WorkspaceClient, coreClient *k8s.CoreClient, crdClient *k8s.CRDClient, imageClient *k8s.ImageClient, metricsBuffer *k8s.MetricsBuffer, dynClient dynamic.Interface, podDefaultClient *k8s.PodDefaultClient, wg *sync.WaitGroup, errc chan error, dbg bool) {

	// Provide the transport specific request decoder and response encoder.
	// The goa http package has built-in support for JSON, XML and gob.
	// Other encodings can be used by providing the corresponding functions,
	// see goa.design/implement/encoding.
	var (
		dec = goahttp.RequestDecoder
		enc = goahttp.ResponseEncoder
	)

	// Build the service HTTP request multiplexer and mount debug and profiler
	// endpoints in debug mode.
	var mux goahttp.Muxer
	{
		mux = goahttp.NewMuxer()
		if dbg {
			// Mount pprof handlers for memory profiling under /debug/pprof.
			debug.MountPprofHandlers(debug.Adapt(mux))
			// Mount /debug endpoint to enable or disable debug logs at runtime.
			debug.MountDebugLogEnabler(debug.Adapt(mux))
		}
	}

	// Wrap the endpoints with the transport specific layers. The generated
	// server packages contains code generated from the design which maps
	// the service input and output data structures to HTTP requests and
	// responses.
	var (
		workspacesServer *workspacessvr.Server
		volumesServer    *volumessvr.Server
		imagesServer     *imagessvr.Server
		namespacesServer *namespacessvr.Server
		sshkeysServer    *sshkeyssvr.Server
		healthServer     *healthsvr.Server
	)
	{
		eh := errorHandler(ctx)
		workspacesServer = workspacessvr.New(workspacesEndpoints, mux, dec, enc, eh, nil)
		volumesServer = volumessvr.New(volumesEndpoints, mux, dec, enc, eh, nil)
		imagesServer = imagessvr.New(imagesEndpoints, mux, dec, enc, eh, nil)
		namespacesServer = namespacessvr.New(namespacesEndpoints, mux, dec, enc, eh, nil)
		sshkeysServer = sshkeyssvr.New(sshkeysEndpoints, mux, dec, enc, eh, nil)
		healthServer = healthsvr.New(healthEndpoints, mux, dec, enc, eh, nil)
	}

	// Configure the mux.
	workspacessvr.Mount(mux, workspacesServer)
	volumessvr.Mount(mux, volumesServer)
	imagessvr.Mount(mux, imagesServer)
	namespacessvr.Mount(mux, namespacesServer)
	sshkeyssvr.Mount(mux, sshkeysServer)
	healthsvr.Mount(mux, healthServer)

	// Serve OpenAPI spec, rewriting the server URL to use EXTERNAL_HOST.
	externalHost := os.Getenv("EXTERNAL_HOST")
	if externalHost == "" {
		externalHost = "localhost:8080"
	}
	var openapi3JSONRewritten []byte
	if externalHost != "localhost:8080" {
		openapi3JSONRewritten = []byte(strings.ReplaceAll(string(openapi3JSON), `"http://localhost:8080"`, `"https://`+externalHost+`"`))
	} else {
		openapi3JSONRewritten = openapi3JSON
	}
	mux.Handle("GET", "/openapi3.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(openapi3JSONRewritten)
	})
	mux.Handle("GET", "/openapi3.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		w.Write(openapi3YAML)
	})

	// Serve Go documentation (generated by gomarkdoc)
	godocSub, _ := fs.Sub(godocFS, "godoc")
	mux.Handle("GET", "/godoc/{file}", func(w http.ResponseWriter, r *http.Request) {
		file := r.PathValue("file")
		if file == "" {
			file = "index.json"
		}
		data, err := fs.ReadFile(godocSub, file)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "file not found"})
			return
		}
		switch {
		case strings.HasSuffix(file, ".json"):
			w.Header().Set("Content-Type", "application/json")
		case strings.HasSuffix(file, ".md"):
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		default:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})
	mux.Handle("GET", "/godoc", func(w http.ResponseWriter, r *http.Request) {
		data, _ := fs.ReadFile(godocSub, "index.json")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})

	// --- Authentication & Authorization ---
	authProvider := auth.NewConfigProvider(dynClient)
	oidcHandler := auth.NewOIDCHandler(authProvider)
	localAuthHandler := auth.NewLocalAuthHandler(authProvider)

	// --- Platform Configuration ---
	platformProvider := platform.NewConfigProvider(dynClient)

	// Auth endpoints (always available, handler logic checks if auth is enabled)
	mux.Handle("GET", "/auth/config", oidcHandler.HandleAuthConfig)
	mux.Handle("GET", "/auth/login", oidcHandler.HandleLogin)
	mux.Handle("GET", "/auth/callback", oidcHandler.HandleCallback)
	mux.Handle("POST", "/auth/logout", oidcHandler.HandleLogout)
	mux.Handle("GET", "/auth/me", oidcHandler.HandleMe)
	mux.Handle("POST", "/auth/login/local", localAuthHandler.HandleLocalLogin)
	mux.Handle("POST", "/auth/change-password", localAuthHandler.HandleChangePassword)

	// Platform version endpoint (public). Reports this build plus the image each
	// component is actually running, so "what is deployed here?" can be answered
	// without cluster access. The API's own version is compiled in; the others are
	// read from their pod specs, since a component cannot be asked over the
	// network without assuming it is healthy.
	mux.Handle("GET", "/platform/version", func(w http.ResponseWriter, r *http.Request) {
		v, c, d := Version()
		resp := map[string]interface{}{
			"api": map[string]string{
				"version":   v,
				"commit":    c,
				"buildDate": d,
				"go":        runtime.Version(),
				"platform":  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			},
		}

		ns := os.Getenv("POD_NAMESPACE")
		if ns == "" {
			ns = "kube-workspaces-system"
		}
		components := map[string]componentStatus{}
		for _, comp := range []string{"controller", "api", "proxy", "frontend"} {
			pods, err := coreClient.ListPods(r.Context(), ns,
				"app.kubernetes.io/component="+comp)
			if err != nil || pods == nil || len(pods.Items) == 0 {
				continue
			}
			components[comp] = summarizeComponent(pods.Items)
		}
		if len(components) > 0 {
			// Back-compat: keep the plain image-per-component map, and add
			// the richer status object for the admin overview badges.
			images := map[string]string{}
			for comp, cs := range components {
				images[comp] = cs.Image
			}
			resp["images"] = images
			resp["components"] = components
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	})

	// Platform config endpoint (public, returns form locks + maintenance status)
	mux.Handle("GET", "/platform/config", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := platformProvider.GetConfig(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"maintenance": map[string]interface{}{"enabled": false},
			})
			return
		}
		response := map[string]interface{}{
			"maintenance": map[string]interface{}{
				"enabled": cfg.Maintenance.Enabled,
				"message": cfg.Maintenance.Message,
			},
		}
		if len(cfg.FormFieldLocks) > 0 {
			response["formFieldLocks"] = cfg.FormFieldLocks
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Admin: user management endpoints
	mux.Handle("GET", "/admin/users", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		list, err := authProvider.ListUsers(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	mux.Handle("GET", "/admin/users/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		name := r.PathValue("name")
		if name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "user name is required"})
			return
		}
		user, err := authProvider.GetUser(r.Context(), name)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})

	mux.Handle("POST", "/admin/users", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		var body struct {
			Email       string   `json:"email"`
			DisplayName string   `json:"displayName"`
			Role        string   `json:"role"`
			Groups      []string `json:"groups"`
			AuthMethod  string   `json:"authMethod"` // "local" or "oidc" (default)
			Password    string   `json:"password"`   // optional; only used when authMethod=local
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}
		if body.Email == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "email is required"})
			return
		}
		if body.Role == "" {
			body.Role = "editor"
		}

		if body.AuthMethod == "local" {
			password, name, err := auth.ProvisionLocalUser(r.Context(), authProvider, body.Email, body.DisplayName, body.Role, body.Password, body.Groups)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"status":   "created",
				"name":     name,
				"password": password, // returned once; never persisted anywhere but the Secret
			})
			return
		}

		if err := auth.ProvisionUser(r.Context(), authProvider, body.Email, body.DisplayName, body.Role, body.Groups); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	})

	mux.Handle("POST", "/admin/users/{name}/reset-password", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		name := r.PathValue("name")
		if name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "user name is required"})
			return
		}
		password, err := auth.ResetLocalUserPassword(r.Context(), authProvider, name)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":   "password reset",
			"password": password, // returned once; never persisted anywhere but the Secret
		})
	})

	mux.Handle("PUT", "/admin/users/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		name := r.PathValue("name")
		if name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "user name is required"})
			return
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}

		user, err := authProvider.GetUser(r.Context(), name)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		// Update spec fields
		spec, _, _ := unstructured.NestedMap(user.Object, "spec")
		if spec == nil {
			spec = make(map[string]interface{})
		}
		if role, ok := body["role"].(string); ok {
			spec["role"] = role
		}
		if displayName, ok := body["displayName"].(string); ok {
			spec["displayName"] = displayName
		}
		if disabled, ok := body["disabled"].(bool); ok {
			spec["disabled"] = disabled
		}
		if groups, ok := body["groups"].([]interface{}); ok {
			spec["groups"] = groups
		}
		if nsAccess, ok := body["namespaceAccess"].([]interface{}); ok {
			spec["namespaceAccess"] = nsAccess
		}

		// Allow enabling local auth for an existing (e.g. OIDC-provisioned) user,
		// adding password login as a secondary method for the same identity.
		if enableLocal, ok := body["enableLocalAuth"].(bool); ok && enableLocal {
			localAuth, _, _ := unstructured.NestedMap(user.Object, "spec", "localAuth")
			alreadyEnabled := localAuth != nil && localAuth["enabled"] == true
			if !alreadyEnabled {
				password, genErr := auth.GeneratePassword()
				if genErr != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": genErr.Error()})
					return
				}
				hash, hashErr := auth.HashPassword(password)
				if hashErr != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": hashErr.Error()})
					return
				}
				secretName := fmt.Sprintf("kw-user-%s-local-auth", name)
				if createErr := authProvider.CreatePasswordSecret(r.Context(), secretName, hash, password); createErr != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": createErr.Error()})
					return
				}
				spec["localAuth"] = map[string]interface{}{
					"enabled": true,
					"passwordSecretRef": map[string]interface{}{
						"name": secretName,
						"key":  "passwordHash",
					},
					"mustChangePassword": true,
				}
				unstructured.SetNestedMap(user.Object, spec, "spec")
				updated, updateErr := authProvider.UpdateUser(r.Context(), user)
				if updateErr != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": updateErr.Error()})
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"user":     updated,
					"password": password,
				})
				return
			}
		}

		unstructured.SetNestedMap(user.Object, spec, "spec")

		// Update labels
		labels := user.GetLabels()
		if labels == nil {
			labels = make(map[string]string)
		}
		if role, ok := spec["role"].(string); ok {
			labels["kubeworkspaces.io/role"] = role
		}
		user.SetLabels(labels)

		updated, err := authProvider.UpdateUser(r.Context(), user)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	})

	mux.Handle("DELETE", "/admin/users/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		name := r.PathValue("name")
		if name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "user name is required"})
			return
		}
		// Best-effort cleanup of the local-auth password secret, if any.
		if userCR, getErr := authProvider.GetUser(r.Context(), name); getErr == nil {
			if secretName, _, _ := unstructured.NestedString(userCR.Object, "spec", "localAuth", "passwordSecretRef", "name"); secretName != "" {
				_ = authProvider.DeletePasswordSecret(r.Context(), secretName)
			}
		}
		if err := authProvider.DeleteUser(r.Context(), name); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	})

	// Admin: get/update AuthConfig
	mux.Handle("GET", "/admin/auth-config", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		obj, err := authProvider.GetAuthConfig(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(obj)
	})

	mux.Handle("PUT", "/admin/auth-config", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}

		obj, err := authProvider.GetAuthConfig(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "AuthConfig not found. Create it first."})
			return
		}

		// Update spec from body
		if spec, ok := body["spec"].(map[string]interface{}); ok {
			unstructured.SetNestedMap(obj.Object, spec, "spec")
		}

		updated, err := authProvider.UpdateAuthConfig(r.Context(), obj)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		authProvider.InvalidateCache()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	})

	// Admin: get/update PlatformConfig
	mux.Handle("GET", "/admin/platform-config", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		obj, err := platformProvider.GetPlatformConfig(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "PlatformConfig not found"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(obj)
	})

	mux.Handle("PUT", "/admin/platform-config", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}

		obj, err := platformProvider.GetPlatformConfig(r.Context())
		if err != nil {
			// Create PlatformConfig if it doesn't exist
			obj = &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "kubeworkspaces.io/v1alpha1",
					"kind":       "PlatformConfig",
					"metadata": map[string]interface{}{
						"name": "default",
					},
					"spec": map[string]interface{}{},
				},
			}
			if spec, ok := body["spec"].(map[string]interface{}); ok {
				unstructured.SetNestedMap(obj.Object, spec, "spec")
			}
			created, err := platformProvider.CreatePlatformConfig(r.Context(), obj)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			platformProvider.InvalidateCache()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(created)
			return
		}

		// Update spec from body
		if spec, ok := body["spec"].(map[string]interface{}); ok {
			unstructured.SetNestedMap(obj.Object, spec, "spec")
		}

		updated, err := platformProvider.UpdatePlatformConfig(r.Context(), obj)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		platformProvider.InvalidateCache()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	})

	// Admin: list CustomResourceDefinitions used by kube-workspaces
	mux.Handle("GET", "/admin/crds/definitions", func(w http.ResponseWriter, r *http.Request) {
		crdNames := []string{"workspaces.kubeworkspaces.io", "images.kubeworkspaces.io", "users.kubeworkspaces.io", "authconfigs.kubeworkspaces.io", "platformconfigs.kubeworkspaces.io", "poddefaults.kubeworkspaces.io", "sshkeys.kubeworkspaces.io"}
		type crdVersion struct {
			Name    string `json:"name"`
			Served  bool   `json:"served"`
			Storage bool   `json:"storage"`
		}
		var items []interface{}
		for _, crdName := range crdNames {
			item, err := crdClient.GetCRD(r.Context(), crdName)
			if err != nil {
				continue
			}
			group, _, _ := unstructured.NestedString(item.Object, "spec", "group")
			kind, _, _ := unstructured.NestedString(item.Object, "spec", "names", "kind")
			plural, _, _ := unstructured.NestedString(item.Object, "spec", "names", "plural")
			scope, _, _ := unstructured.NestedString(item.Object, "spec", "scope")
			versionObjs, _, _ := unstructured.NestedSlice(item.Object, "spec", "versions")
			var versions []crdVersion
			for _, v := range versionObjs {
				if vm, ok := v.(map[string]interface{}); ok {
					name, _ := vm["name"].(string)
					served, _ := vm["served"].(bool)
					storage, _ := vm["storage"].(bool)
					versions = append(versions, crdVersion{name, served, storage})
				}
			}
			summary := map[string]interface{}{
				"name":     crdName,
				"group":    group,
				"kind":     kind,
				"plural":   plural,
				"scope":    scope,
				"versions": versions,
			}
			items = append(items, summary)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"items": items})
	})

	// Admin: get single CustomResourceDefinition
	mux.Handle("GET", "/admin/crds/definitions/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "CRD name is required"})
			return
		}
		obj, err := crdClient.GetCRD(r.Context(), name)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(obj)
	})

	// Admin: list instances of a CRD by group/version/resource
	mux.Handle("GET", "/admin/crds/instances/{group}/{version}/{resource}", func(w http.ResponseWriter, r *http.Request) {
		group := r.PathValue("group")
		version := r.PathValue("version")
		resource := r.PathValue("resource")
		ns := r.URL.Query().Get("namespace")

		list, err := crdClient.ListCRDInstances(r.Context(), group, version, resource, ns)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	// Admin: list raw workspace CRDs
	mux.Handle("GET", "/admin/crds/workspaces", func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = "workspaces"
		}
		list, err := wsClient.ListWorkspaces(r.Context(), ns)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	// Admin: get single raw workspace CRD
	mux.Handle("GET", "/admin/crds/workspaces/{name}", func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = "workspaces"
		}
		name := r.PathValue("name")
		if name == "" {
			// Fallback: extract from URL path
			parts := splitPath(r.URL.Path)
			if len(parts) >= 4 {
				name = parts[3]
			}
		}
		obj, err := wsClient.GetWorkspace(r.Context(), ns, name)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(obj)
	})

	// Admin: get single raw image CR
	mux.Handle("GET", "/admin/crds/images/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" {
			parts := splitPath(r.URL.Path)
			if len(parts) >= 4 {
				name = parts[3]
			}
		}
		obj, err := imageClient.GetImageRaw(r.Context(), name)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(obj)
	})

	// Admin: update image CR
	mux.Handle("PUT", "/admin/crds/images/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" {
			parts := splitPath(r.URL.Path)
			if len(parts) >= 4 {
				name = parts[3]
			}
		}
		if name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "image name is required"})
			return
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid JSON body: %v", err)})
			return
		}

		spec, ok := body["spec"].(map[string]interface{})
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "body must contain a spec object"})
			return
		}

		updated, err := imageClient.UpdateImage(r.Context(), name, spec)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	})

	// Admin: delete image CR
	mux.Handle("DELETE", "/admin/crds/images/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" {
			parts := splitPath(r.URL.Path)
			if len(parts) >= 4 {
				name = parts[3]
			}
		}
		if name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "image name is required"})
			return
		}

		if err := imageClient.DeleteImage(r.Context(), name); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	})

	// Admin: namespace management endpoints
	mux.Handle("GET", "/admin/namespaces", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		nsList, err := coreClient.ListNamespaces(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		type nsInfo struct {
			Name      string            `json:"name"`
			Phase     string            `json:"phase"`
			Enabled   bool              `json:"enabled"`
			Labels    map[string]string `json:"labels,omitempty"`
			CreatedAt string            `json:"created_at"`
		}

		results := make([]nsInfo, 0, len(nsList.Items))
		for i := range nsList.Items {
			ns := &nsList.Items[i]
			enabled := ns.Annotations["kubeworkspaces.io/namespace-enabled"] == "true"
			results = append(results, nsInfo{
				Name:      ns.Name,
				Phase:     string(ns.Status.Phase),
				Enabled:   enabled,
				Labels:    ns.Labels,
				CreatedAt: ns.CreationTimestamp.Format("2006-01-02T15:04:05Z"),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	mux.Handle("PUT", "/admin/namespaces/{name}/enabled", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		name := r.PathValue("name")
		if name == "" {
			parts := splitPath(r.URL.Path)
			if len(parts) >= 3 {
				name = parts[2]
			}
		}
		if name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "namespace name is required"})
			return
		}

		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}

		value := ""
		if body.Enabled {
			value = "true"
		}
		if err := coreClient.AnnotateNamespace(r.Context(), name, "kubeworkspaces.io/namespace-enabled", value); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"name": name, "enabled": body.Enabled})
	})

	// Admin: PodDefaults management
	mux.Handle("GET", "/admin/poddefaults", func(w http.ResponseWriter, r *http.Request) {
		if !auth.IsAdmin(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "admin role required"})
			return
		}
		if podDefaultClient == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "PodDefault client not available"})
			return
		}

		namespace := r.URL.Query().Get("namespace")

		type pdResult struct {
			Name               string            `json:"name"`
			Namespace          string            `json:"namespace"`
			Description        string            `json:"description"`
			Selector           map[string]string `json:"selector,omitempty"`
			EnvCount           int               `json:"env_count"`
			VolumeMountCount   int               `json:"volume_mount_count"`
			VolumeCount        int               `json:"volume_count"`
			ServiceAccountName string            `json:"service_account_name,omitempty"`
			AnnotationCount    int               `json:"annotation_count"`
			LabelCount         int               `json:"label_count"`
		}

		// If namespace is specified, list from that namespace; otherwise list from all enabled namespaces
		var allPDs []pdResult
		if namespace != "" {
			pds, err := podDefaultClient.ListPodDefaults(r.Context(), namespace)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			for _, pd := range pds {
				result := pdResult{
					Name:               pd.Name,
					Namespace:          pd.Namespace,
					Description:        pd.Desc,
					EnvCount:           len(pd.Env),
					VolumeMountCount:   len(pd.VolumeMounts),
					VolumeCount:        len(pd.Volumes),
					ServiceAccountName: pd.ServiceAccountName,
					AnnotationCount:    len(pd.Annotations),
					LabelCount:         len(pd.Labels),
				}
				if pd.Selector != nil && len(pd.Selector.MatchLabels) > 0 {
					result.Selector = pd.Selector.MatchLabels
				}
				allPDs = append(allPDs, result)
			}
		} else {
			// List from all namespaces that have workspaces enabled
			nsList, err := coreClient.ListNamespaces(r.Context())
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			for i := range nsList.Items {
				ns := &nsList.Items[i]
				pds, err := podDefaultClient.ListPodDefaults(r.Context(), ns.Name)
				if err != nil {
					continue
				}
				for _, pd := range pds {
					result := pdResult{
						Name:               pd.Name,
						Namespace:          pd.Namespace,
						Description:        pd.Desc,
						EnvCount:           len(pd.Env),
						VolumeMountCount:   len(pd.VolumeMounts),
						VolumeCount:        len(pd.Volumes),
						ServiceAccountName: pd.ServiceAccountName,
						AnnotationCount:    len(pd.Annotations),
						LabelCount:         len(pd.Labels),
					}
					if pd.Selector != nil && len(pd.Selector.MatchLabels) > 0 {
						result.Selector = pd.Selector.MatchLabels
					}
					allPDs = append(allPDs, result)
				}
			}
		}

		if allPDs == nil {
			allPDs = []pdResult{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(allPDs)
	})

	// Workspace logs: GET /v1/workspaces/{name}/logs
	mux.Handle("GET", "/v1/workspaces/{name}/logs", func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = "workspaces"
		}
		name := extractPathParam(r, "name", 4)
		container := r.URL.Query().Get("container")
		tailLinesStr := r.URL.Query().Get("tail")
		var tailLines int64 = 500
		if tailLinesStr != "" {
			if parsed, err := strconv.ParseInt(tailLinesStr, 10, 64); err == nil {
				tailLines = parsed
			}
		}

		wsType := workspaceType(r.Context(), wsClient, ns, name)
		if wsType == "vm" && container == "" {
			// The guest itself is not reachable via pod logs; the launcher pod's
			// compute container carries guest console output when configured.
			container = "compute"
		}
		podName, err := resolveWorkspacePod(r.Context(), coreClient, ns, name, wsType)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		logs, err := coreClient.GetPodLogs(r.Context(), ns, podName, container, tailLines)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"logs": logs})
	})

	// Workspace events: GET /v1/workspaces/{name}/events
	mux.Handle("GET", "/v1/workspaces/{name}/events", func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = "workspaces"
		}
		name := extractPathParam(r, "name", 4)
		wsType := workspaceType(r.Context(), wsClient, ns, name)

		// Get events related to the workload pod(s) and the owning objects
		podEvents, _ := coreClient.ListEvents(r.Context(), ns,
			fmt.Sprintf("involvedObject.name=%s", name+"-0"))
		vmPodEvents, _ := coreClient.ListEvents(r.Context(), ns,
			fmt.Sprintf("involvedObject.name=virt-launcher-%s", name))
		stsEvents, _ := coreClient.ListEvents(r.Context(), ns,
			fmt.Sprintf("involvedObject.name=%s", name))

		type eventEntry struct {
			Type      string `json:"type"`
			Reason    string `json:"reason"`
			Message   string `json:"message"`
			Object    string `json:"object"`
			FirstSeen string `json:"first_seen,omitempty"`
			LastSeen  string `json:"last_seen,omitempty"`
			Count     int32  `json:"count"`
			Source    string `json:"source,omitempty"`
		}

		var events []eventEntry
		appendPodEvents := func(podEvents *corev1.EventList) {
			if podEvents == nil {
				return
			}
			for _, e := range podEvents.Items {
				events = append(events, eventEntry{
					Type:      e.Type,
					Reason:    e.Reason,
					Message:   e.Message,
					Object:    fmt.Sprintf("Pod/%s", e.InvolvedObject.Name),
					FirstSeen: e.FirstTimestamp.Format(time.RFC3339),
					LastSeen:  e.LastTimestamp.Format(time.RFC3339),
					Count:     e.Count,
					Source:    e.Source.Component,
				})
			}
		}
		appendPodEvents(podEvents)
		if wsType == "vm" {
			appendPodEvents(vmPodEvents)
		}
		if stsEvents != nil {
			for _, e := range stsEvents.Items {
				if e.InvolvedObject.Kind == "StatefulSet" || e.InvolvedObject.Kind == "Workspace" ||
					e.InvolvedObject.Kind == "Deployment" || e.InvolvedObject.Kind == "VirtualMachine" ||
					e.InvolvedObject.Kind == "VirtualMachineInstance" {
					events = append(events, eventEntry{
						Type:      e.Type,
						Reason:    e.Reason,
						Message:   e.Message,
						Object:    fmt.Sprintf("%s/%s", e.InvolvedObject.Kind, e.InvolvedObject.Name),
						FirstSeen: e.FirstTimestamp.Format(time.RFC3339),
						LastSeen:  e.LastTimestamp.Format(time.RFC3339),
						Count:     e.Count,
						Source:    e.Source.Component,
					})
				}
			}
		}

		if events == nil {
			events = []eventEntry{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	})

	// Workspace update: PUT /v1/workspaces/{name}
	mux.Handle("PUT", "/v1/workspaces/{name}", func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = "workspaces"
		}
		name := extractPathParam(r, "name", 4)
		if name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "workspace name is required"})
			return
		}

		var payload struct {
			Image         *string `json:"image"`
			Port          *int    `json:"port"`
			CPURequest    *string `json:"cpu_request"`
			MemoryRequest *string `json:"memory_request"`
			CPULimit      *string `json:"cpu_limit"`
			MemoryLimit   *string `json:"memory_limit"`
			VolumeMounts  *[]struct {
				Name      string `json:"name"`
				MountPath string `json:"mount_path"`
			} `json:"volume_mounts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}

		obj, err := wsClient.GetWorkspace(r.Context(), ns, name)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("workspace %s/%s not found", ns, name)})
			return
		}

		// In-place edits are container-shaped; VM workspaces must be recreated.
		if wsType, _, _ := unstructured.NestedString(obj.Object, "spec", "type"); wsType == "vm" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "editing vm workspaces is not supported; delete and recreate instead"})
			return
		}

		containers, found, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		if !found || len(containers) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "workspace has no containers"})
			return
		}

		container, ok := containers[0].(map[string]interface{})
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid container spec"})
			return
		}

		if payload.Image != nil {
			container["image"] = *payload.Image
			// Inject default args from Image CR
			if img, err := imageClient.GetImageByRef(r.Context(), *payload.Image); err == nil && len(img.DefaultArgs) > 0 {
				args := make([]interface{}, len(img.DefaultArgs))
				for i, a := range img.DefaultArgs {
					args[i] = a
				}
				container["args"] = args
			}
		}

		if payload.Port != nil {
			container["ports"] = []interface{}{
				map[string]interface{}{
					"containerPort": int64(*payload.Port),
					"name":          "workspace-port",
					"protocol":      "TCP",
				},
			}
		}

		resources, _ := container["resources"].(map[string]interface{})
		if resources == nil {
			resources = make(map[string]interface{})
		}

		if payload.CPURequest != nil || payload.MemoryRequest != nil {
			requests, _ := resources["requests"].(map[string]interface{})
			if requests == nil {
				requests = make(map[string]interface{})
			}
			if payload.CPURequest != nil {
				requests["cpu"] = *payload.CPURequest
			}
			if payload.MemoryRequest != nil {
				requests["memory"] = *payload.MemoryRequest
			}
			resources["requests"] = requests
		}

		if payload.CPULimit != nil || payload.MemoryLimit != nil {
			limits, _ := resources["limits"].(map[string]interface{})
			if limits == nil {
				limits = make(map[string]interface{})
			}
			if payload.CPULimit != nil {
				limits["cpu"] = *payload.CPULimit
			}
			if payload.MemoryLimit != nil {
				limits["memory"] = *payload.MemoryLimit
			}
			resources["limits"] = limits
		}

		container["resources"] = resources

		if payload.VolumeMounts != nil {
			vms := make([]interface{}, 0, len(*payload.VolumeMounts))
			for _, vm := range *payload.VolumeMounts {
				vms = append(vms, map[string]interface{}{
					"name":      vm.Name,
					"mountPath": vm.MountPath,
				})
			}
			container["volumeMounts"] = vms

			// Update volumes too
			vols := make([]interface{}, 0, len(*payload.VolumeMounts))
			for _, vm := range *payload.VolumeMounts {
				vols = append(vols, map[string]interface{}{
					"name": vm.Name,
					"persistentVolumeClaim": map[string]interface{}{
						"claimName": vm.Name,
					},
				})
			}
			if err := unstructured.SetNestedSlice(obj.Object, vols, "spec", "template", "spec", "volumes"); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "failed to set volumes"})
				return
			}
		}

		containers[0] = container
		if err := unstructured.SetNestedSlice(obj.Object, containers, "spec", "template", "spec", "containers"); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to update container spec"})
			return
		}

		updated, err := wsClient.UpdateWorkspace(r.Context(), obj)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("failed to update workspace: %v", err)})
			return
		}

		// Return updated workspace using the same format as get
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(unstructuredToWorkspaceResult(updated))
	})

	// Workspace pod YAML: GET /v1/workspaces/{name}/pod
	mux.Handle("GET", "/v1/workspaces/{name}/pod", func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = "workspaces"
		}
		name := extractPathParam(r, "name", 4)

		podName, err := resolveWorkspacePod(r.Context(), coreClient, ns, name, workspaceType(r.Context(), wsClient, ns, name))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		pod, err := coreClient.GetPod(r.Context(), ns, podName)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pod)
	})

	// Workspace pod metrics: GET /v1/workspaces/{name}/metrics
	mux.Handle("GET", "/v1/workspaces/{name}/metrics", func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = "workspaces"
		}
		name := extractPathParam(r, "name", 4)

		if metricsBuffer == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "Metrics server not available"})
			return
		}

		if !metricsBuffer.Client().IsAvailable(r.Context()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "Metrics server not available: install metrics-server in the cluster"})
			return
		}

		windowStr := r.URL.Query().Get("window")
		window, err := parseWindow(windowStr)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid window: %v", err)})
			return
		}

		wsType := workspaceType(r.Context(), wsClient, ns, name)
		if wsType == "vm" {
			// metrics-server reports the virt-launcher pod's overhead, not the
			// guest; nothing useful to show until guest agent metrics exist.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "metrics are not available for vm workspaces"})
			return
		}

		podName, err := resolveWorkspacePod(r.Context(), coreClient, ns, name, wsType)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		metricsContainer := "workspace"
		if wsType == "scratch" {
			metricsContainer = name // scratch containers are named after the workspace
		}
		metricsBuffer.EnsurePod(r.Context(), ns, podName, metricsContainer)

		points, container := metricsBuffer.GetMetrics(ns, podName, window)

		type response struct {
			Container string            `json:"container"`
			Points    []k8s.MetricPoint `json:"points"`
			Message   string            `json:"message,omitempty"`
		}

		resp := response{
			Container: container,
			Points:    points,
		}

		if points == nil {
			resp.Points = []k8s.MetricPoint{}
			resp.Message = "No metrics data yet. Collection has started and will appear shortly."
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Workspace exec (terminal): GET /v1/workspaces/{name}/exec
	// Upgrades to WebSocket and bridges to pod exec via SPDY.
	// Requires editor or admin role when auth is enabled.
	restConfig, err := k8s.GetRESTConfig()
	if err != nil {
		log.Printf(ctx, "WARNING: exec endpoint unavailable: %v", err)
	}
	execClientset, err := k8s.GetClientset()
	if err != nil {
		log.Printf(ctx, "WARNING: exec endpoint unavailable: %v", err)
	}
	if restConfig != nil && execClientset != nil {
		execOpts := &exec.Options{
			RESTConfig: restConfig,
			Clientset:  execClientset,
		}
		execHandler := exec.Handler(execOpts)
		vmConsoleHandler := exec.VMConsoleHandler(execOpts)
		vmVNCHandler := exec.VMVNCHandler(execOpts)
		sshHandler := exec.SSHHandler(&exec.SSHOptions{Clientset: execClientset})

		// requireEditorAccess enforces editor/admin access plus namespace scoping
		// for the console endpoints and returns the resolved workspace name and
		// namespace. Shared by the exec, VNC, serial-console status and take-over
		// routes.
		requireEditorAccess := func(w http.ResponseWriter, r *http.Request) (ns, name string, ok bool) {
			if auth.AuthEnabled(r.Context()) {
				user := auth.UserFromContext(r.Context())
				if user == nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
					return "", "", false
				}
				if !auth.HasMinimumRole(user.Role, "editor") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]string{"error": "editor or admin role required for console access"})
					return "", "", false
				}
				ns = r.URL.Query().Get("namespace")
				if ns == "" {
					ns = "workspaces"
				}
				if !auth.UserHasNamespaceAccess(user, ns) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]string{"error": "no access to namespace"})
					return "", "", false
				}
			} else {
				ns = r.URL.Query().Get("namespace")
				if ns == "" {
					ns = "workspaces"
				}
			}
			name = r.PathValue("name")
			if name == "" {
				name = extractPathParam(r, "name", 4)
			}
			return ns, name, true
		}

		mux.Handle("GET", "/v1/workspaces/{name}/exec", func(w http.ResponseWriter, r *http.Request) {
			ns, name, ok := requireEditorAccess(w, r)
			if !ok {
				return
			}

			// VM workspaces expose the guest serial console instead of a pod exec.
			if workspaceType(r.Context(), wsClient, ns, name) == "vm" {
				vmConsoleHandler(w, r)
				return
			}

			// Scratch workspaces run a plain Deployment; resolve the pod by label.
			// Container workspaces keep the {name}-0 StatefulSet pod convention.
			if wsType := workspaceType(r.Context(), wsClient, ns, name); wsType == "scratch" {
				podName, err := resolveWorkspacePod(r.Context(), coreClient, ns, name, wsType)
				if err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				q := r.URL.Query()
				q.Set("pod", podName)
				r.URL.RawQuery = q.Encode()
			}

			// Determine shell from Image CR if not specified in query
			if r.URL.Query().Get("shell") == "" {
				shell := resolveShell(r.Context(), wsClient, imageClient, ns, name)
				q := r.URL.Query()
				q.Set("shell", shell)
				r.URL.RawQuery = q.Encode()
			}

			execHandler(w, r)
		})

		// Workspace VNC display: GET /v1/workspaces/{name}/vnc
		// Upgrades to WebSocket and bridges to the KubeVirt VMI VNC subresource
		// (raw RFB stream for a noVNC client). VM workspaces only. The bridge is
		// single-session — a second connection gets 409 while another holds it.
		// Requires editor or admin role when auth is enabled.
		mux.Handle("GET", "/v1/workspaces/{name}/vnc", func(w http.ResponseWriter, r *http.Request) {
			ns, name, ok := requireEditorAccess(w, r)
			if !ok {
				return
			}

			// Only VM workspaces expose a graphical display.
			if workspaceType(r.Context(), wsClient, ns, name) != "vm" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "vnc console is only available for VM workspaces"})
				return
			}

			vmVNCHandler(w, r)
		})

		// Serial console session status: GET /v1/workspaces/{name}/console/status
		// KubeVirt's serial console is single-session and last-wins, so the UI
		// checks status before connecting and asks for consent before taking a
		// held console over rather than silently severing the other user.
		mux.Handle("GET", "/v1/workspaces/{name}/console/status", func(w http.ResponseWriter, r *http.Request) {
			ns, name, ok := requireEditorAccess(w, r)
			if !ok {
				return
			}
			if workspaceType(r.Context(), wsClient, ns, name) != "vm" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "serial console is only available for VM workspaces"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"inUse": exec.SerialConsoleInUse(ns, name)})
		})

		// Serial console take-over: POST /v1/workspaces/{name}/console/takeover
		// Force-ends the active serial console session (if any) so the caller
		// can open a fresh one. Only invoked after the user explicitly confirms
		// wanting to disconnect whoever currently holds the console.
		mux.Handle("POST", "/v1/workspaces/{name}/console/takeover", func(w http.ResponseWriter, r *http.Request) {
			ns, name, ok := requireEditorAccess(w, r)
			if !ok {
				return
			}
			if workspaceType(r.Context(), wsClient, ns, name) != "vm" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "serial console is only available for VM workspaces"})
				return
			}
			wasInUse := exec.TakeOverSerialConsole(ns, name)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "wasInUse": wasInUse})
		})

		// VM reboot: POST /v1/workspaces/{name}/reboot
		// Deletes the VMI so KubeVirt recreates it from the VM spec (persistent
		// disk preserved).
		mux.Handle("POST", "/v1/workspaces/{name}/reboot", func(w http.ResponseWriter, r *http.Request) {
			ns, name, ok := requireEditorAccess(w, r)
			if !ok {
				return
			}
			if workspaceType(r.Context(), wsClient, ns, name) != "vm" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "reboot is only available for VM workspaces"})
				return
			}
			gvr := schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}
			if err := dynClient.Resource(gvr).Namespace(ns).Delete(r.Context(), name, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
				log.Printf(r.Context(), "reboot failed for %s/%s: %v", ns, name, err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "failed to reboot VM"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		})

		// Web SSH console: GET /v1/workspaces/{name}/ssh
		// Upgrades to WebSocket and bridges to the guest sshd (via the
		// workspace's masqueraded port on the virt-launcher pod). The client's
		// first WebSocket message must carry {"type":"ssh","user":...,"privateKey":...}.
		// VM workspaces only. Single-session — a second connection gets 409
		// while another holds it. The guest must have the caller's SSH public
		// key seeded (SshKey CRs) for the private-key auth to succeed.
		mux.Handle("GET", "/v1/workspaces/{name}/ssh", func(w http.ResponseWriter, r *http.Request) {
			ns, name, ok := requireEditorAccess(w, r)
			if !ok {
				return
			}
			if workspaceType(r.Context(), wsClient, ns, name) != "vm" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "ssh console is only available for VM workspaces"})
				return
			}
			sshHandler(w, r)
		})

		// Web SSH session status: GET /v1/workspaces/{name}/ssh/status
		mux.Handle("GET", "/v1/workspaces/{name}/ssh/status", func(w http.ResponseWriter, r *http.Request) {
			ns, name, ok := requireEditorAccess(w, r)
			if !ok {
				return
			}
			if workspaceType(r.Context(), wsClient, ns, name) != "vm" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "ssh console is only available for VM workspaces"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"inUse": exec.SSHConsoleInUse(ns, name)})
		})

		// Web SSH take-over: POST /v1/workspaces/{name}/ssh/takeover
		mux.Handle("POST", "/v1/workspaces/{name}/ssh/takeover", func(w http.ResponseWriter, r *http.Request) {
			ns, name, ok := requireEditorAccess(w, r)
			if !ok {
				return
			}
			if workspaceType(r.Context(), wsClient, ns, name) != "vm" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "ssh console is only available for VM workspaces"})
				return
			}
			wasInUse := exec.TakeOverSSHConsole(ns, name)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "wasInUse": wasInUse})
		})
	}

	var handler http.Handler = mux
	if dbg {
		// Log query and response bodies if debug logs are enabled.
		handler = debug.HTTP()(handler)
	}
	handler = log.HTTP(ctx)(handler)

	// Apply auth middleware (no-op when auth is disabled)
	handler = auth.Middleware(authProvider)(handler)

	// Apply maintenance mode middleware (returns 503 for non-admin, non-exempt paths)
	handler = maintenanceMiddleware(platformProvider, handler)

	// Root handler: routes requests to the appropriate handler.
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve a no-op ServiceWorker script for /sw.js requests.
		// Proxied apps (e.g. noVNC, code-server) try to register a SW at the root scope
		// which can't work behind a reverse proxy. A no-op SW satisfies
		// the registration without breaking anything.
		if r.URL.Path == "/sw.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Service-Worker-Allowed", "/")
			w.Write([]byte("// no-op service worker for proxied workspaces\nself.addEventListener('install', () => self.skipWaiting());\nself.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));\n"))
			return
		}

		handler.ServeHTTP(w, r)
	})

	// Wrap handler with CORS for cross-origin requests from the frontend.
	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	corsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			for _, o := range allowedOrigins {
				if strings.TrimSpace(o) == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					break
				}
			}
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		rootHandler.ServeHTTP(w, r)
	})

	// Start HTTP server using default configuration, change the code to
	// configure the server as required by your service.
	srv := &http.Server{Addr: u.Host, Handler: corsHandler, ReadHeaderTimeout: time.Second * 60}
	for _, m := range workspacesServer.Mounts {
		log.Printf(ctx, "HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range volumesServer.Mounts {
		log.Printf(ctx, "HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range imagesServer.Mounts {
		log.Printf(ctx, "HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range namespacesServer.Mounts {
		log.Printf(ctx, "HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}
	for _, m := range healthServer.Mounts {
		log.Printf(ctx, "HTTP %q mounted on %s %s", m.Method, m.Verb, m.Pattern)
	}

	(*wg).Add(1)
	go func() {
		defer (*wg).Done()

		// Start HTTP server in a separate goroutine.
		go func() {
			log.Printf(ctx, "HTTP server listening on %q", u.Host)
			errc <- srv.ListenAndServe()
		}()

		<-ctx.Done()
		log.Printf(ctx, "shutting down HTTP server at %q", u.Host)

		// Shutdown gracefully with a 30s timeout.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()

		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			log.Printf(shutdownCtx, "failed to shutdown: %v", err)
		}
	}()
}

// errorHandler returns a function that writes and logs the given error.
// The function also writes and logs the error unique ID so that it's possible
// to correlate.
func errorHandler(logCtx context.Context) func(context.Context, http.ResponseWriter, error) {
	return func(ctx context.Context, w http.ResponseWriter, err error) {
		log.Printf(logCtx, "ERROR: %s", err.Error())
	}
}

// splitPath splits a URL path into segments, ignoring empty segments.
func splitPath(path string) []string {
	var parts []string
	for _, p := range split(path, '/') {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func split(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// extractPathParam extracts a path parameter value.
// First tries r.PathValue (Go 1.22+ ServeMux), then falls back to positional extraction.
func extractPathParam(r *http.Request, param string, pathIndex int) string {
	if val := r.PathValue(param); val != "" {
		return val
	}
	parts := splitPath(r.URL.Path)
	if len(parts) > pathIndex {
		return parts[pathIndex]
	}
	return ""
}

func parseWindow(s string) (time.Duration, error) {
	if s == "" {
		return 1 * time.Hour, nil
	}

	allowed := map[string]time.Duration{
		"5m":  5 * time.Minute,
		"15m": 15 * time.Minute,
		"1h":  1 * time.Hour,
		"3h":  3 * time.Hour,
		"6h":  6 * time.Hour,
		"24h": 24 * time.Hour,
	}

	dur, ok := allowed[s]
	if !ok {
		return 0, fmt.Errorf("invalid window %q: allowed values: 5m, 15m, 1h, 3h, 6h, 24h", s)
	}
	return dur, nil
}

// componentStatus is the per-component summary returned by /platform/version.
// Status is one of "healthy", "starting" or "down".
type componentStatus struct {
	Version string `json:"version"`
	Image   string `json:"image"`
	Status  string `json:"status"`
	Ready   int    `json:"ready"`
	Total   int    `json:"total"`
}

// summarizeComponent derives a component's running state from its pods. A
// component is "healthy" while at least one replica is Running with all
// containers ready; "starting" while pods exist but none are ready and no pod
// has failed; "down" otherwise.
func summarizeComponent(pods []corev1.Pod) componentStatus {
	cs := componentStatus{Status: "down"}
	for i := range pods {
		p := &pods[i]
		if cs.Image == "" && len(p.Spec.Containers) > 0 {
			cs.Image = p.Spec.Containers[0].Image
			cs.Version = imageTag(cs.Image)
		}
		ready := p.Status.Phase == corev1.PodRunning
		if ready {
			for _, c := range p.Status.ContainerStatuses {
				if !c.Ready {
					ready = false
					break
				}
			}
		}
		if ready {
			cs.Ready++
		}
	}
	cs.Total = len(pods)
	switch {
	case cs.Ready > 0:
		cs.Status = "healthy"
	case cs.Total > 0:
		if componentPodFailed(pods) {
			cs.Status = "down"
		} else {
			cs.Status = "starting"
		}
	}
	return cs
}

// componentPodFailed reports whether any pod is in a terminal/failing state
// (failed/unknown phase, or a container stuck in a well-known crash state).
func componentPodFailed(pods []corev1.Pod) bool {
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase == corev1.PodFailed || p.Status.Phase == corev1.PodUnknown {
			return true
		}
		for _, c := range p.Status.ContainerStatuses {
			if c.State.Waiting == nil {
				continue
			}
			switch c.State.Waiting.Reason {
			case "ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff", "CreateContainerConfigError":
				return true
			}
		}
	}
	return false
}

// imageTag returns the tag suffix of a container image reference, or the whole
// reference when there is no tag.
func imageTag(image string) string {
	if i := strings.LastIndex(image, ":"); i >= 0 {
		return image[i+1:]
	}
	return image
}

// unstructuredToWorkspaceResult converts an unstructured Workspace CR to a JSON-serializable map
// matching the WorkspaceResult shape. This duplicates logic from workspaces.go since it's
// in an unexported function in a different package.
func unstructuredToWorkspaceResult(obj *unstructured.Unstructured) map[string]interface{} {
	result := map[string]interface{}{
		"name":           obj.GetName(),
		"namespace":      obj.GetNamespace(),
		"ready_replicas": 0,
		"stopped":        false,
	}

	wsType, _, _ := unstructured.NestedString(obj.Object, "spec", "type")
	if wsType == "" {
		wsType = "container"
	}
	result["type"] = wsType

	annotations := obj.GetAnnotations()
	if _, ok := annotations["kubeworkspaces.io/stopped"]; ok {
		result["stopped"] = true
	}

	createdAt := obj.GetCreationTimestamp().Format("2006-01-02T15:04:05Z")
	result["created_at"] = createdAt

	containers, found, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
	if found && len(containers) > 0 {
		container, ok := containers[0].(map[string]interface{})
		if ok {
			if image, ok := container["image"].(string); ok {
				result["image"] = image
			}
			if ports, ok := container["ports"].([]interface{}); ok && len(ports) > 0 {
				if portMap, ok := ports[0].(map[string]interface{}); ok {
					if port, ok := portMap["containerPort"].(int64); ok {
						result["port"] = int(port)
					}
				}
			}
			if resources, ok := container["resources"].(map[string]interface{}); ok {
				if requests, ok := resources["requests"].(map[string]interface{}); ok {
					if cpu, ok := requests["cpu"].(string); ok {
						result["cpu_request"] = cpu
					}
					if mem, ok := requests["memory"].(string); ok {
						result["memory_request"] = mem
					}
				}
				if limits, ok := resources["limits"].(map[string]interface{}); ok {
					if cpu, ok := limits["cpu"].(string); ok {
						result["cpu_limit"] = cpu
					}
					if mem, ok := limits["memory"].(string); ok {
						result["memory_limit"] = mem
					}
				}
			}
			if volumeMounts, ok := container["volumeMounts"].([]interface{}); ok {
				var vms []map[string]string
				for _, vm := range volumeMounts {
					if vmMap, ok := vm.(map[string]interface{}); ok {
						name, _ := vmMap["name"].(string)
						mountPath, _ := vmMap["mountPath"].(string)
						if name != "" && mountPath != "" {
							vms = append(vms, map[string]string{"name": name, "mount_path": mountPath})
						}
					}
				}
				if len(vms) > 0 {
					result["volume_mounts"] = vms
				}
			}
		}
	}

	readyReplicas, _, _ := unstructured.NestedInt64(obj.Object, "status", "readyReplicas")
	result["ready_replicas"] = int(readyReplicas)

	containerState, found, _ := unstructured.NestedMap(obj.Object, "status", "containerState")
	if found && len(containerState) > 0 {
		cs := make(map[string]interface{})
		if _, ok := containerState["running"]; ok {
			cs["state"] = "running"
			if running, ok := containerState["running"].(map[string]interface{}); ok {
				if startedAt, ok := running["startedAt"].(string); ok {
					cs["started_at"] = startedAt
				}
			}
		} else if _, ok := containerState["waiting"]; ok {
			cs["state"] = "waiting"
			if waiting, ok := containerState["waiting"].(map[string]interface{}); ok {
				if reason, ok := waiting["reason"].(string); ok {
					cs["reason"] = reason
				}
				if message, ok := waiting["message"].(string); ok {
					cs["message"] = message
				}
			}
		} else if _, ok := containerState["terminated"]; ok {
			cs["state"] = "terminated"
			if terminated, ok := containerState["terminated"].(map[string]interface{}); ok {
				if reason, ok := terminated["reason"].(string); ok {
					cs["reason"] = reason
				}
			}
		}
		if len(cs) > 0 {
			result["container_state"] = cs
		}
	}

	return result
}

// workspaceType returns the workspace's spec.type ("container" when unset).
func workspaceType(ctx context.Context, wsClient *k8s.WorkspaceClient, namespace, name string) string {
	obj, err := wsClient.GetWorkspace(ctx, namespace, name)
	if err != nil {
		return "container"
	}
	wsType, _, _ := unstructured.NestedString(obj.Object, "spec", "type")
	if wsType == "" {
		return "container"
	}
	return wsType
}

// resolveWorkspacePod maps a workspace to the pod that serves it.
// Container workspaces use the StatefulSet convention ({name}-0); scratch and
// vm workspaces resolve their pod by label (Deployment pods have generated
// names; KubeVirt launcher pods are labelled vm.kubevirt.io/name).
func resolveWorkspacePod(ctx context.Context, coreClient *k8s.CoreClient, namespace, name, wsType string) (string, error) {
	switch wsType {
	case "vm":
		pods, err := coreClient.ListPods(ctx, namespace, "vm.kubevirt.io/name="+name)
		if err == nil && len(pods.Items) > 0 {
			return pods.Items[0].Name, nil
		}
		return "", fmt.Errorf("no running VM pod found for workspace %s/%s (is the VM started?)", namespace, name)
	case "scratch":
		pods, err := coreClient.ListPods(ctx, namespace, "workspace-name="+name)
		if err == nil && len(pods.Items) > 0 {
			return pods.Items[0].Name, nil
		}
		return "", fmt.Errorf("no running pod found for workspace %s/%s", namespace, name)
	default:
		return name + "-0", nil
	}
}

// resolveShell determines the shell to use for exec, based on Image CR defaultShell field.
// Returns the configured shell if set, or empty string to trigger auto-detection.
func resolveShell(ctx context.Context, wsClient *k8s.WorkspaceClient, imageClient *k8s.ImageClient, namespace, name string) string {
	// Try to get the workspace to find its image
	obj, err := wsClient.GetWorkspace(ctx, namespace, name)
	if err != nil {
		return "" // trigger auto-detection
	}

	// Extract image reference from workspace spec
	containers, found, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
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

	// Look up the Image CR for this image reference
	img, err := imageClient.GetImageByRef(ctx, imageRef)
	if err != nil {
		return ""
	}

	// Only return a shell if explicitly configured in the Image CR
	return img.DefaultShell
}

// maintenanceMiddleware returns 503 Service Unavailable for non-admin users
// when maintenance mode is enabled. Exempt paths (health, auth, platform config)
// always pass through.
func maintenanceMiddleware(pp *platform.ConfigProvider, next http.Handler) http.Handler {
	exemptPrefixes := []string{
		"/health",
		"/auth/",
		// Covers both /platform/config and /platform/version: neither should be
		// blocked by maintenance mode, since both are used to diagnose it.
		"/platform/",
		"/admin/",
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check exempt paths first
		for _, prefix := range exemptPrefixes {
			if strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
		}

		cfg, _ := pp.GetConfig(r.Context())
		if cfg != nil && cfg.Maintenance.Enabled {
			// Admins bypass maintenance mode
			if auth.IsAdmin(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}

			msg := cfg.Maintenance.Message
			if msg == "" {
				msg = "The platform is currently undergoing maintenance. Please try again later."
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":       "maintenance",
				"message":     msg,
				"maintenance": true,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
