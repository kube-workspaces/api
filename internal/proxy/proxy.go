// Package proxy provides a reverse proxy for workspace services running in-cluster.
// It supports HTTP and WebSocket connections, with Location header rewriting for redirects.
// Proxy behavior is configurable per-image via ProxyConfig.
package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Config holds proxy behavior hints for a specific workspace image.
type Config struct {
	// NeedsNoOpSW: serve a no-op ServiceWorker at /sw.js to prevent SW registration errors.
	NeedsNoOpSW bool
	// WebSocketPaths: paths that use WebSocket (informational — all paths support WS transparently).
	WebSocketPaths []string
	// RewriteHostAbsolutePaths: rewrite requests with absolute paths that escape the proxy
	// prefix by using the Referer header to determine the target workspace.
	RewriteHostAbsolutePaths bool
	// CustomRequestHeaders: additional headers to inject into proxied requests.
	CustomRequestHeaders map[string]string
	// InjectBaseTag: inject a <base> tag into HTML responses (not yet implemented).
	InjectBaseTag bool
	// TLSInsecure: connect to backend over HTTPS with skip-verify (for self-signed certs).
	TLSInsecure bool
}

// ConfigLookup is a function that returns the proxy config for a given workspace image string.
// Returns nil if no specific config is found (default behavior applies).
type ConfigLookup func(imageRef string) *Config

// WorkspaceImageLookup is a function that returns the container image for a workspace
// given its namespace and name. Returns empty string if not found.
type WorkspaceImageLookup func(namespace, name string) string

// HandlerOptions configures the proxy handler.
type HandlerOptions struct {
	// ConfigLookup returns proxy config for a given image reference.
	ConfigLookup ConfigLookup
	// WorkspaceImageLookup returns the image reference for a workspace by ns/name.
	WorkspaceImageLookup WorkspaceImageLookup
	// ExternalHost is the external hostname (e.g. "workspaces.example.com") that
	// clients use to reach this service. When set, it is forwarded as the Host
	// header to backend services so they generate correct remoteAuthority values.
	ExternalHost string
}

// Handler returns an http.Handler that proxies requests to workspace services.
// URL pattern: /proxy/{namespace}/{name}/{rest...}
// Proxies to: http://{name}.{namespace}.svc.cluster.local:80/{rest...}
//
// Supports WebSocket upgrade transparently via httputil.ReverseProxy.
// Applies per-image proxy configuration when available.
func Handler(opts *HandlerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse path: /proxy/{namespace}/{name}/{rest...}
		path := strings.TrimPrefix(r.URL.Path, "/proxy/")
		parts := strings.SplitN(path, "/", 3)

		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			http.Error(w, `{"error":"URL must be /proxy/{namespace}/{name}/..."}`, http.StatusBadRequest)
			return
		}

		namespace := parts[0]
		name := parts[1]
		rest := "/"
		if len(parts) == 3 {
			rest = "/" + parts[2]
		}

		// Look up proxy config for this workspace's image
		var cfg *Config
		if opts != nil && opts.ConfigLookup != nil && opts.WorkspaceImageLookup != nil {
			if imageRef := opts.WorkspaceImageLookup(namespace, name); imageRef != "" {
				cfg = opts.ConfigLookup(imageRef)
			}
		}

		// Build target URL
		// Always specify :80 explicitly so that https scheme doesn't default to port 443.
		targetHost := fmt.Sprintf("%s.%s.svc.cluster.local:80", name, namespace)
		scheme := "http"
		if cfg != nil && cfg.TLSInsecure {
			scheme = "https"
		}
		target := &url.URL{
			Scheme: scheme,
			Host:   targetHost,
		}

		proxyPrefix := fmt.Sprintf("/proxy/%s/%s", namespace, name)

		proxy := &httputil.ReverseProxy{
			// Use custom transport to skip TLS verification for self-signed certs
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg != nil && cfg.TLSInsecure},
			},
			Director: func(req *http.Request) {
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				req.URL.Path = rest
				// Preserve original query string
				req.URL.RawQuery = r.URL.RawQuery

				// Forward the external Host header so that backend services
				// (e.g. code-server) generate correct remoteAuthority values.
				// ExternalHost takes precedence; fall back to the incoming request Host.
				if opts != nil && opts.ExternalHost != "" {
					req.Host = opts.ExternalHost
				} else {
					req.Host = r.Host
				}

				// Set standard forwarding headers
				req.Header.Set("X-Forwarded-Host", r.Host)
				if r.TLS != nil {
					req.Header.Set("X-Forwarded-Proto", "https")
				} else if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
					req.Header.Set("X-Forwarded-Proto", proto)
				} else {
					req.Header.Set("X-Forwarded-Proto", "http")
				}

				// Remove hop-by-hop headers that shouldn't be forwarded,
				// except Connection/Upgrade which are needed for WebSocket.
				if req.Header.Get("Upgrade") == "" {
					req.Header.Del("Connection")
				}

				// Strip Accept-Encoding so Go's transport auto-decompresses the
				// response. httputil.ReverseProxy otherwise passes compressed
				// bytes through raw, which breaks the client.
				req.Header.Del("Accept-Encoding")

				// Inject custom request headers from proxy config
				if cfg != nil && cfg.CustomRequestHeaders != nil {
					for k, v := range cfg.CustomRequestHeaders {
						req.Header.Set(k, v)
					}
				}
			},
			ModifyResponse: func(resp *http.Response) error {
				// Rewrite Location headers to keep redirects under the proxy prefix
				location := resp.Header.Get("Location")
				if location != "" {
					rewritten := rewriteLocation(location, proxyPrefix, rest, target)
					resp.Header.Set("Location", rewritten)
				}

				// Rewrite HTML responses for proxy compatibility.
				if cfg != nil && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
					browserHost := r.Header.Get("X-Forwarded-Host")
					if browserHost == "" {
						browserHost = r.Host
					}
					rewriteHTMLResponse(resp, proxyPrefix, browserHost, cfg.InjectBaseTag)
				}

				return nil
			},
			// FlushInterval -1 enables streaming (important for long-running responses)
			FlushInterval: -1,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprintf(w, `{"error":"Failed to connect to workspace: %s"}`, err.Error())
			},
		}

		proxy.ServeHTTP(w, r)
	})
}

// ShouldServeNoOpSW checks if any image in the registry needs a no-op ServiceWorker.
// Used to decide whether to serve /sw.js at the root level.
func ShouldServeNoOpSW(lookup ConfigLookup, imageRefs []string) bool {
	if lookup == nil {
		return true // default to serving it if no config available
	}
	for _, ref := range imageRefs {
		if cfg := lookup(ref); cfg != nil && cfg.NeedsNoOpSW {
			return true
		}
	}
	return false
}

// ShouldRewriteAbsolutePaths checks if any image in the registry needs Referer-based
// absolute path rewriting.
func ShouldRewriteAbsolutePaths(lookup ConfigLookup, imageRefs []string) bool {
	if lookup == nil {
		return true // default to rewriting if no config available
	}
	for _, ref := range imageRefs {
		if cfg := lookup(ref); cfg != nil && cfg.RewriteHostAbsolutePaths {
			return true
		}
	}
	return false
}

// rewriteLocation rewrites a Location header value to keep it under the proxy prefix.
func rewriteLocation(location, proxyPrefix, currentPath string, target *url.URL) string {
	// Absolute URL pointing to the target host
	if strings.HasPrefix(location, "http://"+target.Host) || strings.HasPrefix(location, "https://"+target.Host) {
		parsed, err := url.Parse(location)
		if err != nil {
			return proxyPrefix + "/" + location
		}
		result := proxyPrefix + parsed.Path
		if parsed.RawQuery != "" {
			result += "?" + parsed.RawQuery
		}
		return result
	}

	// Absolute path
	if strings.HasPrefix(location, "/") {
		return proxyPrefix + location
	}

	// Relative path (./foo, ../foo, or bare foo)
	currentDir := proxyPrefix + currentPath
	if idx := strings.LastIndex(currentDir, "/"); idx >= 0 {
		currentDir = currentDir[:idx]
	}

	if strings.HasPrefix(location, "./") {
		return currentDir + "/" + location[2:]
	}
	if strings.HasPrefix(location, "../") {
		parentDir := currentDir
		if idx := strings.LastIndex(parentDir, "/"); idx >= 0 {
			parentDir = parentDir[:idx]
		}
		return parentDir + "/" + location[3:]
	}

	return currentDir + "/" + location
}

// rewriteHTMLResponse reads an HTML response body, rewrites code-server-specific
// configuration values, optionally injects a <base> tag, and updates the response.
// It handles gzip-encoded responses.
func rewriteHTMLResponse(resp *http.Response, proxyPrefix, browserHost string, injectBaseTag bool) {
	// Read the body (possibly gzip-compressed)
	var body []byte
	var err error
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return
		}
		body, err = io.ReadAll(reader)
		reader.Close()
	} else {
		body, err = io.ReadAll(resp.Body)
	}
	resp.Body.Close()
	if err != nil {
		return
	}

	html := string(body)

	// Inject <base> tag so relative and absolute URL references resolve through the proxy.
	// This is critical for apps like filebrowser that use absolute paths (e.g. /js/app.js).
	if injectBaseTag && proxyPrefix != "" {
		baseTag := fmt.Sprintf(`<base href="%s/">`, proxyPrefix)
		// Insert after <head> if present
		if idx := strings.Index(html, "<head>"); idx >= 0 {
			html = html[:idx+6] + baseTag + html[idx+6:]
		} else if idx := strings.Index(html, "<HEAD>"); idx >= 0 {
			html = html[:idx+6] + baseTag + html[idx+6:]
		} else if idx := strings.Index(html, "<html"); idx >= 0 {
			// Fallback: insert after the opening <html...> tag
			closeIdx := strings.Index(html[idx:], ">")
			if closeIdx >= 0 {
				insertPos := idx + closeIdx + 1
				html = html[:insertPos] + baseTag + html[insertPos:]
			}
		}
	}

	// Rewrite remoteAuthority: replace "remote:443" or similar with the browser's host.
	// code-server hardcodes this based on its internal detection; we need it to match
	// the browser's actual origin so VS Code connects WebSocket through the proxy.
	html = strings.ReplaceAll(html, `"remoteAuthority":"remote:443"`, fmt.Sprintf(`"remoteAuthority":"%s"`, browserHost))
	html = strings.ReplaceAll(html, `"remoteAuthority":"remote:80"`, fmt.Sprintf(`"remoteAuthority":"%s"`, browserHost))

	// Rewrite serverBasePath: "." should be the proxy prefix so VS Code constructs
	// correct URLs for its resources.
	if proxyPrefix != "" {
		html = strings.ReplaceAll(html, `"serverBasePath":"."`, fmt.Sprintf(`"serverBasePath":"%s"`, proxyPrefix))
	}

	// Rewrite rootEndpoint: "." should be the proxy prefix
	if proxyPrefix != "" {
		html = strings.ReplaceAll(html, `"rootEndpoint":"."`, fmt.Sprintf(`"rootEndpoint":"%s"`, proxyPrefix))
	}

	// Re-encode the response
	var newBody []byte
	if resp.Header.Get("Content-Encoding") == "gzip" {
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		gzWriter.Write([]byte(html))
		gzWriter.Close()
		newBody = buf.Bytes()
	} else {
		newBody = []byte(html)
	}

	resp.Body = io.NopCloser(bytes.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
}
