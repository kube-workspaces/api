package auth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Opt-in live acceptance. Creates isolated API pods from the installed
// deployment's template (no Service labels, no deployment scaling), verifies
// cross-process code redemption, then runs the desktop client's live transport
// checks. Every owned resource is removed; credentials are never logged.
// KW_LIVE_CONTEXT, KW_LIVE_URL, KW_LIVE_TOKEN, KW_LIVE_NAMESPACE, KW_LIVE_VM
// are required. The caller supplies an authenticated short-lived test token.
func TestLivePlatformFollowUps(t *testing.T) {
	kubeContext := os.Getenv("KW_LIVE_CONTEXT")
	if kubeContext == "" {
		t.Skip("set KW_LIVE_CONTEXT for live acceptance")
	}
	base, token := os.Getenv("KW_LIVE_URL"), os.Getenv("KW_LIVE_TOKEN")
	if base == "" || token == "" {
		t.Fatal("KW_LIVE_URL and KW_LIVE_TOKEN are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	restConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{CurrentContext: kubeContext}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		t.Fatal(err)
	}
	kube, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		t.Fatal(err)
	}
	provider := NewConfigProvider(dyn)
	cfg, err := provider.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ValidateSessionTokenWithKeys(token, cfg.SessionSigningKeys())
	if err != nil {
		t.Fatal("test token is not valid for this cluster")
	}

	const systemNS = LocalAuthSystemNamespace
	probe := func() string {
		deployment, err := kube.AppsV1().Deployments(systemNS).Get(ctx, "kube-workspaces-api", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{GenerateName: "kw-followup-probe-", Namespace: systemNS, Labels: map[string]string{"kubeworkspaces.io/acceptance": "platform-followups"}}, Spec: deployment.Spec.Template.Spec}
		pod.Spec.RestartPolicy = corev1.RestartPolicyNever
		for i := range pod.Spec.Containers {
			pod.Spec.Containers[i].ImagePullPolicy = corev1.PullAlways
		}
		pod, err = kube.CoreV1().Pods(systemNS).Create(ctx, pod, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			if err := kube.CoreV1().Pods(systemNS).Delete(cleanup, pod.Name, metav1.DeleteOptions{}); err != nil {
				t.Errorf("cleanup API probe pod: %v", err)
			}
		})
		ready := false
		deadline := time.Now().Add(90 * time.Second)
		for !ready && time.Now().Before(deadline) {
			current, err := kube.CoreV1().Pods(systemNS).Get(ctx, pod.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, condition := range current.Status.Conditions {
				ready = ready || condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue
			}
			if !ready {
				time.Sleep(time.Second)
			}
		}
		if !ready {
			t.Fatal("isolated API probe pod did not become ready")
		}
		forwardCtx, stopForward := context.WithCancel(ctx)
		forward := exec.CommandContext(forwardCtx, "kubectl", "--context", kubeContext, "-n", systemNS, "port-forward", "--address", "127.0.0.1", "pod/"+pod.Name, "0:8080")
		stdout, err := forward.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		forward.Stderr = io.Discard
		if err := forward.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stopForward(); _ = forward.Wait() })
		addresses := make(chan string, 1)
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				if address, ok := strings.CutPrefix(scanner.Text(), "Forwarding from 127.0.0.1:"); ok {
					port, _, _ := strings.Cut(address, " ")
					addresses <- "http://127.0.0.1:" + port
					return
				}
			}
		}()
		var other string
		select {
		case other = <-addresses:
		case <-time.After(15 * time.Second):
			t.Fatal("API probe port-forward failed")
		}
		return other
	}
	other := probe()
	// When the installed ingress backend predates the published endpoints,
	// explicitly opt into two isolated published API pods instead.
	isolatedOnly := os.Getenv("KW_LIVE_USE_PROBE_API") == "1"
	if isolatedOnly {
		base = probe()
	}
	httpClient := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(t *testing.T, method, target string, body any, authenticated bool) *http.Response {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, reader)
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal("live HTTP request failed (credentials/code omitted)")
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	t.Run("native-code-cross-process", func(t *testing.T) {
		// Use the production native completion function after authentication,
		// rather than an interactive IdP. Redeem on both independent API pods.
		store := NewK8sCodeStore(dyn)
		defer store.Close()
		issuer := NewOIDCHandlerWithCodes(provider, store)
		verifier := strings.Repeat("a", 43)
		for _, target := range []string{base, other} {
			rec := httptest.NewRecorder()
			issuer.completeNativeLogin(rec, httptest.NewRequest("GET", "/auth/callback", nil), &authState{NativeRedirect: "http://127.0.0.1:12345/callback", CodeChallenge: deriveCodeChallengeS256(verifier)}, token, cfg)
			location, err := url.Parse(rec.Header().Get("Location"))
			if err != nil || rec.Code != http.StatusFound {
				t.Fatal("native issue failed")
			}
			code := location.Query().Get("code")
			if code == "" {
				t.Fatal("native completion did not issue a code")
			}
			t.Cleanup(func() {
				_ = dyn.Resource(authCodeGVR).Namespace(systemNS).Delete(context.Background(), codeSecretName(code), metav1.DeleteOptions{})
			})
			body := map[string]string{"code": code, "code_verifier": verifier}
			resp := request(t, "POST", target+"/auth/native/token", body, false)
			if resp.StatusCode != 200 {
				t.Fatalf("native cross-process redeem status=%d", resp.StatusCode)
			}
			var redeemed struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&redeemed); err != nil || redeemed.Token != token {
				t.Fatal("native redeem returned a different credential")
			}
			if resp := request(t, "POST", target+"/auth/native/token", body, false); resp.StatusCode != 400 {
				t.Fatal("native code replay accepted")
			}
		}
	})

	t.Run("browser-code-cross-replica", func(t *testing.T) {
		for _, pair := range [][2]string{{base, other}, {other, base}} {
			resp := request(t, "POST", pair[0]+"/auth/browser-session/grant", map[string]string{"redirect": "/proxy/acceptance/no-navigation/"}, true)
			if resp.StatusCode != 200 {
				t.Fatalf("browser grant status=%d", resp.StatusCode)
			}
			var grant struct {
				Code string `json:"code"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&grant); err != nil || grant.Code == "" {
				t.Fatal("browser grant missing code")
			}
			t.Cleanup(func() {
				_ = dyn.Resource(authCodeGVR).Namespace(systemNS).Delete(context.Background(), codeSecretName(grant.Code), metav1.DeleteOptions{})
			})
			redeemURL := pair[1] + "/auth/browser-session?code=" + url.QueryEscape(grant.Code)
			redeem := request(t, "GET", redeemURL, nil, false)
			if redeem.StatusCode != 302 {
				t.Fatalf("browser cross-replica redeem status=%d", redeem.StatusCode)
			}
			found := false
			for _, cookie := range redeem.Cookies() {
				found = found || cookie.Name == SessionCookieName && cookie.Value == token && cookie.HttpOnly
			}
			if !found {
				t.Fatal("browser credential cookie missing")
			}
			if replay := request(t, "GET", redeemURL, nil, false); replay.StatusCode != 400 {
				t.Fatal("browser code replay accepted")
			}
		}
	})

	t.Run("desktop-live-consumers", func(t *testing.T) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, "go", "test", "./internal/kwclient", "-run", "^TestLivePlatformFollowUps$", "-v", "-count=1")
		cmd.Dir = filepath.Clean(filepath.Join(cwd, "..", "..", "..", "desktop-client"))
		cmd.Env = append(os.Environ(), "KW_LIVE_URL="+base)
		output, err := cmd.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal("desktop live acceptance failed")
		}
	})
	t.Log("isolated second API pod used; production replica count unchanged")
}
