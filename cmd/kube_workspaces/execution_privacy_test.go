package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecutionPrivacyHeaders(t *testing.T) {
	h := executionPrivacyHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("recording")) }))
	for _, path := range []string{"/v1/executions", "/v1/executions/id/recording/chunks/0"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: missing privacy headers: %v", path, w.Header())
		}
	}
}
