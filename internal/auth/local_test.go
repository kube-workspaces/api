package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestGeneratePassword(t *testing.T) {
	p1, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	if len(p1) != generatedPasswordLength {
		t.Fatalf("GeneratePassword() length = %d, want %d", len(p1), generatedPasswordLength)
	}

	p2, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	if p1 == p2 {
		t.Fatalf("GeneratePassword() produced identical passwords across calls")
	}

	for _, c := range p1 {
		found := false
		for _, allowed := range passwordCharset {
			if c == allowed {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("GeneratePassword() produced character %q outside charset", c)
		}
	}
}

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("a-reasonably-long-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("a-reasonably-long-password")); err != nil {
		t.Fatalf("bcrypt.CompareHashAndPassword() error = %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-password")); err == nil {
		t.Fatalf("expected mismatch error for wrong password, got nil")
	}
}

func TestValidatePasswordComplexity(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "short1", true},
		{"exactly min length", "123456789012", false},
		{"long enough", "a-very-long-and-secure-password", false},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordComplexity(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordComplexity(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestLocalAuthSecretName(t *testing.T) {
	got := localAuthSecretName("admin-at-local")
	want := "kw-user-admin-at-local-local-auth"
	if got != want {
		t.Errorf("localAuthSecretName() = %q, want %q", got, want)
	}
}

func TestLockoutBackoff(t *testing.T) {
	tests := []struct {
		attempts int
		want     time.Duration
	}{
		{5, time.Minute},
		{9, time.Minute},
		{10, 5 * time.Minute},
		{14, 5 * time.Minute},
		{15, 15 * time.Minute},
		{19, 15 * time.Minute},
		{20, 30 * time.Minute},
		{100, 30 * time.Minute},
	}
	for _, tt := range tests {
		if got := lockoutBackoff(tt.attempts); got != tt.want {
			t.Errorf("lockoutBackoff(%d) = %v, want %v", tt.attempts, got, tt.want)
		}
	}
}

func TestIPRateLimiter(t *testing.T) {
	l := newIPRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("expected attempt %d to be allowed", i+1)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatalf("expected 4th attempt to be denied")
	}

	// A different key should not be affected.
	if !l.Allow("5.6.7.8") {
		t.Fatalf("expected different key to be allowed")
	}
}

func TestIPRateLimiterWindowExpiry(t *testing.T) {
	l := newIPRateLimiter(1, 10*time.Millisecond)

	if !l.Allow("1.2.3.4") {
		t.Fatalf("expected first attempt to be allowed")
	}
	if l.Allow("1.2.3.4") {
		t.Fatalf("expected second attempt within window to be denied")
	}

	time.Sleep(20 * time.Millisecond)

	if !l.Allow("1.2.3.4") {
		t.Fatalf("expected attempt after window expiry to be allowed")
	}
}

func TestClientIPFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"remote addr only", "10.0.0.1:12345", "", "10.0.0.1"},
		{"xff single", "10.0.0.1:12345", "203.0.113.5", "203.0.113.5"},
		{"xff list uses first", "10.0.0.1:12345", "203.0.113.5, 10.0.0.1", "203.0.113.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login/local", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := clientIPFromRequest(req); got != tt.want {
				t.Errorf("clientIPFromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}
