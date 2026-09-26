package enforcement

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// backendRecorder is a fake upstream. It COUNTS how many requests
// actually arrived. The counter is the proof: a blocked request must
// leave it at exactly zero, not "probably zero".
type backendRecorder struct {
	hits        int32
	lastBody    []byte
	lastHeaders http.Header
	lastHost    string
}

func newBackend(t *testing.T) (*httptest.Server, *backendRecorder) {
	t.Helper()
	rec := &backendRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&rec.hits, 1)
		body, _ := io.ReadAll(r.Body)
		rec.lastBody = body
		rec.lastHeaders = r.Header.Clone()
		rec.lastHost = r.Host
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-reached"))
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func (rec *backendRecorder) hitCount() int32 {
	return atomic.LoadInt32(&rec.hits)
}

func newEnforcerFor(t *testing.T, rawURL string) (*ReverseProxyEnforcer, *url.URL) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("could not parse backend url: %v", err)
	}
	e, err := NewReverseProxyEnforcer(u)
	if err != nil {
		t.Fatalf("could not build enforcer: %v", err)
	}
	return e, u
}

// --- The two decisive tests ---

func TestEnforce_AllowedRequestReachesBackend(t *testing.T) {
	backend, rec := newBackend(t)
	enforcer, target := newEnforcerFor(t, backend.URL)

	req := httptest.NewRequest(http.MethodPost, "/v1/action", bytes.NewReader([]byte(`{"hello":"world"}`)))
	w := httptest.NewRecorder()

	if err := enforcer.Enforce(w, req, true, target); err != nil {
		t.Fatalf("expected no error on allow, got %v", err)
	}

	if got := rec.hitCount(); got != 1 {
		t.Fatalf("backend hit count: expected exactly 1, got %d", got)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 from backend, got %d", w.Code)
	}
	if body := w.Body.String(); body != "backend-reached" {
		t.Fatalf("expected the backend's own response body, got %q", body)
	}
}

func TestEnforce_DeniedRequestNeverReachesBackend(t *testing.T) {
	backend, rec := newBackend(t)
	enforcer, target := newEnforcerFor(t, backend.URL)

	req := httptest.NewRequest(http.MethodPost, "/v1/action", bytes.NewReader([]byte(`{"hello":"world"}`)))
	w := httptest.NewRecorder()

	err := enforcer.Enforce(w, req, false, target)

	if got := rec.hitCount(); got != 0 {
		t.Fatalf("FAIL OPEN: denied request reached the backend %d time(s)", got)
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", w.Code)
	}
	if body := w.Body.String(); body == "backend-reached" {
		t.Fatal("FAIL OPEN: client received the backend's response on a denied request")
	}
	if err != ErrDeniedByPolicy {
		t.Fatalf("expected ErrDeniedByPolicy, got %v", err)
	}
}

// --- Repeated denials, to show the zero holds ---

func TestEnforce_ManyDenialsStillZeroBackendHits(t *testing.T) {
	backend, rec := newBackend(t)
	enforcer, target := newEnforcerFor(t, backend.URL)

	const attempts = 50
	for i := 0; i < attempts; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/action", bytes.NewReader([]byte(`{}`)))
		w := httptest.NewRecorder()
		enforcer.Enforce(w, req, false, target)
		if w.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: expected 403, got %d", i, w.Code)
		}
	}

	if got := rec.hitCount(); got != 0 {
		t.Fatalf("FAIL OPEN: after %d denials the backend was hit %d time(s)", attempts, got)
	}
}

// --- Fail-closed on bad targets (SSRF guard) ---

func TestEnforce_MismatchedTargetIsBlocked(t *testing.T) {
	backend, rec := newBackend(t)
	enforcer, _ := newEnforcerFor(t, backend.URL)

	// An allowed decision, but pointed somewhere the enforcer was never
	// configured for. Must NOT be forwarded anywhere.
	evil, err := url.Parse("http://169.254.169.254")
	if err != nil {
		t.Fatalf("could not parse url: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/action", nil)
	w := httptest.NewRecorder()

	gotErr := enforcer.Enforce(w, req, true, evil)

	if rec.hitCount() != 0 {
		t.Fatal("FAIL OPEN: request with a mismatched target reached the configured backend")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", w.Code)
	}
	if gotErr != ErrTargetNotPermitted {
		t.Fatalf("expected ErrTargetNotPermitted, got %v", gotErr)
	}
}

func TestEnforce_NilTargetIsBlocked(t *testing.T) {
	backend, rec := newBackend(t)
	enforcer, _ := newEnforcerFor(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/v1/action", nil)
	w := httptest.NewRecorder()

	gotErr := enforcer.Enforce(w, req, true, nil)

	if rec.hitCount() != 0 {
		t.Fatal("FAIL OPEN: request with a nil target reached the backend")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", w.Code)
	}
	if gotErr != ErrNilTarget {
		t.Fatalf("expected ErrNilTarget, got %v", gotErr)
	}
}

// --- Construction refuses unusable upstreams at startup ---

func TestNewReverseProxyEnforcer_RejectsBadTargets(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr error
	}{
		{"empty host", "http://", ErrInvalidTarget},
		{"unsupported scheme file", "file:///etc/passwd", ErrInvalidTarget},
		{"unsupported scheme gopher", "gopher://localhost:70", ErrInvalidTarget},
		{"no scheme", "localhost:9090", ErrInvalidTarget},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			if err != nil {
				return // unparseable is also a rejection
			}
			if _, err := NewReverseProxyEnforcer(u); err == nil {
				t.Fatalf("expected construction to fail for %q, it succeeded", tc.rawURL)
			}
		})
	}

	if _, err := NewReverseProxyEnforcer(nil); err != ErrNilTarget {
		t.Fatalf("expected ErrNilTarget for nil target, got %v", err)
	}
}

// --- Request integrity through the proxy ---

func TestEnforce_ForwardsBodyIntact(t *testing.T) {
	backend, rec := newBackend(t)
	enforcer, target := newEnforcerFor(t, backend.URL)

	payload := []byte(`{"identity_ref":"agent://finance-bot-01","operation":"GET"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/action", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	if err := enforcer.Enforce(w, req, true, target); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(rec.lastBody, payload) {
		t.Fatalf("backend received a different body.\n want: %s\n got:  %s", payload, rec.lastBody)
	}
}

func TestEnforce_StripsCallerSuppliedAetherHeaders(t *testing.T) {
	backend, rec := newBackend(t)
	enforcer, target := newEnforcerFor(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/v1/action", nil)
	req.Header.Set("X-Aether-Decision", "allow-i-promise")
	req.Header.Set("X-Aether-Identity", "agent://admin")
	w := httptest.NewRecorder()

	if err := enforcer.Enforce(w, req, true, target); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := rec.lastHeaders.Get("X-Aether-Identity"); got != "" {
		t.Fatalf("caller-supplied X-Aether-Identity survived to the backend: %q", got)
	}
	if got := rec.lastHeaders.Get("X-Aether-Decision"); got != "allow" {
		t.Fatalf("expected gateway-set decision header 'allow', got %q", got)
	}
}

func TestEnforce_UsesUpstreamHostHeader(t *testing.T) {
	backend, rec := newBackend(t)
	enforcer, target := newEnforcerFor(t, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/v1/action", nil)
	req.Host = "attacker-controlled.example.com"
	w := httptest.NewRecorder()

	if err := enforcer.Enforce(w, req, true, target); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.lastHost == "attacker-controlled.example.com" {
		t.Fatal("caller-supplied Host header was forwarded to the backend")
	}
	if rec.lastHost != target.Host {
		t.Fatalf("expected Host %q at backend, got %q", target.Host, rec.lastHost)
	}
}

// --- Fail closed when the upstream is gone ---

func TestEnforce_DeadUpstreamReturns502NotSuccess(t *testing.T) {
	backend, _ := newBackend(t)
	enforcer, target := newEnforcerFor(t, backend.URL)
	backend.Close() // upstream is now unreachable

	req := httptest.NewRequest(http.MethodGet, "/v1/action", nil)
	w := httptest.NewRecorder()

	enforcer.Enforce(w, req, true, target)

	if w.Code == http.StatusOK {
		t.Fatal("FAIL OPEN: a dead upstream produced a 200 response")
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d", w.Code)
	}
}
