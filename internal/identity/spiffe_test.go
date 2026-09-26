package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// --- Test doubles: simulate SPIFFE without a live SPIRE daemon ---

type fakeWorkloadAPIConnector struct {
	bundle jwtbundle.Source
	err    error
}

func (f fakeWorkloadAPIConnector) Connect(ctx context.Context) (jwtbundle.Source, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.bundle, nil
}

type fakeJWTBundleSource struct{}

func (fakeJWTBundleSource) GetJWTBundleForTrustDomain(td spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	return jwtbundle.New(td), nil
}

type fakeJWTValidator struct {
	svid *jwtsvid.SVID
	err  error
}

func (f *fakeJWTValidator) ParseAndValidate(token string, bundle jwtbundle.Source, audience []string) (*jwtsvid.SVID, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.svid, nil
}

type fakeX509Extractor struct {
	id  spiffeid.ID
	err error
}

func (f fakeX509Extractor) IDFromCert(cert *x509.Certificate) (spiffeid.ID, error) {
	if f.err != nil {
		return spiffeid.ID{}, f.err
	}
	return f.id, nil
}

type hangingConnector struct{}

func (hangingConnector) Connect(ctx context.Context) (jwtbundle.Source, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func mustID(t *testing.T, s string) spiffeid.ID {
	t.Helper()
	id, err := spiffeid.FromString(s)
	if err != nil {
		t.Fatalf("could not build spiffe id %q: %v", s, err)
	}
	return id
}

func newTestProvider(t *testing.T, validator jwtSVIDValidator) *SpiffeIdentityProvider {
	t.Helper()
	p, err := NewSpiffeIdentityProvider(
		context.Background(),
		"aether.example.org",
		[]string{"aether-gateway"},
		fakeWorkloadAPIConnector{bundle: fakeJWTBundleSource{}},
	)
	if err != nil {
		t.Fatalf("could not build provider: %v", err)
	}
	p.jwtValidator = validator
	return p
}

// --- Construction: the ZERO SILENT FALLBACKS proof, at the unit level ---

func TestNewSpiffeIdentityProvider_FailsClosedWhenWorkloadAPIUnreachable(t *testing.T) {
	connector := fakeWorkloadAPIConnector{err: errors.New("simulated: connect: no such file or directory")}

	_, err := NewSpiffeIdentityProvider(context.Background(), "aether.example.org", []string{"aether-gateway"}, connector)

	if err == nil {
		t.Fatal("SECURITY REGRESSION: expected construction to fail when the Workload API is unreachable, got nil error")
	}
	if !errors.Is(err, ErrWorkloadAPIUnreachable) {
		t.Fatalf("expected error to wrap ErrWorkloadAPIUnreachable, got %v", err)
	}
}

func TestNewSpiffeIdentityProvider_SucceedsWhenWorkloadAPIReachable(t *testing.T) {
	connector := fakeWorkloadAPIConnector{bundle: fakeJWTBundleSource{}}

	provider, err := NewSpiffeIdentityProvider(context.Background(), "aether.example.org", []string{"aether-gateway"}, connector)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if provider == nil {
		t.Fatal("expected a non-nil provider")
	}
}

func TestNewSpiffeIdentityProvider_RejectsMissingAudience(t *testing.T) {
	_, err := NewSpiffeIdentityProvider(context.Background(), "aether.example.org", nil, fakeWorkloadAPIConnector{bundle: fakeJWTBundleSource{}})

	if err != ErrMissingAudience {
		t.Fatalf("expected ErrMissingAudience, got %v", err)
	}
}

func TestNewSpiffeIdentityProvider_RejectsInvalidTrustDomain(t *testing.T) {
	_, err := NewSpiffeIdentityProvider(context.Background(), "not a valid trust domain!!", []string{"aether-gateway"}, fakeWorkloadAPIConnector{bundle: fakeJWTBundleSource{}})

	if err == nil {
		t.Fatal("expected an error for an invalid trust domain string, got nil")
	}
}

func TestNewSpiffeIdentityProvider_RespectsContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := NewSpiffeIdentityProvider(ctx, "aether.example.org", []string{"aether-gateway"}, hangingConnector{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the context deadline is exceeded")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("construction took %v -- context timeout was not respected", elapsed)
	}
}

// --- JWT-SVID validation path ---

func TestVerify_JWT_ValidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer some-jwt-svid-token")

	wantID := mustID(t, "spiffe://aether.example.org/finance-bot-01")
	provider := newTestProvider(t, &fakeJWTValidator{svid: &jwtsvid.SVID{ID: wantID}})

	got, err := provider.Verify(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != wantID.String() {
		t.Fatalf("expected identity %q, got %q", wantID.String(), got)
	}
}

func TestVerify_JWT_MalformedTokenRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-jwt-at-all")

	provider := newTestProvider(t, &fakeJWTValidator{err: errors.New("simulated: token is malformed")})

	_, err := provider.Verify(req)
	if err != ErrJWTValidationFailed {
		t.Fatalf("expected ErrJWTValidationFailed, got %v", err)
	}
}

func TestVerify_JWT_ExpiredTokenRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer an-expired-jwt-svid-token")

	provider := newTestProvider(t, &fakeJWTValidator{err: errors.New("simulated: token is expired")})

	_, err := provider.Verify(req)
	if err != ErrJWTValidationFailed {
		t.Fatalf("expected ErrJWTValidationFailed for an expired token, got %v", err)
	}
}

func TestVerify_JWT_WrongTrustDomain(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer token-from-another-trust-domain")

	foreignID := mustID(t, "spiffe://someone-elses-org.example/some-service")
	provider := newTestProvider(t, &fakeJWTValidator{svid: &jwtsvid.SVID{ID: foreignID}})

	_, err := provider.Verify(req)
	if err != ErrWrongTrustDomain {
		t.Fatalf("expected ErrWrongTrustDomain, got %v", err)
	}
}

// --- mTLS / X.509-SVID path ---

func TestVerify_MTLS_ValidCertificate(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}

	wantID := mustID(t, "spiffe://aether.example.org/finance-bot-01")
	provider := newTestProvider(t, &fakeJWTValidator{})
	provider.x509Extractor = fakeX509Extractor{id: wantID}

	got, err := provider.Verify(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != wantID.String() {
		t.Fatalf("expected identity %q, got %q", wantID.String(), got)
	}
}

func TestVerify_MTLS_MalformedCertificateRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}

	provider := newTestProvider(t, &fakeJWTValidator{})
	provider.x509Extractor = fakeX509Extractor{err: errors.New("simulated: no spiffe URI SAN present")}

	_, err := provider.Verify(req)
	if err != ErrX509IDExtractionFailed {
		t.Fatalf("expected ErrX509IDExtractionFailed, got %v", err)
	}
}

func TestVerify_MTLS_WrongTrustDomain(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}

	foreignID := mustID(t, "spiffe://someone-elses-org.example/some-service")
	provider := newTestProvider(t, &fakeJWTValidator{})
	provider.x509Extractor = fakeX509Extractor{id: foreignID}

	_, err := provider.Verify(req)
	if err != ErrWrongTrustDomain {
		t.Fatalf("expected ErrWrongTrustDomain, got %v", err)
	}
}

// --- No credential presented ---

func TestVerify_NoCredentialPresented(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)

	provider := newTestProvider(t, &fakeJWTValidator{})

	_, err := provider.Verify(req)
	if err != ErrNoCredentialPresented {
		t.Fatalf("expected ErrNoCredentialPresented, got %v", err)
	}
}

func TestVerify_MalformedAuthHeaderFallsThroughToNoCredential(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "not-a-bearer-token")

	provider := newTestProvider(t, &fakeJWTValidator{})

	_, err := provider.Verify(req)
	if err != ErrNoCredentialPresented {
		t.Fatalf("expected ErrNoCredentialPresented for a header with no Bearer prefix, got %v", err)
	}
}

// --- Precedence ---

func TestVerify_JWTTakesPrecedenceOverMTLSWhenBothPresent(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer some-jwt-svid-token")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}

	jwtID := mustID(t, "spiffe://aether.example.org/via-jwt")
	mtlsID := mustID(t, "spiffe://aether.example.org/via-mtls")

	provider := newTestProvider(t, &fakeJWTValidator{svid: &jwtsvid.SVID{ID: jwtID}})
	provider.x509Extractor = fakeX509Extractor{id: mtlsID}

	got, err := provider.Verify(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != jwtID.String() {
		t.Fatalf("expected the JWT identity to win, got %q", got)
	}
}
