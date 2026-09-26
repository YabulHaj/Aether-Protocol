package identity

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var (
	ErrMissingAudience        = errors.New("identity(spiffe): missing expected audience")
	ErrNoCredentialPresented  = errors.New("identity(spiffe): no bearer token or mTLS client certificate presented")
	ErrJWTValidationFailed    = errors.New("identity(spiffe): jwt-svid validation failed")
	ErrX509IDExtractionFailed = errors.New("identity(spiffe): could not extract spiffe id from peer certificate")
	ErrWrongTrustDomain       = errors.New("identity(spiffe): spiffe id is not in the configured trust domain")
	ErrWorkloadAPIUnreachable = errors.New("identity(spiffe): could not reach the spiffe workload api")
)

// --- Thin, isolated wrappers around real go-spiffe/v2 calls ---
//
// Every actual call into the go-spiffe library lives in exactly one of
// the three tiny types below. If go-spiffe's real API differs slightly
// from what's written here, the compile error points at one of these
// three spots -- not scattered through business logic.

// workloadAPIConnector abstracts connecting to a local SPIRE agent via
// the SPIFFE Workload API to obtain a JWT trust bundle. Production
// uses realWorkloadAPIConnector; tests use a fake, so spiffe_test.go
// never needs a live SPIRE daemon.
type workloadAPIConnector interface {
	Connect(ctx context.Context) (jwtbundle.Source, error)
}

type realWorkloadAPIConnector struct{}

// Connect is the ONLY line in this file that attempts a real
// connection to a SPIRE agent. It blocks until either a trust bundle
// arrives or ctx's deadline passes.
func (realWorkloadAPIConnector) Connect(ctx context.Context) (jwtbundle.Source, error) {
	return workloadapi.NewJWTSource(ctx)
}

type jwtSVIDValidator interface {
	ParseAndValidate(token string, bundle jwtbundle.Source, audience []string) (*jwtsvid.SVID, error)
}

type realJWTSVIDValidator struct{}

func (realJWTSVIDValidator) ParseAndValidate(token string, bundle jwtbundle.Source, audience []string) (*jwtsvid.SVID, error) {
	return jwtsvid.ParseAndValidate(token, bundle, audience)
}

type x509SVIDExtractor interface {
	IDFromCert(cert *x509.Certificate) (spiffeid.ID, error)
}

type realX509SVIDExtractor struct{}

func (realX509SVIDExtractor) IDFromCert(cert *x509.Certificate) (spiffeid.ID, error) {
	return x509svid.IDFromCert(cert)
}

// SpiffeIdentityProvider verifies caller identity using SPIFFE
// (https://spiffe.io) -- cryptographic workload identity -- instead of
// Day 5's hardcoded token lookup table. An identity is only trusted
// after a real check:
//   - a JWT-SVID bearer token, signature-verified against a trust
//     bundle fetched LIVE from the local SPIRE agent, or
//   - an X.509-SVID presented during mutual TLS, whose certificate
//     chain must already have been verified during the TLS handshake
//     itself -- see the IMPORTANT note on Verify.
type SpiffeIdentityProvider struct {
	trustDomain   spiffeid.TrustDomain
	audience      []string
	jwtBundle     jwtbundle.Source
	jwtValidator  jwtSVIDValidator
	x509Extractor x509SVIDExtractor
}

// NewSpiffeIdentityProvider builds a real SPIFFE identity provider by
// connecting to the local SPIFFE Workload API.
//
// THIS CALL BLOCKS while it attempts that connection, up to whatever
// deadline ctx carries. If the Workload API is unreachable -- no
// SPIRE agent running, wrong socket path, agent hasn't issued a
// bundle yet, anything -- this returns a non-nil error and builds
// NOTHING.
//
// ZERO SILENT FALLBACKS: there is deliberately no fallback logic
// inside this function. The caller (cmd/main.go) decides what
// "construction failed" means for Aether as a whole -- and that
// decision is: refuse to start, never quietly substitute a weaker
// identity provider.
//
// Pass connector as nil in production to use the real Workload API.
// Tests pass a fake for deterministic success/failure without a live
// SPIRE daemon.
func NewSpiffeIdentityProvider(ctx context.Context, trustDomainName string, audience []string, connector workloadAPIConnector) (*SpiffeIdentityProvider, error) {
	if len(audience) == 0 {
		return nil, ErrMissingAudience
	}
	td, err := spiffeid.TrustDomainFromString(trustDomainName)
	if err != nil {
		return nil, err
	}
	if connector == nil {
		connector = realWorkloadAPIConnector{}
	}

	bundle, err := connector.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWorkloadAPIUnreachable, err)
	}

	return &SpiffeIdentityProvider{
		trustDomain:   td,
		audience:      audience,
		jwtBundle:     bundle,
		jwtValidator:  realJWTSVIDValidator{},
		x509Extractor: realX509SVIDExtractor{},
	}, nil
}

// Close releases the underlying Workload API connection, if the
// connected source supports it. Safe to call even if it doesn't.
func (p *SpiffeIdentityProvider) Close() error {
	if closer, ok := p.jwtBundle.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// Verify implements identity.IdentityProvider.
//
// If a caller presents BOTH a bearer token and a client certificate,
// the JWT path is checked first and wins -- deliberate and tested
// (TestVerify_JWTTakesPrecedenceOverMTLSWhenBothPresent), not an
// accident of code order.
//
// IMPORTANT about the mTLS path: this method only EXTRACTS the SPIFFE
// ID already present on an incoming request's peer certificate
// (r.TLS.PeerCertificates). It does NOT itself perform certificate
// chain verification -- that must happen during the TLS handshake, via
// a tls.Config built with go-spiffe's tlsconfig.MTLSServerConfig
// against a trust bundle. Aether does not currently terminate TLS at
// all (see known limitations), so this code path is real and tested
// but cannot yet be reached by an actual request.
func (p *SpiffeIdentityProvider) Verify(r *http.Request) (string, error) {
	if token := bearerToken(r); token != "" {
		return p.verifyJWTSVID(token)
	}
	if cert := peerLeafCert(r); cert != nil {
		return p.verifyX509SVID(cert)
	}
	return "", ErrNoCredentialPresented
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func peerLeafCert(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

func (p *SpiffeIdentityProvider) verifyJWTSVID(token string) (string, error) {
	svid, err := p.jwtValidator.ParseAndValidate(token, p.jwtBundle, p.audience)
	if err != nil {
		// NOTE: this collapses every validation failure -- expired,
		// tampered signature, wrong audience, malformed token -- into
		// one error. This adapter does not claim to distinguish WHICH
		// kind of failure occurred, only THAT one did. See known
		// limitations.
		return "", ErrJWTValidationFailed
	}
	if svid.ID.TrustDomain().String() != p.trustDomain.String() {
		return "", ErrWrongTrustDomain
	}
	return svid.ID.String(), nil
}

func (p *SpiffeIdentityProvider) verifyX509SVID(cert *x509.Certificate) (string, error) {
	id, err := p.x509Extractor.IDFromCert(cert)
	if err != nil {
		return "", ErrX509IDExtractionFailed
	}
	if id.TrustDomain().String() != p.trustDomain.String() {
		return "", ErrWrongTrustDomain
	}
	return id.String(), nil
}
