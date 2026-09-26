package identity

import (
	"errors"
	"net/http"
	"strings"
)

// IdentityProvider is the contract for verifying WHO is making a
// request. It looks only at the raw *http.Request (its headers) --
// never at the JSON body -- and returns the identity that request has
// PROVEN itself to be, or an error if it proved nothing.
//
// This is deliberately separate from the envelope's own "identity_ref"
// field. That field is just text the caller typed into JSON -- anyone
// can write anything there. Verify's job is to produce an identity the
// caller cannot simply type: something derived from a credential. The
// handler in cmd/main.go then checks that the two agree.
type IdentityProvider interface {
	Verify(r *http.Request) (string, error)
}

var (
	ErrMissingAuthHeader   = errors.New("identity: missing Authorization header")
	ErrMalformedAuthHeader = errors.New("identity: Authorization header is not a well-formed Bearer token")
	ErrUnknownToken        = errors.New("identity: token is not recognized")
)

// MockIdentityProvider is a LOCAL-TESTING-ONLY stand-in for real
// identity verification.
//
// *** THIS IS NOT REAL SECURITY. READ THIS BEFORE USING IT ANYWHERE
// EXCEPT YOUR OWN LOCAL MACHINE. ***
//
// It checks a request's Authorization header against a small, static,
// HARDCODED map of token strings to identity strings, defined right
// below in this file. There is:
//   - no cryptography (no signature, no certificate, no key)
//   - no expiry on the tokens themselves
//   - no revocation
//   - the "secret" tokens are plain text sitting in version control
//
// Anyone who reads this source file can impersonate any identity in
// the map. This exists ONLY so Days 5+ can build and test "verified
// identity must match claimed identity" logic before a real identity
// system exists.
//
// Day 6's job is to replace this entirely with genuine SPIFFE/SPIRE
// identity: cryptographically signed documents (SVIDs) issued over
// mutual TLS, verified against a trusted root -- not a lookup table.
type MockIdentityProvider struct {
	tokenToIdentity map[string]string
}

// NewMockIdentityProvider builds the mock with a fixed, small set of
// obviously-fake test tokens, so they're never mistaken for real
// credentials.
func NewMockIdentityProvider() *MockIdentityProvider {
	return &MockIdentityProvider{
		tokenToIdentity: map[string]string{
			"mock-token-finance-bot": "agent://finance-bot-01",
			"mock-token-hr-bot":      "agent://hr-bot-01",
		},
	}
}

// Verify reads the Authorization header, requires the exact form
// "Bearer <token>", and looks the token up in the local map. Matching
// is exact and case-sensitive -- no normalization, no partial match.
func (m *MockIdentityProvider) Verify(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", ErrMissingAuthHeader
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", ErrMalformedAuthHeader
	}

	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", ErrMalformedAuthHeader
	}

	identity, ok := m.tokenToIdentity[token]
	if !ok {
		return "", ErrUnknownToken
	}

	return identity, nil
}
