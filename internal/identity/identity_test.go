package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerify_MissingHeader(t *testing.T) {
	provider := NewMockIdentityProvider()
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)

	_, err := provider.Verify(req)

	if err != ErrMissingAuthHeader {
		t.Fatalf("expected ErrMissingAuthHeader, got %v", err)
	}
}

func TestVerify_MalformedHeader_NoBearerPrefix(t *testing.T) {
	provider := NewMockIdentityProvider()
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "mock-token-finance-bot") // missing "Bearer " prefix

	_, err := provider.Verify(req)

	if err != ErrMalformedAuthHeader {
		t.Fatalf("expected ErrMalformedAuthHeader, got %v", err)
	}
}

func TestVerify_MalformedHeader_EmptyToken(t *testing.T) {
	provider := NewMockIdentityProvider()
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer ")

	_, err := provider.Verify(req)

	if err != ErrMalformedAuthHeader {
		t.Fatalf("expected ErrMalformedAuthHeader, got %v", err)
	}
}

func TestVerify_UnknownToken(t *testing.T) {
	provider := NewMockIdentityProvider()
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer mock-token-does-not-exist")

	_, err := provider.Verify(req)

	if err != ErrUnknownToken {
		t.Fatalf("expected ErrUnknownToken, got %v", err)
	}
}

func TestVerify_ValidToken(t *testing.T) {
	provider := NewMockIdentityProvider()
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer mock-token-finance-bot")

	identity, err := provider.Verify(req)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if identity != "agent://finance-bot-01" {
		t.Fatalf("expected identity agent://finance-bot-01, got %q", identity)
	}
}

func TestVerify_ValidToken_SecondIdentity(t *testing.T) {
	provider := NewMockIdentityProvider()
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer mock-token-hr-bot")

	identity, err := provider.Verify(req)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if identity != "agent://hr-bot-01" {
		t.Fatalf("expected identity agent://hr-bot-01, got %q", identity)
	}
}

func TestVerify_TokenIsCaseSensitive(t *testing.T) {
	provider := NewMockIdentityProvider()
	req := httptest.NewRequest(http.MethodPost, "/v1/action", nil)
	req.Header.Set("Authorization", "Bearer Mock-Token-Finance-Bot")

	_, err := provider.Verify(req)

	if err != ErrUnknownToken {
		t.Fatalf("expected ErrUnknownToken (tokens are case-sensitive), got %v", err)
	}
}
