package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aether-protocol/internal/envelope"
	"aether-protocol/internal/telemetry"
)

func TestTelemetry_DeliveryAndIsolation(t *testing.T) {
	srv, backend, registry, _ := newTestServer(t)
	gateway := httptest.NewServer(srv.Routes())
	defer gateway.Close()

	clientChan := srv.Telemetry.Subscribe()
	defer srv.Telemetry.Unsubscribe(clientChan)

	client := &http.Client{Timeout: 2 * time.Second}

	t.Run("Test 1: Allowed request delivers complete telemetry", func(t *testing.T) {
		body := freshEnvelopeJSON(t, nil)

		req, err := http.NewRequest(
			http.MethodPost,
			gateway.URL+"/v1/action",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatalf("could not create request: %v", err)
		}

		req.Header.Set("Authorization", validAuthHeader)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		select {
		case ev := <-clientChan:
			if ev.Status != http.StatusOK {
				t.Fatalf("expected telemetry status 200, got %d", ev.Status)
			}
			if ev.Reason != "allow_matched_rule" {
				t.Fatalf("expected allow_matched_rule, got %q", ev.Reason)
			}
			if ev.Hash == "" {
				t.Fatal("telemetry event missing tamper hash")
			}
			if !ev.Allowed {
				t.Fatal("expected telemetry Allowed=true")
			}
			if ev.Identity != "agent://finance-bot-01" {
				t.Fatalf("unexpected identity: %q", ev.Identity)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for allowed telemetry event")
		}
	})

	t.Run("Test 2: Revoked request delivers pre-policy telemetry", func(t *testing.T) {
		registry.RevokeNonce("revoked-nonce-123")

		body := freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
			e.NonceID = "revoked-nonce-123"
		})

		req, err := http.NewRequest(
			http.MethodPost,
			gateway.URL+"/v1/action",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatalf("could not create request: %v", err)
		}

		req.Header.Set("Authorization", validAuthHeader)
		req.Header.Set("Content-Type", "application/json")

		beforeHits := backend.hitCount()

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
		}

		if backend.hitCount() != beforeHits {
			t.Fatalf("expected zero backend hits for revoked request")
		}

		select {
		case ev := <-clientChan:
			if ev.Status != http.StatusForbidden {
				t.Fatalf("expected telemetry status 403, got %d", ev.Status)
			}
			if ev.Reason != "REVOKED" {
				t.Fatalf("expected REVOKED, got %q", ev.Reason)
			}
			if ev.Allowed {
				t.Fatal("expected telemetry Allowed=false")
			}
			if ev.Hash == "" {
				t.Fatal("pre-policy telemetry event missing tamper hash")
			}
			if ev.Identity != "agent://finance-bot-01" {
				t.Fatalf("unexpected identity: %q", ev.Identity)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for revoked telemetry event")
		}
	})

	t.Run("Test 3: Full subscriber buffer does not block Broadcast", func(t *testing.T) {
		for i := 0; i < cap(clientChan); i++ {
			select {
			case clientChan <- telemetry.Event{}:
			default:
			}
		}

		done := make(chan struct{})

		go func() {
			srv.Telemetry.Broadcast(telemetry.Event{
				Reason: "dropped_event",
			})
			close(done)
		}()

		select {
		case <-done:
			// Broadcast returned while subscriber was full.
		case <-time.After(500 * time.Millisecond):
			t.Fatal("telemetry Broadcast blocked on a full subscriber")
		}
	})

	t.Run("Test 4: Gateway request succeeds despite saturated subscriber", func(t *testing.T) {
		body := freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
			e.NonceID = "fresh-nonce-test-4"
		})

		req, err := http.NewRequest(
			http.MethodPost,
			gateway.URL+"/v1/action",
			bytes.NewReader(body),
		)
		if err != nil {
			t.Fatalf("could not create request: %v", err)
		}

		req.Header.Set("Authorization", validAuthHeader)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("gateway request failed when subscriber was saturated: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf(
				"gateway failed when UI was stalled: expected 200, got %d",
				resp.StatusCode,
			)
		}

		// Empty the test subscriber before teardown.
		for len(clientChan) > 0 {
			<-clientChan
		}
	})
}
