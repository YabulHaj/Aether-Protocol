package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSSE_EventsStream_AllowedAndRejected(t *testing.T) {
	// 1. Start the existing test server architecture
	srv, backend, _, _ := newTestServer(t)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	// 2. Connect an HTTP client to the SSE endpoint
	req, _ := http.NewRequest("GET", ts.URL+"/v1/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to connect to SSE stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for SSE, got %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)

	// Helper to fire action requests
	sendAction := func(token string) int {
		now := time.Now().UTC()
		body := fmt.Sprintf(`{
			"identity_ref": "agent://finance-bot-01",
			"intent": "summarize",
			"capability": "read:invoices",
			"target_resource": "invoice/12345",
			"operation": "GET",
			"audience": "aether-gateway",
			"nonce_id": "nonce-sse-test-%d",
			"payload_hash": "sha256:deadbeef",
			"issued_at": "%s",
			"expiry": "%s"
		}`, now.UnixNano(), now.Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339))

		actReq, _ := http.NewRequest("POST", ts.URL+"/v1/action", strings.NewReader(body))
		actReq.Header.Set("Authorization", token)
		actReq.Header.Set("Content-Type", "application/json")

		actResp, err := http.DefaultClient.Do(actReq)
		if err != nil {
			t.Fatalf("Failed to execute action request: %v", err)
		}
		defer actResp.Body.Close()
		return actResp.StatusCode
	}

	// Helper to wait for and parse the next SSE data frame
	readEvent := func() map[string]interface{} {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed reading SSE stream: %v", err)
			}
			if strings.HasPrefix(line, "data: ") {
				dataStr := strings.TrimPrefix(line, "data: ")
				var ev map[string]interface{}
				if err := json.Unmarshal([]byte(dataStr), &ev); err != nil {
					t.Fatalf("Failed to decode SSE JSON: %v", err)
				}
				return ev
			}
		}
	}

	// Give the Broker a fraction of a second to register our subscription
	time.Sleep(100 * time.Millisecond)

	// 3. Fire an ALLOWED request
	status1 := sendAction(validAuthHeader) // Uses valid token from main_test.go
	if status1 != http.StatusOK {
		t.Fatalf("Expected 200 OK action, got %d", status1)
	}

	ev1 := readEvent()
	if ev1["identity"] != "agent://finance-bot-01" {
		t.Errorf("Expected identity agent://finance-bot-01, got %v", ev1["identity"])
	}
	if ev1["allowed"] != true {
		t.Errorf("Expected allowed=true for first event")
	}
	if ev1["hash"] == "" || ev1["hash"] == nil {
		t.Errorf("Expected non-empty tamper hash")
	}
	if backend.hitCount() != 1 {
		t.Errorf("Expected backend hits=1, got %d", backend.hitCount())
	}

	// 4. Fire a BLOCKED request
	status2 := sendAction("Bearer dev-invalid-token")
	if status2 != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for bad token, got %d", status2)
	}

	ev2 := readEvent()
	if ev2["allowed"] != false {
		t.Errorf("Expected allowed=false for second event")
	}
	if ev2["reason"] != "IDENTITY_INVALID" {
		t.Errorf("Expected reason IDENTITY_INVALID, got %v", ev2["reason"])
	}
	if backend.hitCount() != 1 {
		t.Errorf("Expected backend hits to remain exactly 1, got %d", backend.hitCount())
	}
}
