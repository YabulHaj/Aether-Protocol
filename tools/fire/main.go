package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	fmt.Println("--- 1. FIRING ALLOWED TEST ---")
	sendRequest("Bearer mock-token-finance-bot")

	fmt.Println("\nWaiting 2 seconds...")
	time.Sleep(2 * time.Second)

	fmt.Println("\n--- 2. FIRING BLOCKED TEST ---")
	sendRequest("Bearer bad-hacker-token")
}

func sendRequest(token string) {
	now := time.Now().UTC()
	payload := fmt.Sprintf(`{
		"identity_ref": "agent://finance-bot-01",
		"intent": "summarize_invoice",
		"capability": "read:invoices",
		"target_resource": "invoice/12345",
		"operation": "GET",
		"audience": "aether-gateway",
		"nonce_id": "nonce-live-test-%d",
		"payload_hash": "sha256:deadbeef",
		"issued_at": "%s",
		"expiry": "%s"
	}`, now.UnixNano(), now.Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339))

	req, _ := http.NewRequest("POST", "http://localhost:8080/v1/action", bytes.NewBuffer([]byte(payload)))
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Failed to connect:", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Gateway Status: %s\nGateway Response: %s\n", resp.Status, string(body))
}
