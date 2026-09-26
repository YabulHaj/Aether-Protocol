package evidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLog_ProducesVerifiableRecord(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStructuredEvidenceLogger(&buf)

	err := logger.Log(EvidenceRecord{
		NonceID:        "nonce-1",
		IdentityRef:    "agent://finance-bot",
		Capability:     "read",
		TargetResource: "/api/orders",
		Operation:      "GET",
		Allowed:        true,
		RuleID:         "rule-1",
		ReasonCode:     ReasonAllow,
	})
	if err != nil {
		t.Fatalf("log failed: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	var parsed EvidenceRecord
	if err := json.Unmarshal([]byte(line), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed.TamperHash == "" {
		t.Fatal("TamperHash must be populated")
	}
	if !VerifyRecordHash(parsed) {
		t.Fatal("VerifyRecordHash must return true on freshly logged record")
	}
}

func TestVerifyRecordHash_DetectsMutation(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStructuredEvidenceLogger(&buf)
	_ = logger.Log(EvidenceRecord{NonceID: "1", IdentityRef: "A", Allowed: true})

	var rec EvidenceRecord
	json.Unmarshal(buf.Bytes(), &rec)

	mutated := rec
	mutated.Allowed = false
	if VerifyRecordHash(mutated) {
		t.Fatal("SECURITY REGRESSION: mutated record must not verify")
	}
}

func TestEvidence_UniqueIDsAcrossInstances(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	l1 := NewStructuredEvidenceLogger(&buf1)
	l2 := NewStructuredEvidenceLogger(&buf2)

	rec1, err1 := l1.LogAndReturn(EvidenceRecord{IdentityRef: "agent-1", ReasonCode: ReasonAllow})
	if err1 != nil {
		t.Fatalf("l1 failed: %v", err1)
	}
	rec2, err2 := l2.LogAndReturn(EvidenceRecord{IdentityRef: "agent-1", ReasonCode: ReasonAllow})
	if err2 != nil {
		t.Fatalf("l2 failed: %v", err2)
	}

	if rec1.RecordID == rec2.RecordID {
		t.Fatalf("SECURITY REGRESSION: distinct logger instances generated identical RecordID %q", rec1.RecordID)
	}
	if !strings.HasPrefix(rec1.RecordID, "AET-EV-") || !strings.HasPrefix(rec2.RecordID, "AET-EV-") {
		t.Fatalf("unexpected record ID prefix: %s / %s", rec1.RecordID, rec2.RecordID)
	}
}

func TestEvidence_TamperHashIncludesIntentAndPayloadHash(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStructuredEvidenceLogger(&buf)

	rec, err := logger.LogAndReturn(EvidenceRecord{
		IdentityRef: "agent-1",
		Intent:      "read_invoice",
		PayloadHash: "sha256:abcd",
		ReasonCode:  ReasonAllow,
	})
	if err != nil {
		t.Fatalf("log failed: %v", err)
	}

	// Mutate intent
	tamperedIntent := rec
	tamperedIntent.Intent = "escalate_privilege"
	if VerifyRecordHash(tamperedIntent) {
		t.Fatal("SECURITY REGRESSION: tampering with Intent must invalidate TamperHash")
	}

	// Mutate payload hash
	tamperedPayload := rec
	tamperedPayload.PayloadHash = "sha256:1111"
	if VerifyRecordHash(tamperedPayload) {
		t.Fatal("SECURITY REGRESSION: tampering with PayloadHash must invalidate TamperHash")
	}
}
