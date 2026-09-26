package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Reason codes for authorization and evidence decisions.
const (
	ReasonAllow            = "ALLOW"
	ReasonPolicyDeny       = "POLICY_DENY"
	ReasonRevoked          = "REVOKED"
	ReasonReplay           = "REPLAY_DETECTED"
	ReasonMalformed        = "MALFORMED"
	ReasonIdentityInvalid  = "IDENTITY_INVALID"
	ReasonIdentityMismatch = "IDENTITY_MISMATCH"
	ReasonMethodNotAllowed = "METHOD_NOT_ALLOWED"
	ReasonRequestTooLarge  = "REQUEST_TOO_LARGE"
	ReasonEvidenceFailure  = "EVIDENCE_FAILURE"
)

type EvidenceLogger interface {
	Log(record EvidenceRecord) error
}

// DetailedEvidenceLogger extends the existing EvidenceLogger contract
// without breaking existing implementations or callers.
type DetailedEvidenceLogger interface {
	EvidenceLogger
	LogAndReturn(record EvidenceRecord) (EvidenceRecord, error)
}

type EvidenceRecord struct {
	RecordID       string `json:"record_id"`
	Timestamp      string `json:"timestamp"`
	NonceID        string `json:"nonce_id,omitempty"`
	IdentityRef    string `json:"identity_ref"`
	Intent         string `json:"intent,omitempty"`
	Capability     string `json:"capability,omitempty"`
	TargetResource string `json:"target_resource,omitempty"`
	Operation      string `json:"operation,omitempty"`
	PayloadHash    string `json:"payload_hash,omitempty"`
	Allowed        bool   `json:"allowed"`
	RuleID         string `json:"rule_id,omitempty"`
	ReasonCode     string `json:"reason_code"`
	PolicyVersion  string `json:"policy_version,omitempty"`
	TamperHash     string `json:"tamper_hash"`
}

// computeTamperHash creates a deterministic SHA-256 hash over the
// canonical evidence fields. TamperHash itself is deliberately excluded.
func computeTamperHash(r EvidenceRecord) string {
	h := sha256.New()

	writeField := func(s string) {
		_, _ = fmt.Fprintf(h, "%d:", len(s))
		_, _ = io.WriteString(h, s)
	}

	writeField(r.RecordID)
	writeField(r.Timestamp)
	writeField(r.NonceID)
	writeField(r.IdentityRef)
	writeField(r.Intent)
	writeField(r.Capability)
	writeField(r.TargetResource)
	writeField(r.Operation)
	writeField(r.PayloadHash)
	writeField(fmt.Sprintf("%t", r.Allowed))
	writeField(r.RuleID)
	writeField(r.ReasonCode)
	writeField(r.PolicyVersion)

	return fmt.Sprintf("%x", h.Sum(nil))
}

// VerifyRecordHash recomputes the canonical record hash and compares it
// against the stored TamperHash using constant-time comparison.
func VerifyRecordHash(record EvidenceRecord) bool {
	expected := computeTamperHash(record)

	return subtle.ConstantTimeCompare(
		[]byte(expected),
		[]byte(record.TamperHash),
	) == 1
}

type StructuredEvidenceLogger struct {
	mu  sync.Mutex
	w   io.Writer
	seq uint64
}

func NewStructuredEvidenceLogger(w io.Writer) *StructuredEvidenceLogger {
	return &StructuredEvidenceLogger{
		w: w,
	}
}

// Log preserves the original EvidenceLogger interface.
func (l *StructuredEvidenceLogger) Log(record EvidenceRecord) error {
	_, err := l.LogAndReturn(record)
	return err
}

// LogAndReturn creates the complete evidence record, including RecordID,
// Timestamp, and TamperHash, and writes it as one NDJSON record.
func (l *StructuredEvidenceLogger) LogAndReturn(
	record EvidenceRecord,
) (EvidenceRecord, error) {
	if l == nil || l.w == nil {
		return record, fmt.Errorf("evidence logger not configured")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if record.RecordID == "" {
		l.seq++
		var rnd [4]byte
		_, _ = rand.Read(rnd[:])
		record.RecordID = fmt.Sprintf(
			"AET-EV-%d-%06d-%x",
			time.Now().UTC().Year(),
			l.seq,
			rnd,
		)
	}

	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	record.TamperHash = computeTamperHash(record)

	data, err := json.Marshal(record)
	if err != nil {
		return record, err
	}

	data = append(data, '\n')

	if _, err := l.w.Write(data); err != nil {
		return record, err
	}

	return record, nil
}
