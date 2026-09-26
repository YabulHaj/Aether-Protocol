package envelope

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ActionEnvelope is the standard wrapper Aether puts around every
// incoming agent action before any policy/enforcement/evidence logic
// looks at it. Each field answers one question a security reviewer
// would ask about a request:
type ActionEnvelope struct {
	IdentityRef    string            `json:"identity_ref"`          // WHO is asking? (agent identity)
	Intent         string            `json:"intent"`                // WHY are they asking? (stated purpose)
	Capability     string            `json:"capability"`            // WHAT permission class are they using?
	TargetResource string            `json:"target_resource"`       // WHAT are they acting on?
	Operation      string            `json:"operation"`             // WHAT verb/method (read, write, delete...)?
	Constraints    map[string]string `json:"constraints,omitempty"` // OPTIONAL extra limits (e.g. max_rows)
	Audience       string            `json:"audience"`              // WHO is this envelope meant for?
	IssuedAt       time.Time         `json:"issued_at"`             // WHEN was it created?
	Expiry         time.Time         `json:"expiry"`                // WHEN does it become invalid?
	NonceID        string            `json:"nonce_id"`              // UNIQUE id for this request
	PayloadHash    string            `json:"payload_hash"`          // fingerprint of the actual payload
	Payload        string            `json:"payload,omitempty"`     // OPTIONAL raw payload content to verify against PayloadHash
}

// Sentinel errors: one specific, named error per possible problem.
// Code that calls Validate() can check exactly which one occurred
// using errors.Is(err, envelope.ErrExpired) etc.
var (
	ErrMissingIdentityRef    = errors.New("envelope: missing identity_ref")
	ErrMissingIntent         = errors.New("envelope: missing intent")
	ErrMissingCapability     = errors.New("envelope: missing capability")
	ErrMissingTargetResource = errors.New("envelope: missing target_resource")
	ErrMissingOperation      = errors.New("envelope: missing operation")
	ErrMissingAudience       = errors.New("envelope: missing audience")
	ErrMissingNonceID        = errors.New("envelope: missing nonce_id")
	ErrMissingPayloadHash    = errors.New("envelope: missing payload_hash")
	ErrMissingIssuedAt       = errors.New("envelope: missing issued_at")
	ErrMissingExpiry         = errors.New("envelope: missing expiry")
	ErrExpiryBeforeIssuedAt  = errors.New("envelope: expiry must be after issued_at")
	ErrIssuedInFuture        = errors.New("envelope: issued_at is in the future")
	ErrExpired               = errors.New("envelope: expired")
	ErrPayloadHashMismatch   = errors.New("envelope: payload_hash does not match payload")
)

// ComputePayloadHash returns the canonical sha256:<hex> string for a byte payload.
func ComputePayloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("sha256:%x", sum)
}

// Validate checks that an envelope is complete and currently fresh.
//
// "now" is passed in rather than read from the system clock inside this
// function. That's the same "hand the ingredients in" pattern we used
// for Policy/Enforcement/Evidence on Day 1 — it means our tests can say
// "pretend it's exactly 12:00:00 on Jan 1" instead of depending on
// whatever time your computer's clock happens to show when you run
// `go test`, which would make tests unreliable.
//
// Validate stops and returns the FIRST problem it finds (fail-fast).
// It does not collect every problem at once — a possible improvement
// for a later day.
func (e *ActionEnvelope) Validate(now time.Time) error {
	if e.IdentityRef == "" {
		return ErrMissingIdentityRef
	}
	if e.Intent == "" {
		return ErrMissingIntent
	}
	if e.Capability == "" {
		return ErrMissingCapability
	}
	if e.TargetResource == "" {
		return ErrMissingTargetResource
	}
	if e.Operation == "" {
		return ErrMissingOperation
	}
	if e.Audience == "" {
		return ErrMissingAudience
	}
	if e.NonceID == "" {
		return ErrMissingNonceID
	}
	if e.PayloadHash == "" {
		return ErrMissingPayloadHash
	}
	if e.IssuedAt.IsZero() {
		return ErrMissingIssuedAt
	}
	if e.Expiry.IsZero() {
		return ErrMissingExpiry
	}
	if !e.Expiry.After(e.IssuedAt) {
		return ErrExpiryBeforeIssuedAt
	}
	if now.Before(e.IssuedAt) {
		return ErrIssuedInFuture
	}
	if now.After(e.Expiry) {
		return ErrExpired
	}
	if e.Payload != "" {
		hash := sha256.Sum256([]byte(e.Payload))
		hexHash := fmt.Sprintf("%x", hash)
		expectedWithPrefix := "sha256:" + hexHash
		cleanPayloadHash := strings.TrimPrefix(e.PayloadHash, "sha256:")
		if subtle.ConstantTimeCompare([]byte(cleanPayloadHash), []byte(hexHash)) != 1 &&
			subtle.ConstantTimeCompare([]byte(e.PayloadHash), []byte(expectedWithPrefix)) != 1 {
			return ErrPayloadHashMismatch
		}
	}
	return nil
}
