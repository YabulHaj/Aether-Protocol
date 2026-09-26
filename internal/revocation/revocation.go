package revocation

import "sync"

// RevocationRegistry provides thread-safe instant revocation for identities and nonces,
// as well as one-time nonce consumption for anti-replay enforcement.
type RevocationRegistry interface {
	RevokeIdentity(id string)
	RevokeNonce(nonce string)
	IsIdentityRevoked(id string) bool
	IsNonceRevoked(nonce string) bool
	IsRevoked(identity, nonce string) bool
	CheckAndConsumeNonce(nonce string) bool
}

type InMemoryRevocationRegistry struct {
	mu             sync.RWMutex
	identities     map[string]struct{}
	nonces         map[string]struct{}
	consumedNonces map[string]struct{}
}

func NewInMemoryRevocationRegistry() *InMemoryRevocationRegistry {
	return &InMemoryRevocationRegistry{
		identities:     make(map[string]struct{}),
		nonces:         make(map[string]struct{}),
		consumedNonces: make(map[string]struct{}),
	}
}

func (r *InMemoryRevocationRegistry) RevokeIdentity(id string) {
	if id == "" {
		return
	}
	r.mu.Lock()
	r.identities[id] = struct{}{}
	r.mu.Unlock()
}

func (r *InMemoryRevocationRegistry) RevokeNonce(nonce string) {
	if nonce == "" {
		return
	}
	r.mu.Lock()
	r.nonces[nonce] = struct{}{}
	r.mu.Unlock()
}

func (r *InMemoryRevocationRegistry) IsIdentityRevoked(id string) bool {
	if id == "" {
		return false
	}
	r.mu.RLock()
	_, ok := r.identities[id]
	r.mu.RUnlock()
	return ok
}

func (r *InMemoryRevocationRegistry) IsNonceRevoked(nonce string) bool {
	if nonce == "" {
		return false
	}
	r.mu.RLock()
	_, ok := r.nonces[nonce]
	r.mu.RUnlock()
	return ok
}

// IsRevoked performs a single-lock combined check to prevent a TOCTOU race.
func (r *InMemoryRevocationRegistry) IsRevoked(identity, nonce string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if identity != "" {
		if _, ok := r.identities[identity]; ok {
			return true
		}
	}
	if nonce != "" {
		if _, ok := r.nonces[nonce]; ok {
			return true
		}
	}
	return false
}

// CheckAndConsumeNonce atomically verifies that a nonce has not been revoked
// and has not been previously consumed, marking it as consumed if fresh.
// Returns true if the nonce is fresh and now consumed; false if it was
// previously consumed (replay) or revoked.
func (r *InMemoryRevocationRegistry) CheckAndConsumeNonce(nonce string) bool {
	if nonce == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, revoked := r.nonces[nonce]; revoked {
		return false
	}
	if _, used := r.consumedNonces[nonce]; used {
		return false
	}
	r.consumedNonces[nonce] = struct{}{}
	return true
}
