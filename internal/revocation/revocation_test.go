package revocation

import (
	"sync"
	"testing"
)

func TestInMemoryRegistry_CombinedCheck(t *testing.T) {
	r := NewInMemoryRevocationRegistry()
	r.RevokeNonce("nonce-bad")

	if !r.IsRevoked("id-ok", "nonce-bad") {
		t.Fatal("SECURITY REGRESSION: combined check must report revoked when nonce is revoked")
	}
	if r.IsRevoked("id-ok", "nonce-ok") {
		t.Fatal("combined check must report not-revoked when neither is revoked")
	}

	r.RevokeIdentity("id-bad")
	if !r.IsRevoked("id-bad", "nonce-ok") {
		t.Fatal("SECURITY REGRESSION: combined check must report revoked when identity is revoked")
	}
}

func TestInMemoryRegistry_ConcurrentAccess(t *testing.T) {
	r := NewInMemoryRevocationRegistry()
	const workers, iters = 10, 1000

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				r.RevokeIdentity("id")
				r.RevokeNonce("nonce")
			}
		}()
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_ = r.IsRevoked("id", "nonce")
			}
		}()
	}
	wg.Wait()

	if !r.IsRevoked("id", "nonce") {
		t.Fatal("after concurrent writes, both must be revoked")
	}
}

func TestInMemoryRegistry_CheckAndConsumeNonce(t *testing.T) {
	r := NewInMemoryRevocationRegistry()

	// First use of fresh nonce must succeed
	if !r.CheckAndConsumeNonce("nonce-unique-1") {
		t.Fatal("first use of fresh nonce must return true")
	}

	// Immediate reuse of the same nonce must be rejected (Anti-Replay)
	if r.CheckAndConsumeNonce("nonce-unique-1") {
		t.Fatal("SECURITY REGRESSION: second use of same nonce must return false (replay detected)")
	}

	// Revoked nonce must not be consumable
	r.RevokeNonce("nonce-revoked-explicit")
	if r.CheckAndConsumeNonce("nonce-revoked-explicit") {
		t.Fatal("SECURITY REGRESSION: explicitly revoked nonce must not be consumable")
	}

	// Empty nonce must return false
	if r.CheckAndConsumeNonce("") {
		t.Fatal("empty nonce must return false")
	}
}

func TestInMemoryRegistry_ConcurrentCheckAndConsumeNonce(t *testing.T) {
	r := NewInMemoryRevocationRegistry()
	const targetNonce = "nonce-race-test"
	const competitors = 20

	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < competitors; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.CheckAndConsumeNonce(targetNonce) {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("SECURITY REGRESSION: exactly 1 competitor must consume the nonce, got %d", successCount)
	}
}
