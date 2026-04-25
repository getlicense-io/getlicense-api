package db

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Integration tests for RefreshTokenRepo. Gating mirrors policy_repo_test.go:
// `-short` skips, `make test-all` runs against the dev Postgres.
//
// Refresh tokens are GLOBAL (no RLS, see migration 010). The fixture
// seeds an identity + refresh_token row directly, runs the test, then
// deletes both unconditionally on cleanup. Unlike the per-tx fixtures
// in customer_repo_test.go, the concurrent-Consume test below needs
// each goroutine to acquire its own connection from the pool, so a
// shared rollback-only tx is not viable.

func TestRefreshTokenRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.RefreshTokenRepository = (*RefreshTokenRepo)(nil)
}

// TestRefreshTokenRepo_Consume_AtomicDelete is the DB-level regression
// guard for PR-1.2. Spawns N goroutines all calling Consume with the
// same hash. The DELETE ... RETURNING contract guarantees exactly one
// goroutine receives the seeded identity_id; every other call must
// return (zero ID, nil).
func TestRefreshTokenRepo_Consume_AtomicDelete(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	repo := NewRefreshTokenRepo(pool)

	identityID := core.NewIdentityID()
	email := "race-" + identityID.String()[:8] + "@example.com"
	if _, err := pool.Exec(ctx,
		`INSERT INTO identities (id, email, password_hash, created_at, updated_at)
		 VALUES ($1, $2, 'hash', NOW(), NOW())`,
		uuid.UUID(identityID), email,
	); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	t.Cleanup(func() {
		// ON DELETE CASCADE on refresh_tokens.identity_id removes the
		// token row alongside the identity. Best-effort cleanup —
		// failure is non-fatal because the test may have already
		// removed the token.
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identities WHERE id = $1`, uuid.UUID(identityID))
	})

	tokenHash := "race-test-token-hash-" + identityID.String()
	if err := repo.Create(ctx, &domain.RefreshToken{
		ID:         uuid.New().String(),
		IdentityID: identityID,
		TokenHash:  tokenHash,
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	const goroutines = 8
	var (
		wg           sync.WaitGroup
		successCount atomic.Int32
		missCount    atomic.Int32
		errCount     atomic.Int32
	)
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			id, err := repo.Consume(ctx, tokenHash)
			if err != nil {
				errCount.Add(1)
				return
			}
			var zero core.IdentityID
			if id == zero {
				missCount.Add(1)
				return
			}
			if id != identityID {
				t.Errorf("Consume returned wrong identity_id: got %s, want %s", id, identityID)
				return
			}
			successCount.Add(1)
		}()
	}
	close(start)
	wg.Wait()

	if errCount.Load() != 0 {
		t.Fatalf("unexpected error count: %d", errCount.Load())
	}
	if successCount.Load() != 1 {
		t.Fatalf("expected exactly 1 success, got %d (miss=%d)", successCount.Load(), missCount.Load())
	}
	if missCount.Load() != goroutines-1 {
		t.Fatalf("expected %d misses, got %d", goroutines-1, missCount.Load())
	}
}

// TestRefreshTokenRepo_Consume_ExpiredTokenReturnsMiss verifies the
// `expires_at > NOW()` predicate: an already-expired token must
// return (zero, nil) and stay in the table (matching the SQL
// semantics — the predicate filter blocks the DELETE entirely).
func TestRefreshTokenRepo_Consume_ExpiredTokenReturnsMiss(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	repo := NewRefreshTokenRepo(pool)

	identityID := core.NewIdentityID()
	email := "exp-" + identityID.String()[:8] + "@example.com"
	if _, err := pool.Exec(ctx,
		`INSERT INTO identities (id, email, password_hash, created_at, updated_at)
		 VALUES ($1, $2, 'hash', NOW(), NOW())`,
		uuid.UUID(identityID), email,
	); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identities WHERE id = $1`, uuid.UUID(identityID))
	})

	tokenHash := "expired-token-" + identityID.String()
	if err := repo.Create(ctx, &domain.RefreshToken{
		ID:         uuid.New().String(),
		IdentityID: identityID,
		TokenHash:  tokenHash,
		ExpiresAt:  time.Now().UTC().Add(-time.Hour), // already expired
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	id, err := repo.Consume(ctx, tokenHash)
	if err != nil {
		t.Fatalf("Consume on expired token: %v", err)
	}
	var zero core.IdentityID
	if id != zero {
		t.Fatalf("expected zero ID for expired token, got %s", id)
	}

	// Sanity: the expired row was NOT deleted (the predicate filter
	// blocks the DELETE; it's not a side effect of the call).
	stored, err := repo.GetByHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetByHash post-Consume: %v", err)
	}
	if stored == nil {
		t.Fatal("expected expired token to still exist after Consume miss")
	}
}
