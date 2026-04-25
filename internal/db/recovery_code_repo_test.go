package db

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Integration tests for RecoveryCodeRepo. Mirrors the fixture
// pattern in refresh_token_repo_test.go: seed an identity directly,
// fan out goroutines on Consume, assert single-winner semantics.
// The `-short` build flag skips integration tests; `make test-all`
// runs them against the dev Postgres.

func TestRecoveryCodeRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.RecoveryCodeRepository = (*RecoveryCodeRepo)(nil)
}

// TestRecoveryCodeRepo_Consume_AtomicOnConcurrentCalls is the
// DB-level regression guard for PR-4.5. The DELETE ... RETURNING
// contract guarantees concurrent calls for the same
// (identity_id, code_hash) tuple produce exactly one (true, nil)
// and N-1 (false, nil). This is the property the previous
// decrypt-list-split-encrypt flow violated under contention.
func TestRecoveryCodeRepo_Consume_AtomicOnConcurrentCalls(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	repo := NewRecoveryCodeRepo(pool)

	identityID := core.NewIdentityID()
	email := "rc-race-" + identityID.String()[:8] + "@example.com"
	if _, err := pool.Exec(ctx,
		`INSERT INTO identities (id, email, password_hash, created_at, updated_at)
		 VALUES ($1, $2, 'hash', NOW(), NOW())`,
		uuid.UUID(identityID), email,
	); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	t.Cleanup(func() {
		// ON DELETE CASCADE on recovery_codes.identity_id removes the
		// rows alongside the identity. Best-effort cleanup.
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identities WHERE id = $1`, uuid.UUID(identityID))
	})

	hash := "race-test-hash-" + identityID.String()
	if err := repo.Insert(ctx, identityID, []string{hash}); err != nil {
		t.Fatalf("seed recovery_code: %v", err)
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
			hit, err := repo.Consume(ctx, identityID, hash)
			if err != nil {
				errCount.Add(1)
				return
			}
			if hit {
				successCount.Add(1)
			} else {
				missCount.Add(1)
			}
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

	// Verify the row is gone.
	n, err := repo.Count(ctx, identityID)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows after consume, got %d", n)
	}
}

// TestRecoveryCodeRepo_Insert_OnConflictDoNothing covers the
// ON CONFLICT (identity_id, code_hash) DO NOTHING idempotency
// behavior. A retry of the same Insert (e.g. the legacy-fallback
// path retrying after a prior crash between Insert and clearing
// the legacy blob) must not error and must not produce duplicate
// rows.
func TestRecoveryCodeRepo_Insert_OnConflictDoNothing(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	repo := NewRecoveryCodeRepo(pool)

	identityID := core.NewIdentityID()
	email := "rc-idem-" + identityID.String()[:8] + "@example.com"
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

	hashes := []string{"h1", "h2", "h3"}
	if err := repo.Insert(ctx, identityID, hashes); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	// Re-insert the same set: must be a no-op, not a unique-violation.
	if err := repo.Insert(ctx, identityID, hashes); err != nil {
		t.Fatalf("second Insert (idempotent): %v", err)
	}
	n, err := repo.Count(ctx, identityID)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != len(hashes) {
		t.Fatalf("expected %d rows after idempotent re-insert, got %d", len(hashes), n)
	}
}

// TestRecoveryCodeRepo_DeleteAll wipes every row for an identity —
// the contract DisableTOTP relies on for re-enrollment cleanliness.
func TestRecoveryCodeRepo_DeleteAll(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	repo := NewRecoveryCodeRepo(pool)

	identityID := core.NewIdentityID()
	email := "rc-del-" + identityID.String()[:8] + "@example.com"
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

	if err := repo.Insert(ctx, identityID, []string{"a", "b", "c"}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := repo.DeleteAll(ctx, identityID); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	n, err := repo.Count(ctx, identityID)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows after DeleteAll, got %d", n)
	}
}
