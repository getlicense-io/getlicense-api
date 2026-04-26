package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// JWTRevocationRepo integration tests.
//
// Gating mirrors policy_repo_test.go: `-short` skips, `make test-all`
// runs against the dev Postgres. Each test opens its own top-level tx
// and rolls back on cleanup so nothing survives.
//
// Unlike most repos, JWTRevocationRepo is NOT RLS-scoped (the tables
// revoked_jtis and identity_session_invalidations span tenants by
// design — checked before any tenant context exists in the request
// lifecycle). The test still uses a rollback-only tx for isolation.

func TestJWTRevocationRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.JWTRevocationRepository = (*JWTRevocationRepo)(nil)
}

func newJWTRevocationFixture(t *testing.T, pool *pgxpool.Pool) (context.Context, pgx.Tx, core.IdentityID) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	identityID := core.NewIdentityID()
	if _, err := tx.Exec(ctx,
		`INSERT INTO identities (id, email, password_hash, created_at, updated_at)
		 VALUES ($1, $2, $3, NOW(), NOW())`,
		uuid.UUID(identityID),
		"jwt-revocation-"+identityID.String()[:8]+"@example.com",
		"x", // password_hash unused by these tests
	); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	ctx = context.WithValue(ctx, ctxKey{}, tx)
	return ctx, tx, identityID
}

func TestJWTRevocationRepo_RevokeAndIsRevoked_Roundtrip(t *testing.T) {
	pool := integrationPool(t)
	ctx, _, identityID := newJWTRevocationFixture(t, pool)
	repo := NewJWTRevocationRepo(pool)

	jti := core.NewJTI()

	// Before insert: not revoked.
	revoked, err := repo.IsJTIRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsJTIRevoked (pre-insert): %v", err)
	}
	if revoked {
		t.Error("IsJTIRevoked: expected false before insert, got true")
	}

	// Insert a revocation valid for the next hour.
	expiresAt := time.Now().UTC().Add(time.Hour)
	if err := repo.RevokeJTI(ctx, jti, identityID, expiresAt, "logout"); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	revoked, err = repo.IsJTIRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsJTIRevoked (post-insert): %v", err)
	}
	if !revoked {
		t.Error("IsJTIRevoked: expected true after insert, got false")
	}

	// Idempotent: a second RevokeJTI on the same jti is a no-op.
	if err := repo.RevokeJTI(ctx, jti, identityID, expiresAt, "logout"); err != nil {
		t.Fatalf("RevokeJTI (second call): %v", err)
	}
}

func TestJWTRevocationRepo_IsRevoked_ExpiredRowsIgnored(t *testing.T) {
	pool := integrationPool(t)
	ctx, _, identityID := newJWTRevocationFixture(t, pool)
	repo := NewJWTRevocationRepo(pool)

	jti := core.NewJTI()
	// Insert with an already-past expires_at.
	if err := repo.RevokeJTI(ctx, jti, identityID, time.Now().UTC().Add(-time.Minute), "logout"); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}

	revoked, err := repo.IsJTIRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsJTIRevoked: %v", err)
	}
	if revoked {
		t.Error("IsJTIRevoked: expected false for past-exp row, got true (the WHERE clause must filter expired rows)")
	}
}

func TestJWTRevocationRepo_SweepExpired_RemovesOnlyPastRows(t *testing.T) {
	pool := integrationPool(t)
	ctx, tx, identityID := newJWTRevocationFixture(t, pool)
	repo := NewJWTRevocationRepo(pool)

	pastJTI := core.NewJTI()
	futureJTI := core.NewJTI()

	if err := repo.RevokeJTI(ctx, pastJTI, identityID, time.Now().UTC().Add(-time.Minute), "logout"); err != nil {
		t.Fatalf("RevokeJTI past: %v", err)
	}
	if err := repo.RevokeJTI(ctx, futureJTI, identityID, time.Now().UTC().Add(time.Hour), "logout"); err != nil {
		t.Fatalf("RevokeJTI future: %v", err)
	}

	n, err := repo.SweepExpired(ctx)
	if err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	if n < 1 {
		t.Errorf("SweepExpired: expected at least 1 row deleted, got %d", n)
	}

	// Verify the future row is still present via raw SQL (avoids the
	// IsJTIRevoked WHERE-clause filter).
	var count int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM revoked_jtis WHERE jti = $1`,
		uuid.UUID(futureJTI),
	).Scan(&count); err != nil {
		t.Fatalf("count future jti: %v", err)
	}
	if count != 1 {
		t.Errorf("future jti row: got %d, want 1 (sweep deleted a row it should have kept)", count)
	}

	// Verify the past row is gone.
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM revoked_jtis WHERE jti = $1`,
		uuid.UUID(pastJTI),
	).Scan(&count); err != nil {
		t.Fatalf("count past jti: %v", err)
	}
	if count != 0 {
		t.Errorf("past jti row: got %d, want 0 (sweep failed to delete an expired row)", count)
	}
}

func TestJWTRevocationRepo_SetSessionInvalidation_Upsert(t *testing.T) {
	pool := integrationPool(t)
	ctx, _, identityID := newJWTRevocationFixture(t, pool)
	repo := NewJWTRevocationRepo(pool)

	// Initial set.
	first := time.Now().UTC().Add(-time.Hour)
	if err := repo.SetSessionInvalidation(ctx, identityID, first); err != nil {
		t.Fatalf("SetSessionInvalidation initial: %v", err)
	}
	got, err := repo.GetSessionMinIAT(ctx, identityID)
	if err != nil {
		t.Fatalf("GetSessionMinIAT initial: %v", err)
	}
	if got == nil {
		t.Fatal("GetSessionMinIAT initial: expected non-nil, got nil")
	}
	if !got.Equal(first) {
		t.Errorf("min_iat after first set: got %v, want %v", *got, first)
	}

	// Second set updates the row (ON CONFLICT DO UPDATE).
	second := time.Now().UTC()
	if err := repo.SetSessionInvalidation(ctx, identityID, second); err != nil {
		t.Fatalf("SetSessionInvalidation second: %v", err)
	}
	got, err = repo.GetSessionMinIAT(ctx, identityID)
	if err != nil {
		t.Fatalf("GetSessionMinIAT second: %v", err)
	}
	if got == nil {
		t.Fatal("GetSessionMinIAT second: expected non-nil, got nil")
	}
	if !got.Equal(second) {
		t.Errorf("min_iat after second set: got %v, want %v (upsert did not update)", *got, second)
	}
}

func TestJWTRevocationRepo_GetSessionMinIAT_NoRowReturnsNil(t *testing.T) {
	pool := integrationPool(t)
	ctx, _, identityID := newJWTRevocationFixture(t, pool)
	repo := NewJWTRevocationRepo(pool)

	got, err := repo.GetSessionMinIAT(ctx, identityID)
	if err != nil {
		t.Fatalf("GetSessionMinIAT: %v", err)
	}
	if got != nil {
		t.Errorf("GetSessionMinIAT: expected nil for never-invalidated identity, got %v", *got)
	}
}
