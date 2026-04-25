package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMembershipRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.AccountMembershipRepository = (*MembershipRepo)(nil)
}

// membershipDetailFixture seeds an account, two identities, and two
// memberships (owner + developer) under a fresh rollback-only tx with
// the RLS GUC pinned to the seeded account. Mirrors the harness used in
// invitation_repo_test.go and customer_repo_test.go.
type membershipDetailFixture struct {
	ctx               context.Context
	tx                pgx.Tx
	accountID         core.AccountID
	ownerIdentityID   core.IdentityID
	ownerEmail        string
	ownerMembershipID core.MembershipID
	devIdentityID     core.IdentityID
	devEmail          string
	devMembershipID   core.MembershipID
	ownerRoleID       core.RoleID
	developerRoleID   core.RoleID
}

func newMembershipDetailFixture(t *testing.T, pool *pgxpool.Pool) *membershipDetailFixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	accountID := core.NewAccountID()
	env := core.Environment("live")

	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.current_account_id', $1, true)`, accountID.String()); err != nil {
		t.Fatalf("set_config account: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.current_environment', $1, true)`, string(env)); err != nil {
		t.Fatalf("set_config env: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(accountID), "Test Account",
		"test-acct-"+accountID.String()[:8],
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	// Look up the preset 'owner' and 'developer' role ids (account_id IS
	// NULL ⇒ preset). Migration 016 seeds them with gen_random_uuid().
	var ownerRoleUUID, developerRoleUUID uuid.UUID
	if err := tx.QueryRow(ctx,
		`SELECT id FROM roles WHERE slug = 'owner' AND account_id IS NULL`,
	).Scan(&ownerRoleUUID); err != nil {
		t.Fatalf("lookup owner role: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`SELECT id FROM roles WHERE slug = 'developer' AND account_id IS NULL`,
	).Scan(&developerRoleUUID); err != nil {
		t.Fatalf("lookup developer role: %v", err)
	}
	ownerRoleID := core.RoleID(ownerRoleUUID)
	developerRoleID := core.RoleID(developerRoleUUID)

	// Seed two identities. Email is deterministic-ish so the assertions
	// can match without coupling to UUIDs.
	ownerIdentityID := core.NewIdentityID()
	ownerEmail := "owner-" + ownerIdentityID.String()[:8] + "@example.com"
	if _, err := tx.Exec(ctx,
		`INSERT INTO identities (id, email, password_hash, created_at, updated_at)
		 VALUES ($1, $2, 'hash', NOW(), NOW())`,
		uuid.UUID(ownerIdentityID), ownerEmail,
	); err != nil {
		t.Fatalf("seed owner identity: %v", err)
	}

	devIdentityID := core.NewIdentityID()
	devEmail := "dev-" + devIdentityID.String()[:8] + "@example.com"
	if _, err := tx.Exec(ctx,
		`INSERT INTO identities (id, email, password_hash, created_at, updated_at)
		 VALUES ($1, $2, 'hash', NOW(), NOW())`,
		uuid.UUID(devIdentityID), devEmail,
	); err != nil {
		t.Fatalf("seed developer identity: %v", err)
	}

	// Seed memberships. Insert times are nudged 1ms apart so the
	// (created_at DESC, id DESC) tuple ordering is deterministic in the
	// assertions: dev created later ⇒ returned first.
	now := time.Now().UTC()
	ownerMembershipID := core.NewMembershipID()
	if _, err := tx.Exec(ctx,
		`INSERT INTO account_memberships
		   (id, account_id, identity_id, role_id, status,
		    joined_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'active', $5, $5, $5)`,
		uuid.UUID(ownerMembershipID), uuid.UUID(accountID),
		uuid.UUID(ownerIdentityID), uuid.UUID(ownerRoleID),
		now,
	); err != nil {
		t.Fatalf("seed owner membership: %v", err)
	}

	devMembershipID := core.NewMembershipID()
	devCreatedAt := now.Add(time.Millisecond)
	if _, err := tx.Exec(ctx,
		`INSERT INTO account_memberships
		   (id, account_id, identity_id, role_id, status,
		    joined_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'active', $5, $5, $5)`,
		uuid.UUID(devMembershipID), uuid.UUID(accountID),
		uuid.UUID(devIdentityID), uuid.UUID(developerRoleID),
		devCreatedAt,
	); err != nil {
		t.Fatalf("seed developer membership: %v", err)
	}

	ctx = context.WithValue(ctx, ctxKey{}, tx)

	return &membershipDetailFixture{
		ctx:               ctx,
		tx:                tx,
		accountID:         accountID,
		ownerIdentityID:   ownerIdentityID,
		ownerEmail:        ownerEmail,
		ownerMembershipID: ownerMembershipID,
		devIdentityID:     devIdentityID,
		devEmail:          devEmail,
		devMembershipID:   devMembershipID,
		ownerRoleID:       ownerRoleID,
		developerRoleID:   developerRoleID,
	}
}

func TestMembershipRepo_ListAccountWithDetails(t *testing.T) {
	pool := integrationPool(t)
	f := newMembershipDetailFixture(t, pool)
	repo := NewMembershipRepo(pool)

	got, hasMore, err := repo.ListAccountWithDetails(f.ctx, core.Cursor{}, 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if hasMore {
		t.Errorf("hasMore = true; want false (only 2 rows seeded with limit 50)")
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}

	// Ordering is (created_at DESC, id DESC) — developer was inserted 1ms
	// later so it should come first.
	if got[0].MembershipID != f.devMembershipID {
		t.Errorf("got[0].MembershipID = %v, want developer membership %v",
			got[0].MembershipID, f.devMembershipID)
	}
	if got[1].MembershipID != f.ownerMembershipID {
		t.Errorf("got[1].MembershipID = %v, want owner membership %v",
			got[1].MembershipID, f.ownerMembershipID)
	}

	// Identity payload: id + email round-trip correctly through the JOIN.
	if got[0].Identity.ID != f.devIdentityID {
		t.Errorf("got[0].Identity.ID = %v, want %v",
			got[0].Identity.ID, f.devIdentityID)
	}
	if got[0].Identity.Email != f.devEmail {
		t.Errorf("got[0].Identity.Email = %q, want %q",
			got[0].Identity.Email, f.devEmail)
	}
	if got[1].Identity.ID != f.ownerIdentityID {
		t.Errorf("got[1].Identity.ID = %v, want %v",
			got[1].Identity.ID, f.ownerIdentityID)
	}
	if got[1].Identity.Email != f.ownerEmail {
		t.Errorf("got[1].Identity.Email = %q, want %q",
			got[1].Identity.Email, f.ownerEmail)
	}

	// Role payload: id + slug + name round-trip correctly through the JOIN.
	if got[0].Role.ID != f.developerRoleID {
		t.Errorf("got[0].Role.ID = %v, want %v",
			got[0].Role.ID, f.developerRoleID)
	}
	if got[0].Role.Slug != "developer" {
		t.Errorf("got[0].Role.Slug = %q, want developer", got[0].Role.Slug)
	}
	if got[0].Role.Name != "Developer" {
		t.Errorf("got[0].Role.Name = %q, want Developer", got[0].Role.Name)
	}
	if got[1].Role.Slug != "owner" {
		t.Errorf("got[1].Role.Slug = %q, want owner", got[1].Role.Slug)
	}
	if got[1].Role.Name != "Owner" {
		t.Errorf("got[1].Role.Name = %q, want Owner", got[1].Role.Name)
	}

	// Joined-at and created-at populated, not zero.
	for i, d := range got {
		if d.JoinedAt.IsZero() {
			t.Errorf("got[%d].JoinedAt is zero", i)
		}
		if d.CreatedAt.IsZero() {
			t.Errorf("got[%d].CreatedAt is zero", i)
		}
	}

	// Defense-in-depth: serialized MembershipDetail must NOT contain any
	// secret-shaped substrings. Ensures we never accidentally widen the
	// view to include password hashes, totp secrets, refresh tokens, etc.
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	lower := strings.ToLower(string(body))
	for _, banned := range []string{"password", "totp", "secret", "hash", "refresh"} {
		if strings.Contains(lower, banned) {
			t.Errorf("MembershipDetail JSON leaks %q-shaped field: %s", banned, body)
		}
	}
}
