package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests for InvitationRepo.
//
// Harness mirrors grant_repo_test.go — each test opens its own pool,
// begins a top-level tx, seeds a rollback-only fixture (account +
// creator identity so the NOT NULL FKs on invitations hold), pins the
// RLS GUC to the seeded account, and rolls back on cleanup. `-short`
// skips.

// invitationFixture holds every seeded ID invitation-repo tests may
// want to reference. The creator identity is required because
// invitations.created_by_identity_id is a NOT NULL FK.
type invitationFixture struct {
	ctx        context.Context
	tx         pgx.Tx
	pool       *pgxpool.Pool
	accountID  core.AccountID
	identityID core.IdentityID
}

func TestInvitationRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.InvitationRepository = (*InvitationRepo)(nil)
}

// setupInvitationRepo is the canonical entry point for every
// InvitationRepo_* integration test. Returns a tx-scoped ctx (with RLS
// GUC pinned to the creator account), a fresh *InvitationRepo, and the
// seeded fixture.
func setupInvitationRepo(t *testing.T) (context.Context, *InvitationRepo, *invitationFixture) {
	t.Helper()
	pool := integrationPool(t)
	f := newInvitationFixture(t, pool)
	f.pool = pool
	return f.ctx, NewInvitationRepo(pool), f
}

func newInvitationFixture(t *testing.T, pool *pgxpool.Pool) *invitationFixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "begin tx")
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	accountID := core.NewAccountID()
	identityID := core.NewIdentityID()
	env := core.Environment("live")

	// Pin the GUC so the invitations RLS policy accepts rows whose
	// created_by_account_id = this account.
	_, err = tx.Exec(ctx,
		`SELECT set_config('app.current_account_id', $1, true)`, accountID.String())
	require.NoError(t, err, "set_config account")
	_, err = tx.Exec(ctx,
		`SELECT set_config('app.current_environment', $1, true)`, string(env))
	require.NoError(t, err, "set_config env")

	// Seed the creator account. Name/slug must be non-empty so the
	// JOIN reads through GetInvitationByIDWithCreator /
	// ListInvitationsByAccountFiltered see populated creator columns.
	_, err = tx.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(accountID), "Test Account", "test-acct-"+accountID.String()[:8],
	)
	require.NoError(t, err, "seed account")

	// Seed the creator identity — invitations.created_by_identity_id is
	// a NOT NULL FK into identities.
	_, err = tx.Exec(ctx,
		`INSERT INTO identities (id, email, password_hash, created_at, updated_at)
		 VALUES ($1, $2, 'hash', NOW(), NOW())`,
		uuid.UUID(identityID), "creator-"+identityID.String()[:8]+"@example.com",
	)
	require.NoError(t, err, "seed identity")

	ctx = context.WithValue(ctx, ctxKey{}, tx)

	return &invitationFixture{
		ctx:        ctx,
		tx:         tx,
		accountID:  accountID,
		identityID: identityID,
	}
}

// invitationOpt tweaks an in-memory *domain.Invitation before Create,
// letting each test override only the fields it cares about.
type invitationOpt func(*domain.Invitation)

func withKind(kind domain.InvitationKind) invitationOpt {
	return func(inv *domain.Invitation) {
		inv.Kind = kind
		switch kind {
		case domain.InvitationKindMembership:
			// invitations_membership_fields CHECK requires account_id and
			// role_id when kind=membership; leave them to whatever caller
			// already set (the default below populates them).
		case domain.InvitationKindGrant:
			// invitations_grant_fields CHECK requires grant_draft when
			// kind=grant. Clear the membership-only fields so we don't
			// paint a mixed row the CHECK would reject.
			inv.AccountID = nil
			inv.RoleID = nil
			if inv.GrantDraft == nil {
				inv.GrantDraft = json.RawMessage(`{}`)
			}
		}
	}
}

// insertTestInvitation seeds a membership-kind invitation by default
// (pending, 24h expiry, references the fixture's account+role). Kind
// is flipped to grant by the withKind opt when needed.
func insertTestInvitation(t *testing.T, ctx context.Context, repo *InvitationRepo, f *invitationFixture, opts ...invitationOpt) *domain.Invitation {
	t.Helper()

	// Seed a role so the membership-kind path has a valid role_id FK.
	// Reuse an existing preset role — roles table is pre-seeded by
	// migration 016 with role_id values tied to preset slugs.
	var roleIDRaw uuid.UUID
	err := f.tx.QueryRow(ctx, `SELECT id FROM roles WHERE slug = 'developer' AND account_id IS NULL LIMIT 1`).Scan(&roleIDRaw)
	require.NoError(t, err, "look up preset developer role")
	roleID := core.RoleID(roleIDRaw)

	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)

	accountID := f.accountID
	inv := &domain.Invitation{
		ID:                  core.NewInvitationID(),
		Kind:                domain.InvitationKindMembership,
		Email:               "invitee-" + core.NewInvitationID().String()[:8] + "@example.com",
		TokenHash:           "hash-" + core.NewInvitationID().String(),
		AccountID:           &accountID,
		RoleID:              &roleID,
		CreatedByIdentityID: f.identityID,
		CreatedByAccountID:  f.accountID,
		ExpiresAt:           expires,
		CreatedAt:           now,
	}
	for _, opt := range opts {
		opt(inv)
	}
	require.NoError(t, repo.Create(ctx, inv), "create invitation")
	return inv
}

func TestInvitationRepo_ListByAccount_FilterByKindAndStatus(t *testing.T) {
	ctx, repo, f := setupInvitationRepo(t)

	// Seed three invitations: one membership (pending), one grant
	// (pending), one grant (accepted). Filtering on (kind=grant,
	// status=pending) should return only the middle one.
	_ = insertTestInvitation(t, ctx, repo, f, withKind(domain.InvitationKindMembership))
	pendingGrant := insertTestInvitation(t, ctx, repo, f, withKind(domain.InvitationKindGrant))
	acceptedGrant := insertTestInvitation(t, ctx, repo, f, withKind(domain.InvitationKindGrant))
	require.NoError(t, repo.MarkAccepted(ctx, acceptedGrant.ID, time.Now().UTC()))

	kindGrant := domain.InvitationKindGrant
	rows, _, err := repo.ListByAccount(ctx, domain.InvitationListFilter{
		Kind:   &kindGrant,
		Status: []string{"pending"},
	}, core.Cursor{}, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, pendingGrant.ID, rows[0].ID)
	assert.Equal(t, "pending", rows[0].Status)
	assert.Equal(t, domain.InvitationKindGrant, rows[0].Kind)
	require.NotNil(t, rows[0].CreatedByAccount, "CreatedByAccount populated via JOIN")
	assert.Equal(t, f.accountID, rows[0].CreatedByAccount.ID)
	assert.Equal(t, "Test Account", rows[0].CreatedByAccount.Name)
}

func TestInvitationRepo_GetByID_PopulatesCreatorAndStatus(t *testing.T) {
	ctx, repo, f := setupInvitationRepo(t)
	inv := insertTestInvitation(t, ctx, repo, f)

	got, err := repo.GetByID(ctx, inv.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "pending", got.Status)
	require.NotNil(t, got.CreatedByAccount)
	assert.Equal(t, f.accountID, got.CreatedByAccount.ID)
	assert.Equal(t, "Test Account", got.CreatedByAccount.Name)
}

func TestInvitationRepo_UpdateTokenHash_RotatesToken(t *testing.T) {
	ctx, repo, f := setupInvitationRepo(t)
	inv := insertTestInvitation(t, ctx, repo, f)

	newHash := "rotated-" + inv.ID.String()
	require.NoError(t, repo.UpdateTokenHash(ctx, inv.ID, newHash))

	// The old hash lookup no longer matches; the new one does.
	oldHit, err := repo.GetByTokenHash(ctx, inv.TokenHash)
	require.NoError(t, err)
	assert.Nil(t, oldHit, "previous token hash must be invalidated")

	newHit, err := repo.GetByTokenHash(ctx, newHash)
	require.NoError(t, err)
	require.NotNil(t, newHit)
	assert.Equal(t, inv.ID, newHit.ID)
}

// TestInvitationRepo_HasActiveGrantInvitation pins the contract the
// Task 18 duplicate guard depends on: the EXISTS query matches on the
// (account, lower(email), product) triple, with kind=grant and
// pending-unexpired discrimination. The service passes emailLower
// already-lowercased; the query applies lower(email) on the ROW side,
// so stored "Partner@Acme.com" still matches param "partner@acme.com".
func TestInvitationRepo_HasActiveGrantInvitation(t *testing.T) {
	ctx, repo, f := setupInvitationRepo(t)

	// Seed a product under the creator account so the grant_draft
	// JSON carries a real product_id the EXISTS query can match.
	productA := core.NewProductID()
	_, err := f.tx.Exec(ctx,
		`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
		uuid.UUID(productA), uuid.UUID(f.accountID),
		"Product A", "product-a-"+f.accountID.String()[:8], "pub-a", []byte{0x00},
		`{}`,
	)
	require.NoError(t, err, "seed product A")

	productB := core.NewProductID()
	_, err = f.tx.Exec(ctx,
		`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
		uuid.UUID(productB), uuid.UUID(f.accountID),
		"Product B", "product-b-"+f.accountID.String()[:8], "pub-b", []byte{0x00},
		`{}`,
	)
	require.NoError(t, err, "seed product B")

	// Seed a pending grant invitation for (account, "Partner@Acme.com",
	// productA). Email is stored as-mixed-case intentionally so we can
	// verify the lower(email) predicate works on the row side.
	draft := json.RawMessage(`{"product_id":"` + productA.String() + `","capabilities":["LICENSE_CREATE"]}`)
	inv := insertTestInvitation(t, ctx, repo, f,
		withKind(domain.InvitationKindGrant),
		func(in *domain.Invitation) {
			in.Email = "Partner@Acme.com"
			in.GrantDraft = draft
		},
	)

	t.Run("matches same (account, email, product)", func(t *testing.T) {
		has, err := repo.HasActiveGrantInvitation(ctx, f.accountID, "partner@acme.com", productA)
		require.NoError(t, err)
		assert.True(t, has, "pending grant invitation should match")
	})

	t.Run("no match on different product", func(t *testing.T) {
		has, err := repo.HasActiveGrantInvitation(ctx, f.accountID, "partner@acme.com", productB)
		require.NoError(t, err)
		assert.False(t, has, "different product must not match")
	})

	t.Run("no match on different email", func(t *testing.T) {
		has, err := repo.HasActiveGrantInvitation(ctx, f.accountID, "other@acme.com", productA)
		require.NoError(t, err)
		assert.False(t, has, "different email must not match")
	})

	t.Run("case-insensitive on row side: mixed case stored, lowercase arg", func(t *testing.T) {
		// Contract: caller lowercases the param; query lowercases the row.
		has, err := repo.HasActiveGrantInvitation(ctx, f.accountID, "partner@acme.com", productA)
		require.NoError(t, err)
		assert.True(t, has, "lower(email) must match mixed-case stored email")
	})

	t.Run("accepted invitation does not match", func(t *testing.T) {
		require.NoError(t, repo.MarkAccepted(ctx, inv.ID, time.Now().UTC()))
		has, err := repo.HasActiveGrantInvitation(ctx, f.accountID, "partner@acme.com", productA)
		require.NoError(t, err)
		assert.False(t, has, "accepted invitation is not active")
	})

	t.Run("expired invitation does not match", func(t *testing.T) {
		// Seed a fresh grant invitation for a distinct email so the
		// prior accepted row from the previous subtest doesn't confuse
		// this case, then rewind expires_at to the past.
		expiredInv := insertTestInvitation(t, ctx, repo, f,
			withKind(domain.InvitationKindGrant),
			func(in *domain.Invitation) {
				in.Email = "expired@acme.com"
				in.GrantDraft = draft
			},
		)
		_, err := f.tx.Exec(ctx,
			`UPDATE invitations SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1`,
			uuid.UUID(expiredInv.ID))
		require.NoError(t, err, "rewind expires_at")

		has, err := repo.HasActiveGrantInvitation(ctx, f.accountID, "expired@acme.com", productA)
		require.NoError(t, err)
		assert.False(t, has, "expired invitation is not active")
	})
}
