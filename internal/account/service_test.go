package account

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/db"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests for account.Service.GetSummary.
//
// The membership branch and the grant-counterparty branches all read
// rows that cross tenant boundaries (an API-key holder in account B
// calling this service to render the counterparty summary of account
// A). RLS on account_memberships / grants would filter those reads
// under a pinned tenant GUC, so every test resets the session GUCs to
// empty strings before calling the service — exactly as production
// does by not wrapping in TxManager.WithTargetAccount.
//
// Each test opens its own top-level tx, seeds fixture rows, injects the
// tx via ctxKey{} (the db package looks it up), and ALWAYS rolls back
// on cleanup. `-short` skips; `make test-all` runs against the dev DB.

const integrationDefaultDBURL = "postgres://getlicense:getlicense@localhost:5432/getlicense?sslmode=disable"

// integrationPool is a package-local copy of the helper in
// internal/db/policy_repo_test.go. We duplicate instead of exporting
// because test-only helpers shouldn't leak into the public db API.
func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (-short)")
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		url = integrationDefaultDBURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("integration DB unavailable (pool): %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("integration DB unavailable (ping): %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// accountFixture seeds two accounts (target + caller) and a caller
// identity, then resets the session RLS GUCs to empty strings so that
// the service's cross-tenant predicate actually sees both rows. The
// target account is the one the caller hits via GetSummary; the caller
// account holds the acting account id and their identity.
type accountFixture struct {
	ctx              context.Context
	tx               pgx.Tx
	service          *Service
	targetAccountID  core.AccountID
	callerAccountID  core.AccountID
	callerIdentityID core.IdentityID
	ownerRoleID      core.RoleID
}

func newAccountFixture(t *testing.T) *accountFixture {
	t.Helper()
	pool := integrationPool(t)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "begin tx")
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	// Seed two disjoint accounts. Slugs include the UUID so parallel
	// runs never collide.
	targetID := core.NewAccountID()
	callerID := core.NewAccountID()

	_, err = tx.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(targetID), "Target Co", "target-"+targetID.String()[:8],
	)
	require.NoError(t, err, "seed target account")

	_, err = tx.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(callerID), "Caller Co", "caller-"+callerID.String()[:8],
	)
	require.NoError(t, err, "seed caller account")

	// Seed caller identity — memberships and grants we create later may
	// reference it.
	identityID := core.NewIdentityID()
	_, err = tx.Exec(ctx,
		`INSERT INTO identities (id, email, password_hash, created_at, updated_at)
		 VALUES ($1, $2, 'hash', NOW(), NOW())`,
		uuid.UUID(identityID), "caller-"+identityID.String()[:8]+"@example.com",
	)
	require.NoError(t, err, "seed caller identity")

	// Look up the owner preset role — memberships need a role_id FK.
	var roleIDRaw uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT id FROM roles WHERE slug = 'owner' AND account_id IS NULL LIMIT 1`).Scan(&roleIDRaw)
	require.NoError(t, err, "lookup owner preset role")

	// Reset RLS GUCs to empty strings. The tests explicitly exercise a
	// cross-tenant predicate; pinning a tenant here would filter the
	// reads the service needs to make. Empty string hits the
	// NULLIF(...) IS NULL escape hatch on every policy in this repo.
	_, err = tx.Exec(ctx, `SELECT set_config('app.current_account_id', '', true)`)
	require.NoError(t, err, "clear account GUC")
	_, err = tx.Exec(ctx, `SELECT set_config('app.current_environment', '', true)`)
	require.NoError(t, err, "clear environment GUC")

	ctx = db.ContextWithTx(ctx, tx)

	return &accountFixture{
		ctx:              ctx,
		tx:               tx,
		service:          NewService(db.NewAccountRepo(pool)),
		targetAccountID:  targetID,
		callerAccountID:  callerID,
		callerIdentityID: identityID,
		ownerRoleID:      core.RoleID(roleIDRaw),
	}
}

// seedMembership attaches the caller identity to a given account with
// the owner preset role. Used by the membership-allowed test.
func (f *accountFixture) seedMembership(t *testing.T, accountID core.AccountID) {
	t.Helper()
	_, err := f.tx.Exec(f.ctx,
		`INSERT INTO account_memberships (id, account_id, identity_id, role_id, status, joined_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'active', NOW(), NOW(), NOW())`,
		uuid.UUID(core.NewMembershipID()),
		uuid.UUID(accountID),
		uuid.UUID(f.callerIdentityID),
		uuid.UUID(f.ownerRoleID),
	)
	require.NoError(t, err, "seed membership")
}

// seedProduct creates a throwaway product under the given account so
// the grants we issue have a valid product_id FK. Product metadata is
// irrelevant to the access predicate — we just need any row.
func (f *accountFixture) seedProduct(t *testing.T, accountID core.AccountID) core.ProductID {
	t.Helper()
	id := core.NewProductID()
	_, err := f.tx.Exec(f.ctx,
		`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
		uuid.UUID(id), uuid.UUID(accountID),
		"Fixture Product", "fixture-product-"+id.String()[:8],
		"test-pub-key", []byte{0x00}, `{}`,
	)
	require.NoError(t, err, "seed product")
	return id
}

// seedGrant inserts a grant with the given grantor/grantee/status. The
// capabilities list is empty — the access predicate only cares about
// the triple (status, grantor, grantee).
func (f *accountFixture) seedGrant(
	t *testing.T,
	grantorID, granteeID core.AccountID,
	productID core.ProductID,
	status domain.GrantStatus,
) {
	t.Helper()
	_, err := f.tx.Exec(f.ctx,
		`INSERT INTO grants (id, grantor_account_id, grantee_account_id, status, product_id, capabilities, constraints, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, ARRAY[]::text[], '{}'::jsonb, NOW(), NOW())`,
		uuid.UUID(core.NewGrantID()),
		uuid.UUID(grantorID),
		uuid.UUID(granteeID),
		string(status),
		uuid.UUID(productID),
	)
	require.NoError(t, err, "seed grant")
}

// --- tests ---

// Membership in the target account authorizes the summary even without
// any grant between caller and target. The caller identity belongs to
// target directly.
func TestGetSummary_Membership_Allowed(t *testing.T) {
	f := newAccountFixture(t)
	f.seedMembership(t, f.targetAccountID)

	sum, err := f.service.GetSummary(f.ctx, f.targetAccountID, f.callerAccountID, f.callerIdentityID)
	require.NoError(t, err)
	require.NotNil(t, sum)
	assert.Equal(t, f.targetAccountID, sum.ID)
	assert.Equal(t, "Target Co", sum.Name)
	assert.NotEmpty(t, sum.Slug)
}

// Caller is the grantor (owns target's capability) → visibility goes
// both ways. Target here is the grantee.
func TestGetSummary_GrantorCounterparty_Allowed(t *testing.T) {
	f := newAccountFixture(t)
	prod := f.seedProduct(t, f.callerAccountID)
	f.seedGrant(t, f.callerAccountID, f.targetAccountID, prod, domain.GrantStatusActive)

	sum, err := f.service.GetSummary(f.ctx, f.targetAccountID, f.callerAccountID, f.callerIdentityID)
	require.NoError(t, err)
	require.NotNil(t, sum)
	assert.Equal(t, f.targetAccountID, sum.ID)
	assert.Equal(t, "Target Co", sum.Name)
}

// Caller is the grantee (uses target's capability). Target here is the
// grantor. The access predicate must allow visibility from both sides.
func TestGetSummary_GranteeCounterparty_Allowed(t *testing.T) {
	f := newAccountFixture(t)
	prod := f.seedProduct(t, f.targetAccountID)
	f.seedGrant(t, f.targetAccountID, f.callerAccountID, prod, domain.GrantStatusActive)

	sum, err := f.service.GetSummary(f.ctx, f.targetAccountID, f.callerAccountID, f.callerIdentityID)
	require.NoError(t, err)
	require.NotNil(t, sum)
	assert.Equal(t, f.targetAccountID, sum.ID)
}

// A stranger with neither membership nor any grant history must see
// exactly "account not found" — never 403, never a leaked name/slug.
func TestGetSummary_Stranger_Returns404(t *testing.T) {
	f := newAccountFixture(t)

	sum, err := f.service.GetSummary(f.ctx, f.targetAccountID, f.callerAccountID, f.callerIdentityID)
	require.Error(t, err)
	assert.Nil(t, sum)

	var appErr *core.AppError
	require.True(t, errors.As(err, &appErr), "expected *core.AppError, got %T", err)
	assert.Equal(t, core.ErrAccountNotFound, appErr.Code)
}

// A revoked (terminal) grant is the only relationship between caller
// and target → visibility must NOT follow the revoked row. The service
// returns 404 exactly as it would for a stranger.
func TestGetSummary_TerminalGrantCounterparty_Returns404(t *testing.T) {
	f := newAccountFixture(t)
	prod := f.seedProduct(t, f.callerAccountID)
	f.seedGrant(t, f.callerAccountID, f.targetAccountID, prod, domain.GrantStatusRevoked)

	sum, err := f.service.GetSummary(f.ctx, f.targetAccountID, f.callerAccountID, f.callerIdentityID)
	require.Error(t, err)
	assert.Nil(t, sum)

	var appErr *core.AppError
	require.True(t, errors.As(err, &appErr), "expected *core.AppError, got %T", err)
	assert.Equal(t, core.ErrAccountNotFound, appErr.Code)
}
