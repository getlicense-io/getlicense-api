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

// Integration tests for GrantRepo.
//
// Harness follows policy_repo_test.go — each test opens its own pool,
// begins a top-level tx, seeds a rollback-only fixture (two accounts to
// satisfy grants_not_self_grant CHECK, two products for FilterByProductID,
// a default policy + customer for license inserts), and ROLLS BACK on
// cleanup. No test pollutes the dev DB. `-short` skips.

// grantFixture holds every seeded ID the grant-repo tests want to
// reference. grantorAccountID is the one pinned into the RLS GUC so
// ListByGrantor / GetByID resolve against it; granteeAccountID is
// seeded separately to satisfy the grants_not_self_grant constraint.
type grantFixture struct {
	ctx               context.Context
	tx                pgx.Tx
	pool              *pgxpool.Pool
	grantorAccountID  core.AccountID
	granteeAccountID  core.AccountID
	productA          core.ProductID
	productB          core.ProductID
	policyID          core.PolicyID
	defaultCustomerID core.CustomerID
}

// setupGrantRepo is the canonical entry point for every Grant*Repo_*
// integration test. Returns a tx-scoped ctx (with RLS GUC pinned to the
// grantor account), a fresh *GrantRepo, and the seeded fixture IDs.
func setupGrantRepo(t *testing.T) (context.Context, *GrantRepo, *grantFixture) {
	t.Helper()
	pool := integrationPool(t)
	f := newGrantFixture(t, pool)
	f.pool = pool
	return f.ctx, NewGrantRepo(pool), f
}

func newGrantFixture(t *testing.T, pool *pgxpool.Pool) *grantFixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "begin tx")
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	grantorID := core.NewAccountID()
	granteeID := core.NewAccountID()
	env := core.Environment("live")

	// Pin the GUC to the grantor account so ListByGrantor / GetByID
	// read that branch of the tenant_grants RLS policy.
	_, err = tx.Exec(ctx,
		`SELECT set_config('app.current_account_id', $1, true)`, grantorID.String())
	require.NoError(t, err, "set_config account")
	_, err = tx.Exec(ctx,
		`SELECT set_config('app.current_environment', $1, true)`, string(env))
	require.NoError(t, err, "set_config env")

	// Seed two accounts so grants_not_self_grant CHECK does not trip.
	slugG := "grantor-" + grantorID.String()[:8]
	_, err = tx.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(grantorID), "Test Grantor", slugG,
	)
	require.NoError(t, err, "seed grantor account")

	slugE := "grantee-" + granteeID.String()[:8]
	_, err = tx.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(granteeID), "Test Grantee", slugE,
	)
	require.NoError(t, err, "seed grantee account")

	// Two products under the grantor so FilterByProductID has two
	// distinct options to discriminate against.
	productA := core.NewProductID()
	_, err = tx.Exec(ctx,
		`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
		uuid.UUID(productA), uuid.UUID(grantorID),
		"Product A", "product-a-"+grantorID.String()[:8], "test-pub-key-a", []byte{0x00},
		`{}`,
	)
	require.NoError(t, err, "seed product A")

	productB := core.NewProductID()
	_, err = tx.Exec(ctx,
		`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
		uuid.UUID(productB), uuid.UUID(grantorID),
		"Product B", "product-b-"+grantorID.String()[:8], "test-pub-key-b", []byte{0x00},
		`{}`,
	)
	require.NoError(t, err, "seed product B")

	ctx = context.WithValue(ctx, ctxKey{}, tx)

	// Seed a default policy via PolicyRepo on productA so license
	// inserts have a valid policy_id FK.
	policyID := core.NewPolicyID()
	now := time.Now().UTC()
	policy := &domain.Policy{
		ID:                        policyID,
		AccountID:                 grantorID,
		ProductID:                 productA,
		Name:                      "Default",
		IsDefault:                 true,
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		CheckoutIntervalSec:       86400,
		MaxCheckoutDurationSec:    604800,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	require.NoError(t, NewPolicyRepo(pool).Create(ctx, policy), "seed policy")

	// Seed a default customer for license fixtures that don't need to
	// exercise the DISTINCT-customer path; tests that care can seed
	// additional customers via insertCustomer.
	customerID := core.NewCustomerID()
	_, err = tx.Exec(ctx,
		`INSERT INTO customers (id, account_id, email, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, '{}'::jsonb, NOW(), NOW())`,
		uuid.UUID(customerID), uuid.UUID(grantorID),
		"fixture-"+grantorID.String()[:8]+"@example.com",
	)
	require.NoError(t, err, "seed default customer")

	return &grantFixture{
		ctx:               ctx,
		tx:                tx,
		grantorAccountID:  grantorID,
		granteeAccountID:  granteeID,
		productA:          productA,
		productB:          productB,
		policyID:          policyID,
		defaultCustomerID: customerID,
	}
}

// grantOpt tweaks an in-memory *domain.Grant before Create. Used so each
// test can override only the fields it cares about without reaching into
// every field of the struct.
type grantOpt func(*domain.Grant)

func withExpiresAt(t time.Time) grantOpt {
	return func(g *domain.Grant) { g.ExpiresAt = &t }
}

func withProduct(p core.ProductID) grantOpt {
	return func(g *domain.Grant) { g.ProductID = p }
}

// insertTestGrant seeds a grant owned by the fixture's grantor with
// sensible defaults (status=active, ProductA, LICENSE_READ capability)
// and returns the persisted in-memory Grant so callers can assert on
// its ID / status downstream. The (created_at DESC, id DESC) ordering
// is stable thanks to the `id DESC` tiebreaker — tests that care about
// ordering never share created_at to the microsecond because each
// insert writes its own wallclock `now`.
func insertTestGrant(t *testing.T, ctx context.Context, repo *GrantRepo, f *grantFixture, opts ...grantOpt) *domain.Grant {
	t.Helper()
	now := time.Now().UTC()
	g := &domain.Grant{
		ID:               core.NewGrantID(),
		GrantorAccountID: f.grantorAccountID,
		GranteeAccountID: f.granteeAccountID,
		ProductID:        f.productA,
		Status:           domain.GrantStatusActive,
		Capabilities:     []domain.GrantCapability{domain.GrantCapLicenseRead},
		Constraints:      json.RawMessage("{}"),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	for _, opt := range opts {
		opt(g)
	}
	require.NoError(t, repo.Create(ctx, g), "create grant")
	return g
}

// insertCustomer seeds an additional customer under the grantor account.
// Used by TestGrantRepo_GetUsage to exercise the DISTINCT COUNT path
// with more than one customer referenced by licenses.
//
// NOTE: core.NewCustomerID returns a UUIDv7, whose leading bytes are a
// millisecond timestamp. Back-to-back calls in the same test tick share
// the same 48-bit prefix, so `[:8]` collides. We key the email off the
// full UUID string instead, which is unique per call.
func insertCustomer(t *testing.T, ctx context.Context, f *grantFixture) core.CustomerID {
	t.Helper()
	id := core.NewCustomerID()
	tx, ok := ctx.Value(ctxKey{}).(pgx.Tx)
	require.True(t, ok, "ctx must carry ambient tx")
	_, err := tx.Exec(ctx,
		`INSERT INTO customers (id, account_id, email, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, '{}'::jsonb, NOW(), NOW())`,
		uuid.UUID(id), uuid.UUID(f.grantorAccountID),
		"c-"+id.String()+"@example.com",
	)
	require.NoError(t, err, "seed extra customer")
	return id
}

// insertLicenseUnderGrantWithCustomer inserts a license attributed to
// the given grant with an explicit customer. Used by the DISTINCT-count
// path; callers that don't care about customer identity can pass the
// fixture's defaultCustomerID.
func insertLicenseUnderGrantWithCustomer(
	t *testing.T,
	ctx context.Context,
	f *grantFixture,
	grantID core.GrantID,
	customerID core.CustomerID,
) core.LicenseID {
	t.Helper()
	id := core.NewLicenseID()
	now := time.Now().UTC()
	gID := grantID
	lic := &domain.License{
		ID:                 id,
		AccountID:          f.grantorAccountID,
		ProductID:          f.productA,
		PolicyID:           f.policyID,
		CustomerID:         customerID,
		KeyPrefix:          "GL_TEST_" + id.String()[:8],
		KeyHash:            "hash_" + id.String(),
		Token:              "tok_" + id.String(),
		Status:             core.LicenseStatusActive,
		Environment:        core.Environment("live"),
		CreatedAt:          now,
		UpdatedAt:          now,
		GrantID:            &gID,
		CreatedByAccountID: f.granteeAccountID,
	}
	require.NoError(t, NewLicenseRepo(f.pool).Create(ctx, lic), "insert license under grant")
	return id
}

// ptrTo returns a pointer to v. Used to thread scalar values into
// UpdateGrantParams's pointer fields inline.
func ptrTo[T any](v T) *T { return &v }

func TestGrantRepo_Update_LabelOnly(t *testing.T) {
	ctx, repo, f := setupGrantRepo(t)
	g := insertTestGrant(t, ctx, repo, f)

	newLabel := "updated label"
	err := repo.Update(ctx, g.ID, domain.UpdateGrantParams{
		Label: ptrTo(&newLabel),
	})
	require.NoError(t, err)

	got, err := repo.GetByID(ctx, g.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.Label)
	assert.Equal(t, "updated label", *got.Label)
	// Other fields must be untouched.
	assert.Equal(t, g.Capabilities, got.Capabilities)
	assert.Equal(t, g.Status, got.Status)
	assert.Equal(t, g.ProductID, got.ProductID)
}

func TestGrantRepo_Update_ClearExpiresAt(t *testing.T) {
	ctx, repo, f := setupGrantRepo(t)
	future := time.Now().Add(24 * time.Hour).UTC()
	g := insertTestGrant(t, ctx, repo, f, withExpiresAt(future))
	require.NotNil(t, g.ExpiresAt, "precondition: grant has expires_at")

	var nilTime *time.Time
	err := repo.Update(ctx, g.ID, domain.UpdateGrantParams{
		ExpiresAt: &nilTime,
	})
	require.NoError(t, err)

	got, err := repo.GetByID(ctx, g.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Nil(t, got.ExpiresAt)
}

func TestGrantRepo_ListByGrantor_FilterByProductID(t *testing.T) {
	ctx, repo, f := setupGrantRepo(t)
	_ = insertTestGrant(t, ctx, repo, f, withProduct(f.productA))
	_ = insertTestGrant(t, ctx, repo, f, withProduct(f.productB))

	pid := f.productA
	rows, _, err := repo.ListByGrantor(ctx, domain.GrantListFilter{
		ProductID: &pid,
	}, core.Cursor{}, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, f.productA, rows[0].ProductID)
}

func TestGrantRepo_ListByGrantor_ExcludesTerminalByDefault(t *testing.T) {
	ctx, repo, f := setupGrantRepo(t)
	active := insertTestGrant(t, ctx, repo, f)
	revoked := insertTestGrant(t, ctx, repo, f)
	require.NoError(t, repo.UpdateStatus(ctx, revoked.ID, domain.GrantStatusRevoked))

	rows, _, err := repo.ListByGrantor(ctx, domain.GrantListFilter{}, core.Cursor{}, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, active.ID, rows[0].ID)
}

func TestGrantRepo_ListByGrantor_IncludeTerminalReturnsAll(t *testing.T) {
	ctx, repo, f := setupGrantRepo(t)
	_ = insertTestGrant(t, ctx, repo, f)
	revoked := insertTestGrant(t, ctx, repo, f)
	require.NoError(t, repo.UpdateStatus(ctx, revoked.ID, domain.GrantStatusRevoked))

	rows, _, err := repo.ListByGrantor(ctx, domain.GrantListFilter{
		IncludeTerminal: true,
	}, core.Cursor{}, 50)
	require.NoError(t, err)
	assert.Len(t, rows, 2)
}

func TestGrantRepo_GetByID_PopulatesAccountSummaries(t *testing.T) {
	ctx, repo, f := setupGrantRepo(t)
	g := insertTestGrant(t, ctx, repo, f)

	got, err := repo.GetByID(ctx, g.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.GrantorAccount)
	require.NotNil(t, got.GranteeAccount)
	assert.NotEmpty(t, got.GrantorAccount.Name)
	assert.NotEmpty(t, got.GranteeAccount.Name)
	assert.Equal(t, got.GrantorAccountID, got.GrantorAccount.ID)
	assert.Equal(t, got.GranteeAccountID, got.GranteeAccount.ID)
	// Sanity-check that the populated names actually match the seeded
	// accounts (not a JOIN-swap bug).
	assert.Equal(t, "Test Grantor", got.GrantorAccount.Name)
	assert.Equal(t, "Test Grantee", got.GranteeAccount.Name)
}

func TestGrantRepo_GetUsage(t *testing.T) {
	ctx, repo, f := setupGrantRepo(t)
	g := insertTestGrant(t, ctx, repo, f)

	// Four licenses across three customers. Two share customer c1 to
	// exercise the DISTINCT COUNT; the fourth uses the fixture's default
	// customer.
	c1 := insertCustomer(t, ctx, f)
	c2 := insertCustomer(t, ctx, f)
	_ = insertLicenseUnderGrantWithCustomer(t, ctx, f, g.ID, c1)
	_ = insertLicenseUnderGrantWithCustomer(t, ctx, f, g.ID, c1)
	_ = insertLicenseUnderGrantWithCustomer(t, ctx, f, g.ID, c2)
	_ = insertLicenseUnderGrantWithCustomer(t, ctx, f, g.ID, f.defaultCustomerID)

	t.Run("zero since covers all rows", func(t *testing.T) {
		usage, err := repo.GetUsage(ctx, g.ID, time.Time{})
		require.NoError(t, err)
		assert.Equal(t, 4, usage.LicensesTotal)
		assert.Equal(t, 4, usage.LicensesThisMonth)
		assert.Equal(t, 3, usage.CustomersTotal)
	})

	t.Run("future since excludes from monthly bucket only", func(t *testing.T) {
		future := time.Now().UTC().Add(24 * time.Hour)
		usage, err := repo.GetUsage(ctx, g.ID, future)
		require.NoError(t, err)
		assert.Equal(t, 4, usage.LicensesTotal)
		assert.Equal(t, 0, usage.LicensesThisMonth)
		assert.Equal(t, 3, usage.CustomersTotal)
	})
}

// TestGrantRepo_HasActiveGrantForProductEmail pins the contract Task 18
// depends on. Because grants has no grantee_email column, the query
// inner-joins invitations on invitation_id and reads email from there.
// That means this test needs a seeded invitation per grant. Directly
// issued grants (invitation_id IS NULL) are intentionally excluded —
// they have no email of record to deduplicate against.
func TestGrantRepo_HasActiveGrantForProductEmail(t *testing.T) {
	ctx, repo, f := setupGrantRepo(t)

	// Seed an identity so invitations.created_by_identity_id FK holds.
	issuerID := core.NewIdentityID()
	_, err := f.tx.Exec(ctx,
		`INSERT INTO identities (id, email, password_hash, created_at, updated_at)
		 VALUES ($1, $2, 'hash', NOW(), NOW())`,
		uuid.UUID(issuerID), "issuer-"+issuerID.String()[:8]+"@example.com",
	)
	require.NoError(t, err, "seed issuer identity")

	// seedGrantWithInvitation inserts an invitation+grant pair linked by
	// invitation_id so the JOIN in HasActiveGrantForProductEmail resolves.
	// email is stored as-is (caller may mix case); productID + status are
	// controlled per call.
	seedGrantWithInvitation := func(t *testing.T, email string, productID core.ProductID, status domain.GrantStatus) core.GrantID {
		t.Helper()
		invID := core.NewInvitationID()
		now := time.Now().UTC()
		draft := json.RawMessage(`{"product_id":"` + productID.String() + `","capabilities":["LICENSE_CREATE"]}`)
		_, err := f.tx.Exec(ctx,
			`INSERT INTO invitations (id, kind, email, token_hash, grant_draft,
				created_by_identity_id, created_by_account_id,
				expires_at, created_at)
			 VALUES ($1, 'grant', $2, $3, $4::jsonb, $5, $6, $7, $8)`,
			uuid.UUID(invID), email, "hash-"+invID.String(), string(draft),
			uuid.UUID(issuerID), uuid.UUID(f.grantorAccountID),
			now.Add(24*time.Hour), now,
		)
		require.NoError(t, err, "seed invitation")

		gID := core.NewGrantID()
		g := &domain.Grant{
			ID:               gID,
			GrantorAccountID: f.grantorAccountID,
			GranteeAccountID: f.granteeAccountID,
			ProductID:        productID,
			Status:           status,
			Capabilities:     []domain.GrantCapability{domain.GrantCapLicenseRead},
			Constraints:      json.RawMessage("{}"),
			InvitationID:     &invID,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		require.NoError(t, repo.Create(ctx, g), "create grant")
		return gID
	}

	// Baseline: active grant for (grantor, Partner@Acme.com, productA).
	_ = seedGrantWithInvitation(t, "Partner@Acme.com", f.productA, domain.GrantStatusActive)

	t.Run("matches same (grantor, email, product)", func(t *testing.T) {
		has, err := repo.HasActiveGrantForProductEmail(ctx, f.grantorAccountID, "partner@acme.com", f.productA)
		require.NoError(t, err)
		assert.True(t, has, "active grant with matching invitation email should match")
	})

	t.Run("no match on different product", func(t *testing.T) {
		has, err := repo.HasActiveGrantForProductEmail(ctx, f.grantorAccountID, "partner@acme.com", f.productB)
		require.NoError(t, err)
		assert.False(t, has, "different product must not match")
	})

	t.Run("case-insensitive on row side", func(t *testing.T) {
		// Email stored as "Partner@Acme.com"; param passed already-lowercased.
		has, err := repo.HasActiveGrantForProductEmail(ctx, f.grantorAccountID, "partner@acme.com", f.productA)
		require.NoError(t, err)
		assert.True(t, has, "lower(i.email) must match mixed-case stored email")
	})

	t.Run("status discrimination", func(t *testing.T) {
		// Seed a second (grantor, email, productB) pair and walk it
		// through each status — pending/active/suspended match; revoked,
		// expired, and left do not.
		targetEmail := "walker@acme.com"
		gID := seedGrantWithInvitation(t, targetEmail, f.productB, domain.GrantStatusPending)

		cases := []struct {
			status domain.GrantStatus
			want   bool
		}{
			{domain.GrantStatusPending, true},
			{domain.GrantStatusActive, true},
			{domain.GrantStatusSuspended, true},
			{domain.GrantStatusRevoked, false},
			{domain.GrantStatusExpired, false},
			{domain.GrantStatusLeft, false},
		}
		for _, c := range cases {
			t.Run(string(c.status), func(t *testing.T) {
				require.NoError(t, repo.UpdateStatus(ctx, gID, c.status))
				has, err := repo.HasActiveGrantForProductEmail(ctx, f.grantorAccountID, targetEmail, f.productB)
				require.NoError(t, err)
				assert.Equal(t, c.want, has, "status=%s should be matchable=%v", c.status, c.want)
			})
		}
	})

	t.Run("directly-issued grant (no invitation) is not matched", func(t *testing.T) {
		// insertTestGrant leaves InvitationID nil — the INNER JOIN on
		// invitations drops it, so the EXISTS query returns false for
		// its (grantor, email, product) triple. This is by design: a
		// direct grant has no email of record.
		_ = insertTestGrant(t, ctx, repo, f, withProduct(f.productA))
		// Use an email that definitely has no invitation-backed grant.
		has, err := repo.HasActiveGrantForProductEmail(ctx, f.grantorAccountID, "no-invite@acme.com", f.productA)
		require.NoError(t, err)
		assert.False(t, has, "grants without invitation_id cannot satisfy the duplicate guard")
	})
}

func TestGrantRepo_ListExpirable(t *testing.T) {
	ctx, repo, f := setupGrantRepo(t)

	past := time.Now().Add(-1 * time.Hour).UTC()
	future := time.Now().Add(24 * time.Hour).UTC()

	expirable := insertTestGrant(t, ctx, repo, f, withExpiresAt(past))
	_ = insertTestGrant(t, ctx, repo, f, withExpiresAt(future))
	_ = insertTestGrant(t, ctx, repo, f) // no expires_at
	revokedPast := insertTestGrant(t, ctx, repo, f, withExpiresAt(past))
	require.NoError(t, repo.UpdateStatus(ctx, revokedPast.ID, domain.GrantStatusRevoked))

	rows, err := repo.ListExpirable(ctx, time.Now().UTC(), 100)
	require.NoError(t, err)
	// Scope to our fixture's grants — the rollback-only tx means our
	// inserts are visible to our own tx, so rows should be exactly {expirable}.
	// ListExpirable runs without tenant filter param, but RLS scopes by
	// the ambient GUC (grantor account) — only our grants surface.
	// Filter defensively in case the tx model ever changes.
	var ours []domain.Grant
	for _, r := range rows {
		if r.GrantorAccountID == f.grantorAccountID {
			ours = append(ours, r)
		}
	}
	require.Len(t, ours, 1)
	assert.Equal(t, expirable.ID, ours[0].ID)
}
