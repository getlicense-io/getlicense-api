package db

import (
	"context"
	"fmt"
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

// Integration tests for ChannelRepo.
//
// Each test opens its own pool, begins a top-level tx, seeds three accounts
// (vendor, partner, unrelated), and ALWAYS rolls back on cleanup. No test
// pollutes the dev DB. `-short` skips.
//
// RLS context is switched inside the ambient tx via:
//
//	SET LOCAL app.current_account_id = '<uuid>'
//
// The dual-branch USING policy on channels allows rows where the GUC matches
// either vendor_account_id or partner_account_id.

type channelFixture struct {
	ctx            context.Context
	tx             pgx.Tx
	pool           *pgxpool.Pool
	vendorAccount  core.AccountID
	partnerAccount core.AccountID
	otherAccount   core.AccountID
}

// newChannelFixture seeds three accounts and returns the fixture with the
// ambient tx pinned to the vendor's RLS context. The tx is rolled back on
// cleanup so nothing persists beyond the test.
func newChannelFixture(t *testing.T, pool *pgxpool.Pool) *channelFixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "begin tx")
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	vendorID := core.NewAccountID()
	partnerID := core.NewAccountID()
	otherID := core.NewAccountID()

	// Seed three accounts.
	for _, row := range []struct {
		id   uuid.UUID
		name string
		slug string
	}{
		{uuid.UUID(vendorID), "Test Vendor", "vendor-" + vendorID.String()[:8]},
		{uuid.UUID(partnerID), "Test Partner", "partner-" + partnerID.String()[:8]},
		{uuid.UUID(otherID), "Test Other", "other-" + otherID.String()[:8]},
	} {
		_, err = tx.Exec(ctx,
			`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
			row.id, row.name, row.slug,
		)
		require.NoError(t, err, "seed account %s", row.name)
	}

	// Pin RLS context to vendor for the initial inserts.
	_, err = tx.Exec(ctx,
		`SELECT set_config('app.current_account_id', $1, true)`, vendorID.String())
	require.NoError(t, err, "set_config vendor account")
	_, err = tx.Exec(ctx,
		`SELECT set_config('app.current_environment', $1, true)`, "live")
	require.NoError(t, err, "set_config env")

	ctx = context.WithValue(ctx, ctxKey{}, tx)

	return &channelFixture{
		ctx:            ctx,
		tx:             tx,
		pool:           pool,
		vendorAccount:  vendorID,
		partnerAccount: partnerID,
		otherAccount:   otherID,
	}
}

// insertTestChannel inserts a channel directly via SQL using the ambient tx.
// The ambient tx must already carry a vendor RLS context that matches the
// vendor argument (or system_context must be set). Returns the new ChannelID.
func insertTestChannel(
	t *testing.T,
	ctx context.Context,
	vendor, partner core.AccountID,
	name string,
	status domain.ChannelStatus,
) core.ChannelID {
	t.Helper()
	tx, ok := ctx.Value(ctxKey{}).(pgx.Tx)
	require.True(t, ok, "ctx must carry ambient tx")

	id := core.NewChannelID()
	now := time.Now().UTC()
	_, err := tx.Exec(ctx,
		`INSERT INTO channels
			(id, vendor_account_id, partner_account_id, name, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $6)`,
		uuid.UUID(id),
		uuid.UUID(vendor),
		uuid.UUID(partner),
		name,
		string(status),
		now,
	)
	require.NoError(t, err, "insert channel %q", name)
	return id
}

// setRLSAccount switches the GUC inside the ambient tx so the next repo call
// runs under a different account's RLS context.
func setRLSAccount(t *testing.T, ctx context.Context, accountID core.AccountID) {
	t.Helper()
	tx, ok := ctx.Value(ctxKey{}).(pgx.Tx)
	require.True(t, ok, "ctx must carry ambient tx for setRLSAccount")
	_, err := tx.Exec(ctx,
		`SELECT set_config('app.current_account_id', $1, true)`, accountID.String())
	require.NoError(t, err, "setRLSAccount to %s", accountID)
}

// setupChannelRepo is the canonical entry point for channel repo integration
// tests. Returns a tx-scoped ctx pinned to the vendor, a fresh *ChannelRepo,
// and the seeded fixture.
func setupChannelRepo(t *testing.T) (context.Context, *ChannelRepo, *channelFixture) {
	t.Helper()
	pool := integrationPool(t)
	f := newChannelFixture(t, pool)
	return f.ctx, NewChannelRepo(pool), f
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestChannelRepo_GetAndListByVendor(t *testing.T) {
	ctx, repo, f := setupChannelRepo(t)

	name := fmt.Sprintf("acme-channel-%s", f.vendorAccount.String()[:8])
	id := insertTestChannel(t, ctx, f.vendorAccount, f.partnerAccount, name, domain.ChannelStatusActive)

	// Get by ID.
	got, err := repo.Get(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got, "Get must return the inserted channel")
	assert.Equal(t, id, got.ID)
	assert.Equal(t, name, got.Name)
	assert.Equal(t, domain.ChannelStatusActive, got.Status)
	assert.Equal(t, f.vendorAccount, got.VendorAccountID)
	require.NotNil(t, got.PartnerAccountID)
	assert.Equal(t, f.partnerAccount, *got.PartnerAccountID)

	// AccountSummary embeds must be populated.
	require.NotNil(t, got.VendorAccount, "VendorAccount embed should be non-nil")
	assert.Equal(t, f.vendorAccount, got.VendorAccount.ID)
	require.NotNil(t, got.PartnerAccount, "PartnerAccount embed should be non-nil")
	assert.Equal(t, f.partnerAccount, got.PartnerAccount.ID)

	// ListByVendor should include the channel.
	list, hasMore, err := repo.ListByVendor(ctx, f.vendorAccount, domain.ChannelListFilter{}, core.Cursor{}, 50)
	require.NoError(t, err)
	assert.False(t, hasMore)
	require.Len(t, list, 1)
	assert.Equal(t, id, list[0].ID)
}

func TestChannelRepo_PartialUniqueIndex(t *testing.T) {
	ctx, _, f := setupChannelRepo(t)

	name := fmt.Sprintf("conflict-channel-%s", f.vendorAccount.String()[:8])

	// First insert should succeed.
	id1 := insertTestChannel(t, ctx, f.vendorAccount, f.partnerAccount, name, domain.ChannelStatusActive)
	require.NotEmpty(t, id1, "first insert must succeed")

	// Second insert with the same vendor, partner, name should fail (partial
	// unique index fires while status != 'closed'). Use a savepoint so we
	// can recover the tx after the intentional constraint violation.
	ambientTx, ok := ctx.Value(ctxKey{}).(pgx.Tx)
	require.True(t, ok)

	_, err := ambientTx.Exec(ctx, `SAVEPOINT before_dup`)
	require.NoError(t, err, "create savepoint")

	id2 := core.NewChannelID()
	now := time.Now().UTC()
	_, insertErr := ambientTx.Exec(ctx,
		`INSERT INTO channels
			(id, vendor_account_id, partner_account_id, name, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'active', $5, $5)`,
		uuid.UUID(id2),
		uuid.UUID(f.vendorAccount),
		uuid.UUID(f.partnerAccount),
		name,
		now,
	)
	require.Error(t, insertErr, "duplicate name must be rejected by partial unique index")

	// Roll back to savepoint so the tx is no longer in an aborted state.
	_, err = ambientTx.Exec(ctx, `ROLLBACK TO SAVEPOINT before_dup`)
	require.NoError(t, err, "rollback to savepoint")

	// Close the first channel via raw SQL (UpdateStatus is not yet
	// implemented in P0).
	_, err = ambientTx.Exec(ctx,
		`UPDATE channels SET status='closed', closed_at=NOW() WHERE id=$1`,
		uuid.UUID(id1),
	)
	require.NoError(t, err, "close first channel")

	// After closing, the same name must be reusable (partial index does not
	// cover closed rows).
	id3 := insertTestChannel(t, ctx, f.vendorAccount, f.partnerAccount, name, domain.ChannelStatusActive)
	require.NotEmpty(t, id3, "insert after close must succeed — partial index released the name")
}

func TestChannelRepo_RLS_VendorCanRead(t *testing.T) {
	ctx, repo, f := setupChannelRepo(t)

	name := fmt.Sprintf("vendor-visible-%s", f.vendorAccount.String()[:8])
	id := insertTestChannel(t, ctx, f.vendorAccount, f.partnerAccount, name, domain.ChannelStatusActive)

	// Context is already scoped to the vendor — Get must succeed.
	setRLSAccount(t, ctx, f.vendorAccount)

	got, err := repo.Get(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got, "vendor should be able to read the channel they own")
	assert.Equal(t, id, got.ID)

	// ListByVendor must also return the channel.
	list, _, err := repo.ListByVendor(ctx, f.vendorAccount, domain.ChannelListFilter{}, core.Cursor{}, 50)
	require.NoError(t, err)
	found := false
	for _, ch := range list {
		if ch.ID == id {
			found = true
			break
		}
	}
	assert.True(t, found, "ListByVendor must include the channel under vendor's RLS context")
}

func TestChannelRepo_RLS_PartnerCanRead(t *testing.T) {
	ctx, repo, f := setupChannelRepo(t)

	name := fmt.Sprintf("partner-visible-%s", f.vendorAccount.String()[:8])
	id := insertTestChannel(t, ctx, f.vendorAccount, f.partnerAccount, name, domain.ChannelStatusActive)

	// Switch RLS context to the partner account.
	setRLSAccount(t, ctx, f.partnerAccount)

	got, err := repo.Get(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got, "partner should be able to read a channel where they are the partner")
	assert.Equal(t, id, got.ID)
}

func TestChannelRepo_RLS_UnrelatedAccountCannotRead(t *testing.T) {
	ctx, repo, f := setupChannelRepo(t)

	name := fmt.Sprintf("hidden-from-other-%s", f.vendorAccount.String()[:8])
	id := insertTestChannel(t, ctx, f.vendorAccount, f.partnerAccount, name, domain.ChannelStatusActive)

	// Switch RLS context to the unrelated third account.
	setRLSAccount(t, ctx, f.otherAccount)

	got, err := repo.Get(ctx, id)
	require.NoError(t, err)
	assert.Nil(t, got, "unrelated account must not see the channel (RLS should filter it out)")

	// ListByVendor under the other account should return zero results.
	list, _, err := repo.ListByVendor(ctx, f.vendorAccount, domain.ChannelListFilter{}, core.Cursor{}, 50)
	require.NoError(t, err)
	assert.Empty(t, list, "ListByVendor must return no rows when RLS context is an unrelated account")
}
