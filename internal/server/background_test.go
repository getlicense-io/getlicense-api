package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/db"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Integration test for the expire_grants background job. Mirrors the
// gating convention of internal/db/*_test.go: `-short` skips, and
// `make test-all` runs against the dev Postgres. Seed is committed via
// the pool (not a rollback-only tx) because expireGrantsTick opens its
// own WithTx against the pool — a nested tx isn't possible.

const integrationDefaultDBURL = "postgres://getlicense:getlicense@localhost:5432/getlicense?sslmode=disable"

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

// TestExpireGrantsTick_FlipsPastExpiresAtToExpired verifies the
// background sweep transitions a grant with expires_at in the past to
// GrantStatusExpired and emits a core.EventTypeGrantExpired event with
// system attribution.
func TestExpireGrantsTick_FlipsPastExpiresAtToExpired(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()

	// Seed two accounts (grantor + grantee) + a product to satisfy the
	// grants FKs and the grants_not_self_grant CHECK.
	grantorID := core.NewAccountID()
	granteeID := core.NewAccountID()
	productID := core.NewProductID()
	grantID := core.NewGrantID()

	slugG := "bg-grantor-" + grantorID.String()[:8]
	slugGr := "bg-grantee-" + granteeID.String()[:8]
	_, err := pool.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(grantorID), "BG Grantor", slugG,
	)
	require.NoError(t, err, "seed grantor")
	_, err = pool.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(granteeID), "BG Grantee", slugGr,
	)
	require.NoError(t, err, "seed grantee")

	_, err = pool.Exec(ctx,
		`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
		uuid.UUID(productID), uuid.UUID(grantorID),
		"BG Product", "bg-product-"+grantorID.String()[:8], "test-pub-key", []byte{0x00}, `{}`,
	)
	require.NoError(t, err, "seed product")

	past := time.Now().UTC().Add(-1 * time.Hour)
	_, err = pool.Exec(ctx,
		`INSERT INTO grants (id, grantor_account_id, grantee_account_id, product_id, status, capabilities, constraints, expires_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'active', ARRAY['LICENSE_READ']::text[], '{}'::jsonb, $5, NOW(), NOW())`,
		uuid.UUID(grantID), uuid.UUID(grantorID), uuid.UUID(granteeID),
		uuid.UUID(productID), past,
	)
	require.NoError(t, err, "seed grant")

	// Clean up grants, events, products, and accounts after the test so
	// we don't pollute the dev DB.
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = pool.Exec(cctx, `DELETE FROM domain_events WHERE resource_type = 'grant' AND resource_id = $1`, grantID.String())
		_, _ = pool.Exec(cctx, `DELETE FROM grants WHERE id = $1`, uuid.UUID(grantID))
		_, _ = pool.Exec(cctx, `DELETE FROM products WHERE id = $1`, uuid.UUID(productID))
		_, _ = pool.Exec(cctx, `DELETE FROM accounts WHERE id IN ($1, $2)`, uuid.UUID(grantorID), uuid.UUID(granteeID))
	})

	// Wire the minimum deps and run the tick.
	txManager := db.NewTxManager(pool)
	grantRepo := db.NewGrantRepo(pool)
	domainEventRepo := db.NewDomainEventRepo(pool)
	auditWriter := audit.NewWriter(domainEventRepo)

	flipped, err := expireGrantsTick(ctx, grantRepo, txManager, auditWriter)
	require.NoError(t, err, "expireGrantsTick")
	assert.GreaterOrEqual(t, flipped, 1, "at least the seeded grant should flip")

	// Grant status should now be 'expired'. Fetch via the pool
	// directly — the RLS escape hatch (NULLIF) lets an unset GUC pass
	// through, matching how the background job itself reads.
	var status string
	err = pool.QueryRow(ctx, `SELECT status FROM grants WHERE id = $1`, uuid.UUID(grantID)).Scan(&status)
	require.NoError(t, err, "fetch grant status")
	assert.Equal(t, string(domain.GrantStatusExpired), status)

	// Exactly one grant.expired event should have been written with
	// system attribution pointing at the grantor account. Separate the
	// count check from the row fetch so a second emit would surface as
	// a test failure instead of being silently truncated by QueryRow.
	var evtCount int
	err = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM domain_events
		 WHERE resource_type = 'grant' AND resource_id = $1`,
		grantID.String(),
	).Scan(&evtCount)
	require.NoError(t, err, "count grant events")
	assert.Equal(t, 1, evtCount, "exactly one grant.expired event per flipped grant")

	var (
		actorKind  string
		eventType  string
		acctID     uuid.UUID
		resourceID string
	)
	err = pool.QueryRow(ctx,
		`SELECT actor_kind, event_type, account_id, resource_id
		 FROM domain_events
		 WHERE resource_type = 'grant' AND resource_id = $1`,
		grantID.String(),
	).Scan(&actorKind, &eventType, &acctID, &resourceID)
	require.NoError(t, err, "fetch grant.expired event")
	assert.Equal(t, string(core.ActorKindSystem), actorKind)
	assert.Equal(t, string(core.EventTypeGrantExpired), eventType)
	assert.Equal(t, uuid.UUID(grantorID), acctID)
	assert.Equal(t, grantID.String(), resourceID)
}
