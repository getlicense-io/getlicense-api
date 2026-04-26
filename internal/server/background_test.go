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
// WithSystemContext (PR-B / migration 034) because expireGrantsTick
// opens its own WithSystemContext against the pool — a nested tx
// isn't possible, and the new fail-closed RLS rejects bare-pool writes
// on tenant-scoped tables.

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
	txManager := db.NewTxManager(pool)

	// Seed two accounts (grantor + grantee) + a product to satisfy the
	// grants FKs and the grants_not_self_grant CHECK.
	grantorID := core.NewAccountID()
	granteeID := core.NewAccountID()
	productID := core.NewProductID()
	grantID := core.NewGrantID()

	// UUIDv7 IDs share a time-ordered prefix; use the random tail so
	// two slugs in the same test never collide.
	tail := func(s string) string { return s[len(s)-12:] }
	slugG := "bg-grantor-" + tail(grantorID.String())
	slugGr := "bg-grantee-" + tail(granteeID.String())

	require.NoError(t, txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		pgxq := db.Conn(ctx, pool)
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
			uuid.UUID(grantorID), "BG Grantor", slugG,
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
			uuid.UUID(granteeID), "BG Grantee", slugGr,
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
			uuid.UUID(productID), uuid.UUID(grantorID),
			"BG Product", "bg-product-"+tail(grantorID.String()), "test-pub-key", []byte{0x00}, `{}`,
		); err != nil {
			return err
		}
		past := time.Now().UTC().Add(-1 * time.Hour)
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO grants (id, grantor_account_id, grantee_account_id, product_id, status, capabilities, constraints, expires_at, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, 'active', ARRAY['LICENSE_READ']::text[], '{}'::jsonb, $5, NOW(), NOW())`,
			uuid.UUID(grantID), uuid.UUID(grantorID), uuid.UUID(granteeID),
			uuid.UUID(productID), past,
		); err != nil {
			return err
		}
		return nil
	}), "seed fixtures")

	// Clean up grants, events, products, and accounts after the test so
	// we don't pollute the dev DB. Cleanup also runs under
	// WithSystemContext so DELETEs against tenant-scoped tables succeed.
	t.Cleanup(func() {
		cctx := context.Background()
		_ = txManager.WithSystemContext(cctx, func(ctx context.Context) error {
			pgxq := db.Conn(ctx, pool)
			_, _ = pgxq.Exec(ctx, `DELETE FROM domain_events WHERE resource_type = 'grant' AND resource_id = $1`, grantID.String())
			_, _ = pgxq.Exec(ctx, `DELETE FROM grants WHERE id = $1`, uuid.UUID(grantID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM products WHERE id = $1`, uuid.UUID(productID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM accounts WHERE id IN ($1, $2)`, uuid.UUID(grantorID), uuid.UUID(granteeID))
			return nil
		})
	})

	// Wire the minimum deps and run the tick.
	grantRepo := db.NewGrantRepo(pool)
	domainEventRepo := db.NewDomainEventRepo(pool)
	auditWriter := audit.NewWriter(domainEventRepo)

	flipped, err := expireGrantsTick(ctx, grantRepo, txManager, auditWriter)
	require.NoError(t, err, "expireGrantsTick")
	assert.GreaterOrEqual(t, flipped, 1, "at least the seeded grant should flip")

	// Grant status should now be 'expired'. Read under WithSystemContext
	// so the new fail-closed RLS (PR-B / migration 034) doesn't reject
	// the lookup.
	var status string
	require.NoError(t, txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		return db.Conn(ctx, pool).QueryRow(ctx,
			`SELECT status FROM grants WHERE id = $1`, uuid.UUID(grantID),
		).Scan(&status)
	}), "fetch grant status")
	assert.Equal(t, string(domain.GrantStatusExpired), status)

	// Exactly one grant.expired event should have been written with
	// system attribution pointing at the grantor account. Separate the
	// count check from the row fetch so a second emit would surface as
	// a test failure instead of being silently truncated by QueryRow.
	var evtCount int
	require.NoError(t, txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		return db.Conn(ctx, pool).QueryRow(ctx,
			`SELECT COUNT(*) FROM domain_events
			 WHERE resource_type = 'grant' AND resource_id = $1`,
			grantID.String(),
		).Scan(&evtCount)
	}), "count grant events")
	assert.Equal(t, 1, evtCount, "exactly one grant.expired event per flipped grant")

	var (
		actorKind  string
		eventType  string
		acctID     uuid.UUID
		resourceID string
	)
	require.NoError(t, txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		return db.Conn(ctx, pool).QueryRow(ctx,
			`SELECT actor_kind, event_type, account_id, resource_id
			 FROM domain_events
			 WHERE resource_type = 'grant' AND resource_id = $1`,
			grantID.String(),
		).Scan(&actorKind, &eventType, &acctID, &resourceID)
	}), "fetch grant.expired event")
	assert.Equal(t, string(core.ActorKindSystem), actorKind)
	assert.Equal(t, string(core.EventTypeGrantExpired), eventType)
	assert.Equal(t, uuid.UUID(grantorID), acctID)
	assert.Equal(t, grantID.String(), resourceID)
}
