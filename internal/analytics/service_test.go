package analytics

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/db"
)

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

func TestSnapshot_LicensesViaGrantsIsEnvironmentScoped(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	txm := db.NewTxManager(pool)

	accountID := core.NewAccountID()
	granteeID := core.NewAccountID()
	productID := core.NewProductID()
	policyID := core.NewPolicyID()
	customerID := core.NewCustomerID()
	grantID := core.NewGrantID()
	liveLicenseID := core.NewLicenseID()
	testLicenseID := core.NewLicenseID()

	// UUIDv7 IDs share a time-ordered prefix; use the random tail so
	// concurrent test runs never collide on slug uniqueness.
	tail := func(s string) string { return s[len(s)-12:] }

	t.Cleanup(func() {
		cctx := context.Background()
		// Cleanup runs under WithSystemContext — DELETEs against
		// tenant-scoped tables would otherwise fail closed under the
		// new RLS (PR-B / migration 034).
		_ = txm.WithSystemContext(cctx, func(ctx context.Context) error {
			pgxq := db.Conn(ctx, pool)
			_, _ = pgxq.Exec(ctx, `DELETE FROM licenses WHERE id IN ($1, $2)`, uuid.UUID(liveLicenseID), uuid.UUID(testLicenseID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM grants WHERE id = $1`, uuid.UUID(grantID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM customers WHERE id = $1`, uuid.UUID(customerID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM policies WHERE id = $1`, uuid.UUID(policyID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM products WHERE id = $1`, uuid.UUID(productID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM accounts WHERE id IN ($1, $2)`, uuid.UUID(accountID), uuid.UUID(granteeID))
			return nil
		})
	})

	// Seed everything under WithSystemContext — products, policies,
	// customers, grants, and licenses are all RLS-scoped tables that
	// reject bare-pool writes after migration 034.
	require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
		pgxq := db.Conn(ctx, pool)
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
			uuid.UUID(accountID), "Analytics Grantor", "analytics-grantor-"+tail(accountID.String()),
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
			uuid.UUID(granteeID), "Analytics Grantee", "analytics-grantee-"+tail(granteeID.String()),
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb, NOW())`,
			uuid.UUID(productID), uuid.UUID(accountID), "Analytics Product",
			"analytics-product-"+tail(productID.String()), "test-pub-key", []byte{0x00},
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO policies (id, account_id, product_id, name, is_default, expiration_strategy, expiration_basis,
			 max_machines, max_seats, floating, strict, require_checkout, checkout_interval_sec,
			 max_checkout_duration_sec, checkout_grace_sec, component_matching_strategy, metadata, created_at, updated_at)
			 VALUES ($1, $2, $3, 'Default', true, 'REVOKE_ACCESS', 'FROM_CREATION',
			 NULL, NULL, false, false, false, 86400, 604800, 86400, 'MATCH_ANY', '{}'::jsonb, NOW(), NOW())`,
			uuid.UUID(policyID), uuid.UUID(accountID), uuid.UUID(productID),
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO customers (id, account_id, email, metadata, created_at, updated_at)
			 VALUES ($1, $2, $3, '{}'::jsonb, NOW(), NOW())`,
			uuid.UUID(customerID), uuid.UUID(accountID), "analytics-"+tail(customerID.String())+"@example.com",
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO grants (id, grantor_account_id, grantee_account_id, product_id, status, capabilities, constraints, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, 'active', ARRAY['LICENSE_CREATE']::text[], '{}'::jsonb, NOW(), NOW())`,
			uuid.UUID(grantID), uuid.UUID(accountID), uuid.UUID(granteeID), uuid.UUID(productID),
		); err != nil {
			return err
		}
		insertLicense := func(id core.LicenseID, env core.Environment, keyHash string) error {
			_, err := pgxq.Exec(ctx,
				`INSERT INTO licenses (id, account_id, product_id, key_prefix, key_hash, token, status,
				 created_at, updated_at, environment, grant_id, created_by_account_id, policy_id, overrides, customer_id)
				 VALUES ($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW(), $7, $8, $9, $10, '{}'::jsonb, $11)`,
				uuid.UUID(id), uuid.UUID(accountID), uuid.UUID(productID), "GLTEST", keyHash, "gl1.test",
				string(env), uuid.UUID(grantID), uuid.UUID(granteeID), uuid.UUID(policyID), uuid.UUID(customerID),
			)
			return err
		}
		if err := insertLicense(liveLicenseID, core.EnvironmentLive, "analytics-live-"+liveLicenseID.String()); err != nil {
			return err
		}
		if err := insertLicense(testLicenseID, core.EnvironmentTest, "analytics-test-"+testLicenseID.String()); err != nil {
			return err
		}
		return nil
	}), "seed analytics fixture")

	svc := NewService(
		db.NewTxManager(pool),
		db.NewLicenseRepo(pool),
		db.NewMachineRepo(pool),
		db.NewCustomerRepo(pool),
		db.NewGrantRepo(pool),
		db.NewDomainEventRepo(pool),
	)
	snap, err := svc.Snapshot(ctx, accountID, core.EnvironmentLive, time.Now().UTC().Add(-24*time.Hour), time.Now().UTC())
	require.NoError(t, err, "snapshot")

	assert.Equal(t, 1, snap.Licenses.Total, "live snapshot should see only live licenses via RLS")
	assert.Equal(t, 1, snap.Grants.ActiveGrants, "active grants are account-scoped")
	assert.Equal(t, 1, snap.Grants.LicensesViaGrants, "grant-issued license count must match the requested environment")
}
