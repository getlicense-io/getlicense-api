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

	accountID := core.NewAccountID()
	granteeID := core.NewAccountID()
	productID := core.NewProductID()
	policyID := core.NewPolicyID()
	customerID := core.NewCustomerID()
	grantID := core.NewGrantID()
	liveLicenseID := core.NewLicenseID()
	testLicenseID := core.NewLicenseID()

	_, err := pool.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(accountID), "Analytics Grantor", "analytics-grantor-"+accountID.String()[:8],
	)
	require.NoError(t, err, "seed grantor account")
	_, err = pool.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(granteeID), "Analytics Grantee", "analytics-grantee-"+granteeID.String()[:8],
	)
	require.NoError(t, err, "seed grantee account")

	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = pool.Exec(cctx, `DELETE FROM licenses WHERE id IN ($1, $2)`, uuid.UUID(liveLicenseID), uuid.UUID(testLicenseID))
		_, _ = pool.Exec(cctx, `DELETE FROM grants WHERE id = $1`, uuid.UUID(grantID))
		_, _ = pool.Exec(cctx, `DELETE FROM customers WHERE id = $1`, uuid.UUID(customerID))
		_, _ = pool.Exec(cctx, `DELETE FROM policies WHERE id = $1`, uuid.UUID(policyID))
		_, _ = pool.Exec(cctx, `DELETE FROM products WHERE id = $1`, uuid.UUID(productID))
		_, _ = pool.Exec(cctx, `DELETE FROM accounts WHERE id IN ($1, $2)`, uuid.UUID(accountID), uuid.UUID(granteeID))
	})

	_, err = pool.Exec(ctx,
		`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb, NOW())`,
		uuid.UUID(productID), uuid.UUID(accountID), "Analytics Product",
		"analytics-product-"+productID.String()[:8], "test-pub-key", []byte{0x00},
	)
	require.NoError(t, err, "seed product")

	_, err = pool.Exec(ctx,
		`INSERT INTO policies (id, account_id, product_id, name, is_default, expiration_strategy, expiration_basis,
		 max_machines, max_seats, floating, strict, require_checkout, checkout_interval_sec,
		 max_checkout_duration_sec, checkout_grace_sec, component_matching_strategy, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, 'Default', true, 'REVOKE_ACCESS', 'FROM_CREATION',
		 NULL, NULL, false, false, false, 86400, 604800, 86400, 'MATCH_ANY', '{}'::jsonb, NOW(), NOW())`,
		uuid.UUID(policyID), uuid.UUID(accountID), uuid.UUID(productID),
	)
	require.NoError(t, err, "seed policy")

	_, err = pool.Exec(ctx,
		`INSERT INTO customers (id, account_id, email, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, '{}'::jsonb, NOW(), NOW())`,
		uuid.UUID(customerID), uuid.UUID(accountID), "analytics-"+customerID.String()[:8]+"@example.com",
	)
	require.NoError(t, err, "seed customer")

	_, err = pool.Exec(ctx,
		`INSERT INTO grants (id, grantor_account_id, grantee_account_id, product_id, status, capabilities, constraints, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'active', ARRAY['LICENSE_CREATE']::text[], '{}'::jsonb, NOW(), NOW())`,
		uuid.UUID(grantID), uuid.UUID(accountID), uuid.UUID(granteeID), uuid.UUID(productID),
	)
	require.NoError(t, err, "seed grant")

	insertLicense := func(id core.LicenseID, env core.Environment, keyHash string) {
		t.Helper()
		_, err := pool.Exec(ctx,
			`INSERT INTO licenses (id, account_id, product_id, key_prefix, key_hash, token, status,
			 created_at, updated_at, environment, grant_id, created_by_account_id, policy_id, overrides, customer_id)
			 VALUES ($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW(), $7, $8, $9, $10, '{}'::jsonb, $11)`,
			uuid.UUID(id), uuid.UUID(accountID), uuid.UUID(productID), "GLTEST", keyHash, "gl1.test",
			string(env), uuid.UUID(grantID), uuid.UUID(granteeID), uuid.UUID(policyID), uuid.UUID(customerID),
		)
		require.NoError(t, err, "seed %s license", env)
	}
	insertLicense(liveLicenseID, core.EnvironmentLive, "analytics-live-"+liveLicenseID.String())
	insertLicense(testLicenseID, core.EnvironmentTest, "analytics-test-"+testLicenseID.String())

	svc := NewService(pool, db.NewTxManager(pool))
	snap, err := svc.Snapshot(ctx, accountID, core.EnvironmentLive, time.Now().UTC().Add(-24*time.Hour), time.Now().UTC())
	require.NoError(t, err, "snapshot")

	assert.Equal(t, 1, snap.Licenses.Total, "live snapshot should see only live licenses via RLS")
	assert.Equal(t, 1, snap.Grants.ActiveGrants, "active grants are account-scoped")
	assert.Equal(t, 1, snap.Grants.LicensesViaGrants, "grant-issued license count must match the requested environment")
}
