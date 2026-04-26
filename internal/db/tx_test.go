package db

import (
	"context"
	"errors"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConn_ReturnsPoolWhenNoTx(t *testing.T) {
	// conn with no tx in context should return the pool (as a querier)
	// We can't test with a real pool here, but we can verify the type assertion path
	ctx := context.Background()
	// When there's no tx in context, conn should not panic and should return non-nil
	// We pass nil pool to verify the fallback path (it returns the pool, which is nil)
	result := conn(ctx, nil)
	assert.Nil(t, result)
}

// TestRLS_BarePoolReadFailsClosed verifies the new explicit-bypass RLS
// (PR-B / migration 034). A read against an RLS-enabled table without
// either WithTargetAccount or WithSystemContext must fail closed —
// the predicate compares against a sentinel UUID
// ('00000000-0000-0000-0000-000000000000') that cannot match any real
// row (UUIDv7 IDs always have a nonzero timestamp prefix), so the
// query returns zero rows instead of silently leaking another
// tenant's data.
//
// This is the regression guard for the security fix: the previous
// fail-open behavior (NULLIF(...) IS NULL escape hatch) would have
// returned ALL rows from any tenant when current_account_id was unset.
//
// (An earlier draft of this PR used a sentinel string that triggered
// `invalid input syntax for type uuid` at runtime, but PostgreSQL's
// planner inlines RLS predicates from sub-table EXISTS subqueries and
// evaluates the cast at plan time even under WithSystemContext, which
// broke legitimate cross-tenant queries. The sentinel-UUID approach
// loses diagnostic value but preserves the security invariant.)
func TestRLS_BarePoolReadFailsClosed(t *testing.T) {
	pool := integrationPool(t)
	txm := NewTxManager(pool)
	ctx := context.Background()

	// Seed a license-bearing account inside a system tx, then commit
	// it (so it survives outside our system tx). We clean up at the end
	// of the test.
	accountID := core.NewAccountID()
	productID := core.NewProductID()
	customerID := core.NewCustomerID()
	policyID := core.NewPolicyID()
	licenseID := core.NewLicenseID()
	slug := "rls-bare-" + accountID.String()[:8]

	cleanup := func() {
		cctx := context.Background()
		_ = txm.WithSystemContext(cctx, func(ctx context.Context) error {
			pgxq := Conn(ctx, pool)
			_, _ = pgxq.Exec(ctx, `DELETE FROM licenses WHERE id = $1`, uuid.UUID(licenseID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM policies WHERE id = $1`, uuid.UUID(policyID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM customers WHERE id = $1`, uuid.UUID(customerID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM products WHERE id = $1`, uuid.UUID(productID))
			_, _ = pgxq.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, uuid.UUID(accountID))
			return nil
		})
	}
	t.Cleanup(cleanup)

	require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
		pgxq := Conn(ctx, pool)
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
			uuid.UUID(accountID), "RLS bare", slug,
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
			uuid.UUID(productID), uuid.UUID(accountID),
			"P", "p-"+accountID.String()[:8], "pub", []byte{0x00}, `{}`,
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO customers (id, account_id, email, metadata, created_at, updated_at)
			 VALUES ($1, $2, $3, '{}'::jsonb, NOW(), NOW())`,
			uuid.UUID(customerID), uuid.UUID(accountID),
			"rls-bare-"+accountID.String()[:8]+"@example.com",
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO policies (id, account_id, product_id, name, is_default,
			    floating, strict, require_checkout,
			    expiration_strategy, expiration_basis,
			    checkout_interval_sec, max_checkout_duration_sec,
			    component_matching_strategy,
			    metadata, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, false, false, false,
			    'REVOKE_ACCESS', 'FROM_CREATION',
			    86400, 604800,
			    'MATCH_ANY',
			    '{}'::jsonb, NOW(), NOW())`,
			uuid.UUID(policyID), uuid.UUID(accountID), uuid.UUID(productID),
			"Default", true,
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO licenses (id, account_id, environment, product_id, policy_id, customer_id,
			    key_prefix, key_hash, token, status, overrides,
			    created_by_account_id, created_at, updated_at)
			 VALUES ($1, $2, 'live', $3, $4, $5,
			    $6, $7, $8, 'active', '{}'::jsonb,
			    $2, NOW(), NOW())`,
			uuid.UUID(licenseID), uuid.UUID(accountID), uuid.UUID(productID),
			uuid.UUID(policyID), uuid.UUID(customerID),
			"gl_t_", "h-"+licenseID.String(), "tok-"+licenseID.String(),
		); err != nil {
			return err
		}
		return nil
	}))

	// Bare-pool read MUST return ErrNoRows — the seeded license has a
	// real account_id (UUIDv7), and the RLS predicate compares it
	// against the sentinel '00000000-0000-...' which cannot match.
	// Critically, a 0-row result here is the SECURE outcome: the row
	// exists but is invisible. A nonzero result would mean RLS is
	// fail-open and the seeded license leaked to a bare-pool reader.
	var gotID uuid.UUID
	row := pool.QueryRow(ctx, `SELECT id FROM licenses WHERE id = $1`, uuid.UUID(licenseID))
	err := row.Scan(&gotID)
	if err == nil {
		t.Fatalf("bare-pool read returned a row (id=%s) — RLS is fail-open!", gotID)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected pgx.ErrNoRows from fail-closed RLS, got: %v", err)
	}
}

// TestRLS_WithSystemContextSeesAllAccounts verifies that
// WithSystemContext is the explicit bypass: a read of licenses across
// two seeded accounts returns BOTH rows. This complements the
// fail-closed test above: together they prove the only path to
// cross-tenant access is the explicit helper.
func TestRLS_WithSystemContextSeesAllAccounts(t *testing.T) {
	pool := integrationPool(t)
	txm := NewTxManager(pool)
	ctx := context.Background()

	type seed struct {
		accountID  core.AccountID
		productID  core.ProductID
		customerID core.CustomerID
		policyID   core.PolicyID
		licenseID  core.LicenseID
	}
	mkSeed := func() seed {
		return seed{
			accountID:  core.NewAccountID(),
			productID:  core.NewProductID(),
			customerID: core.NewCustomerID(),
			policyID:   core.NewPolicyID(),
			licenseID:  core.NewLicenseID(),
		}
	}
	a := mkSeed()
	b := mkSeed()

	t.Cleanup(func() {
		cctx := context.Background()
		_ = txm.WithSystemContext(cctx, func(ctx context.Context) error {
			pgxq := Conn(ctx, pool)
			for _, s := range []seed{a, b} {
				_, _ = pgxq.Exec(ctx, `DELETE FROM licenses WHERE id = $1`, uuid.UUID(s.licenseID))
				_, _ = pgxq.Exec(ctx, `DELETE FROM policies WHERE id = $1`, uuid.UUID(s.policyID))
				_, _ = pgxq.Exec(ctx, `DELETE FROM customers WHERE id = $1`, uuid.UUID(s.customerID))
				_, _ = pgxq.Exec(ctx, `DELETE FROM products WHERE id = $1`, uuid.UUID(s.productID))
				_, _ = pgxq.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, uuid.UUID(s.accountID))
			}
			return nil
		})
	})

	insert := func(s seed) {
		require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
			pgxq := Conn(ctx, pool)
			// UUIDv7 IDs share a time-ordered prefix; use the LAST 12
			// chars (the random tail) so two seeds in the same test
			// don't collide on slug/email uniqueness.
			full := s.accountID.String()
			suffix := full[len(full)-12:]
			if _, err := pgxq.Exec(ctx,
				`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
				uuid.UUID(s.accountID), "All-acct "+suffix, "rls-allacct-"+suffix,
			); err != nil {
				return err
			}
			if _, err := pgxq.Exec(ctx,
				`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
				uuid.UUID(s.productID), uuid.UUID(s.accountID),
				"P", "p-"+suffix, "pub", []byte{0x00}, `{}`,
			); err != nil {
				return err
			}
			if _, err := pgxq.Exec(ctx,
				`INSERT INTO customers (id, account_id, email, metadata, created_at, updated_at)
				 VALUES ($1, $2, $3, '{}'::jsonb, NOW(), NOW())`,
				uuid.UUID(s.customerID), uuid.UUID(s.accountID),
				"rls-allacct-"+suffix+"@example.com",
			); err != nil {
				return err
			}
			if _, err := pgxq.Exec(ctx,
				`INSERT INTO policies (id, account_id, product_id, name, is_default,
				    floating, strict, require_checkout,
				    expiration_strategy, expiration_basis,
				    checkout_interval_sec, max_checkout_duration_sec,
				    component_matching_strategy,
				    metadata, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5, false, false, false,
				    'REVOKE_ACCESS', 'FROM_CREATION',
				    86400, 604800,
				    'MATCH_ANY',
				    '{}'::jsonb, NOW(), NOW())`,
				uuid.UUID(s.policyID), uuid.UUID(s.accountID), uuid.UUID(s.productID),
				"Default", true,
			); err != nil {
				return err
			}
			if _, err := pgxq.Exec(ctx,
				`INSERT INTO licenses (id, account_id, environment, product_id, policy_id, customer_id,
				    key_prefix, key_hash, token, status, overrides,
				    created_by_account_id, created_at, updated_at)
				 VALUES ($1, $2, 'live', $3, $4, $5,
				    $6, $7, $8, 'active', '{}'::jsonb,
				    $2, NOW(), NOW())`,
				uuid.UUID(s.licenseID), uuid.UUID(s.accountID), uuid.UUID(s.productID),
				uuid.UUID(s.policyID), uuid.UUID(s.customerID),
				"gl_t_", "h-"+s.licenseID.String(), "tok-"+s.licenseID.String(),
			); err != nil {
				return err
			}
			return nil
		}))
	}
	insert(a)
	insert(b)

	// With WithSystemContext, a SELECT scoped to the two seeded IDs
	// returns BOTH rows — this is the explicit cross-tenant read.
	var ids []uuid.UUID
	require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
		pgxq := Conn(ctx, pool)
		rows, err := pgxq.Query(ctx,
			`SELECT id FROM licenses WHERE id = ANY($1::uuid[])`,
			[]uuid.UUID{uuid.UUID(a.licenseID), uuid.UUID(b.licenseID)},
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}))
	require.Len(t, ids, 2, "WithSystemContext should see licenses from both seeded accounts")

	// Sanity: the same query under WithTargetAccount(a.accountID, live)
	// returns only a's license, demonstrating that the system bypass is
	// per-tx and doesn't leak into tenant scopes.
	var scopedIDs []uuid.UUID
	require.NoError(t, txm.WithTargetAccount(ctx, a.accountID, core.Environment("live"), func(ctx context.Context) error {
		pgxq := Conn(ctx, pool)
		rows, err := pgxq.Query(ctx,
			`SELECT id FROM licenses WHERE id = ANY($1::uuid[])`,
			[]uuid.UUID{uuid.UUID(a.licenseID), uuid.UUID(b.licenseID)},
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			scopedIDs = append(scopedIDs, id)
		}
		return rows.Err()
	}))
	require.Len(t, scopedIDs, 1)
	require.Equal(t, uuid.UUID(a.licenseID), scopedIDs[0])
}
