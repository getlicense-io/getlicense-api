package db

import (
	"context"
	"fmt"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the common interface between pgxpool.Pool and pgx.Tx.
// Structurally identical to sqlcgen.DBTX (both have Exec/Query/QueryRow),
// but kept as a separate type because sqlc-generated code lives in a
// subpackage and cannot import this one. Exported so packages outside
// db (e.g. internal/analytics) that still run hand-written pgx queries
// can call Conn() to resolve the active tx-or-pool.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type ctxKey struct{}

// TxManager implements domain.TxManager using pgxpool.
type TxManager struct {
	pool *pgxpool.Pool
}

var _ domain.TxManager = (*TxManager)(nil)

func NewTxManager(pool *pgxpool.Pool) *TxManager {
	return &TxManager{pool: pool}
}

func (m *TxManager) WithTargetAccount(ctx context.Context, targetAccountID core.AccountID, env core.Environment, fn func(context.Context) error) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, "SELECT set_config('app.current_account_id', $1, true)", targetAccountID.String())
	if err != nil {
		return fmt.Errorf("setting target account context: %w", err)
	}

	_, err = tx.Exec(ctx, "SELECT set_config('app.current_environment', $1, true)", string(env))
	if err != nil {
		return fmt.Errorf("setting environment context: %w", err)
	}

	ctx = context.WithValue(ctx, ctxKey{}, tx)
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (m *TxManager) WithTx(ctx context.Context, fn func(context.Context) error) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ctx = context.WithValue(ctx, ctxKey{}, tx)
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// WithSystemContext begins a transaction with app.system_context='true'
// set on the connection. RLS policies short-circuit their tenant
// checks when this GUC is true, allowing the tx to read/write across
// all tenants.
//
// USE SPARINGLY. Legitimate callers:
//   - Background sweeps (license expiry, lease decay, grant expiry,
//     domain-event-to-webhook fan-out, webhook worker pool claim,
//     dispatcher checkpoint reads/writes)
//   - Bootstrap operations (signup — before any tenant exists; refresh
//     and login — pre-tenant lookups by hash/email)
//   - Middleware-level auth lookups (API key by hash, JWT membership
//     resolution) — runs before the tenant context can be derived
//
// Default for new code is WithTargetAccount; reaching for
// WithSystemContext should be deliberate and justified inline.
//
// The matching RLS policies (migration 034) check
// `current_setting('app.system_context', true) = 'true'` as the only
// bypass branch — the previous fail-open `IS NULL` escape on
// app.current_account_id is gone, so a missed WithTargetAccount/
// WithSystemContext now hits a fail-closed empty-string uuid cast.
func (m *TxManager) WithSystemContext(ctx context.Context, fn func(context.Context) error) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT set_config('app.system_context', 'true', true)"); err != nil {
		return fmt.Errorf("setting system context: %w", err)
	}

	ctx = context.WithValue(ctx, ctxKey{}, tx)
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// conn returns the tx from context, or falls back to the pool.
func conn(ctx context.Context, pool *pgxpool.Pool) Querier {
	if tx, ok := ctx.Value(ctxKey{}).(pgx.Tx); ok {
		return tx
	}
	return pool
}

// Conn is the exported variant of conn. It returns the transaction
// stored in ctx by WithTargetAccount/WithTx, falling back to the pool
// when no tx is active. Packages outside db (e.g. analytics) use this
// to run queries on the caller's RLS-scoped transaction.
func Conn(ctx context.Context, pool *pgxpool.Pool) Querier {
	return conn(ctx, pool)
}

// ContextWithTx returns a context carrying tx under the same key that
// Conn / conn look up. Test-only helper for external _test.go files
// that want rollback-only semantics via t.Cleanup(tx.Rollback) instead
// of the commit-on-success shape of TxManager.WithTx. Production code
// must go through TxManager.WithTx / WithTargetAccount.
func ContextWithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, ctxKey{}, tx)
}
