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
