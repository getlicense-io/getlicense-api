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

// querier is the common interface between pgxpool.Pool and pgx.Tx.
type querier interface {
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

func (m *TxManager) WithTenant(ctx context.Context, accountID core.AccountID, fn func(context.Context) error) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, "SET LOCAL app.current_account_id = $1", accountID.String())
	if err != nil {
		return fmt.Errorf("setting tenant context: %w", err)
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
	defer tx.Rollback(ctx)

	ctx = context.WithValue(ctx, ctxKey{}, tx)
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// conn returns the tx from context, or falls back to the pool.
func conn(ctx context.Context, pool *pgxpool.Pool) querier {
	if tx, ok := ctx.Value(ctxKey{}).(pgx.Tx); ok {
		return tx
	}
	return pool
}
