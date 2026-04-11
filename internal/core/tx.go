package core

import "context"

// TxManager provides transactional boundaries for service operations.
type TxManager interface {
	// WithTenant runs fn in a transaction with RLS tenant context set.
	WithTenant(ctx context.Context, accountID AccountID, fn func(ctx context.Context) error) error

	// WithTx runs fn in a plain transaction without tenant context.
	// Used for global operations like signup where no tenant exists yet.
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}
