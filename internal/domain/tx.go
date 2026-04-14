package domain

import (
	"context"
	"encoding/json"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// TxManager provides transactional boundaries for service operations.
type TxManager interface {
	// WithTargetAccount runs fn in a transaction with the given target
	// account + environment as the RLS scope. The target account is the
	// account whose data is being touched — for direct operations it
	// equals the acting account; for reseller grant operations (see
	// internal/grant) it's the grantor. The Postgres GUC
	// app.current_account_id is set to targetAccountID so RLS policies
	// filter all downstream reads/writes to that tenant.
	WithTargetAccount(ctx context.Context, targetAccountID core.AccountID, env core.Environment, fn func(ctx context.Context) error) error

	// WithTx runs fn in a plain transaction without any tenant context.
	// Used only by signup (before any tenant exists) and truly global
	// queries.
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// EventDispatcher sends webhook events. Implemented by webhook.Service.
type EventDispatcher interface {
	Dispatch(ctx context.Context, accountID core.AccountID, env core.Environment, eventType core.EventType, payload json.RawMessage)
}
