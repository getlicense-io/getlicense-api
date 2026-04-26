package domain

import (
	"context"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// TxManager provides transactional boundaries for service operations.
type TxManager interface {
	// WithTargetAccount runs fn in a transaction with the given target
	// account + environment as the RLS scope. The target account is the
	// account whose data is being touched — for direct operations it
	// equals the acting account; for grant operations (see
	// internal/grant) it's the grantor. The Postgres GUC
	// app.current_account_id is set to targetAccountID so RLS policies
	// filter all downstream reads/writes to that tenant.
	WithTargetAccount(ctx context.Context, targetAccountID core.AccountID, env core.Environment, fn func(ctx context.Context) error) error

	// WithTx runs fn in a plain transaction without any tenant context.
	// Used only by signup (before any tenant exists) and truly global
	// queries.
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error

	// WithSystemContext runs fn in a transaction with
	// app.system_context='true' set so RLS policies short-circuit their
	// tenant predicate. Use SPARINGLY — only for background sweeps,
	// bootstrap operations (signup, refresh), webhook worker pool
	// claims, and middleware-level lookups (API key by hash, JWT
	// membership resolution) that legitimately run before any tenant
	// is known. New code defaults to WithTargetAccount; reaching for
	// WithSystemContext should be deliberate and justified inline.
	WithSystemContext(ctx context.Context, fn func(ctx context.Context) error) error
}
