// Package testfakes contains in-memory test doubles shared across the
// internal package's *_test.go files. The package is import-only from
// _test files and adds no production-time dependencies.
package testfakes

import (
	"context"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// accountIDKey is the unexported context key TxManager uses to stash
// the currently-scoped account id. Fake repositories that simulate
// account-scoped RLS read it via AccountFromCtx.
type accountIDKey struct{}

// TxManager is a domain.TxManager fake for unit tests. Each WithTargetAccount
// call stashes the supplied accountID in the context via an unexported key
// so fakes that simulate RLS scoping can read it via AccountFromCtx.
// Tests that don't need RLS simulation can ignore the stashed value.
//
// WithTx and WithSystemContext are pure passthrough — no tenant context
// is set.
type TxManager struct{}

// Compile-time check that TxManager satisfies domain.TxManager.
var _ domain.TxManager = TxManager{}

func (TxManager) WithTargetAccount(ctx context.Context, accountID core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(context.WithValue(ctx, accountIDKey{}, accountID))
}

func (TxManager) WithTx(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (TxManager) WithSystemContext(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

// AccountFromCtx returns the account id stashed by TxManager.WithTargetAccount,
// if any. Use in fake repositories to simulate account-scoped RLS filters.
func AccountFromCtx(ctx context.Context) (core.AccountID, bool) {
	v, ok := ctx.Value(accountIDKey{}).(core.AccountID)
	return v, ok
}
