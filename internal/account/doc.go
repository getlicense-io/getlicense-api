// Package account provides the narrow read-only service for account
// summary lookups used by the sharing v2 API (Task 22).
//
// The service owns one responsibility: resolve a target account id to
// an AccountSummary only when the caller has a visibility relationship
// with it — either a membership on the target, or a non-terminal grant
// between caller and target in either direction. All other cases
// collapse to ErrAccountNotFound (404) so the endpoint never leaks the
// existence of accounts the caller has no business knowing about.
//
// Service methods do NOT open their own transactions. The access
// predicate runs across tenant boundaries and must therefore execute
// without a pinned tenant RLS GUC; handlers MUST call this service
// without wrapping in TxManager.WithTargetAccount.
package account
