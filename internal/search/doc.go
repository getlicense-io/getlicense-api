// Package search implements the global discovery DSL. The parser
// tokenises type:X / field:Y / bare-word inputs and validates them
// against per-resource whitelists. The service fans out parallel
// sub-queries (licenses, machines, customers, products) under
// WithTargetAccount transactions for RLS scoping, with RBAC pre-
// filtering: resource types the caller cannot read are silently
// omitted (no 403 leak).
package search
