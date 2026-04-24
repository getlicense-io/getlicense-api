# Comprehensive Code Review Findings

## Summary

- Status: Task 7 e2e contract coverage review complete
- Review started: 2026-04-24
- Contract source: `api/openapi.yaml`
- Runtime route source: `internal/server/routes.go`

## Findings

- Task 3: No route/spec drift findings. All 93 OpenAPI operations have matching runtime Fiber registrations, and all 93 runtime Fiber registrations are represented in OpenAPI.
- Task 4 fixed: `attachPolicyEntitlements`, `replacePolicyEntitlements`, `attachLicenseEntitlements`, and `replaceLicenseEntitlements` returned `204`, but OpenAPI documented `200`. Updated handlers to return `200` and updated `e2e/scenarios/22_entitlements.hurl` expectations.
- Task 4 fixed: `setDefaultPolicy` returned a `Policy` response body and existing e2e tests assert that body, but OpenAPI documented only a bare `200`. Updated OpenAPI to document the `Policy` response.
- Task 5 reviewed: `internal/licensing`, `internal/grant`, `internal/customer`, `internal/invitation`, `internal/policy`, `internal/entitlement`, `internal/webhook`, `internal/auth`, `internal/identity`, `internal/search`, `internal/analytics`, and `internal/audit` service invariants against `CLAUDE.md`.
- Task 5 fixed: `analytics.Service.Snapshot` counted `licenses_via_grants` across all environments even though the metrics snapshot is documented as account+environment scoped. Added an environment-scoped regression test and filtered that aggregate by `environment`.
- Task 5 fixed: `policy.Service.Update` enforced `validation_ttl_sec` bounds but allowed other invalid policy values that `Create` rejects: blank names, non-positive duration, non-positive machine/seat limits, and negative checkout intervals. Added focused update validation coverage and mirrored create-time constraints for present update fields.
- Task 5 fixed: `grant.Service.Revoke` could mutate Sharing v2 terminal `left` and `expired` grants to `revoked`. Added focused lifecycle coverage and preserved terminal statuses.
- Task 6 reviewed: `internal/db/*.go`, `internal/db/sqlc/queries/*.sql`, and `migrations/*.sql` for sqlc generation freshness, explicit SELECT lists, `sqlc.narg` casts, tuple cursor casts, named `sqlc.arg` usage, Get/ErrNoRows branches, row conversion seams, nullable helper usage, pagination helpers, unique-constraint classification, and RLS account/environment scoping.
- Task 6 fixed: `GetCustomerByEmail` used positional `lower($2)`, causing sqlc to generate an ambiguous `Lower` param. Changed the query to `sqlc.arg('email')::text`, regenerated sqlc, and updated the adapter to use `Email`.
- Task 6 fixed: `ListDomainEventsSince` used positional `$1`/`$2`, causing sqlc to generate generic `ID` and `Limit` params. Changed the query to `sqlc.arg('after_id')` and `sqlc.arg('limit_rows')`, regenerated sqlc, and updated the adapter to use `AfterID`/`LimitRows`.
- Task 6 finding: No confirmed repository behavior or RLS migration defect was found. Tenant-scoped environment tables (`licenses`, `machines`, `webhook_endpoints`, `webhook_events`, `domain_events`) include both account and environment RLS predicates; account-level metadata (`products`, `customers`, `policies`, `entitlements`, `environments`, `roles`, `account_memberships`, `grants`) follows the documented account/preset/grantor-grantee scope.
- Task 7 reviewed: Mapped all 93 OpenAPI route matrix rows to concrete Hurl e2e scenarios. Coverage is 93 e2e, 0 unit-only, 0 integration-only, 0 missing.
- Task 7 added: Product and license list pagination e2e assertions now cover `limit`, `next_cursor`, `has_more`, and second-page retrieval for high-value cursor contract coverage.

## Open Questions

- Task 5 open question: `grant.Service.Issue` and `grant.Service.Accept` currently allow `expires_at` values that are already in the past; `RequireActive` and the background `expire_grants` tick treat them as expired later. Product decision needed: should past-expiring grants be rejected at issue/accept time, or is delayed/background expiry the intended model?

## Verification Log

- 2026-04-24: `rg -n "v1\\.|\\.Group\\(|\\.Get\\(|\\.Post\\(|\\.Patch\\(|\\.Put\\(|\\.Delete\\(" internal/server/routes.go` captured runtime route registrations.
- 2026-04-24: `rg -c "\\.(Get|Post|Patch|Put|Delete)\\(" internal/server/routes.go` returned `93`.
- 2026-04-24: `awk '/^\\| matched / {count++} END {print count}' docs/plans/2026-04-24-openapi-route-matrix.md` returned `93` after mapping.
- 2026-04-24: `rg -n "operationId:" api/openapi.yaml` returned 93 OpenAPI operations.
- 2026-04-24: Red-stage `make e2e` after changing `e2e/scenarios/22_entitlements.hurl` expectations failed with 29/30 scenario files passing and 1 failing, confirming the entitlement status contract drift before the handler fix.
- 2026-04-24: `go test ./internal/server/... -count=1` passed.
- 2026-04-24: Post-fix `make e2e` passed with 30/30 scenario files and 445/445 requests.
- 2026-04-24: Red-stage `go test ./internal/analytics -count=1 -run TestSnapshot_LicensesViaGrantsIsEnvironmentScoped` failed with `LicensesViaGrants` actual `2`, expected `1`, confirming cross-environment analytics drift before the service fix.
- 2026-04-24: Post-fix `go test ./internal/analytics -count=1 -run TestSnapshot_LicensesViaGrantsIsEnvironmentScoped` passed.
- 2026-04-24: Red-stage `go test ./internal/policy -count=1 -run TestService_UpdateRejectsInvalidPolicyConstraints` failed for all invalid update cases with nil errors, confirming missing policy update validation before the service fix.
- 2026-04-24: Post-fix `go test ./internal/policy -count=1 -run TestService_UpdateRejectsInvalidPolicyConstraints` passed.
- 2026-04-24: Red-stage `go test ./internal/grant -count=1 -run TestRevoke_TerminalLeftOrExpiredReturnsNotActive` failed because `Revoke` returned nil for `left` and `expired`, confirming terminal state mutation before the service fix.
- 2026-04-24: Post-fix `go test ./internal/grant -count=1 -run TestRevoke_TerminalLeftOrExpiredReturnsNotActive` passed.
- 2026-04-24: `go test ./internal/analytics -count=1` passed.
- 2026-04-24: `go test ./internal/policy -count=1` passed.
- 2026-04-24: `go test ./internal/grant -count=1` passed.
- 2026-04-24: Initial `make sqlc-verify` with `/opt/homebrew/bin/sqlc v1.24.0` failed only on generated version headers versus committed `sqlc v1.29.0`. Installed `sqlc v1.29.0` into `/tmp/getlicense-sqlc-bin` for task verification.
- 2026-04-24: Baseline `PATH=/tmp/getlicense-sqlc-bin:$PATH make sqlc-verify` passed before query changes.
- 2026-04-24: After Task 6 query changes, `PATH=/tmp/getlicense-sqlc-bin:$PATH make sqlc-verify` failed with the expected generated diff for `internal/db/sqlc/gen/customers.sql.go` and `internal/db/sqlc/gen/domain_events.sql.go`; this is expected until the generated files are committed with the query changes.
- 2026-04-24: Sandboxed `make test-all` was blocked by Go build-cache and `httptest` local socket permissions.
- 2026-04-24: Escalated `make test-all` passed, including `internal/db` and `internal/db/sqlc/gen`.
- 2026-04-24: `rg -n "TBD|unit-only|integration-only|missing" docs/plans/2026-04-24-openapi-route-matrix.md` returned no rows after Task 7 mapping.
- 2026-04-24: Task 7 `make e2e` passed with 30/30 scenario files and 451/451 requests.
