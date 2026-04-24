# Comprehensive Code Review Findings

## Summary

- Status: Task 5 service invariant review complete
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
