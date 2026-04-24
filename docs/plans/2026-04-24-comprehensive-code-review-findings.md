# Comprehensive Code Review Findings

## Summary

- Status: Task 4 handler contract review complete
- Review started: 2026-04-24
- Contract source: `api/openapi.yaml`
- Runtime route source: `internal/server/routes.go`

## Findings

- Task 3: No route/spec drift findings. All 93 OpenAPI operations have matching runtime Fiber registrations, and all 93 runtime Fiber registrations are represented in OpenAPI.
- Task 4 fixed: `attachPolicyEntitlements`, `replacePolicyEntitlements`, `attachLicenseEntitlements`, and `replaceLicenseEntitlements` returned `204`, but OpenAPI documented `200`. Updated handlers to return `200` and updated `e2e/scenarios/22_entitlements.hurl` expectations.
- Task 4 fixed: `setDefaultPolicy` returned a `Policy` response body and existing e2e tests assert that body, but OpenAPI documented only a bare `200`. Updated OpenAPI to document the `Policy` response.

## Open Questions

No open questions recorded.

## Verification Log

- 2026-04-24: `rg -n "v1\\.|\\.Group\\(|\\.Get\\(|\\.Post\\(|\\.Patch\\(|\\.Put\\(|\\.Delete\\(" internal/server/routes.go` captured runtime route registrations.
- 2026-04-24: `rg -c "\\.(Get|Post|Patch|Put|Delete)\\(" internal/server/routes.go` returned `93`.
- 2026-04-24: `awk '/^\\| matched / {count++} END {print count}' docs/plans/2026-04-24-openapi-route-matrix.md` returned `93` after mapping.
- 2026-04-24: `rg -n "operationId:" api/openapi.yaml` returned 93 OpenAPI operations.
- 2026-04-24: Red-stage `make e2e` after changing `e2e/scenarios/22_entitlements.hurl` expectations failed with 29/30 scenario files passing and 1 failing, confirming the entitlement status contract drift before the handler fix.
- 2026-04-24: `go test ./internal/server/... -count=1` passed.
- 2026-04-24: Post-fix `make e2e` passed with 30/30 scenario files and 445/445 requests.
