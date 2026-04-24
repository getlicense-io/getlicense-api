# Comprehensive Code Review Design

## Goal

Ensure the GetLicense API implementation matches `api/openapi.yaml`, follows the repository's documented conventions, and has no known correctness gaps in core API behavior.

## Scope

This is a review-and-fix effort. Findings should be corrected when they are local and well understood, with tests added at the narrowest useful level. Larger product or contract questions should be recorded as explicit review findings instead of being silently resolved.

The review covers:

- OpenAPI operation coverage against `internal/server/routes.go`
- Handler conformance for request parsing, auth, permissions, status codes, pagination, and response shape
- Service and repository correctness for tenant isolation, RLS, transaction boundaries, environment scoping, grants, sharing v2, policies, entitlements, customers, validation, webhooks, events, metrics, and search
- Test coverage through unit tests, repository integration tests, and Hurl e2e scenarios
- Quality gates: formatting, linting, vetting, sqlc verification, unit tests, integration tests, and e2e tests

## Recommended Approach

Use a spec-led deep review. Treat `api/openapi.yaml` as the external contract, then prove every operation has a matching route, handler behavior, service behavior, and test path. This is more expensive than a recent-change review, but it directly answers whether the OpenAPI spec is fully implemented.

## Architecture Review Model

The review follows the project architecture:

```text
HTTP request -> Handler -> Service -> Repository -> PostgreSQL
```

Handlers should stay thin and only parse input, authorize, call services, and serialize responses. Services own business rules and must call repositories inside the correct transaction and RLS scope. Repositories should be thin sqlc adapters with explicit conversions and predictable pagination.

## Contract Inventory

Build a route matrix from `api/openapi.yaml` and `internal/server/routes.go`. For each operation record:

- method and path
- `operationId`
- handler method
- auth middleware and rate limit
- RBAC permission
- path/query/body parameters
- success status and response schema
- documented error behavior
- test coverage file

Every OpenAPI operation must map to a live route. Every live public route under `/v1` must appear in OpenAPI.

## Handler and Service Conformance

For each operation, verify:

- path params are parsed and validated consistently
- query params use documented defaults and bounds
- request bodies match OpenAPI schemas
- auth mode matches the spec
- RBAC permissions match the intended role model
- `ActingAccountID` and `TargetAccountID` are used correctly
- `X-Environment` and API-key environment behavior are preserved
- success status codes match the spec
- response bodies do not leak secrets or cross-tenant data
- error mapping uses stable, documented API error codes where applicable

Grant-scoped routes need extra review because `ResolveGrant` intentionally changes `TargetAccountID` while preserving the acting grantee account.

## Behavioral Correctness

The deep review should prioritize invariants that can cause production bugs:

- RLS and environment isolation for licenses, machines, webhooks, events, and grant-scoped data
- cursor pagination order, limits, and `next_cursor` generation
- service transaction boundaries and rollback behavior
- sqlc query conventions and generated-code freshness
- policy resolution and license override semantics
- customer attribution and sharing v2 privacy scrubbing
- grant capability enforcement and constraints
- validation TTL token re-minting behavior
- webhook SSRF protections, delivery logs, and redelivery behavior
- domain event creation and visibility
- metrics and search scoping

## Testing Strategy

Use the narrowest useful test for each issue:

- Unit tests for pure service logic and crypto/domain helpers
- Repository integration tests for SQL, RLS, pagination, constraints, and generated sqlc behavior
- Hurl e2e tests for API contract behavior, auth flows, OpenAPI route coverage, and cross-resource workflows
- Generated or scripted checks for OpenAPI route drift

The final quality gate is:

```bash
make test
make test-all
make e2e
make lint
make check
```

## Completion Criteria

The review is complete when:

- the route matrix has no missing OpenAPI operations or undocumented public routes
- all high-confidence bugs found during review are fixed with tests
- unresolved product/contract questions are documented as findings
- generated sqlc output is current
- all final quality gates pass, or any remaining failures are documented with exact causes
