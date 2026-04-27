# Service Route Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce cognitive load in route registration, server startup wiring, and large service files without changing public API behavior.

**Architecture:** Keep exported service and handler APIs stable. Split large orchestration functions into cohesive private builders and route group registration helpers. Preserve existing route order where it matters and rely on the existing API, handler, auth, middleware, and e2e suites for behavior coverage.

**Tech Stack:** Go 1.26, Fiber v3, sqlc, pgx, Redis client, existing Makefile test/e2e targets.

---

### Task 1: Route Registration Structure

**Files:**
- Modify: `internal/server/routes.go`
- Create: `internal/server/routes_auth.go`
- Create: `internal/server/routes_resources.go`
- Create: `internal/server/routes_collaboration.go`

**Steps:**
1. Keep `registerRoutes(app, deps)` as the single entry point.
2. Introduce `routeMiddleware` and `authRateLimits` private structs in `routes.go`.
3. Move auth/rate-limit setup into `buildRouteMiddleware(deps)`.
4. Move public/auth/identity routes into `registerAuthRoutes`.
5. Move products/licenses/policies/entitlements/customers/validate/api-keys/webhooks/events/metrics/search/environments/account/member routes into cohesive helpers.
6. Move invitation/grant routes into collaboration helpers.
7. Run `go test ./internal/server/... -count=1 -short`.
8. Run `go test ./... -count=1 -short`.

### Task 2: Server Startup Construction

**Files:**
- Modify: `cmd/server/serve.go`
- Create: `cmd/server/wiring.go`

**Steps:**
1. Extract logging setup to `configureLogger`.
2. Extract Redis setup to `connectRedis`.
3. Introduce `serverRepositories` and `serverServices` private structs.
4. Extract repo creation to `newServerRepositories`.
5. Extract service creation to `newServerServices`.
6. Extract `server.Deps` construction to `newServerDeps`.
7. Keep `runServe` as high-level orchestration only.
8. Run `go test ./cmd/server ./internal/server/... -count=1 -short`.
9. Run `go test ./... -count=1 -short`.

### Task 3: Auth Service File Organization

**Files:**
- Modify: `internal/auth/service.go`
- Create: `internal/auth/types.go`
- Create: `internal/auth/signup.go`
- Create: `internal/auth/login.go`
- Create: `internal/auth/apikeys.go`

**Steps:**
1. Move request/result types into `types.go`.
2. Move signup workflow into `signup.go`.
3. Move login, TOTP, refresh/logout, switch/me workflows into `login.go`.
4. Move API key lifecycle methods into `apikeys.go`.
5. Keep receiver methods and exported signatures unchanged.
6. Run `go test ./internal/auth -count=1 -short`.
7. Run `go test ./... -count=1 -short`.

### Task 4: Verification

**Steps:**
1. Run `go test ./... -count=1 -short`.
2. Run `make check`.
3. Run `make e2e`.
4. Report exact command outcomes and any residual risks.
