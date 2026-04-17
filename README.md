# GetLicense API

[![CI](https://github.com/getlicense-io/getlicense-api/actions/workflows/ci.yml/badge.svg)](https://github.com/getlicense-io/getlicense-api/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg)](https://go.dev/)
[![License: BSL](https://img.shields.io/badge/license-BSL-blue.svg)](LICENSE)

The open-source alternative to [keygen.sh](https://keygen.sh). Software licensing, distribution, and analytics — self-hostable, offline-first, developer-friendly.

## Quick Start

### Docker (recommended)

```bash
docker compose -f docker/docker-compose.yml up --build
```

The API starts at `http://localhost:3000`.

### Local Development

Prerequisites: Go 1.26+, PostgreSQL 17+, [hurl](https://hurl.dev) (for e2e tests)

```bash
make db          # start Postgres via Docker
make run         # run migrations + start server
```

### Configuration

```bash
DATABASE_URL=postgres://...              # required
GETLICENSE_MASTER_KEY=<64-hex-chars>     # required (32 bytes, hex-encoded)
GETLICENSE_HOST=0.0.0.0                  # default
GETLICENSE_PORT=3000                     # default
GETLICENSE_ENV=development               # enables debug logs + HTTP webhook URLs
```

Generate a master key:

```bash
openssl rand -hex 32
```

## API

Full OpenAPI 3.1 spec in [`api/openapi.yaml`](api/openapi.yaml).

### Endpoints

| Group | Endpoints |
|-------|-----------|
| Auth | signup, login (+ TOTP step), refresh, logout, switch account, me |
| Identity | TOTP enroll / activate / verify / disable |
| Memberships | list, invite, role updates, suspend/unsuspend, remove |
| Invitations | create (membership or grant), lookup by token, accept |
| Grants | issue, accept, suspend, revoke; grantee-scoped license management |
| Products | CRUD with Ed25519 keypair generation |
| Licenses | create, bulk create, list, get, revoke, suspend, reinstate |
| Machines | activate, deactivate, heartbeat |
| Environments | list, create, delete (max 5 per account) |
| Validation | public license key validation |
| API Keys | create, list, delete |
| Webhooks | endpoint CRUD, automatic dispatch |

All list endpoints use opaque cursor pagination: `?cursor=<opaque>&limit=<1..200>` (default 50). Responses return `{data, has_more, next_cursor}`.

### Authentication

- **API keys**: `gl_live_*` (production) / `gl_test_*` (sandbox) — `Authorization: Bearer <key>`
- **JWT**: 15-minute access tokens via login — `Authorization: Bearer <token>`. Pass `X-Environment: test` to scope JWT requests to a non-live environment.
- **TOTP**: opt-in second factor. Enabled identities get a two-step login: `login` returns a short-lived pending token, then `login/step2` exchanges it for access + refresh tokens.
- **License keys**: `POST /v1/validate` — no auth required

### Authorization (RBAC)

Four preset roles: `owner`, `admin`, `developer`, `operator`. Handlers gate on flat permission strings like `license:create`, re-resolved from the database on every request so a stolen JWT can't forge elevated permissions.

### Capability Grants

An account can delegate a narrow slice of its licensing capability to another account (internal team, channel partner, OEM) via a grant. The grantor picks the capabilities (`license.create`, `license.suspend`, ...) and constraints (max licenses, monthly cap, allowed email pattern), the grantee accepts, and the grantee then manages licenses in the grantor's tenant via `/v1/grants/{id}/...` routes. License rows store both `grant_id` and `created_by_account_id` for attribution.

### Environments

Each account gets up to 5 environments. `live` and `test` are seeded at signup; custom environments can be added at runtime. API keys carry their environment; JWTs opt in per request via `X-Environment`. Licenses, machines, webhook endpoints, and webhook events are partitioned by environment via Row-Level Security. Products are environment-agnostic.

## Architecture

```
HTTP Request -> Handler (parse, auth) -> Service (business logic) -> Repository (data access) -> PostgreSQL
```

Single Go binary, single PostgreSQL database. No Redis, no message queue.

### Key Design Decisions

- **Offline-first**: Ed25519 signed license tokens can be validated without server connectivity
- **RLS multi-tenancy**: tenant isolation enforced at the database level, not application level
- **Single binary**: `getlicense-server serve` or `getlicense-server migrate`
- **Minimal entities**: accounts, products, licenses, machines, webhooks

## CLI

```bash
getlicense-server              # start API server (default)
getlicense-server serve        # same as above
getlicense-server migrate      # run migrations and exit
```

## Development

```bash
make test        # unit tests (no DB required)
make test-all    # unit + integration tests
make e2e         # full e2e tests (builds binary, resets DB, runs hurl scenarios)
make lint        # golangci-lint
make check       # go vet
make hooks       # install pre-commit hook (gofmt + go vet)
```

## License

BSL (Business Source License) — source-available, self-hostable, converts to Apache 2.0 after the Change Date.
