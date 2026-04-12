# GetLicense API

The open-source alternative to [keygen.sh](https://keygen.sh). Software licensing, distribution, and analytics — self-hostable, offline-first, developer-friendly.

## Quick Start

### Docker (recommended)

```bash
docker compose -f docker/docker-compose.yml up --build
```

The API starts at `http://localhost:3000`.

### Local Development

Prerequisites: Go 1.24+, PostgreSQL 17+, [hurl](https://hurl.dev) (for e2e tests)

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

Full OpenAPI 3.1 spec in [`openapi.yaml`](openapi.yaml).

### Endpoints

| Group | Endpoints |
|-------|-----------|
| Auth | signup, login, refresh, logout, me |
| Products | CRUD with Ed25519 keypair generation |
| Licenses | create, bulk create, list, get, revoke, suspend, reinstate |
| Machines | activate, deactivate, heartbeat |
| Validation | public license key validation |
| API Keys | create, list, delete |
| Webhooks | endpoint CRUD, automatic dispatch |

### Authentication

- **API keys**: `gl_live_*` (production) / `gl_test_*` (sandbox) — `Authorization: Bearer <key>`
- **JWT**: 15-minute access tokens via login — `Authorization: Bearer <token>`
- **License keys**: `POST /v1/validate` — no auth required

### Environment Isolation

Test and live data are fully isolated at the database level via Row-Level Security. A `gl_test_` API key only sees test licenses, machines, and webhooks. Products are shared across environments.

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
