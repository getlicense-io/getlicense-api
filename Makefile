.PHONY: build run test test-all lint fmt check db db-reset db-reset-e2e migrate e2e docker clean hooks release release-patch release-minor release-major sqlc sqlc-verify sqlc-lint

BINARY=getlicense-server
BUILD_DIR=.

# Default env vars for local development (override with .env or shell exports)
export DATABASE_URL ?= postgres://getlicense:getlicense@localhost:5432/getlicense?sslmode=disable
export GETLICENSE_MASTER_KEY ?= 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
export GETLICENSE_ENV ?= development

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/server

release:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY) ./cmd/server

run: migrate
	go run ./cmd/server serve

test:
	go test ./internal/... -count=1 -short

test-all:
	go test ./... -count=1

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .
	goimports -w .

check:
	go vet ./...
	$(MAKE) sqlc-verify

db:
	docker compose -f docker/docker-compose.yml up -d --wait postgres

# Nukes the entire Postgres volume — wipes dev data AND the e2e DB.
# Only use this if local state is corrupted. `make e2e` does NOT call
# this anymore; it resets only the getlicense_e2e database.
db-reset:
	docker compose -f docker/docker-compose.yml down -v
	docker compose -f docker/docker-compose.yml up -d --wait postgres

# Drop-and-recreate the getlicense_e2e database without touching the
# dev `getlicense` database. Runs inside the Postgres container as the
# postgres superuser so we can FORCE-drop even if a previous e2e run
# left stale connections open.
db-reset-e2e: db
	@docker compose -f docker/docker-compose.yml exec -T postgres \
		psql -U postgres -v ON_ERROR_STOP=1 \
		-c "DROP DATABASE IF EXISTS getlicense_e2e WITH (FORCE);" > /dev/null
	@docker compose -f docker/docker-compose.yml exec -T postgres \
		psql -U postgres -v ON_ERROR_STOP=1 \
		-c "CREATE DATABASE getlicense_e2e OWNER getlicense;" > /dev/null
	@echo "e2e database ready: getlicense_e2e"

migrate:
	go run ./cmd/server migrate

# Connection string for the isolated e2e database. Points at the same
# Postgres instance as dev but a different DB so hurl scenarios never
# clobber your signed-in session, products, or licenses.
E2E_DATABASE_URL := postgres://getlicense:getlicense@localhost:5432/getlicense_e2e?sslmode=disable

e2e: build db-reset-e2e
	@DATABASE_URL="$(E2E_DATABASE_URL)" ./$(BINARY) migrate
	$(eval E2E_PORT := $(shell python3 -c 'import random; print(random.randint(10000, 60000))'))
	@DATABASE_URL="$(E2E_DATABASE_URL)" GETLICENSE_PORT=$(E2E_PORT) ./$(BINARY) serve & echo $$! > /tmp/getlicense-e2e.pid
	@sleep 2
	@hurl --test --variable base_url=http://localhost:$(E2E_PORT) e2e/scenarios/*.hurl; \
		EXIT_CODE=$$?; \
		kill $$(cat /tmp/getlicense-e2e.pid) 2>/dev/null; \
		wait $$(cat /tmp/getlicense-e2e.pid) 2>/dev/null; \
		rm -f /tmp/getlicense-e2e.pid; \
		exit $$EXIT_CODE

docker:
	docker compose -f docker/docker-compose.yml up --build

clean:
	rm -f $(BINARY)
	go clean ./...

hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed."

release:
	@./scripts/release.sh

release-patch:
	@./scripts/release.sh patch

release-minor:
	@./scripts/release.sh minor

release-major:
	@./scripts/release.sh major

SQLC_VERSION := v1.29.0

sqlc:
	@command -v sqlc >/dev/null 2>&1 || go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)
	sqlc generate

sqlc-verify: sqlc
	@git diff --exit-code internal/db/sqlc/gen/ \
	  || (echo "ERROR: generated sqlc code is out of date. Run 'make sqlc' and commit."; exit 1)

sqlc-lint:
	@command -v sqlc >/dev/null 2>&1 || go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)
	sqlc vet
