.PHONY: build run test test-all lint fmt check db db-reset migrate e2e docker clean hooks release

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

db:
	docker compose -f docker/docker-compose.yml up -d postgres

db-reset:
	docker compose -f docker/docker-compose.yml down -v
	docker compose -f docker/docker-compose.yml up -d postgres
	@echo "Waiting for Postgres..."
	@sleep 2

migrate:
	go run ./cmd/server migrate

e2e: build db-reset
	@sleep 2
	./$(BINARY) migrate
	$(eval E2E_PORT := $(shell python3 -c 'import random; print(random.randint(10000, 60000))'))
	@GETLICENSE_PORT=$(E2E_PORT) ./$(BINARY) serve & echo $$! > /tmp/getlicense-e2e.pid
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
