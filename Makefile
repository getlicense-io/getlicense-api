.PHONY: build run test test-all lint fmt check db db-reset migrate e2e docker clean

BINARY=getlicense-server
BUILD_DIR=.

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/server

release:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY) ./cmd/server

run: migrate
	GETLICENSE_ENV=development go run ./cmd/server serve

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

e2e: db-reset
	@sleep 2
	go run ./cmd/server migrate
	@GETLICENSE_ENV=development go run ./cmd/server serve &
	@sleep 2
	hurl --test --variable base_url=http://localhost:3000 e2e/scenarios/*.hurl
	@pkill -f "getlicense-server" || true

docker:
	docker compose -f docker/docker-compose.yml up --build

clean:
	rm -f $(BINARY)
	go clean ./...
