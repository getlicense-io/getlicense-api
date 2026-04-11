# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /getlicense-server ./cmd/server

# Runtime stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /getlicense-server /getlicense-server

USER nonroot:nonroot

EXPOSE 3000

ENTRYPOINT ["/getlicense-server"]
CMD ["serve"]
