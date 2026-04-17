// Package api holds the committed OpenAPI 3.1 specification, embedded
// at compile time via //go:embed. The spec is consumed by the Swagger
// UI middleware in internal/server/docs.go. Embedding is mandatory
// because the production image (distroless/static) contains only the
// Go binary — there is no filesystem to read the YAML from at runtime.
package api

import _ "embed"

//go:embed openapi.yaml
var OpenAPISpec []byte
