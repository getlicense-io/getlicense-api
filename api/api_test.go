package api

import (
	"strings"
	"testing"
)

func TestOpenAPISpecEmbedded(t *testing.T) {
	if len(OpenAPISpec) == 0 {
		t.Fatal("OpenAPISpec is empty; //go:embed directive did not load openapi.yaml")
	}
	head := strings.TrimSpace(string(OpenAPISpec[:min(len(OpenAPISpec), 256)]))
	if !strings.HasPrefix(head, "openapi:") {
		t.Fatalf("OpenAPISpec does not look like an OpenAPI document; first bytes: %q", head)
	}
}
