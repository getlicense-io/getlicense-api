package server

import (
	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/product"
	"github.com/getlicense-io/getlicense-api/internal/webhook"
)

// Deps holds all service and repository dependencies needed by the HTTP server.
type Deps struct {
	AuthService    *auth.Service
	ProductService *product.Service
	LicenseService *licensing.Service
	WebhookService *webhook.Service
	APIKeyRepo     domain.APIKeyRepository
	MasterKey      *crypto.MasterKey
	Config         *Config
}
