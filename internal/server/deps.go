package server

import (
	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/environment"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/product"
	"github.com/getlicense-io/getlicense-api/internal/webhook"
)

// Deps holds all service and repository dependencies needed by the HTTP server.
type Deps struct {
	AuthService        *auth.Service
	ProductService     *product.Service
	LicenseService     *licensing.Service
	WebhookService     *webhook.Service
	EnvironmentService *environment.Service
	APIKeyRepo         domain.APIKeyRepository
	MembershipRepo     domain.AccountMembershipRepository
	RoleRepo           domain.RoleRepository
	MasterKey          *crypto.MasterKey
	Config             *Config
}
