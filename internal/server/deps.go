package server

import (
	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
	"github.com/getlicense-io/getlicense-api/internal/environment"
	"github.com/getlicense-io/getlicense-api/internal/grant"
	"github.com/getlicense-io/getlicense-api/internal/identity"
	"github.com/getlicense-io/getlicense-api/internal/invitation"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/policy"
	"github.com/getlicense-io/getlicense-api/internal/product"
	"github.com/getlicense-io/getlicense-api/internal/webhook"
)

// Deps holds all service and repository dependencies needed by the HTTP server.
type Deps struct {
	AuthService        *auth.Service
	IdentityService    *identity.Service
	ProductService     *product.Service
	PolicyService      *policy.Service
	LicenseService     *licensing.Service
	CustomerService    *customer.Service
	WebhookService     *webhook.Service
	EnvironmentService *environment.Service
	InvitationService  *invitation.Service
	GrantService       *grant.Service
	EntitlementService *entitlement.Service
	TxManager          domain.TxManager
	LicenseRepo        domain.LicenseRepository
	PolicyRepo         domain.PolicyRepository
	APIKeyRepo         domain.APIKeyRepository
	MembershipRepo     domain.AccountMembershipRepository
	AdminRole          *domain.Role
	MasterKey          *crypto.MasterKey
	Config             *Config
}
