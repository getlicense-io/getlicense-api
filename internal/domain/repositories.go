package domain

import (
	"context"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

type AccountRepository interface {
	Create(ctx context.Context, account *Account) error
	GetByID(ctx context.Context, id core.AccountID) (*Account, error)
	GetBySlug(ctx context.Context, slug string) (*Account, error)
}

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id core.UserID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
}

type ProductRepository interface {
	Create(ctx context.Context, product *Product) error
	GetByID(ctx context.Context, id core.ProductID) (*Product, error)
	List(ctx context.Context, limit, offset int) ([]Product, int, error)
	Update(ctx context.Context, id core.ProductID, params UpdateProductParams) (*Product, error)
	Delete(ctx context.Context, id core.ProductID) error
}

type LicenseRepository interface {
	Create(ctx context.Context, license *License) error
	BulkCreate(ctx context.Context, licenses []*License) error
	GetByID(ctx context.Context, id core.LicenseID) (*License, error)
	GetByIDForUpdate(ctx context.Context, id core.LicenseID) (*License, error)
	GetByKeyHash(ctx context.Context, keyHash string) (*License, error)
	List(ctx context.Context, limit, offset int) ([]License, int, error)
	UpdateStatus(ctx context.Context, id core.LicenseID, from core.LicenseStatus, to core.LicenseStatus) (time.Time, error)
	CountByProduct(ctx context.Context, productID core.ProductID) (int, error)
	ExpireActive(ctx context.Context) ([]License, error)
}

type MachineRepository interface {
	Create(ctx context.Context, machine *Machine) error
	GetByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*Machine, error)
	CountByLicense(ctx context.Context, licenseID core.LicenseID) (int, error)
	DeleteByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) error
	UpdateHeartbeat(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*Machine, error)
	DeactivateStale(ctx context.Context) (int, error)
}

type APIKeyRepository interface {
	Create(ctx context.Context, key *APIKey) error
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)
	ListByAccount(ctx context.Context, limit, offset int) ([]APIKey, int, error)
	Delete(ctx context.Context, id core.APIKeyID) error
}

type WebhookRepository interface {
	CreateEndpoint(ctx context.Context, ep *WebhookEndpoint) error
	ListEndpoints(ctx context.Context, limit, offset int) ([]WebhookEndpoint, int, error)
	DeleteEndpoint(ctx context.Context, id core.WebhookEndpointID) error
	GetActiveEndpointsByEvent(ctx context.Context, eventType core.EventType) ([]WebhookEndpoint, error)
	CreateEvent(ctx context.Context, event *WebhookEvent) error
	UpdateEventStatus(ctx context.Context, id core.WebhookEventID, status core.DeliveryStatus, attempts int, responseStatus *int) error
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *RefreshToken) error
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteByHash(ctx context.Context, tokenHash string) error
	DeleteByUserID(ctx context.Context, userID core.UserID) error
}
