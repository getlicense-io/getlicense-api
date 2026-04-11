package core

import "context"

type AccountRepository interface {
	Create(ctx context.Context, account *Account) error
	GetByID(ctx context.Context, id AccountID) (*Account, error)
	GetBySlug(ctx context.Context, slug string) (*Account, error)
}

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id UserID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
}

type ProductRepository interface {
	Create(ctx context.Context, product *Product) error
	GetByID(ctx context.Context, id ProductID) (*Product, error)
	List(ctx context.Context, limit, offset int) ([]Product, int, error)
	Update(ctx context.Context, id ProductID, params UpdateProductParams) (*Product, error)
	Delete(ctx context.Context, id ProductID) error
}

type LicenseRepository interface {
	Create(ctx context.Context, license *License) error
	GetByID(ctx context.Context, id LicenseID) (*License, error)
	GetByKeyHash(ctx context.Context, keyHash string) (*License, error)
	List(ctx context.Context, limit, offset int) ([]License, int, error)
	UpdateStatus(ctx context.Context, id LicenseID, status LicenseStatus) error
	ExpireActive(ctx context.Context) ([]License, error)
}

type MachineRepository interface {
	Create(ctx context.Context, machine *Machine) error
	GetByFingerprint(ctx context.Context, licenseID LicenseID, fingerprint string) (*Machine, error)
	CountByLicense(ctx context.Context, licenseID LicenseID) (int, error)
	DeleteByFingerprint(ctx context.Context, licenseID LicenseID, fingerprint string) error
	UpdateHeartbeat(ctx context.Context, licenseID LicenseID, fingerprint string) (*Machine, error)
}

type APIKeyRepository interface {
	Create(ctx context.Context, key *APIKey) error
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)
	ListByAccount(ctx context.Context, limit, offset int) ([]APIKey, int, error)
	Delete(ctx context.Context, id APIKeyID) error
}

type WebhookRepository interface {
	CreateEndpoint(ctx context.Context, ep *WebhookEndpoint) error
	ListEndpoints(ctx context.Context, limit, offset int) ([]WebhookEndpoint, int, error)
	DeleteEndpoint(ctx context.Context, id WebhookEndpointID) error
	GetActiveEndpointsByEvent(ctx context.Context, eventType EventType) ([]WebhookEndpoint, error)
	CreateEvent(ctx context.Context, event *WebhookEvent) error
	UpdateEventStatus(ctx context.Context, id WebhookEventID, status DeliveryStatus, attempts int, responseStatus *int) error
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *RefreshToken) error
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteByHash(ctx context.Context, tokenHash string) error
	DeleteByUserID(ctx context.Context, userID UserID) error
}
