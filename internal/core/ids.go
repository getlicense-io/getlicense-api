package core

import "github.com/google/uuid"

// newUUIDv7 generates a UUID v7 or panics.
func newUUIDv7() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate UUID v7: " + err.Error())
	}
	return id
}

// ID is a generic typed UUID. Each domain concept gets a distinct type
// via a phantom tag type, preventing accidental mixing of AccountID
// with LicenseID at compile time.
type ID[T any] uuid.UUID

// NewID generates a new typed UUID v7.
func NewID[T any]() ID[T] { return ID[T](newUUIDv7()) }

// ParseID parses a string into a typed UUID.
func ParseID[T any](s string) (ID[T], error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return ID[T]{}, err
	}
	return ID[T](id), nil
}

func (id ID[T]) String() string               { return uuid.UUID(id).String() }
func (id ID[T]) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *ID[T]) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = ID[T](u)
	return nil
}

// --- Phantom tag types (unexported, zero-size) ---
type accountTag struct{}
type identityTag struct{}
type membershipTag struct{}
type roleTag struct{}
type productTag struct{}
type licenseTag struct{}
type machineTag struct{}
type apiKeyTag struct{}
type webhookEndpointTag struct{}
type webhookEventTag struct{}
type environmentTag struct{}
type invitationTag struct{}
type grantTag struct{}
type policyTag struct{}
type customerTag struct{}
type entitlementTag struct{}
type domainEventTag struct{}
type recoveryCodeTag struct{}

// --- Public type aliases ---
type AccountID = ID[accountTag]
type IdentityID = ID[identityTag]
type MembershipID = ID[membershipTag]
type RoleID = ID[roleTag]
type ProductID = ID[productTag]
type LicenseID = ID[licenseTag]
type MachineID = ID[machineTag]
type APIKeyID = ID[apiKeyTag]
type WebhookEndpointID = ID[webhookEndpointTag]
type WebhookEventID = ID[webhookEventTag]
type EnvironmentID = ID[environmentTag]
type InvitationID = ID[invitationTag]
type GrantID = ID[grantTag]
type PolicyID = ID[policyTag]
type CustomerID = ID[customerTag]
type EntitlementID = ID[entitlementTag]
type DomainEventID = ID[domainEventTag]
type RecoveryCodeID = ID[recoveryCodeTag]

// --- Convenience constructors (so callers don't need type params) ---
func NewAccountID() AccountID                          { return NewID[accountTag]() }
func ParseAccountID(s string) (AccountID, error)       { return ParseID[accountTag](s) }
func NewIdentityID() IdentityID                        { return NewID[identityTag]() }
func ParseIdentityID(s string) (IdentityID, error)     { return ParseID[identityTag](s) }
func NewMembershipID() MembershipID                    { return NewID[membershipTag]() }
func ParseMembershipID(s string) (MembershipID, error) { return ParseID[membershipTag](s) }
func NewRoleID() RoleID                                { return NewID[roleTag]() }
func ParseRoleID(s string) (RoleID, error)             { return ParseID[roleTag](s) }
func NewProductID() ProductID                          { return NewID[productTag]() }
func ParseProductID(s string) (ProductID, error)       { return ParseID[productTag](s) }
func NewLicenseID() LicenseID                          { return NewID[licenseTag]() }
func ParseLicenseID(s string) (LicenseID, error)       { return ParseID[licenseTag](s) }
func NewMachineID() MachineID                          { return NewID[machineTag]() }
func ParseMachineID(s string) (MachineID, error)       { return ParseID[machineTag](s) }
func NewAPIKeyID() APIKeyID                            { return NewID[apiKeyTag]() }
func ParseAPIKeyID(s string) (APIKeyID, error)         { return ParseID[apiKeyTag](s) }
func NewWebhookEndpointID() WebhookEndpointID          { return NewID[webhookEndpointTag]() }
func ParseWebhookEndpointID(s string) (WebhookEndpointID, error) {
	return ParseID[webhookEndpointTag](s)
}
func NewWebhookEventID() WebhookEventID                    { return NewID[webhookEventTag]() }
func ParseWebhookEventID(s string) (WebhookEventID, error) { return ParseID[webhookEventTag](s) }
func NewEnvironmentID() EnvironmentID                      { return NewID[environmentTag]() }
func ParseEnvironmentID(s string) (EnvironmentID, error)   { return ParseID[environmentTag](s) }
func NewInvitationID() InvitationID                        { return NewID[invitationTag]() }
func ParseInvitationID(s string) (InvitationID, error)     { return ParseID[invitationTag](s) }
func NewGrantID() GrantID                                  { return NewID[grantTag]() }
func ParseGrantID(s string) (GrantID, error)               { return ParseID[grantTag](s) }
func NewPolicyID() PolicyID                                { return NewID[policyTag]() }
func ParsePolicyID(s string) (PolicyID, error)             { return ParseID[policyTag](s) }
func NewCustomerID() CustomerID                            { return NewID[customerTag]() }
func ParseCustomerID(s string) (CustomerID, error)         { return ParseID[customerTag](s) }
func NewEntitlementID() EntitlementID                      { return NewID[entitlementTag]() }
func ParseEntitlementID(s string) (EntitlementID, error)   { return ParseID[entitlementTag](s) }
func NewDomainEventID() DomainEventID                      { return NewID[domainEventTag]() }
func ParseDomainEventID(s string) (DomainEventID, error)   { return ParseID[domainEventTag](s) }
func NewRecoveryCodeID() RecoveryCodeID                    { return NewID[recoveryCodeTag]() }
func ParseRecoveryCodeID(s string) (RecoveryCodeID, error) { return ParseID[recoveryCodeTag](s) }
