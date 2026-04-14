package core

import "github.com/google/uuid"

// AccountID is a typed UUID v7 for accounts.
type AccountID uuid.UUID

// NewAccountID generates a new AccountID using UUID v7.
func NewAccountID() AccountID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate AccountID: " + err.Error())
	}
	return AccountID(id)
}

// ParseAccountID parses a UUID string into an AccountID.
func ParseAccountID(s string) (AccountID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return AccountID{}, err
	}
	return AccountID(id), nil
}

// String returns the string representation of the AccountID.
func (id AccountID) String() string { return uuid.UUID(id).String() }

// MarshalText implements encoding.TextMarshaler (used by JSON).
func (id AccountID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler (used by JSON).
func (id *AccountID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = AccountID(u)
	return nil
}

// UserID is a typed UUID v7 for users.
type UserID uuid.UUID

// NewUserID generates a new UserID using UUID v7.
func NewUserID() UserID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate UserID: " + err.Error())
	}
	return UserID(id)
}

// ParseUserID parses a UUID string into a UserID.
func ParseUserID(s string) (UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return UserID{}, err
	}
	return UserID(id), nil
}

func (id UserID) String() string                  { return uuid.UUID(id).String() }
func (id UserID) MarshalText() ([]byte, error)    { return uuid.UUID(id).MarshalText() }
func (id *UserID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = UserID(u)
	return nil
}

// ProductID is a typed UUID v7 for products.
type ProductID uuid.UUID

// NewProductID generates a new ProductID using UUID v7.
func NewProductID() ProductID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate ProductID: " + err.Error())
	}
	return ProductID(id)
}

// ParseProductID parses a UUID string into a ProductID.
func ParseProductID(s string) (ProductID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return ProductID{}, err
	}
	return ProductID(id), nil
}

func (id ProductID) String() string                  { return uuid.UUID(id).String() }
func (id ProductID) MarshalText() ([]byte, error)    { return uuid.UUID(id).MarshalText() }
func (id *ProductID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = ProductID(u)
	return nil
}

// LicenseID is a typed UUID v7 for licenses.
type LicenseID uuid.UUID

// NewLicenseID generates a new LicenseID using UUID v7.
func NewLicenseID() LicenseID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate LicenseID: " + err.Error())
	}
	return LicenseID(id)
}

// ParseLicenseID parses a UUID string into a LicenseID.
func ParseLicenseID(s string) (LicenseID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return LicenseID{}, err
	}
	return LicenseID(id), nil
}

func (id LicenseID) String() string                  { return uuid.UUID(id).String() }
func (id LicenseID) MarshalText() ([]byte, error)    { return uuid.UUID(id).MarshalText() }
func (id *LicenseID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = LicenseID(u)
	return nil
}

// MachineID is a typed UUID v7 for machines.
type MachineID uuid.UUID

// NewMachineID generates a new MachineID using UUID v7.
func NewMachineID() MachineID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate MachineID: " + err.Error())
	}
	return MachineID(id)
}

// ParseMachineID parses a UUID string into a MachineID.
func ParseMachineID(s string) (MachineID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return MachineID{}, err
	}
	return MachineID(id), nil
}

func (id MachineID) String() string                  { return uuid.UUID(id).String() }
func (id MachineID) MarshalText() ([]byte, error)    { return uuid.UUID(id).MarshalText() }
func (id *MachineID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = MachineID(u)
	return nil
}

// APIKeyID is a typed UUID v7 for API keys.
type APIKeyID uuid.UUID

// NewAPIKeyID generates a new APIKeyID using UUID v7.
func NewAPIKeyID() APIKeyID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate APIKeyID: " + err.Error())
	}
	return APIKeyID(id)
}

// ParseAPIKeyID parses a UUID string into an APIKeyID.
func ParseAPIKeyID(s string) (APIKeyID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return APIKeyID{}, err
	}
	return APIKeyID(id), nil
}

func (id APIKeyID) String() string                  { return uuid.UUID(id).String() }
func (id APIKeyID) MarshalText() ([]byte, error)    { return uuid.UUID(id).MarshalText() }
func (id *APIKeyID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = APIKeyID(u)
	return nil
}

// WebhookEndpointID is a typed UUID v7 for webhook endpoints.
type WebhookEndpointID uuid.UUID

// NewWebhookEndpointID generates a new WebhookEndpointID using UUID v7.
func NewWebhookEndpointID() WebhookEndpointID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate WebhookEndpointID: " + err.Error())
	}
	return WebhookEndpointID(id)
}

// ParseWebhookEndpointID parses a UUID string into a WebhookEndpointID.
func ParseWebhookEndpointID(s string) (WebhookEndpointID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return WebhookEndpointID{}, err
	}
	return WebhookEndpointID(id), nil
}

func (id WebhookEndpointID) String() string               { return uuid.UUID(id).String() }
func (id WebhookEndpointID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *WebhookEndpointID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = WebhookEndpointID(u)
	return nil
}

// WebhookEventID is a typed UUID v7 for webhook events.
type WebhookEventID uuid.UUID

// NewWebhookEventID generates a new WebhookEventID using UUID v7.
func NewWebhookEventID() WebhookEventID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate WebhookEventID: " + err.Error())
	}
	return WebhookEventID(id)
}

// ParseWebhookEventID parses a UUID string into a WebhookEventID.
func ParseWebhookEventID(s string) (WebhookEventID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return WebhookEventID{}, err
	}
	return WebhookEventID(id), nil
}

func (id WebhookEventID) String() string               { return uuid.UUID(id).String() }
func (id WebhookEventID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *WebhookEventID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = WebhookEventID(u)
	return nil
}

// EnvironmentID is a typed UUID v7 for environments. It identifies a
// row in the `environments` metadata table; tenant-scoped data rows
// still reference environments by slug, not by ID.
type EnvironmentID uuid.UUID

// NewEnvironmentID generates a new EnvironmentID using UUID v7.
func NewEnvironmentID() EnvironmentID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate EnvironmentID: " + err.Error())
	}
	return EnvironmentID(id)
}

// ParseEnvironmentID parses a UUID string into an EnvironmentID.
func ParseEnvironmentID(s string) (EnvironmentID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return EnvironmentID{}, err
	}
	return EnvironmentID(id), nil
}

func (id EnvironmentID) String() string               { return uuid.UUID(id).String() }
func (id EnvironmentID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *EnvironmentID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = EnvironmentID(u)
	return nil
}

// IdentityID is a typed UUID v7 for global login identities.
type IdentityID uuid.UUID

// NewIdentityID generates a new IdentityID using UUID v7.
func NewIdentityID() IdentityID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate IdentityID: " + err.Error())
	}
	return IdentityID(id)
}

// ParseIdentityID parses a UUID string into an IdentityID.
func ParseIdentityID(s string) (IdentityID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return IdentityID{}, err
	}
	return IdentityID(id), nil
}

func (id IdentityID) String() string               { return uuid.UUID(id).String() }
func (id IdentityID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *IdentityID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = IdentityID(u)
	return nil
}

// MembershipID is a typed UUID v7 for account memberships.
type MembershipID uuid.UUID

// NewMembershipID generates a new MembershipID using UUID v7.
func NewMembershipID() MembershipID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate MembershipID: " + err.Error())
	}
	return MembershipID(id)
}

// ParseMembershipID parses a UUID string into a MembershipID.
func ParseMembershipID(s string) (MembershipID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return MembershipID{}, err
	}
	return MembershipID(id), nil
}

func (id MembershipID) String() string               { return uuid.UUID(id).String() }
func (id MembershipID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *MembershipID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = MembershipID(u)
	return nil
}

// RoleID is a typed UUID v7 for roles (preset or custom).
type RoleID uuid.UUID

// NewRoleID generates a new RoleID using UUID v7.
func NewRoleID() RoleID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate RoleID: " + err.Error())
	}
	return RoleID(id)
}

// ParseRoleID parses a UUID string into a RoleID.
func ParseRoleID(s string) (RoleID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return RoleID{}, err
	}
	return RoleID(id), nil
}

func (id RoleID) String() string               { return uuid.UUID(id).String() }
func (id RoleID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *RoleID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = RoleID(u)
	return nil
}

// InvitationID is a typed UUID v7 for invitations.
type InvitationID uuid.UUID

// NewInvitationID generates a new InvitationID using UUID v7.
func NewInvitationID() InvitationID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate InvitationID: " + err.Error())
	}
	return InvitationID(id)
}

// ParseInvitationID parses a UUID string into an InvitationID.
func ParseInvitationID(s string) (InvitationID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return InvitationID{}, err
	}
	return InvitationID(id), nil
}

func (id InvitationID) String() string               { return uuid.UUID(id).String() }
func (id InvitationID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *InvitationID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = InvitationID(u)
	return nil
}

// GrantID is a typed UUID v7 for reseller grants.
type GrantID uuid.UUID

// NewGrantID generates a new GrantID using UUID v7.
func NewGrantID() GrantID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate GrantID: " + err.Error())
	}
	return GrantID(id)
}

// ParseGrantID parses a UUID string into a GrantID.
func ParseGrantID(s string) (GrantID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return GrantID{}, err
	}
	return GrantID(id), nil
}

func (id GrantID) String() string               { return uuid.UUID(id).String() }
func (id GrantID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *GrantID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = GrantID(u)
	return nil
}
