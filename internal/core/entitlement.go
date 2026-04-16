package core

import "github.com/google/uuid"

// EntitlementID is a typed UUID v7 for entitlements.
type EntitlementID uuid.UUID

// NewEntitlementID generates a new EntitlementID using UUID v7.
func NewEntitlementID() EntitlementID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate EntitlementID: " + err.Error())
	}
	return EntitlementID(id)
}

// ParseEntitlementID parses a UUID string into an EntitlementID.
func ParseEntitlementID(s string) (EntitlementID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return EntitlementID{}, err
	}
	return EntitlementID(id), nil
}

// String returns the string representation of the EntitlementID.
func (id EntitlementID) String() string { return uuid.UUID(id).String() }

// MarshalText implements encoding.TextMarshaler (used by JSON).
func (id EntitlementID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler (used by JSON).
func (id *EntitlementID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = EntitlementID(u)
	return nil
}
