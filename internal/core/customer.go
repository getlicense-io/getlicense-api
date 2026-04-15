package core

import "github.com/google/uuid"

// CustomerID is a typed UUID v7 for customers.
type CustomerID uuid.UUID

// NewCustomerID generates a new CustomerID using UUID v7.
func NewCustomerID() CustomerID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate CustomerID: " + err.Error())
	}
	return CustomerID(id)
}

// ParseCustomerID parses a UUID string into a CustomerID.
func ParseCustomerID(s string) (CustomerID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return CustomerID{}, err
	}
	return CustomerID(id), nil
}

// String returns the string representation of the CustomerID.
func (id CustomerID) String() string { return uuid.UUID(id).String() }

// MarshalText implements encoding.TextMarshaler (used by JSON).
func (id CustomerID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler (used by JSON).
func (id *CustomerID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = CustomerID(u)
	return nil
}
