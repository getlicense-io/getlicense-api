package core

import "github.com/google/uuid"

// DomainEventID is a typed UUID v7 for domain events.
type DomainEventID uuid.UUID

// NewDomainEventID generates a new DomainEventID using UUID v7.
func NewDomainEventID() DomainEventID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate DomainEventID: " + err.Error())
	}
	return DomainEventID(id)
}

// ParseDomainEventID parses a UUID string into a DomainEventID.
func ParseDomainEventID(s string) (DomainEventID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return DomainEventID{}, err
	}
	return DomainEventID(id), nil
}

func (id DomainEventID) String() string               { return uuid.UUID(id).String() }
func (id DomainEventID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }
func (id *DomainEventID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = DomainEventID(u)
	return nil
}

// ActorKind identifies how an actor authenticated when producing an event.
type ActorKind string

const (
	ActorKindIdentity ActorKind = "identity"
	ActorKindAPIKey   ActorKind = "api_key"
	ActorKindSystem   ActorKind = "system"
	ActorKindPublic   ActorKind = "public"
)

// IsValid reports whether k is one of the known actor kinds.
func (k ActorKind) IsValid() bool {
	switch k {
	case ActorKindIdentity, ActorKindAPIKey, ActorKindSystem, ActorKindPublic:
		return true
	default:
		return false
	}
}
