package core

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
