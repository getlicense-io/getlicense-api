package audit

import (
	"encoding/json"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Attribution carries the caller identity extracted from the request
// auth context. Handlers populate it from middleware.AuthContext and
// pass it through the service layer so audit.Writer can stamp events
// without depending on the HTTP middleware package.
type Attribution struct {
	AccountID       core.AccountID
	Environment     core.Environment
	ActingAccountID *core.AccountID
	IdentityID      *core.IdentityID
	ActorKind       core.ActorKind
	ActorLabel      string
	APIKeyID        *core.APIKeyID
	GrantID         *core.GrantID
	RequestID       *string
	IPAddress       *string
}

// EventFrom builds a DomainEvent from attribution details and event
// metadata. It does NOT stamp ID or CreatedAt — Writer.Record does
// that so events receive a monotonic UUID v7 at write time.
func EventFrom(attr Attribution, eventType core.EventType, resourceType, resourceID string, payload json.RawMessage) domain.DomainEvent {
	var resID *string
	if resourceID != "" {
		resID = &resourceID
	}
	return domain.DomainEvent{
		AccountID:       attr.AccountID,
		Environment:     attr.Environment,
		EventType:       eventType,
		ResourceType:    resourceType,
		ResourceID:      resID,
		ActingAccountID: attr.ActingAccountID,
		IdentityID:      attr.IdentityID,
		ActorLabel:      attr.ActorLabel,
		ActorKind:       attr.ActorKind,
		APIKeyID:        attr.APIKeyID,
		GrantID:         attr.GrantID,
		RequestID:       attr.RequestID,
		IPAddress:       attr.IPAddress,
		Payload:         payload,
	}
}
