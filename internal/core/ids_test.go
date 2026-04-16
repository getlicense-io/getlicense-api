package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIDGeneration(t *testing.T) {
	ids := []struct {
		name string
		gen  func() string
	}{
		{"AccountID", func() string { return NewAccountID().String() }},
		{"ProductID", func() string { return NewProductID().String() }},
		{"LicenseID", func() string { return NewLicenseID().String() }},
		{"MachineID", func() string { return NewMachineID().String() }},
		{"APIKeyID", func() string { return NewAPIKeyID().String() }},
		{"WebhookEndpointID", func() string { return NewWebhookEndpointID().String() }},
		{"WebhookEventID", func() string { return NewWebhookEventID().String() }},
		{"IdentityID", func() string { return NewIdentityID().String() }},
		{"MembershipID", func() string { return NewMembershipID().String() }},
		{"RoleID", func() string { return NewRoleID().String() }},
		{"InvitationID", func() string { return NewInvitationID().String() }},
		{"GrantID", func() string { return NewGrantID().String() }},
		{"PolicyID", func() string { return NewPolicyID().String() }},
		{"CustomerID", func() string { return NewCustomerID().String() }},
		{"EntitlementID", func() string { return NewEntitlementID().String() }},
		{"DomainEventID", func() string { return NewDomainEventID().String() }},
		{"EnvironmentID", func() string { return NewEnvironmentID().String() }},
	}

	for _, tt := range ids {
		t.Run(tt.name, func(t *testing.T) {
			id := tt.gen()
			assert.NotEmpty(t, id)
			// UUIDs are 36 chars with hyphens
			assert.Len(t, id, 36)
		})
	}
}

func TestIDUniqueness(t *testing.T) {
	id1 := NewLicenseID()
	id2 := NewLicenseID()
	assert.NotEqual(t, id1, id2)
}

func TestIDJSONRoundtrip(t *testing.T) {
	original := NewLicenseID()
	b, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed LicenseID
	require.NoError(t, json.Unmarshal(b, &parsed))
	assert.Equal(t, original, parsed)
}

func TestIDParseValid(t *testing.T) {
	original := NewAccountID()
	str := original.String()

	parsed, err := ParseAccountID(str)
	require.NoError(t, err)
	assert.Equal(t, original, parsed)
}

func TestIDParseInvalid(t *testing.T) {
	_, err := ParseAccountID("not-a-uuid")
	assert.Error(t, err)
}

func TestIDJSONMarshalQuoted(t *testing.T) {
	id := NewProductID()
	b, err := json.Marshal(id)
	require.NoError(t, err)
	// JSON output should be a quoted string
	var s string
	require.NoError(t, json.Unmarshal(b, &s))
	assert.Equal(t, id.String(), s)
}
