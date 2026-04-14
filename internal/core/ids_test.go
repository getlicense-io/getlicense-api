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
		{"UserID", func() string { return NewUserID().String() }},
		{"ProductID", func() string { return NewProductID().String() }},
		{"LicenseID", func() string { return NewLicenseID().String() }},
		{"MachineID", func() string { return NewMachineID().String() }},
		{"APIKeyID", func() string { return NewAPIKeyID().String() }},
		{"WebhookEndpointID", func() string { return NewWebhookEndpointID().String() }},
		{"WebhookEventID", func() string { return NewWebhookEventID().String() }},
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

func TestAllIDParseRoundtrips(t *testing.T) {
	t.Run("UserID", func(t *testing.T) {
		id := NewUserID()
		parsed, err := ParseUserID(id.String())
		require.NoError(t, err)
		assert.Equal(t, id, parsed)
	})
	t.Run("ProductID", func(t *testing.T) {
		id := NewProductID()
		parsed, err := ParseProductID(id.String())
		require.NoError(t, err)
		assert.Equal(t, id, parsed)
	})
	t.Run("LicenseID", func(t *testing.T) {
		id := NewLicenseID()
		parsed, err := ParseLicenseID(id.String())
		require.NoError(t, err)
		assert.Equal(t, id, parsed)
	})
	t.Run("MachineID", func(t *testing.T) {
		id := NewMachineID()
		parsed, err := ParseMachineID(id.String())
		require.NoError(t, err)
		assert.Equal(t, id, parsed)
	})
	t.Run("APIKeyID", func(t *testing.T) {
		id := NewAPIKeyID()
		parsed, err := ParseAPIKeyID(id.String())
		require.NoError(t, err)
		assert.Equal(t, id, parsed)
	})
	t.Run("WebhookEndpointID", func(t *testing.T) {
		id := NewWebhookEndpointID()
		parsed, err := ParseWebhookEndpointID(id.String())
		require.NoError(t, err)
		assert.Equal(t, id, parsed)
	})
	t.Run("WebhookEventID", func(t *testing.T) {
		id := NewWebhookEventID()
		parsed, err := ParseWebhookEventID(id.String())
		require.NoError(t, err)
		assert.Equal(t, id, parsed)
	})
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

func TestIdentityID_RoundTrip(t *testing.T) {
	id := NewIdentityID()
	parsed, err := ParseIdentityID(id.String())
	require.NoError(t, err)
	assert.Equal(t, id, parsed)
}

func TestMembershipID_RoundTrip(t *testing.T) {
	id := NewMembershipID()
	parsed, err := ParseMembershipID(id.String())
	require.NoError(t, err)
	assert.Equal(t, id, parsed)
}

func TestRoleID_RoundTrip(t *testing.T) {
	id := NewRoleID()
	parsed, err := ParseRoleID(id.String())
	require.NoError(t, err)
	assert.Equal(t, id, parsed)
}

func TestInvitationID_RoundTrip(t *testing.T) {
	id := NewInvitationID()
	parsed, err := ParseInvitationID(id.String())
	require.NoError(t, err)
	assert.Equal(t, id, parsed)
}

func TestGrantID_RoundTrip(t *testing.T) {
	id := NewGrantID()
	parsed, err := ParseGrantID(id.String())
	require.NoError(t, err)
	assert.Equal(t, id, parsed)
}
