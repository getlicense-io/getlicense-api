package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLicenseTypeValid(t *testing.T) {
	tests := []struct {
		input    string
		expected LicenseType
	}{
		{"perpetual", LicenseTypePerpetual},
		{"timed", LicenseTypeTimed},
		{"subscription", LicenseTypeSubscription},
		{"trial", LicenseTypeTrial},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			lt, err := ParseLicenseType(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, lt)
		})
	}
}

func TestParseLicenseTypeInvalid(t *testing.T) {
	_, err := ParseLicenseType("unknown")
	assert.Error(t, err)
}

func TestLicenseTypeJSONRoundtrip(t *testing.T) {
	lt := LicenseTypeSubscription
	b, err := json.Marshal(lt)
	require.NoError(t, err)

	var parsed LicenseType
	require.NoError(t, json.Unmarshal(b, &parsed))
	assert.Equal(t, lt, parsed)
}

func TestLicenseStatusCanSuspend(t *testing.T) {
	assert.True(t, LicenseStatusActive.CanSuspend())
	assert.False(t, LicenseStatusInactive.CanSuspend())
	assert.False(t, LicenseStatusSuspended.CanSuspend())
	assert.False(t, LicenseStatusRevoked.CanSuspend())
	assert.False(t, LicenseStatusExpired.CanSuspend())
}

func TestLicenseStatusCanRevoke(t *testing.T) {
	assert.True(t, LicenseStatusActive.CanRevoke())
	assert.True(t, LicenseStatusSuspended.CanRevoke())
	assert.False(t, LicenseStatusInactive.CanRevoke())
	assert.False(t, LicenseStatusRevoked.CanRevoke())
	assert.False(t, LicenseStatusExpired.CanRevoke())
}

func TestLicenseStatusCanReinstate(t *testing.T) {
	assert.True(t, LicenseStatusSuspended.CanReinstate())
	assert.False(t, LicenseStatusActive.CanReinstate())
	assert.False(t, LicenseStatusInactive.CanReinstate())
	assert.False(t, LicenseStatusRevoked.CanReinstate())
	assert.False(t, LicenseStatusExpired.CanReinstate())
}

func TestUserRoleAtLeast(t *testing.T) {
	assert.True(t, UserRoleOwner.AtLeast(UserRoleOwner))
	assert.True(t, UserRoleOwner.AtLeast(UserRoleAdmin))
	assert.True(t, UserRoleOwner.AtLeast(UserRoleMember))

	assert.False(t, UserRoleAdmin.AtLeast(UserRoleOwner))
	assert.True(t, UserRoleAdmin.AtLeast(UserRoleAdmin))
	assert.True(t, UserRoleAdmin.AtLeast(UserRoleMember))

	assert.False(t, UserRoleMember.AtLeast(UserRoleOwner))
	assert.False(t, UserRoleMember.AtLeast(UserRoleAdmin))
	assert.True(t, UserRoleMember.AtLeast(UserRoleMember))
}

func TestEventTypeValues(t *testing.T) {
	events := []EventType{
		EventTypeLicenseCreated,
		EventTypeLicenseUpdated,
		EventTypeLicenseActivated,
		EventTypeLicenseValidated,
		EventTypeLicenseSuspended,
		EventTypeLicenseRevoked,
		EventTypeLicenseExpired,
		EventTypeMachineActivated,
		EventTypeMachineDeactivated,
	}

	expected := []string{
		"license.created",
		"license.updated",
		"license.activated",
		"license.validated",
		"license.suspended",
		"license.revoked",
		"license.expired",
		"machine.activated",
		"machine.deactivated",
	}

	for i, ev := range events {
		assert.Equal(t, expected[i], string(ev))
	}
}

func TestAPIKeyPrefixConstants(t *testing.T) {
	assert.Equal(t, "gl_live_", APIKeyPrefixLive)
	assert.Equal(t, "gl_test_", APIKeyPrefixTest)
	assert.Equal(t, "rt_", RefreshTokenPrefix)
}

func TestDeliveryStatusValues(t *testing.T) {
	assert.Equal(t, DeliveryStatus("pending"), DeliveryStatusPending)
	assert.Equal(t, DeliveryStatus("delivered"), DeliveryStatusDelivered)
	assert.Equal(t, DeliveryStatus("failed"), DeliveryStatusFailed)
}

func TestAPIKeyScopeValues(t *testing.T) {
	assert.Equal(t, APIKeyScope("account_wide"), APIKeyScopeAccountWide)
	assert.Equal(t, APIKeyScope("product"), APIKeyScopeProduct)
}
