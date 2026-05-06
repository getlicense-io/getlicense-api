package rbac

import (
	"testing"
)

// presetSeedPermissions is the static union of what the preset role
// seed migrations (016_memberships_and_roles.sql + later additive
// updates like 038_channels.sql) put onto the `owner`, `admin`,
// `developer`, `operator`, `read_only` rows. Keep this in sync with
// the migrations. If you change one, change the other.
//
// The test below asserts that every Permission constant declared in
// rbac.All() appears at least once in this set. A permission not
// assigned to any preset role is dead weight that no one can exercise.
var presetSeedPermissions = map[string]bool{
	// owner + admin coverage
	LicenseCreate:     true,
	LicenseRead:       true,
	LicenseUpdate:     true,
	LicenseSuspend:    true,
	LicenseRevoke:     true,
	MachineRead:       true,
	MachineDeactivate: true,
	ProductCreate:     true,
	ProductRead:       true,
	ProductUpdate:     true,
	ProductDelete:     true,
	PolicyRead:        true,
	PolicyWrite:       true,
	PolicyDelete:      true,
	CustomerRead:      true,
	CustomerWrite:     true,
	CustomerDelete:    true,
	EntitlementRead:   true,
	EntitlementWrite:  true,
	EntitlementDelete: true,
	APIKeyCreate:      true,
	APIKeyRead:        true,
	APIKeyRevoke:      true,
	WebhookCreate:     true,
	WebhookRead:       true,
	WebhookUpdate:     true,
	WebhookDelete:     true,
	EnvironmentCreate: true,
	EnvironmentRead:   true,
	EnvironmentDelete: true,
	UserInvite:        true,
	UserRemove:        true,
	UserChangeRole:    true,
	UserList:          true,
	GrantIssue:        true,
	GrantRevoke:       true,
	GrantAccept:       true,
	GrantUse:          true,
	GrantUpdate:       true,
	ChannelRead:       true,
	ChannelCreate:     true,
	ChannelManage:     true,
	MetricsRead:       true,
	EventsRead:        true,
	BillingRead:       true,
	BillingManage:     true,
	AccountUpdate:     true,
	AccountDelete:     true,
}

func TestPresetSeed_CoversAllDeclaredPermissions(t *testing.T) {
	for _, p := range All() {
		if !presetSeedPermissions[p] {
			t.Errorf("permission %q exists in rbac.All() but is not covered by any preset role in migration 016_memberships_and_roles.sql. Either add it to a preset or update presetSeedPermissions in this test.", p)
		}
	}
}

// Sanity check: the test table only contains known permissions. If
// this fails, presetSeedPermissions has a typo that isn't in All().
func TestPresetSeed_HasNoUnknownPermissions(t *testing.T) {
	known := map[string]bool{}
	for _, p := range All() {
		known[p] = true
	}
	for p := range presetSeedPermissions {
		if !known[p] {
			t.Errorf("presetSeedPermissions contains %q which is not in rbac.All()", p)
		}
	}
}
