package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// roleWith builds a synthetic *domain.Role with the supplied permission
// list. Uses a fresh role id and a synthetic slug so two roles built in
// the same test never collide on identity equality.
func roleWith(perms ...rbac.Permission) *domain.Role {
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = string(p)
	}
	return &domain.Role{
		ID:          core.NewRoleID(),
		Slug:        "test-role",
		Name:        "Test Role",
		Permissions: out,
	}
}

func TestApplyInvitationListPermissions_OwnerSeesAllKinds(t *testing.T) {
	// Owner-equivalent role has both kind permissions; nothing should be
	// gated and no kind filter should be auto-narrowed.
	role := roleWith(rbac.UserInvite, rbac.UserList, rbac.GrantIssue, rbac.GrantUse)
	identity := core.NewIdentityID()
	filter := domain.InvitationListFilter{}

	returnEmpty := applyInvitationListPermissions(&filter, role, &identity)

	assert.False(t, returnEmpty)
	assert.Nil(t, filter.Kind, "no narrowing when caller can see both kinds")
	assert.Nil(t, filter.CreatedByIdentityID, "owner sees all rows, not just own")
}

func TestApplyInvitationListPermissions_DeveloperSeesMembershipNarrowsKind(t *testing.T) {
	// developer (post-migration 030) carries user:list but not grant:issue
	// or grant:use. With no explicit kind filter, the helper should narrow
	// to membership-kind so the repo never returns grant rows.
	role := roleWith(rbac.UserList)
	identity := core.NewIdentityID()
	filter := domain.InvitationListFilter{}

	returnEmpty := applyInvitationListPermissions(&filter, role, &identity)

	assert.False(t, returnEmpty)
	if assert.NotNil(t, filter.Kind, "should narrow to membership kind") {
		assert.Equal(t, domain.InvitationKindMembership, *filter.Kind)
	}
	assert.Nil(t, filter.CreatedByIdentityID, "membership side is fully visible — no own-only narrowing")
}

func TestApplyInvitationListPermissions_DeveloperRequestingGrantKindGatedToOwn(t *testing.T) {
	// developer asking explicitly for grant kind: lacks both grant
	// permissions, so own-only narrowing kicks in.
	role := roleWith(rbac.UserList)
	identity := core.NewIdentityID()
	kind := domain.InvitationKindGrant
	filter := domain.InvitationListFilter{Kind: &kind}

	returnEmpty := applyInvitationListPermissions(&filter, role, &identity)

	assert.False(t, returnEmpty)
	if assert.NotNil(t, filter.CreatedByIdentityID) {
		assert.Equal(t, identity, *filter.CreatedByIdentityID)
	}
	assert.Equal(t, domain.InvitationKindGrant, *filter.Kind, "explicit kind preserved")
}

func TestApplyInvitationListPermissions_OperatorSeesBothBecauseGrantUse(t *testing.T) {
	// operator has user:list (post-030) and grant:use; both kinds visible.
	role := roleWith(rbac.UserList, rbac.GrantUse)
	identity := core.NewIdentityID()
	filter := domain.InvitationListFilter{}

	returnEmpty := applyInvitationListPermissions(&filter, role, &identity)

	assert.False(t, returnEmpty)
	assert.Nil(t, filter.Kind)
	assert.Nil(t, filter.CreatedByIdentityID)
}

func TestApplyInvitationListPermissions_LowPrivilegeRoleNoExplicitKindGatedToOwn(t *testing.T) {
	// A role with neither user:* nor grant:* permissions (e.g. a custom
	// barebones role). No explicit kind filter → both kinds gated → own
	// only, no kind narrowing.
	role := roleWith() // empty permissions
	identity := core.NewIdentityID()
	filter := domain.InvitationListFilter{}

	returnEmpty := applyInvitationListPermissions(&filter, role, &identity)

	assert.False(t, returnEmpty)
	assert.Nil(t, filter.Kind, "both gated → no kind narrowing, just own-only")
	if assert.NotNil(t, filter.CreatedByIdentityID) {
		assert.Equal(t, identity, *filter.CreatedByIdentityID)
	}
}

func TestApplyInvitationListPermissions_APIKeyWithoutPermissionsReturnsEmpty(t *testing.T) {
	// API-key caller has nil IdentityID. With no kind permissions at
	// all, the helper signals returnEmpty so the handler can short-
	// circuit instead of leaking everything by passing a nil
	// CreatedByIdentityID downstream.
	role := roleWith() // empty permissions
	filter := domain.InvitationListFilter{}

	returnEmpty := applyInvitationListPermissions(&filter, role, nil)

	assert.True(t, returnEmpty, "API-key caller without permissions must short-circuit to empty")
}

func TestApplyInvitationListPermissions_APIKeyWithMembershipPermissionNoEmpty(t *testing.T) {
	// An API key minted for a role carrying user:list can see all
	// membership invitations; no own-only gating applies, no need to
	// short-circuit. The helper must also narrow to membership-kind
	// because the API key has nil identity and no own grant rows exist.
	role := roleWith(rbac.UserList)
	filter := domain.InvitationListFilter{}

	returnEmpty := applyInvitationListPermissions(&filter, role, nil)

	assert.False(t, returnEmpty)
	if assert.NotNil(t, filter.Kind) {
		assert.Equal(t, domain.InvitationKindMembership, *filter.Kind)
	}
}

func TestApplyInvitationListPermissions_NilRoleNilIdentityReturnsEmpty(t *testing.T) {
	// Defense in depth: if somehow auth.Role is nil (unauthenticated
	// shouldn't have reached this handler, but the helper must handle
	// it without panicking) and identity is also nil, return empty.
	filter := domain.InvitationListFilter{}

	returnEmpty := applyInvitationListPermissions(&filter, nil, nil)

	assert.True(t, returnEmpty)
}

func TestApplyInvitationListPermissions_OperatorRequestingMembershipNotGated(t *testing.T) {
	// operator (user:list + grant:use) asking for membership kind:
	// fully visible, no own-only narrowing.
	role := roleWith(rbac.UserList, rbac.GrantUse)
	identity := core.NewIdentityID()
	kind := domain.InvitationKindMembership
	filter := domain.InvitationListFilter{Kind: &kind}

	returnEmpty := applyInvitationListPermissions(&filter, role, &identity)

	assert.False(t, returnEmpty)
	assert.Nil(t, filter.CreatedByIdentityID)
	assert.Equal(t, domain.InvitationKindMembership, *filter.Kind)
}
