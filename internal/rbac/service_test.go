package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

func TestChecker_Can_ReturnsTrueForGrantedPermission(t *testing.T) {
	role := &domain.Role{
		Slug:        "admin",
		Permissions: []string{LicenseCreate, LicenseRead},
	}
	c := NewChecker(role)
	assert.True(t, c.Can(LicenseCreate))
	assert.True(t, c.Can(LicenseRead))
	assert.False(t, c.Can(BillingManage))
}

func TestChecker_Can_NilRoleDeniesAll(t *testing.T) {
	c := NewChecker(nil)
	assert.False(t, c.Can(LicenseCreate))
}

func TestChecker_Require_ReturnsErrorWhenDenied(t *testing.T) {
	role := &domain.Role{Slug: "read_only", Permissions: []string{LicenseRead}}
	c := NewChecker(role)
	assert.NoError(t, c.Require(LicenseRead))

	err := c.Require(LicenseCreate)
	var appErr *core.AppError
	assert.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPermissionDenied, appErr.Code)
}

func TestChecker_Role_ReturnsUnderlying(t *testing.T) {
	role := &domain.Role{Slug: "admin"}
	c := NewChecker(role)
	assert.Same(t, role, c.Role())
}

func TestChecker_Role_NilWhenNoRole(t *testing.T) {
	c := NewChecker(nil)
	assert.Nil(t, c.Role())
}
