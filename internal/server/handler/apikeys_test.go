package handler

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

func TestNormalizeAPIKeyPermissions_DefaultsToCallerRole(t *testing.T) {
	req := auth.CreateAPIKeyRequest{}
	role := &domain.Role{Permissions: []string{rbac.APIKeyCreate, rbac.ProductRead}}

	require.NoError(t, normalizeAPIKeyPermissions(&req, role))

	assert.Equal(t, []string{rbac.APIKeyCreate, rbac.ProductRead}, req.Permissions)
	req.Permissions[0] = rbac.BillingManage
	assert.Equal(t, rbac.APIKeyCreate, role.Permissions[0], "normalization must not alias role permissions")
}

func TestNormalizeAPIKeyPermissions_RejectsPermissionCallerDoesNotHave(t *testing.T) {
	req := auth.CreateAPIKeyRequest{Permissions: []string{rbac.BillingManage}}
	role := &domain.Role{Permissions: []string{rbac.APIKeyCreate}}

	err := normalizeAPIKeyPermissions(&req, role)

	var appErr *core.AppError
	require.True(t, errors.As(err, &appErr))
	assert.Equal(t, core.ErrPermissionDenied, appErr.Code)
}

func TestNormalizeAPIKeyPermissions_RejectsUnknownPermission(t *testing.T) {
	req := auth.CreateAPIKeyRequest{Permissions: []string{"root:everything"}}
	role := &domain.Role{Permissions: []string{rbac.APIKeyCreate, "root:everything"}}

	err := normalizeAPIKeyPermissions(&req, role)

	var appErr *core.AppError
	require.True(t, errors.As(err, &appErr))
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}
