package rbac

import (
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Checker decides whether a given role may perform a permission. One
// Checker is built per request by middleware from the authenticated
// identity's membership role (or from an API key's synthetic role).
type Checker struct {
	role *domain.Role
	set  map[string]struct{}
}

// NewChecker builds a Checker from a role. A nil role denies everything
// — this is the safe default when the caller hasn't been authorized.
func NewChecker(role *domain.Role) *Checker {
	c := &Checker{role: role, set: map[string]struct{}{}}
	if role != nil {
		for _, p := range role.Permissions {
			c.set[p] = struct{}{}
		}
	}
	return c
}

// Can reports whether the role grants the given permission.
func (c *Checker) Can(perm Permission) bool {
	_, ok := c.set[perm]
	return ok
}

// Require returns a typed ErrPermissionDenied error if the role does
// not grant the permission. Handlers call this as the first line after
// extracting the auth context.
func (c *Checker) Require(perm Permission) error {
	if !c.Can(perm) {
		return core.NewAppError(core.ErrPermissionDenied, "Permission denied: "+perm)
	}
	return nil
}

// Role returns the underlying role or nil.
func (c *Checker) Role() *domain.Role {
	return c.role
}
