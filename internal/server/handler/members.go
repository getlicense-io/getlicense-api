package handler

import (
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/membership"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// MemberHandler serves the team-page member listing.
type MemberHandler struct {
	svc *membership.Service
}

// NewMemberHandler constructs a MemberHandler wired to the membership service.
func NewMemberHandler(svc *membership.Service) *MemberHandler {
	return &MemberHandler{svc: svc}
}

// List returns a cursor-paginated list of members for the path account.
// The path :account_id MUST equal the caller's acting account
// (requirePathAccountMatch returns 422 validation_error otherwise — the
// rbac.UserList gate already prevents arbitrary callers from probing
// foreign accounts, so there is no existence-leak vector to defend
// against here).
//
// Permission: rbac.UserList. Distribution matches every other read
// permission in the codebase (owner, admin, developer, operator, read_only).
//
// Route: GET /v1/accounts/:account_id/members
func (h *MemberHandler) List(c fiber.Ctx) error {
	auth, err := authz(c, rbac.UserList)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	rows, hasMore, err := h.svc.List(c.Context(), auth.TargetAccountID, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(rows, hasMore, func(m domain.MembershipDetail) core.Cursor {
		return core.Cursor{CreatedAt: m.CreatedAt, ID: uuid.UUID(m.MembershipID)}
	}))
}
